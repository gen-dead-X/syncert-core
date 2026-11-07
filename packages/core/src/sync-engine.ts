import { ulid, itemFromWire, itemToWire, type SyncItem } from '@syncert/protocol';
import { decryptItem, encryptItem, type SpaceKeys } from '@syncert/crypto';
import type { PluginRegistry } from './plugin.js';
import type { SyncTransport, TransportState, Unsubscribe } from './transport.js';
import { TransportAuthenticationError } from './websocket-transport.js';

export interface QueuedItem {
  item: SyncItem;
}

export interface SyncEngineState {
  lastItemId: string | null;
  queue: QueuedItem[];
}

export interface SyncEngineOptions {
  spaceId: string;
  deviceId: string;
  keys: SpaceKeys;
  registry: PluginRegistry;
  transport: SyncTransport;
  initialState?: Partial<SyncEngineState>;
  onState?: (state: SyncEngineState) => void;
  onItem?: (kind: string, content: unknown, item: SyncItem) => Promise<void> | void;
  onStatus?: (status: TransportState | 'synced') => void;
  onError?: (error: Error) => void;
  random?: () => number;
  now?: () => number;
}

/** Coordinates encryption, retryable delivery, catch-up and LWW item application. */
export class SyncEngine {
  #queue: QueuedItem[];
  #everStarted = false;
  #lastItemId: string | null;
  #seen = new Set<string>();
  #latestByKind = new Map<string, { createdAt: number; id: string }>();
  #running = false;
  #connecting = false;
  #flushing = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #attempt = 0;
  #unsubscribe: Unsubscribe[] = [];
  #processing: Promise<void> = Promise.resolve();
  #batches: { items: ReturnType<typeof itemToWire>[]; hasMore: boolean }[] = [];
  #batchWaiters = new Set<{
    resolve: (batch: { items: ReturnType<typeof itemToWire>[]; hasMore: boolean }) => void;
    reject: (error: Error) => void;
    timer?: ReturnType<typeof setTimeout>;
  }>();

  constructor(private readonly options: SyncEngineOptions) {
    this.#queue = options.initialState?.queue ?? [];
    this.#lastItemId = options.initialState?.lastItemId ?? null;
  }

  get snapshot(): SyncEngineState {
    return { lastItemId: this.#lastItemId, queue: this.#queue };
  }

  start(): void {
    if (this.#running) return;
    this.#running = true;
    this.#everStarted = true;
    this.#unsubscribe.push(
      this.options.transport.onFrame((frame) => {
        this.#processing = this.#processing
          .then(() => this.#onFrame(frame))
          .catch((error: unknown) => {
            if (this.#running || this.#everStarted) this.#error(error);
          });
      }),
      this.options.transport.onStateChange((state) => {
        this.options.onStatus?.(state);
        if (state === 'closed' && this.#running) this.#schedule();
      }),
    );
    void this.#connect();
  }

  async stop(): Promise<void> {
    this.#running = false;
    this.#everStarted = false;
    for (const waiter of this.#batchWaiters) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error('sync stopped'));
    }
    this.#batchWaiters.clear();
    if (this.#timer) clearTimeout(this.#timer);
    for (const unsubscribe of this.#unsubscribe) unsubscribe();
    this.#unsubscribe = [];
    await this.options.transport.close();
    await this.#processing;
  }

  /** Encrypt and durably enqueue locally first. Network delivery is asynchronous. */
  async publish(kind: string, value: unknown): Promise<SyncItem> {
    const plugin = this.options.registry.get(kind);
    if (!plugin) throw new Error(`no plugin registered for ${kind}`);
    const plaintext = plugin.serialize(value);
    const item = await encryptItem(
      this.options.keys,
      {
        id: ulid(),
        spaceId: this.options.spaceId,
        originDeviceId: this.options.deviceId,
        kind,
        schemaVersion: plugin.schemaVersion,
        createdAt: (this.options.now ?? Date.now)(),
      },
      plaintext,
    );
    if (!this.#queue.some((queued) => queued.item.contentHash === item.contentHash)) {
      this.#queue.push({ item });
      this.#persist();
    }
    await this.options.onItem?.(kind, value, item);
    await this.#flush();
    return item;
  }

  #persist(): void {
    this.options.onState?.(this.snapshot);
  }
  #error(error: unknown): void {
    this.options.onError?.(error instanceof Error ? error : new Error('sync failed'));
  }

  async #connect(): Promise<void> {
    if (!this.#running || this.#connecting || this.options.transport.state === 'open') return;
    this.#connecting = true;
    try {
      await this.options.transport.connect();
      this.#attempt = 0;
      await this.#catchUp();
      await this.#flush();
      this.options.onStatus?.('synced');
    } catch (error) {
      this.#error(error);
      if (error instanceof TransportAuthenticationError) {
        await this.stop();
        return;
      }
      this.#schedule();
    } finally {
      this.#connecting = false;
    }
  }

  #schedule(): void {
    if (!this.#running || this.#timer || this.#connecting) return;
    const delay =
      Math.min(30_000, 500 * 2 ** Math.min(this.#attempt++, 6)) *
      (0.75 + (this.options.random ?? Math.random)() * 0.5);
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      void this.#connect();
    }, delay);
  }

  async #catchUp(): Promise<void> {
    while (this.#running && this.options.transport.state === 'open') {
      const cursor = this.#lastItemId;
      await this.options.transport.send({ type: 'sync.since', lastItemId: cursor });
      // Frame handling is serialized by the subscription above. This promise only sends;
      // a small state barrier is supplied by waitForBatch, not by socket timing guesses.
      const batch = await this.waitForBatch();
      for (const wire of batch.items) await this.#receive(itemFromWire(wire));
      if (!batch.hasMore) break;
    }
  }

  /** Overridable batch hook keeps scheduling deterministic in tests. */
  protected waitForBatch(): Promise<{ items: ReturnType<typeof itemToWire>[]; hasMore: boolean }> {
    const buffered = this.#batches.shift();
    if (buffered) return Promise.resolve(buffered);
    return new Promise((resolve, reject) => {
      const waiter: {
        resolve: (batch: { items: ReturnType<typeof itemToWire>[]; hasMore: boolean }) => void;
        reject: (error: Error) => void;
        timer?: ReturnType<typeof setTimeout>;
      } = { resolve, reject };
      waiter.timer = setTimeout(() => {
        this.#batchWaiters.delete(waiter);
        reject(new Error('sync batch timed out'));
      }, 15_000);
      this.#batchWaiters.add(waiter);
    });
  }

  async #onFrame(frame: { type: string; [key: string]: unknown }): Promise<void> {
    if (frame.type === 'item.new') await this.#receive(itemFromWire(frame.item));
    if (frame.type === 'sync.batch') {
      if (this.#batchWaiters.size === 0) this.#batches.push(frame as never);
      for (const waiter of this.#batchWaiters) {
        clearTimeout(waiter.timer);
        waiter.resolve(frame as never);
      }
      this.#batchWaiters.clear();
    }
    if (frame.type === 'error')
      this.#error(new Error(typeof frame.message === 'string' ? frame.message : 'relay error'));
    if (frame.type === 'item.ack' && typeof frame.id === 'string') {
      this.#queue = this.#queue.filter((entry) => entry.item.id !== frame.id);
      this.#persist();
    }
  }

  async #receive(item: SyncItem): Promise<void> {
    if (this.#seen.has(item.id)) return;
    this.#seen.add(item.id);
    this.#lastItemId = item.id;
    this.#persist();
    if (item.originDeviceId === this.options.deviceId) return;
    const plugin = this.options.registry.get(item.kind);
    if (!plugin) return;
    const latest = this.#latestByKind.get(item.kind);
    if (
      latest &&
      (item.createdAt < latest.createdAt ||
        (item.createdAt === latest.createdAt && item.id < latest.id))
    )
      return;
    try {
      const content = plugin.deserialize(
        await decryptItem(this.options.keys, item),
        item.schemaVersion,
      );
      await plugin.apply({ meta: item, content });
      this.#latestByKind.set(item.kind, { createdAt: item.createdAt, id: item.id });
      await this.options.onItem?.(item.kind, content, item);
    } catch (error) {
      this.#error(error);
    }
  }

  async #flush(): Promise<void> {
    if (this.#flushing || !this.#running || this.options.transport.state !== 'open') return;
    this.#flushing = true;
    try {
      const pending = [...this.#queue];
      for (const entry of pending) {
        if (
          !this.#queue.some((q) => q.item.id === entry.item.id) ||
          this.options.transport.state !== 'open'
        )
          continue;
        await this.options.transport.send({ type: 'item.push', item: itemToWire(entry.item) });
      }
    } catch (error) {
      this.#error(error);
    } finally {
      this.#flushing = false;
    }
  }
}
