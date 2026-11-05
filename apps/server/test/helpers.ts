import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  decryptItem,
  decodePairingPayload,
  encodePairingPayload,
  encryptItem,
  generateSpaceKey,
  importSpaceKey,
  type SpaceKeys,
} from '@syncert/crypto';
import {
  KIND_CLIPBOARD_TEXT,
  PROTOCOL_VERSION,
  decodeServerFrame,
  encodeClientFrame,
  itemFromWire,
  itemToWire,
  ulid,
  utf8Decode,
  utf8Encode,
  type ClientFrame,
  type ServerFrame,
  type WireSyncItem,
} from '@syncert/protocol';
import WebSocket from 'ws';
import type { RelayConfig } from '../src/config.ts';
import { createLogger } from '../src/logger.ts';
import { createRelay, WS_PATH, type Relay } from '../src/server.ts';
import type { Credentials } from '../src/store.ts';

export interface TestRelay {
  relay: Relay;
  baseUrl: string;
  wsUrl: string;
  dir: string;
  dbPath: string;
  logs: string[];
  clock: { now: number };
  stop(): Promise<void>;
}

/** Start a relay on a random port with a fresh temp database and a fake clock. */
export async function startRelay(config: Partial<RelayConfig> = {}): Promise<TestRelay> {
  const dir = mkdtempSync(path.join(tmpdir(), 'syncert-relay-'));
  const dbPath = path.join(dir, 'relay.db');
  const logs: string[] = [];
  const clock = { now: Date.now() };
  const relay = createRelay({
    config: { port: 0, host: '127.0.0.1', dbPath, ...config },
    logger: createLogger('debug', (line) => logs.push(line)),
    now: () => clock.now,
  });
  const { port } = await relay.listen();
  const baseUrl = `http://127.0.0.1:${port}`;
  let stopped = false;
  return {
    relay,
    baseUrl,
    wsUrl: `ws://127.0.0.1:${port}`,
    dir,
    dbPath,
    logs,
    clock,
    async stop() {
      if (stopped) return;
      stopped = true;
      await relay.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

export async function api<T = Record<string, unknown>>(
  t: TestRelay,
  method: string,
  route: string,
  opts: { token?: string; body?: unknown } = {},
): Promise<{ status: number; body: T }> {
  const res = await fetch(t.baseUrl + route, {
    method,
    headers: {
      ...(opts.token && { authorization: `Bearer ${opts.token}` }),
      ...(opts.body !== undefined && { 'content-type': 'application/json' }),
    },
    ...(opts.body !== undefined && { body: JSON.stringify(opts.body) }),
  });
  return { status: res.status, body: (await res.json()) as T };
}

/** A device: credentials + space keys + an optional socket. */
export interface TestDevice extends Credentials {
  keys: SpaceKeys;
  spaceKey: Uint8Array;
}

export async function createSpace(t: TestRelay): Promise<TestDevice> {
  const res = await api<Credentials>(t, 'POST', '/spaces');
  if (res.status !== 201) throw new Error(`create space failed: ${res.status}`);
  const spaceKey = generateSpaceKey();
  return { ...res.body, spaceKey, keys: await importSpaceKey(spaceKey) };
}

/** Pair a new device via a real pairing string, as a QR scan would. */
export async function pairDevice(t: TestRelay, existing: TestDevice): Promise<TestDevice> {
  const tok = await api<{ joinToken: string; expiresAt: number }>(t, 'POST', '/pair/token', {
    token: existing.deviceToken,
  });
  if (tok.status !== 201) throw new Error(`pair token failed: ${tok.status}`);
  const pairing = encodePairingPayload({
    spaceKey: existing.spaceKey,
    relayUrl: t.wsUrl,
    joinToken: tok.body.joinToken,
  });
  // --- on the new device ---
  const scanned = decodePairingPayload(pairing);
  const res = await api<Credentials>(t, 'POST', '/pair/join', {
    body: { joinToken: scanned.joinToken },
  });
  if (res.status !== 201) throw new Error(`join failed: ${res.status}`);
  return { ...res.body, spaceKey: scanned.spaceKey, keys: await importSpaceKey(scanned.spaceKey) };
}

export async function encryptText(
  device: TestDevice,
  text: string,
  id = ulid(),
): Promise<WireSyncItem> {
  const item = await encryptItem(
    device.keys,
    {
      id,
      spaceId: device.spaceId,
      originDeviceId: device.deviceId,
      kind: KIND_CLIPBOARD_TEXT,
      schemaVersion: 1,
      createdAt: Date.now(),
    },
    utf8Encode(text),
  );
  return itemToWire(item);
}

export async function decryptText(device: TestDevice, wire: WireSyncItem): Promise<string> {
  return utf8Decode(await decryptItem(device.keys, itemFromWire(wire)));
}

/** Minimal protocol client over `ws` with an inbox for awaiting frames. */
export class TestClient {
  readonly frames: ServerFrame[] = [];
  readonly ws: WebSocket;
  readonly opened: Promise<void>;
  readonly closed: Promise<{ code: number; reason: string }>;
  #waiters: { pred: (f: ServerFrame) => boolean; resolve: (f: ServerFrame) => void }[] = [];

  constructor(url: string, opts: WebSocket.ClientOptions = {}) {
    this.ws = new WebSocket(url + WS_PATH, opts);
    this.opened = new Promise((resolve, reject) => {
      this.ws.once('open', () => resolve());
      this.ws.once('error', reject);
    });
    this.closed = new Promise((resolve) => {
      this.ws.once('close', (code, reason) => resolve({ code, reason: reason.toString() }));
    });
    this.ws.on('message', (data) => {
      const frame = decodeServerFrame(data.toString());
      const i = this.#waiters.findIndex((w) => w.pred(frame));
      if (i >= 0) this.#waiters.splice(i, 1)[0]!.resolve(frame);
      else this.frames.push(frame);
    });
  }

  static async connect(t: TestRelay, opts?: WebSocket.ClientOptions): Promise<TestClient> {
    const c = new TestClient(t.wsUrl, opts);
    await c.opened;
    return c;
  }

  /** Connect and authenticate. */
  static async hello(t: TestRelay, device: TestDevice, opts?: WebSocket.ClientOptions) {
    const c = await TestClient.connect(t, opts);
    c.send({ type: 'hello', protocolVersion: PROTOCOL_VERSION, deviceToken: device.deviceToken });
    const welcome = await c.next('welcome');
    return { client: c, welcome };
  }

  send(frame: ClientFrame): void {
    this.ws.send(encodeClientFrame(frame));
  }

  sendRaw(raw: string): void {
    this.ws.send(raw);
  }

  /** Wait for the next frame of a type (already-received frames are checked first). */
  next<T extends ServerFrame['type']>(
    type: T,
    timeoutMs = 2000,
  ): Promise<Extract<ServerFrame, { type: T }>> {
    const pred = (f: ServerFrame) => f.type === type;
    const i = this.frames.findIndex(pred);
    if (i >= 0)
      return Promise.resolve(this.frames.splice(i, 1)[0] as Extract<ServerFrame, { type: T }>);
    return new Promise((resolve, reject) => {
      const waiter = {
        pred,
        resolve: (f: ServerFrame) => {
          clearTimeout(timer);
          resolve(f as Extract<ServerFrame, { type: T }>);
        },
      };
      const timer = setTimeout(() => {
        this.#waiters = this.#waiters.filter((w) => w !== waiter);
        reject(new Error(`timed out waiting for ${type}`));
      }, timeoutMs);
      this.#waiters.push(waiter);
    });
  }

  /** Assert no frame of `type` arrives within `ms`. */
  async expectNone(type: ServerFrame['type'], ms = 200): Promise<void> {
    await new Promise((r) => setTimeout(r, ms));
    const found = this.frames.find((f) => f.type === type);
    if (found) throw new Error(`unexpected ${type} frame`);
  }

  async close(): Promise<void> {
    if (this.ws.readyState === WebSocket.CLOSED) return;
    this.ws.close();
    await this.closed;
  }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
