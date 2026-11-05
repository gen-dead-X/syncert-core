import {
  MAX_ITEM_PAYLOAD_BYTES,
  MAX_SYNC_BATCH_ITEMS,
  PROTOCOL_VERSION,
  ProtocolError,
  bytesToBase64,
  base64ToBytes,
  decodeClientFrame,
  encodeServerFrame,
  type ClientFrame,
  type ErrorCode,
  type ServerFrame,
  type WireSyncItem,
} from '@syncert/protocol';
import type { WebSocket } from 'ws';
import type { RelayConfig } from './config.js';
import type { Logger } from './logger.js';
import type { RateLimiter } from './rate-limit.js';
import type { RelayStore, StoredItem } from './store.js';

/** Application close codes sent by the relay (4000-4999 are reserved for apps). */
export const CloseCode = {
  /** Malformed or out-of-order frames before authentication. */
  BadRequest: 4000,
  /** Missing, unknown or revoked device token. */
  Unauthorized: 4001,
  /** Client protocolVersion is not supported. */
  UnsupportedProtocolVersion: 4002,
  /** The device was revoked while connected. */
  Revoked: 4003,
  /** No `hello` within HELLO_TIMEOUT. */
  HelloTimeout: 4008,
  /** The client could not keep up with outgoing frames. */
  SlowConsumer: 4009,
  /** Server shutting down. */
  GoingAway: 1001,
} as const;

/** Decoded size of a base64 string, computed from its length (no decoding). */
const base64DecodedLength = (b64: string) =>
  Math.floor((b64.length * 3) / 4) - (b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0);
/** Disconnect clients whose unsent backlog exceeds this many bytes. */
const MAX_BUFFERED_BYTES = 16 * 1024 * 1024;
const REQ_ID = /^[A-Za-z0-9_-]{1,64}$/;

interface Conn {
  ws: WebSocket;
  id: number;
  alive: boolean;
  deviceId: string | null;
  spaceId: string | null;
  helloTimer: NodeJS.Timeout | null;
}

export function toWireItem(item: StoredItem): WireSyncItem {
  return {
    id: item.id,
    spaceId: item.spaceId,
    originDeviceId: item.originDeviceId,
    kind: item.kind,
    schemaVersion: item.schemaVersion,
    createdAt: item.createdAt,
    payload: bytesToBase64(item.ciphertext),
    nonce: bytesToBase64(item.nonce),
    contentHash: item.contentHash,
  };
}

/** Tracks authenticated sockets per space and implements the frame handlers. */
export class Hub {
  readonly #conns = new Set<Conn>();
  readonly #bySpace = new Map<string, Set<Conn>>();
  #nextId = 1;

  constructor(
    private readonly deps: {
      config: RelayConfig;
      store: RelayStore;
      log: Logger;
      limiter: RateLimiter;
      now: () => number;
    },
  ) {}

  get connectionCount(): number {
    return this.#conns.size;
  }

  /** Register a freshly upgraded socket. */
  accept(ws: WebSocket, remote: string): void {
    const conn: Conn = {
      ws,
      id: this.#nextId++,
      alive: true,
      deviceId: null,
      spaceId: null,
      helloTimer: null,
    };
    this.#conns.add(conn);
    this.deps.log.debug('ws connected', { conn: conn.id, remote });

    conn.helloTimer = setTimeout(() => {
      this.#fail(conn, 'unauthorized', 'hello timeout', CloseCode.HelloTimeout);
    }, this.deps.config.helloTimeoutMs);

    ws.on('pong', () => {
      conn.alive = true;
    });
    ws.on('message', (data, isBinary) => {
      conn.alive = true;
      try {
        this.#onMessage(conn, data, isBinary);
      } catch (err) {
        this.deps.log.error('ws handler failed', {
          conn: conn.id,
          device: conn.deviceId,
          error: err instanceof Error ? err.name : 'unknown',
        });
        this.#send(conn, { type: 'error', code: 'internal', message: 'internal error' });
      }
    });
    ws.on('close', (code) => this.#onClose(conn, code));
    ws.on('error', (err) => {
      this.deps.log.warn('ws error', { conn: conn.id, device: conn.deviceId, error: err.message });
    });
  }

  /** Ping every socket; terminate those that did not answer the previous ping. */
  heartbeat(): void {
    for (const conn of this.#conns) {
      if (!conn.alive) {
        this.deps.log.info('ws heartbeat timeout', { conn: conn.id, device: conn.deviceId });
        conn.ws.terminate();
        continue;
      }
      conn.alive = false;
      try {
        conn.ws.ping();
      } catch {
        conn.ws.terminate();
      }
    }
  }

  /** Close every socket of a device (used on revocation). */
  disconnectDevice(deviceId: string, code: number, message: string): number {
    let n = 0;
    for (const conn of this.#conns) {
      if (conn.deviceId !== deviceId) continue;
      this.#fail(conn, 'unauthorized', message, code);
      n++;
    }
    return n;
  }

  /** Close everything (server shutdown). */
  closeAll(): void {
    for (const conn of this.#conns) conn.ws.close(CloseCode.GoingAway, 'server shutting down');
  }

  terminateAll(): void {
    for (const conn of this.#conns) conn.ws.terminate();
  }

  // ---- internals ----------------------------------------------------------

  #onClose(conn: Conn, code: number): void {
    if (conn.helloTimer) clearTimeout(conn.helloTimer);
    this.#conns.delete(conn);
    if (conn.spaceId) {
      const set = this.#bySpace.get(conn.spaceId);
      set?.delete(conn);
      if (set && set.size === 0) this.#bySpace.delete(conn.spaceId);
    }
    if (conn.deviceId) {
      try {
        this.deps.store.touchDevice(conn.deviceId, this.deps.now());
      } catch {
        // The store may already be closed during shutdown.
      }
    }
    this.deps.log.debug('ws closed', { conn: conn.id, device: conn.deviceId, code });
  }

  #send(conn: Conn, frame: ServerFrame): void {
    if (conn.ws.readyState !== conn.ws.OPEN) return;
    if (conn.ws.bufferedAmount > MAX_BUFFERED_BYTES) {
      this.deps.log.warn('ws slow consumer', { conn: conn.id, device: conn.deviceId });
      conn.ws.close(CloseCode.SlowConsumer, 'slow consumer');
      return;
    }
    conn.ws.send(encodeServerFrame(frame));
  }

  #error(conn: Conn, code: ErrorCode, message: string, reqId?: string): void {
    this.#send(
      conn,
      reqId === undefined
        ? { type: 'error', code, message }
        : { type: 'error', reqId, code, message },
    );
  }

  /** Send an error frame, then close the socket. */
  #fail(conn: Conn, code: ErrorCode, message: string, closeCode: number, reqId?: string): void {
    this.#error(conn, code, message, reqId);
    if (conn.ws.readyState === conn.ws.OPEN || conn.ws.readyState === conn.ws.CONNECTING) {
      conn.ws.close(closeCode, message);
    }
  }

  #onMessage(conn: Conn, data: unknown, isBinary: boolean): void {
    const authed = conn.deviceId !== null;
    if (isBinary) {
      if (authed) return this.#error(conn, 'bad_request', 'binary frames are not supported');
      return this.#fail(
        conn,
        'bad_request',
        'binary frames are not supported',
        CloseCode.BadRequest,
      );
    }
    const raw = Buffer.isBuffer(data)
      ? data.toString('utf8')
      : Array.isArray(data)
        ? Buffer.concat(data as Buffer[]).toString('utf8')
        : Buffer.from(data as ArrayBuffer).toString('utf8');

    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch {
      if (authed) return this.#error(conn, 'bad_request', 'frame is not valid JSON');
      return this.#fail(conn, 'bad_request', 'frame is not valid JSON', CloseCode.BadRequest);
    }
    const obj = (typeof json === 'object' && json !== null ? json : {}) as Record<string, unknown>;
    const reqId = typeof obj.reqId === 'string' && REQ_ID.test(obj.reqId) ? obj.reqId : undefined;

    if (authed && !this.deps.limiter.take(conn.deviceId!)) {
      this.deps.log.warn('rate limited', { device: conn.deviceId, frame: String(obj.type) });
      return this.#error(conn, 'rate_limited', 'too many frames, slow down', reqId);
    }

    // Size check before full validation so the client gets a specific error.
    if (obj.type === 'item.push') {
      const item = obj.item as Record<string, unknown> | undefined;
      if (
        typeof item?.payload === 'string' &&
        base64DecodedLength(item.payload) > MAX_ITEM_PAYLOAD_BYTES
      ) {
        this.deps.log.info('item rejected: too large', {
          device: conn.deviceId,
          size: base64DecodedLength(item.payload),
        });
        return authed
          ? this.#error(
              conn,
              'payload_too_large',
              `payload exceeds ${MAX_ITEM_PAYLOAD_BYTES} bytes`,
              reqId,
            )
          : this.#fail(conn, 'unauthorized', 'send hello first', CloseCode.Unauthorized, reqId);
      }
    }

    let frame: ClientFrame;
    try {
      frame = decodeClientFrame(raw);
    } catch (err) {
      const issues = err instanceof ProtocolError ? (err.issues ?? []).slice(0, 3).join('; ') : '';
      const message = `invalid frame${issues ? `: ${issues}` : ''}`.slice(0, 1024);
      if (authed) return this.#error(conn, 'bad_request', message, reqId);
      return this.#fail(conn, 'bad_request', message, CloseCode.BadRequest, reqId);
    }

    if (!authed) {
      if (frame.type !== 'hello') {
        return this.#fail(conn, 'unauthorized', 'send hello first', CloseCode.Unauthorized, reqId);
      }
      return this.#onHello(conn, frame);
    }

    switch (frame.type) {
      case 'hello':
        return this.#error(conn, 'bad_request', 'already authenticated', reqId);
      case 'item.push':
        return this.#onPush(conn, frame);
      case 'sync.since':
        return this.#onSyncSince(conn, frame);
      case 'device.list':
        return this.#onDeviceList(conn, frame);
      case 'device.revoke':
        return this.#onDeviceRevoke(conn, frame);
    }
  }

  #onHello(conn: Conn, frame: Extract<ClientFrame, { type: 'hello' }>): void {
    if (frame.protocolVersion !== PROTOCOL_VERSION) {
      this.deps.log.info('hello rejected: protocol version', {
        conn: conn.id,
        version: frame.protocolVersion,
      });
      return this.#fail(
        conn,
        'unsupported_protocol_version',
        `unsupported protocolVersion ${frame.protocolVersion}; this relay speaks ${PROTOCOL_VERSION}`,
        CloseCode.UnsupportedProtocolVersion,
        frame.reqId,
      );
    }
    const device = this.deps.store.authenticate(frame.deviceToken);
    if (!device) {
      this.deps.log.info('hello rejected: bad token', { conn: conn.id });
      return this.#fail(
        conn,
        'unauthorized',
        'invalid device token',
        CloseCode.Unauthorized,
        frame.reqId,
      );
    }
    if (conn.helloTimer) clearTimeout(conn.helloTimer);
    conn.helloTimer = null;
    conn.deviceId = device.deviceId;
    conn.spaceId = device.spaceId;
    let set = this.#bySpace.get(device.spaceId);
    if (!set) this.#bySpace.set(device.spaceId, (set = new Set()));
    set.add(conn);
    const now = this.deps.now();
    this.deps.store.touchDevice(device.deviceId, now);
    this.deps.log.info('device connected', {
      conn: conn.id,
      device: device.deviceId,
      space: device.spaceId,
    });
    this.#send(conn, {
      type: 'welcome',
      ...(frame.reqId !== undefined && { reqId: frame.reqId }),
      protocolVersion: PROTOCOL_VERSION,
      deviceId: device.deviceId,
      spaceId: device.spaceId,
      serverTime: now,
    });
  }

  #onPush(conn: Conn, frame: Extract<ClientFrame, { type: 'item.push' }>): void {
    const { item, reqId } = frame;
    if (item.spaceId !== conn.spaceId || item.originDeviceId !== conn.deviceId) {
      return this.#error(
        conn,
        'forbidden',
        'item spaceId/originDeviceId must match this device',
        reqId,
      );
    }
    const stored: StoredItem = {
      id: item.id,
      spaceId: item.spaceId,
      originDeviceId: item.originDeviceId,
      kind: item.kind,
      schemaVersion: item.schemaVersion,
      createdAt: item.createdAt,
      receivedAt: this.deps.now(),
      ciphertext: base64ToBytes(item.payload),
      nonce: base64ToBytes(item.nonce),
      contentHash: item.contentHash,
    };
    const result = this.deps.store.insertItem(stored);
    if (result === 'conflict') {
      return this.#error(conn, 'bad_request', 'item id already used for different content', reqId);
    }
    this.deps.log.info(result === 'stored' ? 'item stored' : 'item duplicate', {
      device: conn.deviceId,
      space: conn.spaceId,
      item: item.id,
      kind: item.kind,
      size: stored.ciphertext.length,
    });
    this.#send(conn, { type: 'item.ack', ...(reqId !== undefined && { reqId }), id: item.id });
    if (result !== 'stored') return;
    const wire = toWireItem(stored);
    for (const peer of this.#bySpace.get(item.spaceId) ?? []) {
      if (peer.deviceId === conn.deviceId) continue;
      this.#send(peer, { type: 'item.new', item: wire });
    }
  }

  #onSyncSince(conn: Conn, frame: Extract<ClientFrame, { type: 'sync.since' }>): void {
    const { items, hasMore } = this.deps.store.itemsSince(
      conn.spaceId!,
      frame.lastItemId,
      conn.deviceId!,
      MAX_SYNC_BATCH_ITEMS,
      this.deps.now(),
    );
    this.#send(conn, {
      type: 'sync.batch',
      ...(frame.reqId !== undefined && { reqId: frame.reqId }),
      items: items.map(toWireItem),
      hasMore,
    });
  }

  #onDeviceList(conn: Conn, frame: Extract<ClientFrame, { type: 'device.list' }>): void {
    const devices = this.deps.store.listDevices(conn.spaceId!).slice(0, 1000);
    this.#send(conn, {
      type: 'device.list.result',
      ...(frame.reqId !== undefined && { reqId: frame.reqId }),
      devices: devices.map((d) => ({
        deviceId: d.deviceId,
        createdAt: d.createdAt,
        lastSeenAt: d.lastSeenAt,
      })),
    });
  }

  #onDeviceRevoke(conn: Conn, frame: Extract<ClientFrame, { type: 'device.revoke' }>): void {
    const ok = this.deps.store.revokeDevice(conn.spaceId!, frame.deviceId, this.deps.now());
    if (!ok) return this.#error(conn, 'not_found', 'no such device in this space', frame.reqId);
    this.deps.log.info('device revoked', {
      device: frame.deviceId,
      space: conn.spaceId,
      by: conn.deviceId,
    });
    this.#send(conn, {
      type: 'device.revoked',
      ...(frame.reqId !== undefined && { reqId: frame.reqId }),
      deviceId: frame.deviceId,
    });
    this.disconnectDevice(frame.deviceId, CloseCode.Revoked, 'device revoked');
  }
}
