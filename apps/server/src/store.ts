import Database from 'better-sqlite3';
import { generateId, generateToken, hashToken } from './tokens.js';

/** An encrypted item exactly as the relay stores it. No plaintext, ever. */
export interface StoredItem {
  id: string;
  spaceId: string;
  originDeviceId: string;
  kind: string;
  schemaVersion: number;
  createdAt: number;
  receivedAt: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  contentHash: string;
}

export interface DeviceRecord {
  deviceId: string;
  spaceId: string;
  createdAt: number;
  lastSeenAt: number | null;
}

export interface Credentials {
  spaceId: string;
  deviceId: string;
  /** Returned to the client once; only its SHA-256 is stored. */
  deviceToken: string;
}

export type InsertResult = 'stored' | 'duplicate' | 'conflict';

/**
 * Schema migrations, applied in order and tracked with `PRAGMA user_version`.
 * Never edit a released migration; append a new one.
 */
const MIGRATIONS: string[] = [
  `
  CREATE TABLE spaces (
    space_id    TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE devices (
    device_id     TEXT PRIMARY KEY,
    space_id      TEXT NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    revoked       INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER,
    revoked_at    INTEGER
  ) STRICT;
  CREATE INDEX devices_space ON devices(space_id);

  CREATE TABLE join_tokens (
    token_hash            TEXT PRIMARY KEY,
    space_id              TEXT NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
    created_by_device_id  TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    used_at               INTEGER
  ) STRICT;
  CREATE INDEX join_tokens_expiry ON join_tokens(expires_at);

  -- seq is the relay's arrival order: sync.since pages by it, so items from
  -- devices with skewed clocks (client-generated ULIDs) are never skipped.
  CREATE TABLE items (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    space_id        TEXT NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
    item_id         TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    kind            TEXT NOT NULL,
    schema_version  INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    received_at     INTEGER NOT NULL,
    size            INTEGER NOT NULL,
    ciphertext      BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    content_hash    TEXT NOT NULL,
    UNIQUE (space_id, item_id)
  ) STRICT;
  CREATE INDEX items_space_seq ON items(space_id, seq);
  CREATE INDEX items_received ON items(received_at);
  `,
];

interface ItemRow {
  seq: number;
  space_id: string;
  item_id: string;
  device_id: string;
  kind: string;
  schema_version: number;
  created_at: number;
  received_at: number;
  ciphertext: Buffer;
  nonce: Buffer;
  content_hash: string;
}

const toItem = (r: ItemRow): StoredItem => ({
  id: r.item_id,
  spaceId: r.space_id,
  originDeviceId: r.device_id,
  kind: r.kind,
  schemaVersion: r.schema_version,
  createdAt: r.created_at,
  receivedAt: r.received_at,
  ciphertext: new Uint8Array(r.ciphertext),
  nonce: new Uint8Array(r.nonce),
  contentHash: r.content_hash,
});

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/**
 * better-sqlite3's bundled prebuilds target Node-API 10 (Node >= 22.14). Older
 * runtimes crash with SIGSEGV when the addon loads, so fail with a clear error first.
 */
const REQUIRED_NAPI_VERSION = 10;

export function assertNodeSupported(napi = process.versions.napi): void {
  if (!(Number(napi) >= REQUIRED_NAPI_VERSION)) {
    throw new Error(
      `syncert-server requires Node.js >= 22.14 (Node-API ${REQUIRED_NAPI_VERSION}); ` +
        `this is Node.js ${process.version} (Node-API ${napi || 'unknown'})`,
    );
  }
}

/** SQLite persistence for the relay (better-sqlite3, synchronous, WAL). */
export class RelayStore {
  readonly db: Database.Database;

  constructor(
    dbPath: string,
    private readonly opts: { itemTtlMs: number; maxItemsPerSpace: number; joinTokenTtlMs: number },
  ) {
    assertNodeSupported();
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 5000');
    // Overwrite deleted content (expired ciphertext, revoked token hashes) with zeros.
    this.db.pragma('secure_delete = ON');
    this.#migrate();
  }

  #migrate(): void {
    const current = this.db.pragma('user_version', { simple: true }) as number;
    for (let v = current; v < MIGRATIONS.length; v++) {
      this.db.transaction(() => {
        this.db.exec(MIGRATIONS[v]!);
        this.db.pragma(`user_version = ${v + 1}`);
      })();
    }
  }

  close(): void {
    if (!this.db.open) return;
    try {
      this.db.pragma('wal_checkpoint(TRUNCATE)');
    } finally {
      this.db.close();
    }
  }

  ping(): boolean {
    return this.db.prepare('SELECT 1 AS ok').get() !== undefined;
  }

  // ---- spaces & devices ---------------------------------------------------

  #insertDevice(spaceId: string, now: number): Credentials {
    const deviceId = generateId();
    const deviceToken = generateToken();
    this.db
      .prepare(
        'INSERT INTO devices (device_id, space_id, token_hash, created_at) VALUES (?, ?, ?, ?)',
      )
      .run(deviceId, spaceId, hashToken(deviceToken), now);
    return { spaceId, deviceId, deviceToken };
  }

  /** Create a space together with its first device. */
  createSpace(now: number): Credentials {
    return this.db.transaction(() => {
      const spaceId = generateId();
      this.db.prepare('INSERT INTO spaces (space_id, created_at) VALUES (?, ?)').run(spaceId, now);
      return this.#insertDevice(spaceId, now);
    })();
  }

  /** Resolve a device token to an active (non-revoked) device. */
  authenticate(deviceToken: string): DeviceRecord | null {
    const row = this.db
      .prepare(
        `SELECT device_id, space_id, created_at, last_seen_at FROM devices
         WHERE token_hash = ? AND revoked = 0`,
      )
      .get(hashToken(deviceToken)) as
      | { device_id: string; space_id: string; created_at: number; last_seen_at: number | null }
      | undefined;
    if (!row) return null;
    return {
      deviceId: row.device_id,
      spaceId: row.space_id,
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
    };
  }

  isActive(deviceId: string): boolean {
    return (
      this.db.prepare('SELECT 1 FROM devices WHERE device_id = ? AND revoked = 0').get(deviceId) !==
      undefined
    );
  }

  touchDevice(deviceId: string, now: number): void {
    this.db.prepare('UPDATE devices SET last_seen_at = ? WHERE device_id = ?').run(now, deviceId);
  }

  /** Active devices in a space, oldest first. */
  listDevices(spaceId: string): DeviceRecord[] {
    const rows = this.db
      .prepare(
        `SELECT device_id, space_id, created_at, last_seen_at FROM devices
         WHERE space_id = ? AND revoked = 0 ORDER BY created_at, device_id`,
      )
      .all(spaceId) as {
      device_id: string;
      space_id: string;
      created_at: number;
      last_seen_at: number | null;
    }[];
    return rows.map((r) => ({
      deviceId: r.device_id,
      spaceId: r.space_id,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
    }));
  }

  /**
   * Revoke a device in `spaceId`. Its token stops working immediately and any
   * unused join tokens it issued are deleted. Returns false if no active
   * device with that id exists in the space.
   */
  revokeDevice(spaceId: string, deviceId: string, now: number): boolean {
    return this.db.transaction(() => {
      const res = this.db
        .prepare(
          `UPDATE devices SET revoked = 1, revoked_at = ?
           WHERE device_id = ? AND space_id = ? AND revoked = 0`,
        )
        .run(now, deviceId, spaceId);
      if (res.changes === 0) return false;
      this.db
        .prepare('DELETE FROM join_tokens WHERE created_by_device_id = ? AND used_at IS NULL')
        .run(deviceId);
      return true;
    })();
  }

  // ---- pairing ------------------------------------------------------------

  /** Issue a one-time join token for the device's space. */
  createJoinToken(device: DeviceRecord, now: number): { joinToken: string; expiresAt: number } {
    const joinToken = generateToken();
    const expiresAt = now + this.opts.joinTokenTtlMs;
    this.db
      .prepare(
        `INSERT INTO join_tokens (token_hash, space_id, created_by_device_id, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(hashToken(joinToken), device.spaceId, device.deviceId, now, expiresAt);
    return { joinToken, expiresAt };
  }

  /** Redeem a join token (single use, unexpired) for new device credentials. */
  redeemJoinToken(joinToken: string, now: number): Credentials | null {
    return this.db.transaction(() => {
      const res = this.db
        .prepare(
          `UPDATE join_tokens SET used_at = ?
           WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
           RETURNING space_id`,
        )
        .get(now, hashToken(joinToken), now) as { space_id: string } | undefined;
      if (!res) return null;
      return this.#insertDevice(res.space_id, now);
    })();
  }

  // ---- items --------------------------------------------------------------

  /**
   * Store an item. Re-pushing an identical item (same id, nonce, content hash
   * and ciphertext) is a no-op `duplicate`; reusing an id for different
   * content is a `conflict`.
   */
  insertItem(item: StoredItem): InsertResult {
    return this.db.transaction((): InsertResult => {
      const existing = this.db
        .prepare('SELECT * FROM items WHERE space_id = ? AND item_id = ?')
        .get(item.spaceId, item.id) as ItemRow | undefined;
      if (existing) {
        const e = toItem(existing);
        const same =
          e.originDeviceId === item.originDeviceId &&
          e.contentHash === item.contentHash &&
          sameBytes(e.nonce, item.nonce) &&
          sameBytes(e.ciphertext, item.ciphertext);
        return same ? 'duplicate' : 'conflict';
      }
      this.db
        .prepare(
          `INSERT INTO items (space_id, item_id, device_id, kind, schema_version, created_at,
             received_at, size, ciphertext, nonce, content_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          item.spaceId,
          item.id,
          item.originDeviceId,
          item.kind,
          item.schemaVersion,
          item.createdAt,
          item.receivedAt,
          item.ciphertext.length,
          Buffer.from(item.ciphertext),
          Buffer.from(item.nonce),
          item.contentHash,
        );
      // Bound per-space storage: keep only the newest maxItemsPerSpace items.
      this.db
        .prepare(
          `DELETE FROM items WHERE space_id = ? AND seq <= (
             SELECT seq FROM items WHERE space_id = ? ORDER BY seq DESC LIMIT 1 OFFSET ?
           )`,
        )
        .run(item.spaceId, item.spaceId, this.opts.maxItemsPerSpace);
      return 'stored';
    })();
  }

  /**
   * Items in a space that arrived after `lastItemId`, in arrival order,
   * excluding those pushed by `excludeDeviceId`. An unknown cursor (expired,
   * pruned, or from another space) restarts from the oldest buffered item.
   */
  itemsSince(
    spaceId: string,
    lastItemId: string | null,
    excludeDeviceId: string,
    limit: number,
    now: number,
  ): { items: StoredItem[]; hasMore: boolean } {
    let cursor = 0;
    if (lastItemId !== null) {
      const row = this.db
        .prepare('SELECT seq FROM items WHERE space_id = ? AND item_id = ?')
        .get(spaceId, lastItemId) as { seq: number } | undefined;
      cursor = row?.seq ?? 0;
    }
    const rows = this.db
      .prepare(
        `SELECT * FROM items
         WHERE space_id = ? AND seq > ? AND device_id != ? AND received_at > ?
         ORDER BY seq LIMIT ?`,
      )
      .all(spaceId, cursor, excludeDeviceId, now - this.opts.itemTtlMs, limit + 1) as ItemRow[];
    const hasMore = rows.length > limit;
    return { items: rows.slice(0, limit).map(toItem), hasMore };
  }

  countItems(spaceId?: string): number {
    const row = (
      spaceId === undefined
        ? this.db.prepare('SELECT COUNT(*) AS n FROM items').get()
        : this.db.prepare('SELECT COUNT(*) AS n FROM items WHERE space_id = ?').get(spaceId)
    ) as { n: number };
    return row.n;
  }

  // ---- maintenance --------------------------------------------------------

  /** Delete items older than the TTL and expired or used join tokens. */
  cleanup(now: number): { items: number; joinTokens: number } {
    return this.db.transaction(() => {
      const items = this.db
        .prepare('DELETE FROM items WHERE received_at <= ?')
        .run(now - this.opts.itemTtlMs).changes;
      const joinTokens = this.db
        .prepare('DELETE FROM join_tokens WHERE expires_at <= ? OR used_at IS NOT NULL')
        .run(now).changes;
      return { items, joinTokens };
    })();
  }
}
