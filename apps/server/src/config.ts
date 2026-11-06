import path from 'node:path';
import { z } from 'zod';

/** Fully resolved relay configuration. All durations are milliseconds. */
export interface RelayConfig {
  /** TCP port to listen on (0 = random, useful in tests). */
  port: number;
  /** Interface to bind. */
  host: string;
  /** SQLite database file path, or `:memory:`. */
  dbPath: string;
  /** How long items are buffered before the cleanup job deletes them. */
  itemTtlMs: number;
  /** Interval of the cleanup job (expired items and join tokens). */
  cleanupIntervalMs: number;
  /** Maximum buffered items per space; the oldest are pruned beyond this. */
  maxItemsPerSpace: number;
  /** Lifetime of one-time join tokens. */
  joinTokenTtlMs: number;
  /** Per-device token bucket for WebSocket frames: burst size. */
  rateLimitBurst: number;
  /** Per-device token bucket for WebSocket frames: refill rate (frames per second). */
  rateLimitPerSec: number;
  /** Per-IP token bucket for unauthenticated REST endpoints: burst size. */
  restRateLimitBurst: number;
  /** Per-IP token bucket for unauthenticated REST endpoints: refill per minute. */
  restRateLimitPerMin: number;
  /** WebSocket ping interval; a socket that misses one pong is terminated. */
  heartbeatIntervalMs: number;
  /** Time a new socket has to send `hello`. */
  helloTimeoutMs: number;
  /** If set, POST /spaces requires `Authorization: Bearer <secret>`. */
  spaceCreationSecret: string | null;
  /** Use the left-most X-Forwarded-For address as the client IP (behind a reverse proxy). */
  trustProxy: boolean;
  logLevel: LogLevel;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

const UNITS: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

/**
 * Parse a duration such as `24h`, `30m`, `90s`, `500ms`, `7d`, or a bare
 * number of seconds (`3600`).
 */
export function parseDuration(value: string): number {
  const match = /^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$/i.exec(value);
  if (!match) throw new Error(`invalid duration "${value}" (use e.g. 24h, 30m, 90s, 500ms)`);
  const unit = (match[2] ?? 's').toLowerCase();
  const ms = Math.round(Number(match[1]) * UNITS[unit]!);
  if (!Number.isSafeInteger(ms)) throw new Error(`duration "${value}" is out of range`);
  return ms;
}

const duration = (min: number) =>
  z
    .string()
    .transform((v, ctx) => {
      try {
        return parseDuration(v);
      } catch (err) {
        ctx.addIssue({ code: 'custom', message: (err as Error).message });
        return z.NEVER;
      }
    })
    .pipe(z.number().min(min));

const int = (min: number, max = Number.MAX_SAFE_INTEGER) =>
  z.coerce.number().int().min(min).max(max);
const positive = z.coerce.number().positive();
const bool = z
  .string()
  .transform((v) => v.trim().toLowerCase())
  .pipe(z.enum(['1', '0', 'true', 'false', 'yes', 'no', 'on', 'off']))
  .transform((v) => ['1', 'true', 'yes', 'on'].includes(v));

const EnvSchema = z.object({
  PORT: int(0, 65535).default(8787),
  HOST: z.string().min(1).default('0.0.0.0'),
  DATA_DIR: z.string().min(1).default('./data'),
  DB_PATH: z.string().min(1).optional(),
  ITEM_TTL: duration(1000).default(24 * 3_600_000),
  CLEANUP_INTERVAL: duration(1000).default(60_000),
  MAX_ITEMS_PER_SPACE: int(1).default(500),
  JOIN_TOKEN_TTL: duration(1000).default(10 * 60_000),
  RATE_LIMIT_BURST: int(1).default(60),
  RATE_LIMIT_PER_SEC: positive.default(10),
  REST_RATE_LIMIT_BURST: int(1).default(20),
  REST_RATE_LIMIT_PER_MIN: positive.default(20),
  HEARTBEAT_INTERVAL: duration(100).default(30_000),
  HELLO_TIMEOUT: duration(100).default(10_000),
  SPACE_CREATION_SECRET: z.string().min(16).optional(),
  TRUST_PROXY: bool.default(false),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error', 'silent']).default('info'),
});

/** Build a config from environment variables (see README for the list). */
export function loadConfig(env: Record<string, string | undefined> = process.env): RelayConfig {
  // Treat empty strings as unset so `FOO=` in a compose file falls back to the default.
  const cleaned = Object.fromEntries(
    Object.entries(env).filter(([, v]) => v !== undefined && v !== ''),
  );
  const parsed = EnvSchema.safeParse(cleaned);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
    throw new Error(`invalid configuration:\n  ${issues.join('\n  ')}`);
  }
  const e = parsed.data;
  return {
    port: e.PORT,
    host: e.HOST,
    dbPath: e.DB_PATH ?? path.join(e.DATA_DIR, 'syncert.db'),
    itemTtlMs: e.ITEM_TTL,
    cleanupIntervalMs: e.CLEANUP_INTERVAL,
    maxItemsPerSpace: e.MAX_ITEMS_PER_SPACE,
    joinTokenTtlMs: e.JOIN_TOKEN_TTL,
    rateLimitBurst: e.RATE_LIMIT_BURST,
    rateLimitPerSec: e.RATE_LIMIT_PER_SEC,
    restRateLimitBurst: e.REST_RATE_LIMIT_BURST,
    restRateLimitPerMin: e.REST_RATE_LIMIT_PER_MIN,
    heartbeatIntervalMs: e.HEARTBEAT_INTERVAL,
    helloTimeoutMs: e.HELLO_TIMEOUT,
    spaceCreationSecret: e.SPACE_CREATION_SECRET ?? null,
    trustProxy: e.TRUST_PROXY,
    logLevel: e.LOG_LEVEL,
  };
}

/** Defaults with overrides; handy for embedding and tests. */
export function defineConfig(overrides: Partial<RelayConfig> = {}): RelayConfig {
  return { ...loadConfig({}), ...overrides };
}
