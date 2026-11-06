import { describe, expect, it } from 'vitest';
import { loadConfig, parseDuration } from '../src/config.ts';
import { createLogger } from '../src/logger.ts';
import { RateLimiter, TokenBucket } from '../src/rate-limit.ts';
import { generateToken, hashToken } from '../src/tokens.ts';
import { assertNodeSupported } from '../src/store.ts';

describe('parseDuration', () => {
  it.each([
    ['24h', 86_400_000],
    ['30m', 1_800_000],
    ['90s', 90_000],
    ['500ms', 500],
    ['7d', 604_800_000],
    ['3600', 3_600_000],
    ['1.5h', 5_400_000],
  ])('%s', (input, ms) => expect(parseDuration(input)).toBe(ms));

  it.each(['', 'abc', '-1h', '10 weeks'])('rejects %j', (input) =>
    expect(() => parseDuration(input)).toThrow(),
  );
});

describe('loadConfig', () => {
  it('has sane defaults', () => {
    const c = loadConfig({});
    expect(c).toMatchObject({
      port: 8787,
      host: '0.0.0.0',
      itemTtlMs: 86_400_000,
      joinTokenTtlMs: 600_000,
      spaceCreationSecret: null,
      trustProxy: false,
    });
    expect(c.dbPath).toMatch(/data[/\\]syncert\.db$/);
  });

  it('reads env vars', () => {
    const c = loadConfig({
      PORT: '9000',
      DATA_DIR: '/srv/syncert',
      ITEM_TTL: '1h',
      RATE_LIMIT_BURST: '5',
      RATE_LIMIT_PER_SEC: '0.5',
      TRUST_PROXY: 'true',
      LOG_LEVEL: 'warn',
      HOST: '',
    });
    expect(c).toMatchObject({
      port: 9000,
      host: '0.0.0.0',
      dbPath: '/srv/syncert/syncert.db',
      itemTtlMs: 3_600_000,
      rateLimitBurst: 5,
      rateLimitPerSec: 0.5,
      trustProxy: true,
      logLevel: 'warn',
    });
    expect(loadConfig({ DB_PATH: '/tmp/x.db', DATA_DIR: '/nope' }).dbPath).toBe('/tmp/x.db');
  });

  it('rejects invalid values with a readable message', () => {
    expect(() => loadConfig({ PORT: 'eighty' })).toThrow(/PORT/);
    expect(() => loadConfig({ ITEM_TTL: 'soon' })).toThrow(/ITEM_TTL/);
    expect(() => loadConfig({ SPACE_CREATION_SECRET: 'short' })).toThrow(/SPACE_CREATION_SECRET/);
  });
});

describe('TokenBucket / RateLimiter', () => {
  it('allows a burst then refills over time', () => {
    const b = new TokenBucket(3, 1 / 1000, 0);
    expect([b.take(0), b.take(0), b.take(0), b.take(0)]).toEqual([true, true, true, false]);
    expect(b.take(999)).toBe(false);
    expect(b.take(1000)).toBe(true);
    expect(b.isFull(10_000)).toBe(true);
  });

  it('keys buckets independently and sweeps idle ones', () => {
    let now = 0;
    const rl = new RateLimiter(1, 1 / 1000, () => now);
    expect(rl.take('a')).toBe(true);
    expect(rl.take('a')).toBe(false);
    expect(rl.take('b')).toBe(true);
    now = 5000;
    rl.sweep();
    expect(rl.size).toBe(0);
  });
});

describe('logger', () => {
  it('emits JSON lines and redacts secret-looking fields', () => {
    const lines: string[] = [];
    const log = createLogger('info', (l) => lines.push(l));
    log.debug('hidden');
    log.info('hello', { device: 'd1', deviceToken: 'tok', payload: 'abc', size: 3 });
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]!);
    expect(entry).toMatchObject({ level: 'info', msg: 'hello', device: 'd1', size: 3 });
    expect(entry.deviceToken).toBe('[redacted]');
    expect(entry.payload).toBe('[redacted]');
  });
});

describe('tokens', () => {
  it('generates 256-bit base64url tokens and hashes them', () => {
    const tok = generateToken();
    expect(tok).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(hashToken(tok)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken(tok)).not.toContain(tok);
  });
});

describe('assertNodeSupported', () => {
  it('rejects runtimes without Node-API 10', () => {
    expect(() => assertNodeSupported('9')).toThrow(/Node.js >= 22.14/);
    expect(() => assertNodeSupported('')).toThrow(/Node-API unknown/);
    expect(() => assertNodeSupported('10')).not.toThrow();
  });
});
