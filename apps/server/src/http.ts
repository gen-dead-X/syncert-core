import { timingSafeEqual } from 'node:crypto';
import type { HttpBindings } from '@hono/node-server';
import { PROTOCOL_VERSION, type ErrorCode } from '@syncert/protocol';
import { Hono, type Context } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { z } from 'zod';
import type { RelayConfig } from './config.js';
import type { Logger } from './logger.js';
import type { RateLimiter } from './rate-limit.js';
import type { DeviceRecord, RelayStore } from './store.js';
import { hashToken } from './tokens.js';

type Env = { Bindings: HttpBindings; Variables: { device: DeviceRecord } };

const STATUS: Record<ErrorCode, 400 | 401 | 403 | 404 | 413 | 429 | 500> = {
  bad_request: 400,
  unsupported_protocol_version: 400,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  payload_too_large: 413,
  rate_limited: 429,
  internal: 500,
};

const fail = (c: Context, code: ErrorCode, message: string) =>
  c.json({ error: { code, message } }, STATUS[code]);

const JoinBodySchema = z.strictObject({
  joinToken: z
    .string()
    .min(16)
    .max(256)
    .regex(/^[A-Za-z0-9_-]+$/),
});

function bearer(c: Context): string | null {
  const header = c.req.header('authorization');
  const m = header ? /^Bearer\s+(\S+)\s*$/i.exec(header) : null;
  return m ? m[1]! : null;
}

/** Constant-time string comparison via fixed-length digests. */
function secretEquals(a: string, b: string): boolean {
  return timingSafeEqual(Buffer.from(hashToken(a), 'hex'), Buffer.from(hashToken(b), 'hex'));
}

export function clientIp(c: Context<Env>, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = c.req.header('x-forwarded-for')?.split(',')[0]?.trim();
    if (xff) return xff;
  }
  return c.env?.incoming?.socket?.remoteAddress ?? 'unknown';
}

/** REST API: space creation, pairing, health. */
export function createHttpApp(deps: {
  config: RelayConfig;
  store: RelayStore;
  log: Logger;
  restLimiter: RateLimiter;
  now: () => number;
  version: string;
}): Hono<Env> {
  const { config, store, log, restLimiter, now } = deps;
  const app = new Hono<Env>();

  app.use(
    '*',
    bodyLimit({
      maxSize: 4 * 1024,
      onError: (c) => fail(c, 'payload_too_large', 'request body too large'),
    }),
  );

  const limitByIp = async (c: Context<Env>, next: () => Promise<void>) => {
    const ip = clientIp(c, config.trustProxy);
    if (!restLimiter.take(`ip:${ip}`)) {
      log.warn('rest rate limited', { path: c.req.path });
      return fail(c, 'rate_limited', 'too many requests, slow down');
    }
    await next();
  };

  const requireDevice = async (c: Context<Env>, next: () => Promise<void>) => {
    const token = bearer(c);
    const device = token ? store.authenticate(token) : null;
    if (!device) return fail(c, 'unauthorized', 'missing or invalid device token');
    if (!restLimiter.take(`dev:${device.deviceId}`)) {
      return fail(c, 'rate_limited', 'too many requests, slow down');
    }
    c.set('device', device);
    await next();
  };

  app.get('/health', (c) => {
    let db: boolean;
    try {
      db = store.ping();
    } catch {
      db = false;
    }
    return c.json(
      { status: db ? 'ok' : 'error', version: deps.version, protocolVersion: PROTOCOL_VERSION },
      db ? 200 : 503,
    );
  });

  app.post('/spaces', limitByIp, (c) => {
    if (config.spaceCreationSecret !== null) {
      const token = bearer(c);
      if (!token || !secretEquals(token, config.spaceCreationSecret)) {
        return fail(c, 'unauthorized', 'space creation requires the relay secret');
      }
    }
    const creds = store.createSpace(now());
    log.info('space created', { space: creds.spaceId, device: creds.deviceId });
    return c.json(creds, 201);
  });

  app.post('/pair/token', requireDevice, (c) => {
    const device = c.get('device');
    const { joinToken, expiresAt } = store.createJoinToken(device, now());
    log.info('join token issued', { space: device.spaceId, device: device.deviceId, expiresAt });
    return c.json({ joinToken, expiresAt }, 201);
  });

  app.post('/pair/join', limitByIp, async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return fail(c, 'bad_request', 'body must be JSON {"joinToken": "..."}');
    }
    const parsed = JoinBodySchema.safeParse(body);
    if (!parsed.success) return fail(c, 'bad_request', 'body must be JSON {"joinToken": "..."}');
    const creds = store.redeemJoinToken(parsed.data.joinToken, now());
    if (!creds) {
      log.info('join rejected', {});
      return fail(c, 'unauthorized', 'join token is invalid, expired or already used');
    }
    log.info('device joined', { space: creds.spaceId, device: creds.deviceId });
    return c.json(creds, 201);
  });

  app.notFound((c) => fail(c, 'not_found', 'not found'));
  app.onError((err, c) => {
    log.error('http handler failed', { path: c.req.path, error: err.name });
    return fail(c, 'internal', 'internal error');
  });

  return app;
}
