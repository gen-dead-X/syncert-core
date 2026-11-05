import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { getRequestListener } from '@hono/node-server';
import { WebSocketServer } from 'ws';
import { defineConfig, type RelayConfig } from './config.js';
import { createHttpApp } from './http.js';
import { Hub } from './hub.js';
import { createLogger, type Logger } from './logger.js';
import { RateLimiter } from './rate-limit.js';
import { RelayStore } from './store.js';

/** Path of the WebSocket endpoint. */
export const WS_PATH = '/ws';

/**
 * Largest client frame accepted. A maximal `item.push` is ~342 KiB of base64
 * plus metadata; anything above 1 MiB is dropped by `ws` (close 1009) before
 * it is buffered or parsed.
 */
export const MAX_CLIENT_FRAME_BYTES = 1024 * 1024;

export interface RelayOptions {
  config?: Partial<RelayConfig>;
  logger?: Logger;
  /** Clock (Unix ms), injectable for tests. */
  now?: () => number;
}

export interface Relay {
  readonly config: RelayConfig;
  readonly store: RelayStore;
  readonly hub: Hub;
  readonly http: Server;
  /** Start listening; resolves with the bound port. */
  listen(): Promise<{ port: number; host: string }>;
  /** Run the TTL cleanup job once. */
  cleanup(): { items: number; joinTokens: number };
  /** Gracefully close sockets, the HTTP server and the database. */
  close(): Promise<void>;
}

function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export function createRelay(options: RelayOptions = {}): Relay {
  const config = defineConfig(options.config);
  const log = options.logger ?? createLogger(config.logLevel);
  const now = options.now ?? Date.now;
  const store = new RelayStore(config.dbPath, config);
  const limiter = new RateLimiter(config.rateLimitBurst, config.rateLimitPerSec / 1000, now);
  const restLimiter = new RateLimiter(
    config.restRateLimitBurst,
    config.restRateLimitPerMin / 60_000,
    now,
  );
  const hub = new Hub({ config, store, log, limiter, now });
  const app = createHttpApp({ config, store, log, restLimiter, now, version: readVersion() });

  const http = createServer(getRequestListener(app.fetch));
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_CLIENT_FRAME_BYTES });

  http.on('upgrade', (req, socket, head) => {
    const { pathname } = new URL(req.url ?? '/', 'http://relay');
    if (pathname !== WS_PATH) {
      socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      const xff = config.trustProxy
        ? (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim()
        : undefined;
      hub.accept(ws, xff ?? req.socket.remoteAddress ?? 'unknown');
    });
  });

  const timers: NodeJS.Timeout[] = [];
  const cleanup = () => {
    const res = store.cleanup(now());
    limiter.sweep();
    restLimiter.sweep();
    if (res.items || res.joinTokens) log.info('cleanup', res);
    return res;
  };

  let closed: Promise<void> | null = null;

  return {
    config,
    store,
    hub,
    http,
    cleanup,
    listen() {
      return new Promise((resolve, reject) => {
        http.once('error', reject);
        http.listen(config.port, config.host, () => {
          http.off('error', reject);
          const addr = http.address() as AddressInfo;
          timers.push(setInterval(() => hub.heartbeat(), config.heartbeatIntervalMs).unref());
          timers.push(
            setInterval(() => {
              try {
                cleanup();
              } catch (err) {
                log.error('cleanup failed', { error: err instanceof Error ? err.name : 'unknown' });
              }
            }, config.cleanupIntervalMs).unref(),
          );
          log.info('relay listening', {
            host: addr.address,
            port: addr.port,
            itemTtlMs: config.itemTtlMs,
          });
          resolve({ port: addr.port, host: addr.address });
        });
      });
    },
    close() {
      closed ??= (async () => {
        for (const t of timers) clearInterval(t);
        hub.closeAll();
        await new Promise<void>((resolve) => {
          const force = setTimeout(() => hub.terminateAll(), 2000).unref();
          wss.close(() => {
            clearTimeout(force);
            resolve();
          });
          if (hub.connectionCount === 0) resolve();
        });
        hub.terminateAll();
        await new Promise<void>((resolve) => {
          if (!http.listening) return resolve();
          http.close(() => resolve());
          http.closeAllConnections();
        });
        store.close();
        log.info('relay stopped');
      })();
      return closed;
    },
  };
}
