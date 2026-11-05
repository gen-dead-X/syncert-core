#!/usr/bin/env node
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { loadConfig, type RelayConfig } from './config.js';
import { createLogger } from './logger.js';
import { createRelay } from './server.js';
import { assertNodeSupported } from './store.js';

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  process.stdout.write(
    'syncert-server: end-to-end-encrypted clipboard relay\n' +
      'Configure with environment variables (PORT, DATA_DIR, ITEM_TTL, ...);\n' +
      'see https://github.com/gen-dead-X/syncert-core#self-hosting\n',
  );
  process.exit(0);
}

let config: RelayConfig;
try {
  assertNodeSupported();
  config = loadConfig(process.env);
} catch (err) {
  process.stderr.write(`syncert-server: ${(err as Error).message}\n`);
  process.exit(1);
}

const log = createLogger(config.logLevel);
if (config.dbPath !== ':memory:')
  mkdirSync(path.dirname(path.resolve(config.dbPath)), { recursive: true });

const relay = createRelay({ config, logger: log });
await relay.listen();

let stopping = false;
const shutdown = (signal: string) => {
  if (stopping) return;
  stopping = true;
  log.info('shutting down', { signal });
  relay.close().then(
    () => process.exit(0),
    () => process.exit(1),
  );
};
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
