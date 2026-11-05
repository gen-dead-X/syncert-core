import type { LogLevel } from './config.js';

/**
 * Structured fields attached to a log line. Deliberately restricted to
 * primitives: callers pass ids, counts and sizes, never frames, items, request
 * bodies or tokens. Keys that look like secrets or payloads are dropped as a
 * second line of defence.
 */
export type LogFields = Record<string, string | number | boolean | null | undefined>;

export interface Logger {
  debug(msg: string, fields?: LogFields): void;
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
}

const LEVELS: Record<Exclude<LogLevel, 'silent'>, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

/** Field names that must never reach a log line. */
const FORBIDDEN_KEY = /token|secret|payload|ciphertext|nonce|plaintext|authorization|key/i;

/**
 * Minimal JSON-lines logger (one object per line on the given sink, stdout by
 * default). Avoids a logging dependency; the relay only needs leveled,
 * structured, payload-free output.
 */
export function createLogger(
  level: LogLevel,
  sink: (line: string) => void = (line) => process.stdout.write(line + '\n'),
): Logger {
  const threshold = level === 'silent' ? Infinity : LEVELS[level];
  const log = (lvl: Exclude<LogLevel, 'silent'>, msg: string, fields?: LogFields) => {
    if (LEVELS[lvl] < threshold) return;
    const entry: Record<string, unknown> = { time: new Date().toISOString(), level: lvl, msg };
    if (fields) {
      for (const [k, v] of Object.entries(fields)) {
        if (v === undefined) continue;
        entry[k] = FORBIDDEN_KEY.test(k) ? '[redacted]' : v;
      }
    }
    sink(JSON.stringify(entry));
  };
  return {
    debug: (m, f) => log('debug', m, f),
    info: (m, f) => log('info', m, f),
    warn: (m, f) => log('warn', m, f),
    error: (m, f) => log('error', m, f),
  };
}
