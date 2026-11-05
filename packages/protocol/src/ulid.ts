/**
 * Minimal ULID (https://github.com/ulid/spec) support: 48-bit millisecond
 * timestamp + 80 bits of randomness, Crockford base32, 26 chars.
 */

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Canonical (uppercase) ULID. First char ≤ 7 so the timestamp fits in 48 bits. */
export const ULID_REGEX = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

export function isUlid(value: string): boolean {
  return ULID_REGEX.test(value);
}

/** Generate a ULID using `crypto.getRandomValues`. */
export function ulid(timeMs: number = Date.now()): string {
  if (!Number.isSafeInteger(timeMs) || timeMs < 0 || timeMs > 2 ** 48 - 1) {
    throw new RangeError('ULID timestamp out of range');
  }
  let time = '';
  let t = timeMs;
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[t % 32]! + time;
    t = Math.floor(t / 32);
  }
  const rand = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let random = '';
  for (let i = 0; i < 16; i++) random += CROCKFORD[rand[i]! & 31]!;
  return time + random;
}

/** Extract the millisecond timestamp encoded in a ULID. */
export function ulidTime(id: string): number {
  if (!isUlid(id)) throw new TypeError('invalid ULID');
  let t = 0;
  for (let i = 0; i < 10; i++) t = t * 32 + CROCKFORD.indexOf(id[i]!);
  return t;
}
