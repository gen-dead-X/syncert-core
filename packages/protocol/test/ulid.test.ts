import { describe, expect, it } from 'vitest';
import { isUlid, ulid, ulidTime } from '../src/index.js';

describe('ulid', () => {
  it('generates valid, unique, time-ordered ids', () => {
    const a = ulid(1_700_000_000_000);
    const b = ulid(1_700_000_000_001);
    expect(isUlid(a)).toBe(true);
    expect(a < b).toBe(true);
    expect(ulidTime(a)).toBe(1_700_000_000_000);
    const ids = new Set(Array.from({ length: 1000 }, () => ulid()));
    expect(ids.size).toBe(1000);
  });

  it('rejects invalid ids', () => {
    expect(isUlid('01ARZ3NDEKTSV4RRFFQ69G5FAV')).toBe(true);
    expect(isUlid('01arz3ndektsv4rrffq69g5fav')).toBe(false);
    expect(isUlid('81ARZ3NDEKTSV4RRFFQ69G5FAV')).toBe(false);
    expect(isUlid('01ARZ3NDEKTSV4RRFFQ69G5FAI')).toBe(false);
    expect(isUlid('01ARZ3NDEKTSV4RRFFQ69G5FA')).toBe(false);
    expect(() => ulid(-1)).toThrow(RangeError);
  });
});
