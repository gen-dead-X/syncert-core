import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
  utf8Decode,
  utf8Encode,
} from '../src/index.js';

describe('base64 / base64url / hex', () => {
  it('matches Node Buffer for many lengths', () => {
    for (let len = 0; len < 70; len++) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      const b = Buffer.from(bytes);
      expect(bytesToBase64(bytes)).toBe(b.toString('base64'));
      expect(bytesToBase64Url(bytes)).toBe(b.toString('base64url'));
      expect(bytesToHex(bytes)).toBe(b.toString('hex'));
      expect(base64ToBytes(b.toString('base64'))).toEqual(bytes);
      expect(base64UrlToBytes(b.toString('base64url'))).toEqual(bytes);
      expect(hexToBytes(b.toString('hex'))).toEqual(bytes);
    }
  });

  it('rejects malformed input', () => {
    for (const bad of ['A', 'AB', 'AB=', 'A===', '****', 'AB==AB==', 'AB-_', 'QR==']) {
      expect(() => base64ToBytes(bad), bad).toThrow(TypeError);
    }
    for (const bad of ['A', 'AB==', 'AB+/', 'QR']) {
      expect(() => base64UrlToBytes(bad), bad).toThrow(TypeError);
    }
    expect(() => hexToBytes('abc')).toThrow(TypeError);
    expect(() => hexToBytes('zz')).toThrow(TypeError);
  });

  it('utf8 round trips and rejects invalid sequences', () => {
    const s = 'héllo 🌍 नमस्ते';
    expect(utf8Decode(utf8Encode(s))).toBe(s);
    expect(() => utf8Decode(new Uint8Array([0xff, 0xfe]))).toThrow();
  });
});
