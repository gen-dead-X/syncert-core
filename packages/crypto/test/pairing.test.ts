import { bytesToBase64Url, utf8Encode } from '@syncert/protocol';
import { describe, expect, it } from 'vitest';
import {
  PAIRING_PREFIX,
  PairingError,
  decodePairingPayload,
  encodePairingPayload,
  generateSpaceKey,
} from '../src/index.js';

const valid = () => ({
  spaceKey: generateSpaceKey(),
  relayUrl: 'wss://relay.example.com/v1',
  joinToken: 'jt_0123456789abcdefABCDEF',
});

const wrap = (body: unknown) => PAIRING_PREFIX + bytesToBase64Url(utf8Encode(JSON.stringify(body)));

describe('pairing payload', () => {
  it('round trips', () => {
    const p = valid();
    const encoded = encodePairingPayload(p);
    expect(encoded.startsWith('syncert1:')).toBe(true);
    expect(encoded).toMatch(/^syncert1:[A-Za-z0-9_-]+$/);
    expect(encoded.length).toBeLessThan(300);
    expect(decodePairingPayload(encoded)).toEqual(p);
    expect(decodePairingPayload(`  ${encoded}\n`)).toEqual(p);
  });

  it('allows ws:// for local development', () => {
    const p = { ...valid(), relayUrl: 'ws://localhost:8787' };
    expect(decodePairingPayload(encodePairingPayload(p))).toEqual(p);
  });

  it('refuses to encode invalid payloads', () => {
    expect(() => encodePairingPayload({ ...valid(), spaceKey: new Uint8Array(31) })).toThrow(
      PairingError,
    );
    expect(() => encodePairingPayload({ ...valid(), relayUrl: 'https://x.example' })).toThrow(
      PairingError,
    );
    expect(() => encodePairingPayload({ ...valid(), joinToken: 'short' })).toThrow(PairingError);
  });

  const p = valid();
  const k = bytesToBase64Url(p.spaceKey);
  const good = { v: 1, k, r: p.relayUrl, t: p.joinToken };

  it.each([
    ['empty string', ''],
    ['missing prefix', encodePairingPayload(p).slice(PAIRING_PREFIX.length)],
    ['wrong version prefix', encodePairingPayload(p).replace('syncert1:', 'syncert2:')],
    ['uppercase prefix', encodePairingPayload(p).replace('syncert1:', 'SYNCERT1:')],
    ['bad base64url', 'syncert1:@@@@'],
    ['base64 with padding', encodePairingPayload(p) + '='],
    ['not JSON', PAIRING_PREFIX + bytesToBase64Url(utf8Encode('nope'))],
    ['JSON array', wrap([1, 2, 3])],
    ['version 2', wrap({ ...good, v: 2 })],
    ['short key', wrap({ ...good, k: bytesToBase64Url(new Uint8Array(31)) })],
    ['long key', wrap({ ...good, k: bytesToBase64Url(new Uint8Array(33)) })],
    ['key non-canonical', wrap({ ...good, k: k.slice(0, 42) + 'B' })],
    ['http relay', wrap({ ...good, r: 'http://relay.example.com' })],
    ['relay with credentials', wrap({ ...good, r: 'wss://user:pw@relay.example.com' })],
    ['relay not a URL', wrap({ ...good, r: 'relay' })],
    ['short token', wrap({ ...good, t: 'abc' })],
    ['token bad chars', wrap({ ...good, t: 'abc def ghi jkl mno p' })],
    ['missing token', wrap({ v: 1, k, r: p.relayUrl })],
    ['extra field', wrap({ ...good, x: 1 })],
    ['too long', PAIRING_PREFIX + 'A'.repeat(2000)],
  ])('rejects %s', (_name, input) => {
    expect(() => decodePairingPayload(input)).toThrow(PairingError);
  });
});
