import { createDecipheriv, hkdfSync } from 'node:crypto';
import { ulid, utf8Decode, utf8Encode, type SyncItem, type SyncItemMeta } from '@syncert/protocol';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  DecryptionError,
  computeContentHash,
  decryptItem,
  deriveSubkeyBytes,
  encodeItemAssociatedData,
  encryptItem,
  generateSpaceKey,
  HKDF_INFO_CONTENT_HASH,
  HKDF_INFO_ENCRYPTION,
  HKDF_SALT,
  importSpaceKey,
  type SpaceKeys,
} from '../src/index.js';

const meta = (): SyncItemMeta => ({
  id: ulid(),
  spaceId: 'space_1',
  originDeviceId: 'device_A',
  kind: 'clipboard.text',
  schemaVersion: 1,
  createdAt: 1_767_225_600_000,
});

let spaceKey: Uint8Array;
let keys: SpaceKeys;
beforeAll(async () => {
  spaceKey = generateSpaceKey();
  keys = await importSpaceKey(spaceKey);
});

const flip = (bytes: Uint8Array, index = 0): Uint8Array => {
  const copy = new Uint8Array(bytes);
  copy[index] = copy[index]! ^ 0x01;
  return copy;
};

describe('space keys', () => {
  it('are 256-bit and random', () => {
    const a = generateSpaceKey();
    const b = generateSpaceKey();
    expect(a.length).toBe(32);
    expect(a).not.toEqual(b);
  });

  it('rejects wrong-length keys', async () => {
    await expect(importSpaceKey(new Uint8Array(16))).rejects.toThrow(TypeError);
  });

  it('derives distinct subkeys matching an independent HKDF implementation', async () => {
    const enc = await deriveSubkeyBytes(spaceKey, HKDF_INFO_ENCRYPTION);
    const mac = await deriveSubkeyBytes(spaceKey, HKDF_INFO_CONTENT_HASH);
    expect(enc).not.toEqual(mac);
    const nodeEnc = new Uint8Array(
      hkdfSync('sha256', spaceKey, HKDF_SALT, HKDF_INFO_ENCRYPTION, 32),
    );
    expect(enc).toEqual(nodeEnc);
  });
});

describe('encryptItem / decryptItem', () => {
  it('round trips text including empty and unicode', async () => {
    for (const text of ['hello', '', 'héllo 🌍 नमस्ते', 'x'.repeat(256 * 1024)]) {
      const item = await encryptItem(keys, meta(), utf8Encode(text));
      expect(item.nonce.length).toBe(12);
      expect(item.payload.length).toBe(utf8Encode(text).length + 16);
      expect(utf8Decode(await decryptItem(keys, item))).toBe(text);
    }
  });

  it('refuses plaintext over the size limit', async () => {
    await expect(encryptItem(keys, meta(), new Uint8Array(256 * 1024 + 1))).rejects.toThrow(
      RangeError,
    );
  });

  it('ciphertext never contains the plaintext', async () => {
    const pt = utf8Encode('super secret clipboard content');
    const item = await encryptItem(keys, meta(), pt);
    expect(Buffer.from(item.payload).includes(Buffer.from(pt))).toBe(false);
  });

  it('is interoperable with node:crypto AES-256-GCM using the documented construction', async () => {
    const m = meta();
    const pt = utf8Encode('interop');
    const item = await encryptItem(keys, m, pt);
    const key = await deriveSubkeyBytes(spaceKey, HKDF_INFO_ENCRYPTION);
    const d = createDecipheriv('aes-256-gcm', key, item.nonce);
    d.setAAD(encodeItemAssociatedData(m));
    d.setAuthTag(item.payload.subarray(item.payload.length - 16));
    const out = Buffer.concat([d.update(item.payload.subarray(0, -16)), d.final()]);
    expect(out.toString('utf8')).toBe('interop');
  });

  it('uses a fresh nonce for every item', async () => {
    const pt = utf8Encode('same plaintext');
    const m = meta();
    const nonces = new Set<string>();
    const payloads = new Set<string>();
    for (let i = 0; i < 500; i++) {
      const item = await encryptItem(keys, m, pt);
      nonces.add(Buffer.from(item.nonce).toString('hex'));
      payloads.add(Buffer.from(item.payload).toString('hex'));
    }
    expect(nonces.size).toBe(500);
    expect(payloads.size).toBe(500);
  });

  it('fails with the wrong key', async () => {
    const item = await encryptItem(keys, meta(), utf8Encode('hello'));
    const other = await importSpaceKey(generateSpaceKey());
    await expect(decryptItem(other, item)).rejects.toThrow(DecryptionError);
  });

  describe('tamper detection', () => {
    let item: SyncItem;
    beforeAll(async () => {
      item = await encryptItem(keys, meta(), utf8Encode('tamper me'));
    });

    it('detects ciphertext modification (first byte, last byte / tag)', async () => {
      await expect(decryptItem(keys, { ...item, payload: flip(item.payload, 0) })).rejects.toThrow(
        DecryptionError,
      );
      await expect(
        decryptItem(keys, { ...item, payload: flip(item.payload, item.payload.length - 1) }),
      ).rejects.toThrow(DecryptionError);
    });

    it('detects truncated ciphertext', async () => {
      await expect(
        decryptItem(keys, { ...item, payload: item.payload.subarray(0, 10) }),
      ).rejects.toThrow(DecryptionError);
      await expect(
        decryptItem(keys, { ...item, payload: item.payload.subarray(0, item.payload.length - 1) }),
      ).rejects.toThrow(DecryptionError);
    });

    it('detects nonce modification', async () => {
      await expect(decryptItem(keys, { ...item, nonce: flip(item.nonce, 5) })).rejects.toThrow(
        DecryptionError,
      );
      await expect(
        decryptItem(keys, { ...item, nonce: item.nonce.subarray(0, 11) }),
      ).rejects.toThrow(DecryptionError);
    });

    it.each([
      ['spaceId', { spaceId: 'space_2' }],
      ['id', { id: '01ARZ3NDEKTSV4RRFFQ69G5FAV' }],
      ['originDeviceId', { originDeviceId: 'device_B' }],
      ['kind', { kind: 'clipboard.html' }],
      ['schemaVersion', { schemaVersion: 2 }],
      ['createdAt', { createdAt: 1_767_225_600_001 }],
    ] as const)('detects modification of associated data field %s', async (_f, change) => {
      await expect(decryptItem(keys, { ...item, ...change })).rejects.toThrow(DecryptionError);
    });

    it('detects a swapped content hash', async () => {
      const other = await computeContentHash(keys, utf8Encode('something else'));
      await expect(decryptItem(keys, { ...item, contentHash: other })).rejects.toThrow(
        DecryptionError,
      );
    });

    it('does not accept a ciphertext moved to another item', async () => {
      const second = await encryptItem(keys, meta(), utf8Encode('other'));
      await expect(
        decryptItem(keys, { ...second, payload: item.payload, nonce: item.nonce }),
      ).rejects.toThrow(DecryptionError);
    });
  });
});

describe('associated data encoding', () => {
  it('is injective across field boundaries', () => {
    const a = encodeItemAssociatedData({ ...meta(), id: 'X', spaceId: 'ab', originDeviceId: 'c' });
    const b = encodeItemAssociatedData({ ...meta(), id: 'X', spaceId: 'a', originDeviceId: 'bc' });
    expect(a).not.toEqual(b);
  });

  it('rejects out-of-range integers', () => {
    expect(() => encodeItemAssociatedData({ ...meta(), createdAt: -1 })).toThrow(RangeError);
    expect(() => encodeItemAssociatedData({ ...meta(), createdAt: 2 ** 53 })).toThrow(RangeError);
    expect(() => encodeItemAssociatedData({ ...meta(), schemaVersion: 2 ** 32 })).toThrow(
      RangeError,
    );
  });
});

describe('keyed content hash', () => {
  it('is deterministic per space and differs across spaces and from plain SHA-256', async () => {
    const pt = utf8Encode('123456');
    const h1 = await computeContentHash(keys, pt);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
    expect(await computeContentHash(keys, pt)).toBe(h1);
    const other = await importSpaceKey(generateSpaceKey());
    expect(await computeContentHash(other, pt)).not.toBe(h1);
    const plain = Buffer.from(await crypto.subtle.digest('SHA-256', new Uint8Array(pt))).toString(
      'hex',
    );
    expect(h1).not.toBe(plain);
  });
});
