/**
 * Deterministic cross-platform test vectors (test-vectors/v1.json).
 *
 * Normal runs verify the committed file against this implementation.
 * `pnpm vectors:update` (UPDATE_VECTORS=1) regenerates it; the regenerated file
 * must be reviewed, since any diff means a wire-format change.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createCipheriv, createHmac } from 'node:crypto';
import {
  bytesToHex,
  hexToBytes,
  itemFromWire,
  itemToWire,
  utf8Decode,
  utf8Encode,
  type SyncItemMeta,
  type WireSyncItem,
} from '@syncert/protocol';
import { describe, expect, it } from 'vitest';
import { encryptItemWithNonce } from '../src/aead.js';
import {
  DecryptionError,
  HKDF_INFO_CONTENT_HASH,
  HKDF_INFO_ENCRYPTION,
  HKDF_SALT,
  ITEM_AD_TAG,
  decodePairingPayload,
  decryptItem,
  deriveSubkeyBytes,
  encodeItemAssociatedData,
  encodePairingPayload,
  importSpaceKey,
} from '../src/index.js';

const VECTORS_URL = new URL('../test-vectors/v1.json', import.meta.url);

interface ItemVector {
  name: string;
  spaceKey: string;
  meta: SyncItemMeta;
  plaintextUtf8: string;
  plaintext: string;
  nonce: string;
  associatedData: string;
  ciphertext: string;
  contentHash: string;
  wire: WireSyncItem;
}

interface Vectors {
  description: string;
  version: 1;
  encoding: Record<string, string>;
  kdf: {
    algorithm: string;
    salt: string;
    infoEncryption: string;
    infoContentHash: string;
    cases: { spaceKey: string; encryptionKey: string; contentHashKey: string }[];
  };
  aead: { algorithm: string; associatedDataTag: string; items: ItemVector[] };
  tampered: { name: string; base: string; wire: WireSyncItem }[];
  pairing: {
    valid: { spaceKey: string; relayUrl: string; joinToken: string; encoded: string }[];
    invalid: { name: string; encoded: string }[];
  };
}

const SPACE_KEY_A = bytesToHex(Uint8Array.from({ length: 32 }, (_, i) => i));
const SPACE_KEY_B = 'ff'.repeat(32);

const ITEM_INPUTS: {
  name: string;
  spaceKey: string;
  nonce: string;
  meta: SyncItemMeta;
  text: string;
}[] = [
  {
    name: 'ascii',
    spaceKey: SPACE_KEY_A,
    nonce: '000102030405060708090a0b',
    meta: {
      id: '01KDXQ3J00ABCDEFGHJKMNPQRS',
      spaceId: 'space_test_1',
      originDeviceId: 'device_mac_1',
      kind: 'clipboard.text',
      schemaVersion: 1,
      createdAt: 1767225600000,
    },
    text: 'hello, syncert',
  },
  {
    name: 'unicode',
    spaceKey: SPACE_KEY_A,
    nonce: 'a0a1a2a3a4a5a6a7a8a9aaab',
    meta: {
      id: '01KDXQ3J01ABCDEFGHJKMNPQRS',
      spaceId: 'space_test_1',
      originDeviceId: 'device_android_1',
      kind: 'clipboard.text',
      schemaVersion: 1,
      createdAt: 1767225600123,
    },
    text: 'héllo 🌍 नमस्ते — "quotes" \n newline',
  },
  {
    name: 'empty',
    spaceKey: SPACE_KEY_B,
    nonce: 'ffffffffffffffffffffffff',
    meta: {
      id: '7ZZZZZZZZZZZZZZZZZZZZZZZZZ',
      spaceId: 'S',
      originDeviceId: 'D',
      kind: 'clipboard.text',
      schemaVersion: 1,
      createdAt: 0,
    },
    text: '',
  },
];

const PAIRING_INPUTS = [
  {
    spaceKey: SPACE_KEY_A,
    relayUrl: 'wss://relay.syncert.example/v1',
    joinToken: 'jt_AAAAAAAAAAAAAAAAAAAAAA',
  },
  { spaceKey: SPACE_KEY_B, relayUrl: 'ws://localhost:8787', joinToken: '0123456789abcdef' },
];

async function generate(): Promise<Vectors> {
  const items: ItemVector[] = [];
  for (const input of ITEM_INPUTS) {
    const keys = await importSpaceKey(hexToBytes(input.spaceKey));
    const pt = utf8Encode(input.text);
    const item = await encryptItemWithNonce(keys, input.meta, pt, hexToBytes(input.nonce));
    items.push({
      name: input.name,
      spaceKey: input.spaceKey,
      meta: input.meta,
      plaintextUtf8: input.text,
      plaintext: bytesToHex(pt),
      nonce: input.nonce,
      associatedData: bytesToHex(encodeItemAssociatedData(input.meta)),
      ciphertext: bytesToHex(item.payload),
      contentHash: item.contentHash,
      wire: itemToWire(item),
    });
  }
  const base = items[0]!;
  const flipHex = (hex: string, at: number) =>
    hex.slice(0, at) + (parseInt(hex[at]!, 16) ^ 1).toString(16) + hex.slice(at + 1);
  const b64 = (hex: string) => Buffer.from(hexToBytes(hex)).toString('base64');
  const tampered = [
    {
      name: 'ciphertext bit flip',
      wire: { ...base.wire, payload: b64(flipHex(base.ciphertext, 1)) },
    },
    {
      name: 'tag bit flip',
      wire: { ...base.wire, payload: b64(flipHex(base.ciphertext, base.ciphertext.length - 1)) },
    },
    { name: 'nonce bit flip', wire: { ...base.wire, nonce: b64(flipHex(base.nonce, 1)) } },
    { name: 'spaceId changed', wire: { ...base.wire, spaceId: 'space_test_2' } },
    { name: 'id changed', wire: { ...base.wire, id: '01KDXQ3J00ABCDEFGHJKMNPQRT' } },
    { name: 'originDeviceId changed', wire: { ...base.wire, originDeviceId: 'device_mac_2' } },
    { name: 'kind changed', wire: { ...base.wire, kind: 'clipboard.html' } },
    { name: 'schemaVersion changed', wire: { ...base.wire, schemaVersion: 2 } },
    { name: 'createdAt changed', wire: { ...base.wire, createdAt: base.meta.createdAt + 1 } },
    {
      name: 'contentHash changed',
      wire: { ...base.wire, contentHash: flipHex(base.contentHash, 0) },
    },
  ].map((t) => ({ ...t, base: base.name }));

  const kdfCases = [];
  for (const spaceKey of [SPACE_KEY_A, SPACE_KEY_B]) {
    const k = hexToBytes(spaceKey);
    kdfCases.push({
      spaceKey,
      encryptionKey: bytesToHex(await deriveSubkeyBytes(k, HKDF_INFO_ENCRYPTION)),
      contentHashKey: bytesToHex(await deriveSubkeyBytes(k, HKDF_INFO_CONTENT_HASH)),
    });
  }

  const valid = PAIRING_INPUTS.map((p) => ({
    ...p,
    encoded: encodePairingPayload({ ...p, spaceKey: hexToBytes(p.spaceKey) }),
  }));
  const good = valid[0]!.encoded;
  const invalid = [
    { name: 'wrong prefix', encoded: good.replace('syncert1:', 'syncert2:') },
    { name: 'missing prefix', encoded: good.slice('syncert1:'.length) },
    { name: 'truncated', encoded: good.slice(0, good.length - 5) },
    { name: 'padded base64', encoded: good + '=' },
    { name: 'non-base64url character', encoded: good.slice(0, -1) + '+' },
    {
      name: 'space key too short',
      encoded:
        'syncert1:' +
        Buffer.from(
          JSON.stringify({
            v: 1,
            k: Buffer.alloc(31).toString('base64url'),
            r: 'wss://relay.syncert.example/v1',
            t: 'jt_AAAAAAAAAAAAAAAAAAAAAA',
          }),
        ).toString('base64url'),
    },
  ];

  return {
    description:
      'syncert v1 compatibility vectors. Hex is lowercase. Wire binary fields are standard base64 with padding; pairing uses unpadded base64url.',
    version: 1,
    encoding: {
      associatedData:
        'u32be-length-prefixed UTF-8 of [associatedDataTag, spaceId, id, originDeviceId, kind] || u32be(schemaVersion) || u64be(createdAt)',
      ciphertext: 'AES-256-GCM ciphertext || 16-byte tag',
      contentHash: 'lowercase hex HMAC-SHA-256(contentHashKey, plaintext)',
      pairing:
        '"syncert1:" + base64url(JSON {"v":1,"k":base64url(spaceKey),"r":relayUrl,"t":joinToken})',
    },
    kdf: {
      algorithm: 'HKDF-SHA-256, 32-byte output',
      salt: bytesToHex(HKDF_SALT),
      infoEncryption: bytesToHex(HKDF_INFO_ENCRYPTION),
      infoContentHash: bytesToHex(HKDF_INFO_CONTENT_HASH),
      cases: kdfCases,
    },
    aead: {
      algorithm: 'AES-256-GCM, 96-bit nonce, 128-bit tag',
      associatedDataTag: ITEM_AD_TAG,
      items,
    },
    tampered,
    pairing: { valid, invalid },
  };
}

if (process.env.UPDATE_VECTORS === '1') {
  writeFileSync(VECTORS_URL, JSON.stringify(await generate(), null, 2) + '\n');
}

const vectors = JSON.parse(readFileSync(VECTORS_URL, 'utf8')) as Vectors;

describe('test vectors v1', () => {
  it('committed file matches what this implementation generates', async () => {
    expect(await generate()).toEqual(vectors);
  });

  it.each(vectors.kdf.cases)('HKDF subkeys for $spaceKey', async (c) => {
    const k = hexToBytes(c.spaceKey);
    expect(bytesToHex(await deriveSubkeyBytes(k, hexToBytes(vectors.kdf.infoEncryption)))).toBe(
      c.encryptionKey,
    );
    expect(bytesToHex(await deriveSubkeyBytes(k, hexToBytes(vectors.kdf.infoContentHash)))).toBe(
      c.contentHashKey,
    );
  });

  it.each(vectors.aead.items)('item "$name" decrypts and matches', async (v) => {
    expect(bytesToHex(encodeItemAssociatedData(v.meta))).toBe(v.associatedData);
    const keys = await importSpaceKey(hexToBytes(v.spaceKey));
    const pt = await decryptItem(keys, itemFromWire(v.wire));
    expect(bytesToHex(pt)).toBe(v.plaintext);
    expect(utf8Decode(pt)).toBe(v.plaintextUtf8);
  });

  it.each(vectors.aead.items)(
    'item "$name" matches an independent node:crypto computation',
    (v) => {
      const kdf = vectors.kdf.cases.find((c) => c.spaceKey === v.spaceKey)!;
      const c = createCipheriv('aes-256-gcm', hexToBytes(kdf.encryptionKey), hexToBytes(v.nonce));
      c.setAAD(hexToBytes(v.associatedData));
      const ct = Buffer.concat([c.update(hexToBytes(v.plaintext)), c.final(), c.getAuthTag()]);
      expect(ct.toString('hex')).toBe(v.ciphertext);
      const mac = createHmac('sha256', hexToBytes(kdf.contentHashKey))
        .update(hexToBytes(v.plaintext))
        .digest('hex');
      expect(mac).toBe(v.contentHash);
    },
  );

  it.each(vectors.tampered)('tampered "$name" is rejected', async (t) => {
    const base = vectors.aead.items.find((i) => i.name === t.base)!;
    const keys = await importSpaceKey(hexToBytes(base.spaceKey));
    await expect(decryptItem(keys, itemFromWire(t.wire))).rejects.toThrow(DecryptionError);
  });

  it.each(vectors.pairing.valid)('pairing $relayUrl round trips', (p) => {
    expect(encodePairingPayload({ ...p, spaceKey: hexToBytes(p.spaceKey) })).toBe(p.encoded);
    const decoded = decodePairingPayload(p.encoded);
    expect(bytesToHex(decoded.spaceKey)).toBe(p.spaceKey);
    expect(decoded.relayUrl).toBe(p.relayUrl);
    expect(decoded.joinToken).toBe(p.joinToken);
  });

  it.each(vectors.pairing.invalid)('pairing "$name" is rejected', (p) => {
    expect(() => decodePairingPayload(p.encoded)).toThrow();
  });
});
