import {
  AEAD_TAG_BYTES,
  MAX_ITEM_PAYLOAD_BYTES,
  NONCE_BYTES,
  type SyncItem,
  type SyncItemMeta,
  utf8Encode,
} from '@syncert/protocol';
import { computeContentHash } from './content-hash.js';
import { DecryptionError } from './errors.js';
import type { SpaceKeys } from './keys.js';
import { buf, constantTimeEqual, randomBytes, subtle } from './util.js';

/** Domain-separation tag at the start of the associated data. */
export const ITEM_AD_TAG = 'syncert/v1/item-ad';

/**
 * Canonical associated-data encoding of item metadata.
 *
 * Layout (all integers big-endian):
 *   lp(ITEM_AD_TAG) || lp(spaceId) || lp(id) || lp(originDeviceId) || lp(kind)
 *   || u32(schemaVersion) || u64(createdAt)
 * where lp(s) = u32(byteLength(utf8(s))) || utf8(s).
 *
 * Length prefixes make the encoding injective, and it is trivial to reproduce
 * in Swift/Kotlin (no JSON canonicalization rules involved).
 */
export function encodeItemAssociatedData(meta: SyncItemMeta): Uint8Array {
  if (
    !Number.isInteger(meta.schemaVersion) ||
    meta.schemaVersion < 0 ||
    meta.schemaVersion > 0xffff_ffff
  ) {
    throw new RangeError('schemaVersion must be a u32');
  }
  if (!Number.isSafeInteger(meta.createdAt) || meta.createdAt < 0) {
    throw new RangeError('createdAt must be a non-negative safe integer');
  }
  const parts = [ITEM_AD_TAG, meta.spaceId, meta.id, meta.originDeviceId, meta.kind].map((s) =>
    utf8Encode(s),
  );
  const size = parts.reduce((n, p) => n + 4 + p.length, 0) + 4 + 8;
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let o = 0;
  for (const p of parts) {
    view.setUint32(o, p.length);
    o += 4;
    out.set(p, o);
    o += p.length;
  }
  view.setUint32(o, meta.schemaVersion);
  o += 4;
  view.setBigUint64(o, BigInt(meta.createdAt));
  return out;
}

/** @internal Encrypt with a caller-supplied nonce. Only for deterministic test vectors. */
export async function encryptItemWithNonce(
  keys: SpaceKeys,
  meta: SyncItemMeta,
  plaintext: Uint8Array,
  nonce: Uint8Array,
): Promise<SyncItem> {
  if (nonce.length !== NONCE_BYTES) throw new RangeError(`nonce must be ${NONCE_BYTES} bytes`);
  if (plaintext.length + AEAD_TAG_BYTES > MAX_ITEM_PAYLOAD_BYTES) {
    throw new RangeError('plaintext exceeds maximum item size');
  }
  const ad = encodeItemAssociatedData(meta);
  const [ct, contentHash] = await Promise.all([
    subtle().encrypt(
      { name: 'AES-GCM', iv: buf(nonce), additionalData: buf(ad), tagLength: AEAD_TAG_BYTES * 8 },
      keys.encryptionKey,
      buf(plaintext),
    ),
    computeContentHash(keys, plaintext),
  ]);
  return {
    id: meta.id,
    spaceId: meta.spaceId,
    originDeviceId: meta.originDeviceId,
    kind: meta.kind,
    schemaVersion: meta.schemaVersion,
    createdAt: meta.createdAt,
    payload: new Uint8Array(ct),
    nonce: new Uint8Array(nonce),
    contentHash,
  };
}

/**
 * Encrypt a plaintext into a {@link SyncItem} with AES-256-GCM, a fresh random
 * 96-bit nonce, and the item's metadata as associated data.
 */
export function encryptItem(
  keys: SpaceKeys,
  meta: SyncItemMeta,
  plaintext: Uint8Array,
): Promise<SyncItem> {
  return encryptItemWithNonce(keys, meta, plaintext, randomBytes(NONCE_BYTES));
}

/**
 * Decrypt and authenticate an item. Verifies the GCM tag over ciphertext and
 * metadata, then verifies the keyed content hash. Throws {@link DecryptionError}
 * on any failure.
 */
export async function decryptItem(keys: SpaceKeys, item: SyncItem): Promise<Uint8Array> {
  if (item.nonce.length !== NONCE_BYTES || item.payload.length < AEAD_TAG_BYTES) {
    throw new DecryptionError();
  }
  let ad: Uint8Array;
  try {
    ad = encodeItemAssociatedData(item);
  } catch {
    throw new DecryptionError();
  }
  let plaintext: Uint8Array;
  try {
    const pt = await subtle().decrypt(
      {
        name: 'AES-GCM',
        iv: buf(item.nonce),
        additionalData: buf(ad),
        tagLength: AEAD_TAG_BYTES * 8,
      },
      keys.encryptionKey,
      buf(item.payload),
    );
    plaintext = new Uint8Array(pt);
  } catch {
    throw new DecryptionError();
  }
  const expected = await computeContentHash(keys, plaintext);
  if (!constantTimeEqual(expected, item.contentHash)) throw new DecryptionError();
  return plaintext;
}
