import { utf8Encode } from '@syncert/protocol';
import { buf, randomBytes, subtle } from './util.js';

/** Space keys are 256-bit random secrets shared by every device in a space. */
export const SPACE_KEY_BYTES = 32;

/** HKDF-SHA-256 salt (fixed, public). */
export const HKDF_SALT = utf8Encode('syncert/v1/hkdf-salt');
/** HKDF info for the AES-256-GCM item encryption key. */
export const HKDF_INFO_ENCRYPTION = utf8Encode('syncert/v1/item-encryption');
/** HKDF info for the HMAC-SHA-256 content-hash key. */
export const HKDF_INFO_CONTENT_HASH = utf8Encode('syncert/v1/content-hash');

/**
 * Non-extractable WebCrypto keys derived from a space key. The raw space key
 * itself is only needed for pairing; day-to-day crypto uses these subkeys.
 */
export interface SpaceKeys {
  /** AES-256-GCM key. */
  readonly encryptionKey: CryptoKey;
  /** HMAC-SHA-256 key for keyed content hashes. */
  readonly contentHashKey: CryptoKey;
}

/** Generate a fresh random 256-bit space key. */
export function generateSpaceKey(): Uint8Array {
  return randomBytes(SPACE_KEY_BYTES);
}

function assertSpaceKey(spaceKey: Uint8Array): void {
  if (!(spaceKey instanceof Uint8Array) || spaceKey.length !== SPACE_KEY_BYTES) {
    throw new TypeError(`space key must be ${SPACE_KEY_BYTES} bytes`);
  }
}

/**
 * HKDF-SHA-256(spaceKey, salt=HKDF_SALT, info) → 32 bytes.
 * Exposed so test vectors can pin derived key material for other platforms.
 */
export async function deriveSubkeyBytes(
  spaceKey: Uint8Array,
  info: Uint8Array,
): Promise<Uint8Array> {
  assertSpaceKey(spaceKey);
  const s = subtle();
  const ikm = await s.importKey('raw', buf(spaceKey), 'HKDF', false, ['deriveBits']);
  const bits = await s.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: buf(HKDF_SALT), info: buf(info) },
    ikm,
    256,
  );
  return new Uint8Array(bits);
}

/** Derive the non-extractable subkeys used for item encryption and content hashing. */
export async function importSpaceKey(spaceKey: Uint8Array): Promise<SpaceKeys> {
  assertSpaceKey(spaceKey);
  const s = subtle();
  const ikm = await s.importKey('raw', buf(spaceKey), 'HKDF', false, ['deriveKey']);
  const [encryptionKey, contentHashKey] = await Promise.all([
    s.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: buf(HKDF_SALT), info: buf(HKDF_INFO_ENCRYPTION) },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    ),
    s.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: buf(HKDF_SALT), info: buf(HKDF_INFO_CONTENT_HASH) },
      ikm,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign'],
    ),
  ]);
  return { encryptionKey, contentHashKey };
}
