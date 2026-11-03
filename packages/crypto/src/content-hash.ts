import { bytesToHex } from '@syncert/protocol';
import type { SpaceKeys } from './keys.js';
import { buf, subtle } from './util.js';

/**
 * Keyed content hash: lowercase hex of HMAC-SHA-256(contentHashKey, plaintext),
 * where contentHashKey = HKDF-SHA-256(spaceKey, info "syncert/v1/content-hash").
 *
 * Why keyed: clients use the hash to de-duplicate (e.g. not re-applying the
 * clipboard text they just copied). A plain SHA-256 would let the relay, which
 * stores the hash next to the ciphertext, confirm guesses of low-entropy
 * clipboard content ("is it this password / OTP?"). Keying it with a secret
 * only space members know removes that oracle.
 */
export async function computeContentHash(keys: SpaceKeys, plaintext: Uint8Array): Promise<string> {
  const mac = await subtle().sign('HMAC', keys.contentHashKey, buf(plaintext));
  return bytesToHex(new Uint8Array(mac));
}
