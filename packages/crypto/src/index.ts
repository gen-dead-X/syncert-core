export { ITEM_AD_TAG, decryptItem, encodeItemAssociatedData, encryptItem } from './aead.js';
export { computeContentHash } from './content-hash.js';
export { DecryptionError, PairingError } from './errors.js';
export {
  HKDF_INFO_CONTENT_HASH,
  HKDF_INFO_ENCRYPTION,
  HKDF_SALT,
  SPACE_KEY_BYTES,
  deriveSubkeyBytes,
  generateSpaceKey,
  importSpaceKey,
  type SpaceKeys,
} from './keys.js';
export {
  MAX_PAIRING_STRING_LENGTH,
  PAIRING_PREFIX,
  decodePairingPayload,
  encodePairingPayload,
  type PairingPayload,
} from './pairing.js';
