/**
 * Thrown when an item fails to decrypt or authenticate: wrong key, tampered
 * ciphertext/nonce/metadata, or content-hash mismatch. Deliberately carries no
 * detail about which check failed.
 */
export class DecryptionError extends Error {
  override readonly name = 'DecryptionError';
  constructor(message = 'item failed to decrypt or authenticate') {
    super(message);
  }
}

/** Thrown when a pairing string is malformed. */
export class PairingError extends Error {
  override readonly name = 'PairingError';
}
