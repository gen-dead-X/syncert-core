import { createHash, randomBytes } from 'node:crypto';

/** 256-bit random secret, base64url (43 chars). Valid as both device and join token. */
export function generateToken(): string {
  return randomBytes(32).toString('base64url');
}

/** Opaque 128-bit random identifier for spaces and devices (base64url, 22 chars). */
export function generateId(): string {
  return randomBytes(16).toString('base64url');
}

/**
 * SHA-256 of a token, hex. Tokens are 256-bit random values, so a fast hash is
 * sufficient (no password-style stretching needed): the database alone never
 * lets anyone recover or forge a token.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}
