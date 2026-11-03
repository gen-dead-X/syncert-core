import { base64UrlToBytes, bytesToBase64Url, utf8Decode, utf8Encode } from '@syncert/protocol';
import { z } from 'zod';
import { PairingError } from './errors.js';
import { SPACE_KEY_BYTES } from './keys.js';

/** Prefix of every pairing string; the digit is the pairing format version. */
export const PAIRING_PREFIX = 'syncert1:';

/** Upper bound on pairing string length (keeps QR codes scannable). */
export const MAX_PAIRING_STRING_LENGTH = 1024;

/**
 * Everything a new device needs to join a space. Shown as a QR code on an
 * existing device. Contains the space key, so it must only travel over a
 * channel the user controls (screen → camera), never via the relay.
 */
export interface PairingPayload {
  /** 256-bit space key. */
  spaceKey: Uint8Array;
  /** Relay WebSocket URL (ws:// or wss://). */
  relayUrl: string;
  /** One-time join token issued by the relay. */
  joinToken: string;
}

const RelayUrlSchema = z
  .string()
  .max(512)
  .refine((value) => {
    try {
      const u = new URL(value);
      return (
        (u.protocol === 'wss:' || u.protocol === 'ws:') && u.username === '' && u.password === ''
      );
    } catch {
      return false;
    }
  }, 'relay URL must be a ws:// or wss:// URL without credentials');

const JoinTokenSchema = z
  .string()
  .min(16)
  .max(256)
  .regex(/^[A-Za-z0-9_-]+$/, 'join token must be base64url characters');

/** JSON body of a pairing string (short keys keep the QR small). */
const PairingJsonSchema = z.strictObject({
  v: z.literal(1),
  k: z
    .string()
    .length(43)
    .regex(/^[A-Za-z0-9_-]+$/),
  r: RelayUrlSchema,
  t: JoinTokenSchema,
});

/**
 * Encode a pairing payload as `syncert1:` + base64url(JSON), unpadded.
 * JSON key order is fixed: {"v":1,"k":<base64url key>,"r":<url>,"t":<token>}.
 */
export function encodePairingPayload(payload: PairingPayload): string {
  if (!(payload.spaceKey instanceof Uint8Array) || payload.spaceKey.length !== SPACE_KEY_BYTES) {
    throw new PairingError(`space key must be ${SPACE_KEY_BYTES} bytes`);
  }
  const body = {
    v: 1 as const,
    k: bytesToBase64Url(payload.spaceKey),
    r: payload.relayUrl,
    t: payload.joinToken,
  };
  const parsed = PairingJsonSchema.safeParse(body);
  if (!parsed.success)
    throw new PairingError(`invalid pairing payload: ${parsed.error.issues[0]?.message}`);
  const out = PAIRING_PREFIX + bytesToBase64Url(utf8Encode(JSON.stringify(body)));
  if (out.length > MAX_PAIRING_STRING_LENGTH) throw new PairingError('pairing payload too long');
  return out;
}

/** Decode and strictly validate a pairing string. Throws {@link PairingError}. */
export function decodePairingPayload(input: string): PairingPayload {
  if (typeof input !== 'string') throw new PairingError('pairing payload must be a string');
  const text = input.trim();
  if (text.length > MAX_PAIRING_STRING_LENGTH) throw new PairingError('pairing payload too long');
  if (!text.startsWith(PAIRING_PREFIX)) throw new PairingError('not a syncert1 pairing payload');
  let json: unknown;
  try {
    json = JSON.parse(utf8Decode(base64UrlToBytes(text.slice(PAIRING_PREFIX.length))));
  } catch {
    throw new PairingError('pairing payload is not valid base64url JSON');
  }
  const parsed = PairingJsonSchema.safeParse(json);
  if (!parsed.success) {
    throw new PairingError(`invalid pairing payload: ${parsed.error.issues[0]?.message}`);
  }
  let spaceKey: Uint8Array;
  try {
    spaceKey = base64UrlToBytes(parsed.data.k);
  } catch {
    throw new PairingError('invalid space key encoding');
  }
  if (spaceKey.length !== SPACE_KEY_BYTES) throw new PairingError('invalid space key length');
  return { spaceKey, relayUrl: parsed.data.r, joinToken: parsed.data.t };
}
