/**
 * Dependency-free byte encodings shared by every syncert package.
 * Works identically in Node 20+, browsers and Tauri webviews (no Buffer).
 */

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function buildLookup(alphabet: string): Int16Array {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) table[alphabet.charCodeAt(i)] = i;
  return table;
}
const B64_LOOKUP = buildLookup(B64_ALPHABET);
const B64URL_LOOKUP = buildLookup(B64URL_ALPHABET);

function encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      alphabet[(n >>> 18) & 63]! +
      alphabet[(n >>> 12) & 63]! +
      alphabet[(n >>> 6) & 63]! +
      alphabet[n & 63]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += alphabet[(n >>> 18) & 63]! + alphabet[(n >>> 12) & 63]! + (pad ? '==' : '');
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      alphabet[(n >>> 18) & 63]! +
      alphabet[(n >>> 12) & 63]! +
      alphabet[(n >>> 6) & 63]! +
      (pad ? '=' : '');
  }
  return out;
}

function decode(input: string, lookup: Int16Array, padded: boolean, label: string): Uint8Array {
  let body = input;
  if (padded) {
    if (input.length % 4 !== 0) throw new TypeError(`invalid ${label}: bad length`);
    if (body.endsWith('==')) body = body.slice(0, -2);
    else if (body.endsWith('=')) body = body.slice(0, -1);
  }
  const rem = body.length % 4;
  if (rem === 1) throw new TypeError(`invalid ${label}: bad length`);
  const outLen = Math.floor((body.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body.charCodeAt(i);
    const v = c < 128 ? lookup[c]! : -1;
    if (v < 0) throw new TypeError(`invalid ${label}: unexpected character`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  // Reject non-canonical encodings (non-zero trailing bits).
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) {
    throw new TypeError(`invalid ${label}: non-canonical trailing bits`);
  }
  return out;
}

/** Standard base64 (RFC 4648 §4) with padding. Used for payload/nonce on the wire. */
export function bytesToBase64(bytes: Uint8Array): string {
  return encode(bytes, B64_ALPHABET, true);
}

/** Strict standard base64 decoder; throws TypeError on malformed or non-canonical input. */
export function base64ToBytes(b64: string): Uint8Array {
  return decode(b64, B64_LOOKUP, true, 'base64');
}

/** URL-safe base64 (RFC 4648 §5) without padding. Used for pairing payloads. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return encode(bytes, B64URL_ALPHABET, false);
}

/** Strict unpadded base64url decoder; throws TypeError on malformed or non-canonical input. */
export function base64UrlToBytes(b64url: string): Uint8Array {
  return decode(b64url, B64URL_LOOKUP, false, 'base64url');
}

/** Lowercase hex. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Strict hex decoder (case-insensitive); throws TypeError on malformed input. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new TypeError('invalid hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/** Encode a string as UTF-8. */
export function utf8Encode(text: string): Uint8Array {
  return textEncoder.encode(text);
}

/** Decode UTF-8; throws TypeError on invalid sequences. */
export function utf8Decode(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}
