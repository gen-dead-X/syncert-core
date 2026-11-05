/** Wire protocol version. Bumped on any breaking change to frames or item encoding. */
export const PROTOCOL_VERSION = 1 as const;

/** Item kind for plain-text clipboard content (UTF-8). */
export const KIND_CLIPBOARD_TEXT = 'clipboard.text' as const;

/** Maximum plaintext size for `clipboard.text` items: 256 KiB of UTF-8. */
export const MAX_TEXT_PAYLOAD_BYTES = 256 * 1024;

/** AES-256-GCM nonce length in bytes (96 bits). */
export const NONCE_BYTES = 12;

/** AES-256-GCM authentication tag length in bytes (128 bits). */
export const AEAD_TAG_BYTES = 16;

/**
 * Maximum ciphertext size of a single item on the wire (plaintext limit + GCM tag).
 * The relay enforces this without being able to see plaintext.
 */
export const MAX_ITEM_PAYLOAD_BYTES = MAX_TEXT_PAYLOAD_BYTES + AEAD_TAG_BYTES;

/** Maximum number of items in a single `sync.batch` frame. */
export const MAX_SYNC_BATCH_ITEMS = 10;

/**
 * Maximum size of a single serialized WebSocket frame, in UTF-16 code units
 * (JSON text is ASCII here, so this equals bytes). Sized to fit a full batch of
 * maximum-size items after base64 expansion.
 */
export const MAX_FRAME_CHARS = 4 * 1024 * 1024;

/** Length of a keyed content hash in hex characters (HMAC-SHA-256 → 32 bytes). */
export const CONTENT_HASH_HEX_LENGTH = 64;
