import {
  KIND_CLIPBOARD_TEXT,
  MAX_TEXT_PAYLOAD_BYTES,
  utf8Decode,
  utf8Encode,
} from '@syncert/protocol';
import type { DecodedItem, KindPlugin } from './plugin.js';

/** Platform clipboard access supplied by each app (Tauri, Android, ...). */
export interface TextClipboardAdapter {
  readText(): Promise<string | null>;
  writeText(text: string): Promise<void>;
}

/** Schema version 1: UTF-8 text, at most MAX_TEXT_PAYLOAD_BYTES. */
export const CLIPBOARD_TEXT_SCHEMA_VERSION = 1;

/** Reference `clipboard.text` plugin over a platform adapter. */
export function createTextClipboardPlugin(adapter: TextClipboardAdapter): KindPlugin<string> {
  return {
    kind: KIND_CLIPBOARD_TEXT,
    schemaVersion: CLIPBOARD_TEXT_SCHEMA_VERSION,
    async capture() {
      const text = await adapter.readText();
      if (text === null || text === '') return null;
      if (utf8Encode(text).length > MAX_TEXT_PAYLOAD_BYTES) return null;
      return text;
    },
    async apply(item: DecodedItem<string>) {
      await adapter.writeText(item.content);
    },
    serialize(value) {
      const bytes = utf8Encode(value);
      if (bytes.length > MAX_TEXT_PAYLOAD_BYTES) throw new RangeError('text exceeds maximum size');
      return bytes;
    },
    deserialize(bytes, schemaVersion) {
      if (schemaVersion !== CLIPBOARD_TEXT_SCHEMA_VERSION) {
        throw new Error(`unsupported clipboard.text schemaVersion ${schemaVersion}`);
      }
      if (bytes.length > MAX_TEXT_PAYLOAD_BYTES) throw new RangeError('text exceeds maximum size');
      return utf8Decode(bytes);
    },
  };
}
