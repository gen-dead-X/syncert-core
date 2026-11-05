export type { SyncTransport, TransportState, Unsubscribe } from './transport.js';
export { PluginRegistry, type DecodedItem, type KindPlugin } from './plugin.js';
export {
  CLIPBOARD_TEXT_SCHEMA_VERSION,
  createTextClipboardPlugin,
  type TextClipboardAdapter,
} from './text-clipboard.js';
export { StubTransport } from './stub-transport.js';
