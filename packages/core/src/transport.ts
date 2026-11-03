import type { ClientFrame, ServerFrame } from '@syncert/protocol';

export type TransportState = 'idle' | 'connecting' | 'open' | 'closing' | 'closed';

export type Unsubscribe = () => void;

/**
 * A bidirectional, message-oriented channel to the relay. Implementations
 * (WebSocket in the browser/Tauri webview, OkHttp on Android, an in-memory
 * stub for tests) are responsible only for moving validated frames; the sync
 * engine owns retries, ordering and crypto.
 *
 * Implementations must never log frame contents: even though item payloads
 * are ciphertext, frames carry device tokens.
 */
export interface SyncTransport {
  readonly state: TransportState;
  /** Open the connection. Resolves once the transport is `open`. */
  connect(): Promise<void>;
  /** Close the connection. Idempotent. */
  close(code?: number, reason?: string): Promise<void>;
  /** Send a frame. Rejects if the transport is not `open` or the frame is invalid. */
  send(frame: ClientFrame): Promise<void>;
  /** Subscribe to validated frames from the relay. */
  onFrame(listener: (frame: ServerFrame) => void): Unsubscribe;
  /** Subscribe to state changes. */
  onStateChange(listener: (state: TransportState) => void): Unsubscribe;
}
