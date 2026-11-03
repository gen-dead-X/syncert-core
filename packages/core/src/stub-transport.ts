import {
  decodeServerFrame,
  encodeClientFrame,
  encodeServerFrame,
  type ClientFrame,
  type ServerFrame,
} from '@syncert/protocol';
import type { SyncTransport, TransportState, Unsubscribe } from './transport.js';

/**
 * In-memory {@link SyncTransport} for tests and early app development.
 * Frames are round-tripped through the real encoders so schema violations
 * surface exactly as they would over a socket.
 */
export class StubTransport implements SyncTransport {
  #state: TransportState = 'idle';
  readonly #frameListeners = new Set<(frame: ServerFrame) => void>();
  readonly #stateListeners = new Set<(state: TransportState) => void>();
  /** Frames sent by the client, in order. */
  readonly sent: ClientFrame[] = [];

  get state(): TransportState {
    return this.#state;
  }

  async connect(): Promise<void> {
    this.#setState('connecting');
    this.#setState('open');
  }

  async close(): Promise<void> {
    if (this.#state === 'closed') return;
    this.#setState('closing');
    this.#setState('closed');
  }

  async send(frame: ClientFrame): Promise<void> {
    if (this.#state !== 'open') throw new Error('transport is not open');
    this.sent.push(JSON.parse(encodeClientFrame(frame)) as ClientFrame);
  }

  onFrame(listener: (frame: ServerFrame) => void): Unsubscribe {
    this.#frameListeners.add(listener);
    return () => this.#frameListeners.delete(listener);
  }

  onStateChange(listener: (state: TransportState) => void): Unsubscribe {
    this.#stateListeners.add(listener);
    return () => this.#stateListeners.delete(listener);
  }

  /** Simulate the relay sending a frame to the client. */
  receive(frame: ServerFrame): void {
    const decoded = decodeServerFrame(encodeServerFrame(frame));
    for (const l of this.#frameListeners) l(decoded);
  }

  #setState(state: TransportState): void {
    this.#state = state;
    for (const l of this.#stateListeners) l(state);
  }
}
