import type { ServerFrame } from '@syncert/protocol';
import {
  decodeServerFrame,
  encodeClientFrame,
  PROTOCOL_VERSION,
  type ClientFrame,
} from '@syncert/protocol';
import type { SyncTransport, TransportState, Unsubscribe } from './transport.js';

export type WebSocketFactory = (url: string) => WebSocket;

/** Permanent authentication failures mean credentials must be replaced. */
export class TransportAuthenticationError extends Error {
  constructor() {
    super('The relay rejected this device. Pair this device again.');
    this.name = 'TransportAuthenticationError';
  }
}

/** Browser/WebView WebSocket implementation of the small relay transport seam. */
export class WebSocketTransport implements SyncTransport {
  #state: TransportState = 'idle';
  #socket?: WebSocket;
  #connectPromise: Promise<void> | undefined;
  #frameListeners = new Set<(frame: ServerFrame) => void>();
  #stateListeners = new Set<(state: TransportState) => void>();

  constructor(
    readonly relayUrl: string,
    private readonly deviceToken: string,
    private readonly socketFactory: WebSocketFactory = (url) => new WebSocket(url),
  ) {
    const url = new URL(relayUrl);
    if (!['ws:', 'wss:'].includes(url.protocol) || url.username || url.password) {
      throw new TypeError('relay URL must be a ws:// or wss:// URL without credentials');
    }
    this.relayUrl = new URL(`${url.pathname.replace(/\/$/, '')}/ws`, url).toString();
  }

  get state(): TransportState {
    return this.#state;
  }

  #setState(state: TransportState): void {
    if (this.#state === state) return;
    this.#state = state;
    for (const listener of this.#stateListeners) listener(state);
  }

  connect(): Promise<void> {
    if (this.#state === 'open') return Promise.resolve();
    if (this.#connectPromise) return this.#connectPromise;
    this.#setState('connecting');
    const socket = this.socketFactory(this.relayUrl);
    this.#socket = socket;
    this.#connectPromise = new Promise<void>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error) => {
        if (settled || this.#socket !== socket) return;
        settled = true;
        clearTimeout(timer);
        if (error) {
          this.#setState('closed');
          reject(error);
        } else {
          this.#setState('open');
          resolve();
        }
      };
      const timer = setTimeout(() => {
        socket.close();
        finish(new Error('relay handshake timed out'));
      }, 10_000);
      socket.onopen = () => {
        try {
          socket.send(
            encodeClientFrame({
              type: 'hello',
              protocolVersion: PROTOCOL_VERSION,
              deviceToken: this.deviceToken,
            }),
          );
        } catch {
          finish(new Error('could not authenticate with relay'));
        }
      };
      socket.onmessage = (event) => {
        let frame: ServerFrame;
        try {
          if (typeof event.data !== 'string') throw new Error();
          frame = decodeServerFrame(event.data);
        } catch {
          socket.close(1002);
          finish(new Error('relay sent an invalid frame'));
          return;
        }
        if (this.#socket !== socket) return;
        if (this.#state === 'connecting') {
          if (frame.type === 'welcome') finish();
          else if (
            frame.type === 'error' &&
            ['unauthorized', 'unsupported_protocol_version'].includes(frame.code)
          ) {
            socket.close();
            finish(new TransportAuthenticationError());
          } else {
            socket.close();
            finish(new Error('relay did not complete authentication'));
          }
          return;
        }
        for (const listener of this.#frameListeners) listener(frame);
      };
      socket.onerror = () => {
        if (this.#state === 'connecting') finish(new Error('could not connect to relay'));
      };
      socket.onclose = (event) => {
        if (this.#socket !== socket) return;
        this.#setState('closed');
        if (this.#state === 'connecting' || !settled)
          finish(
            event.code === 4001 || event.code === 4003
              ? new TransportAuthenticationError()
              : new Error('relay connection closed'),
          );
      };
    }).finally(() => {
      this.#connectPromise = undefined;
    });
    return this.#connectPromise;
  }

  async close(code = 1000, reason = 'client closing'): Promise<void> {
    if (this.#state === 'closed' || this.#state === 'idle') {
      this.#setState('closed');
      return;
    }
    this.#setState('closing');
    const socket = this.#socket;
    if (!socket) return;
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(resolve, 1000);
      const previous = socket.onclose;
      socket.onclose = (event) => {
        clearTimeout(timeout);
        previous?.call(socket, event);
        resolve();
      };
      socket.close(code, reason);
    });
    this.#setState('closed');
  }

  send(frame: ClientFrame): Promise<void> {
    if (this.#state !== 'open' || !this.#socket)
      return Promise.reject(new Error('transport is not open'));
    try {
      this.#socket.send(encodeClientFrame(frame));
      return Promise.resolve();
    } catch {
      return Promise.reject(new Error('could not send frame'));
    }
  }

  onFrame(listener: (frame: ServerFrame) => void): Unsubscribe {
    this.#frameListeners.add(listener);
    return () => this.#frameListeners.delete(listener);
  }

  onStateChange(listener: (state: TransportState) => void): Unsubscribe {
    this.#stateListeners.add(listener);
    return () => this.#stateListeners.delete(listener);
  }
}
