import type { SyncItemMeta } from '@syncert/protocol';

/** A decrypted, deserialized item handed to a kind plugin. */
export interface DecodedItem<T> {
  readonly meta: SyncItemMeta;
  readonly content: T;
}

/**
 * A kind plugin teaches the engine how to capture, serialize and apply one
 * content kind (e.g. `clipboard.text`). Everything a plugin produces is
 * encrypted by the engine before it leaves the device.
 */
export interface KindPlugin<T = unknown> {
  /** Kind identifier, e.g. `clipboard.text`. */
  readonly kind: string;
  /** Current serialization version written into `SyncItem.schemaVersion`. */
  readonly schemaVersion: number;
  /** Read the current local value, or null if there is nothing to sync. */
  capture(): Promise<T | null>;
  /** Apply a remote item locally (e.g. write it to the clipboard). */
  apply(item: DecodedItem<T>): Promise<void>;
  /** Serialize a value to plaintext bytes (encrypted afterwards by the engine). */
  serialize(value: T): Uint8Array;
  /**
   * Deserialize plaintext bytes written with `schemaVersion`. Must throw on
   * unsupported versions or malformed input.
   */
  deserialize(bytes: Uint8Array, schemaVersion: number): T;
}

/** Holds the kind plugins enabled on this device. */
export class PluginRegistry {
  readonly #plugins = new Map<string, KindPlugin<unknown>>();

  /** Register a plugin. Throws if the kind is already registered. */
  register<T>(plugin: KindPlugin<T>): this {
    if (this.#plugins.has(plugin.kind)) {
      throw new Error(`plugin already registered for kind "${plugin.kind}"`);
    }
    this.#plugins.set(plugin.kind, plugin as KindPlugin<unknown>);
    return this;
  }

  unregister(kind: string): boolean {
    return this.#plugins.delete(kind);
  }

  has(kind: string): boolean {
    return this.#plugins.has(kind);
  }

  /** Look up a plugin; returns undefined for unknown kinds (which should be ignored, not errored). */
  get<T = unknown>(kind: string): KindPlugin<T> | undefined {
    return this.#plugins.get(kind) as KindPlugin<T> | undefined;
  }

  kinds(): string[] {
    return [...this.#plugins.keys()];
  }
}
