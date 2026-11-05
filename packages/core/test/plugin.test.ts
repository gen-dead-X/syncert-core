import { describe, expect, it } from 'vitest';
import { PluginRegistry, createTextClipboardPlugin, type KindPlugin } from '../src/index.js';

const memoryClipboard = (initial: string | null = null) => {
  let value = initial;
  return {
    readText: async () => value,
    writeText: async (t: string) => {
      value = t;
    },
    get value() {
      return value;
    },
  };
};

const meta = {
  id: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
  spaceId: 's',
  originDeviceId: 'd',
  kind: 'clipboard.text',
  schemaVersion: 1,
  createdAt: 0,
};

describe('PluginRegistry', () => {
  it('registers, looks up and unregisters plugins', () => {
    const reg = new PluginRegistry();
    const text = createTextClipboardPlugin(memoryClipboard());
    reg.register(text);
    expect(reg.has('clipboard.text')).toBe(true);
    expect(reg.get<string>('clipboard.text')).toBe(text);
    expect(reg.kinds()).toEqual(['clipboard.text']);
    expect(reg.get('clipboard.image')).toBeUndefined();
    expect(reg.unregister('clipboard.text')).toBe(true);
    expect(reg.has('clipboard.text')).toBe(false);
  });

  it('rejects duplicate kinds', () => {
    const reg = new PluginRegistry();
    reg.register(createTextClipboardPlugin(memoryClipboard()));
    expect(() => reg.register(createTextClipboardPlugin(memoryClipboard()))).toThrow(/already/);
  });

  it('accepts custom kinds', () => {
    const custom: KindPlugin<number> = {
      kind: 'test.counter',
      schemaVersion: 1,
      capture: async () => 1,
      apply: async () => {},
      serialize: (n) => new Uint8Array([n]),
      deserialize: (b) => b[0]!,
    };
    const reg = new PluginRegistry().register(custom);
    expect(reg.get<number>('test.counter')!.deserialize(new Uint8Array([7]), 1)).toBe(7);
  });
});

describe('clipboard.text plugin', () => {
  it('captures, serializes, deserializes and applies', async () => {
    const clip = memoryClipboard('héllo 🌍');
    const plugin = createTextClipboardPlugin(clip);
    const captured = await plugin.capture();
    expect(captured).toBe('héllo 🌍');
    const bytes = plugin.serialize(captured!);
    expect(plugin.deserialize(bytes, 1)).toBe('héllo 🌍');
    await plugin.apply({ meta, content: 'from phone' });
    expect(clip.value).toBe('from phone');
  });

  it('skips empty or oversized clipboard content', async () => {
    expect(await createTextClipboardPlugin(memoryClipboard('')).capture()).toBeNull();
    expect(await createTextClipboardPlugin(memoryClipboard(null)).capture()).toBeNull();
    const huge = 'x'.repeat(256 * 1024 + 1);
    expect(await createTextClipboardPlugin(memoryClipboard(huge)).capture()).toBeNull();
    expect(() => createTextClipboardPlugin(memoryClipboard()).serialize(huge)).toThrow(RangeError);
  });

  it('rejects unknown schema versions and invalid UTF-8', () => {
    const plugin = createTextClipboardPlugin(memoryClipboard());
    expect(() => plugin.deserialize(new Uint8Array([104]), 2)).toThrow(/schemaVersion/);
    expect(() => plugin.deserialize(new Uint8Array([0xff]), 1)).toThrow();
  });
});
