import { describe, expect, it, vi } from 'vitest';
import { decryptItem, generateSpaceKey, importSpaceKey } from '@syncert/crypto';
import {
  PluginRegistry,
  createTextClipboardPlugin,
  StubTransport,
  SyncEngine,
} from '../src/index.js';
async function setup() {
  const keys = await importSpaceKey(generateSpaceKey());
  let text = '';
  const registry = new PluginRegistry().register(
    createTextClipboardPlugin({
      readText: () => Promise.resolve(text),
      writeText: (t) => {
        text = t;
        return Promise.resolve();
      },
    }),
  );
  const transport = new StubTransport();
  const engine = new SyncEngine({
    spaceId: 'space',
    deviceId: 'device',
    keys,
    registry,
    transport,
  });
  return { keys, registry, transport, engine, texts: () => text };
}
describe('SyncEngine', () => {
  it('encrypts before enqueueing and acks remove persisted work', async () => {
    const { transport, engine, keys: currentKeys } = await setup();
    await engine.publish('clipboard.text', 'sensitive text');
    expect(engine.snapshot.queue).toHaveLength(1);
    expect(engine.snapshot.queue[0]?.item.payload.length).toBeGreaterThan(0);
    const item = engine.snapshot.queue[0]?.item;
    expect(new TextDecoder().decode(await decryptItem(currentKeys, item!))).toBe('sensitive text');
    engine.start();
    await vi.waitFor(() => {
      if (transport.state !== 'open') throw new Error();
    });
    transport.receive({ type: 'item.ack', id: item!.id });
    await vi.waitFor(() => {
      if (engine.snapshot.queue.length) throw new Error();
    });
    expect(engine.snapshot.queue).toHaveLength(0);
    await engine.stop();
  });
  it('deduplicates duplicate catches and ignores local origins', async () => {
    const { transport, engine, keys: currentKeys } = await setup();
    engine.start();
    const { encryptItem } = await import('@syncert/crypto');
    const { ulid } = await import('@syncert/protocol');
    const item = await encryptItem(
      currentKeys,
      {
        id: ulid(),
        spaceId: 'space',
        originDeviceId: 'device',
        kind: 'clipboard.text',
        schemaVersion: 1,
        createdAt: Date.now(),
      },
      new TextEncoder().encode('local'),
    );
    transport.receive({
      type: 'item.new',
      item: {
        ...item,
        payload: Buffer.from(item.payload).toString('base64'),
        nonce: Buffer.from(item.nonce).toString('base64'),
      },
    });
    transport.receive({
      type: 'item.new',
      item: {
        ...item,
        payload: Buffer.from(item.payload).toString('base64'),
        nonce: Buffer.from(item.nonce).toString('base64'),
      },
    });
    await vi.waitFor(() => {
      if (engine.snapshot.lastItemId !== item.id) throw new Error();
    });
    expect(engine.snapshot.queue).toHaveLength(0);
    await engine.stop();
  });
});
