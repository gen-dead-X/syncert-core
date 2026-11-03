import { PROTOCOL_VERSION, ProtocolError, type ServerFrame } from '@syncert/protocol';
import { describe, expect, it } from 'vitest';
import { StubTransport, type TransportState } from '../src/index.js';

describe('StubTransport', () => {
  it('tracks state, sends validated frames and delivers received frames', async () => {
    const t = new StubTransport();
    const states: TransportState[] = [];
    const frames: ServerFrame[] = [];
    t.onStateChange((s) => states.push(s));
    const off = t.onFrame((f) => frames.push(f));

    await expect(t.send({ type: 'device.list' })).rejects.toThrow(/not open/);
    await t.connect();
    expect(t.state).toBe('open');

    await t.send({
      type: 'hello',
      protocolVersion: PROTOCOL_VERSION,
      deviceToken: 'tok_0123456789abcdef',
    });
    expect(t.sent).toHaveLength(1);
    await expect(t.send({ type: 'hello', protocolVersion: 1, deviceToken: 'bad' })).rejects.toThrow(
      ProtocolError,
    );

    const welcome: ServerFrame = {
      type: 'welcome',
      protocolVersion: 1,
      deviceId: 'device_A',
      spaceId: 'space_1',
      serverTime: Date.now(),
    };
    t.receive(welcome);
    expect(frames).toEqual([welcome]);
    off();
    t.receive(welcome);
    expect(frames).toHaveLength(1);

    await t.close();
    await t.close();
    expect(states).toEqual(['connecting', 'open', 'closing', 'closed']);
  });
});
