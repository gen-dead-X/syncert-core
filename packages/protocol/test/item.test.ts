import { describe, expect, it } from 'vitest';
import {
  MAX_ITEM_PAYLOAD_BYTES,
  ProtocolError,
  WireSyncItemSchema,
  itemFromWire,
  itemToWire,
} from '../src/index.js';
import { wireItem } from './fixtures.js';

describe('SyncItem wire form', () => {
  it('round trips', () => {
    const wire = wireItem();
    const item = itemFromWire(wire);
    expect(item.payload).toBeInstanceOf(Uint8Array);
    expect(item.payload.length).toBe(32);
    expect(item.nonce.length).toBe(12);
    expect(itemToWire(item)).toEqual(wire);
  });

  it('accepts a maximum-size payload and rejects one byte more', () => {
    const max = Buffer.alloc(MAX_ITEM_PAYLOAD_BYTES).toString('base64');
    expect(WireSyncItemSchema.safeParse(wireItem({ payload: max })).success).toBe(true);
    const over = Buffer.alloc(MAX_ITEM_PAYLOAD_BYTES + 1).toString('base64');
    expect(WireSyncItemSchema.safeParse(wireItem({ payload: over })).success).toBe(false);
  });

  it.each([
    ['bad ulid', { id: 'not-a-ulid' }],
    ['empty spaceId', { spaceId: '' }],
    ['bad deviceId chars', { originDeviceId: 'dev ice' }],
    ['bad kind', { kind: 'Clipboard' }],
    ['schemaVersion 0', { schemaVersion: 0 }],
    ['fractional createdAt', { createdAt: 1.5 }],
    ['negative createdAt', { createdAt: -1 }],
    ['short nonce', { nonce: Buffer.alloc(11).toString('base64') }],
    ['long nonce', { nonce: Buffer.alloc(13).toString('base64') }],
    ['payload shorter than tag', { payload: Buffer.alloc(15).toString('base64') }],
    ['payload not base64', { payload: '!!!!' }],
    ['uppercase content hash', { contentHash: 'AB'.repeat(32) }],
    ['short content hash', { contentHash: 'ab'.repeat(31) }],
  ] as const)('rejects %s', (_name, overrides) => {
    expect(() => itemFromWire(wireItem(overrides as never))).toThrow(ProtocolError);
  });

  it('rejects unknown fields', () => {
    expect(() => itemFromWire({ ...wireItem(), plaintext: 'leak' })).toThrow(ProtocolError);
  });
});
