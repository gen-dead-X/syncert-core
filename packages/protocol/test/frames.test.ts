import { describe, expect, it } from 'vitest';
import {
  MAX_FRAME_CHARS,
  MAX_SYNC_BATCH_ITEMS,
  PROTOCOL_VERSION,
  ProtocolError,
  decodeClientFrame,
  decodeFrame,
  decodeServerFrame,
  encodeClientFrame,
  encodeServerFrame,
  type ClientFrame,
  type ServerFrame,
} from '../src/index.js';
import { wireItem } from './fixtures.js';

const token = 'tok_abcdefghijklmnop';

const clientFrames: ClientFrame[] = [
  { type: 'hello', protocolVersion: PROTOCOL_VERSION, deviceToken: token },
  { type: 'item.push', reqId: 'r1', item: wireItem() },
  { type: 'sync.since', lastItemId: null },
  { type: 'sync.since', lastItemId: '01ARZ3NDEKTSV4RRFFQ69G5FAV' },
  { type: 'device.list' },
  { type: 'device.revoke', deviceId: 'device_B' },
];

const serverFrames: ServerFrame[] = [
  { type: 'welcome', protocolVersion: 1, deviceId: 'device_A', spaceId: 'space_1', serverTime: 1 },
  { type: 'item.ack', reqId: 'r1', id: '01ARZ3NDEKTSV4RRFFQ69G5FAV' },
  { type: 'item.new', item: wireItem() },
  { type: 'sync.batch', items: [wireItem(), wireItem()], hasMore: false },
  {
    type: 'device.list.result',
    devices: [{ deviceId: 'device_A', createdAt: 1, lastSeenAt: null }],
  },
  { type: 'device.revoked', deviceId: 'device_B' },
  { type: 'error', reqId: 'r1', code: 'payload_too_large', message: 'item too large' },
];

describe('frames', () => {
  it.each(clientFrames)('client frame $type round trips', (frame) => {
    expect(decodeClientFrame(encodeClientFrame(frame))).toEqual(frame);
    expect(decodeFrame(encodeClientFrame(frame))).toEqual(frame);
  });

  it.each(serverFrames)('server frame $type round trips', (frame) => {
    expect(decodeServerFrame(encodeServerFrame(frame))).toEqual(frame);
    expect(decodeFrame(encodeServerFrame(frame))).toEqual(frame);
  });

  it('keeps directions separate', () => {
    expect(() => decodeServerFrame(encodeClientFrame(clientFrames[0]!))).toThrow(ProtocolError);
    expect(() => decodeClientFrame(encodeServerFrame(serverFrames[0]!))).toThrow(ProtocolError);
  });

  it.each([
    ['not JSON', '{'],
    ['not an object', '42'],
    ['unknown type', JSON.stringify({ type: 'item.delete', id: 'x' })],
    ['missing field', JSON.stringify({ type: 'hello', protocolVersion: 1 })],
    ['short device token', JSON.stringify({ type: 'hello', protocolVersion: 1, deviceToken: 'x' })],
    [
      'extra field',
      JSON.stringify({ type: 'hello', protocolVersion: 1, deviceToken: token, debug: true }),
    ],
    ['bad lastItemId', JSON.stringify({ type: 'sync.since', lastItemId: 'abc' })],
    ['bad nested item', JSON.stringify({ type: 'item.push', item: { ...wireItem(), nonce: '' } })],
    ['bad revoke id', JSON.stringify({ type: 'device.revoke', deviceId: '' })],
  ])('decodeClientFrame rejects %s', (_name, raw) => {
    expect(() => decodeClientFrame(raw)).toThrow(ProtocolError);
  });

  it.each([
    [
      'welcome with wrong protocol version',
      { type: 'welcome', protocolVersion: 2, deviceId: 'd', spaceId: 's', serverTime: 1 },
    ],
    ['unknown error code', { type: 'error', code: 'teapot', message: '' }],
    [
      'oversized batch',
      {
        type: 'sync.batch',
        items: Array.from({ length: MAX_SYNC_BATCH_ITEMS + 1 }, () => wireItem()),
        hasMore: true,
      },
    ],
    ['batch missing hasMore', { type: 'sync.batch', items: [] }],
  ])('decodeServerFrame rejects %s', (_name, frame) => {
    expect(() => decodeServerFrame(JSON.stringify(frame))).toThrow(ProtocolError);
  });

  it('rejects oversized raw frames before parsing', () => {
    expect(() => decodeClientFrame(' '.repeat(MAX_FRAME_CHARS + 1))).toThrow(/MAX_FRAME_CHARS/);
  });

  it('refuses to encode invalid frames', () => {
    expect(() =>
      encodeClientFrame({ type: 'hello', protocolVersion: 1, deviceToken: 'short' }),
    ).toThrow(ProtocolError);
  });
});
