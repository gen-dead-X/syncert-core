import type { WireSyncItem } from '../src/index.js';

export const wireItem = (overrides: Partial<WireSyncItem> = {}): WireSyncItem => ({
  id: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
  spaceId: 'space_1',
  originDeviceId: 'device_A',
  kind: 'clipboard.text',
  schemaVersion: 1,
  createdAt: 1_767_225_600_000,
  payload: Buffer.alloc(32, 7).toString('base64'),
  nonce: Buffer.alloc(12, 1).toString('base64'),
  contentHash: 'ab'.repeat(32),
  ...overrides,
});
