import { z } from 'zod';
import { MAX_FRAME_CHARS, MAX_SYNC_BATCH_ITEMS, PROTOCOL_VERSION } from './constants.js';
import { ProtocolError } from './errors.js';
import {
  IdSchema,
  TimestampMsSchema,
  UlidSchema,
  WireSyncItemSchema,
  formatIssues,
} from './item.js';

/**
 * WebSocket frames. Every frame is a JSON object with a `type` discriminator.
 * Requests may carry an optional client-chosen `reqId`, which the relay echoes
 * on the matching response or `error` frame.
 */

const ReqId = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9_-]+$/)
  .optional();

/** Opaque device credential issued by the relay. Never logged. */
const DeviceTokenSchema = z
  .string()
  .min(16)
  .max(512)
  .regex(/^[A-Za-z0-9_.~-]+$/);

// ---- client → server ------------------------------------------------------

export const HelloFrameSchema = z.strictObject({
  type: z.literal('hello'),
  reqId: ReqId,
  protocolVersion: z.number().int().min(1),
  deviceToken: DeviceTokenSchema,
});

export const ItemPushFrameSchema = z.strictObject({
  type: z.literal('item.push'),
  reqId: ReqId,
  item: WireSyncItemSchema,
});

export const SyncSinceFrameSchema = z.strictObject({
  type: z.literal('sync.since'),
  reqId: ReqId,
  /** Last item id the client has seen, or null to sync from the beginning. */
  lastItemId: UlidSchema.nullable(),
});

export const DeviceListFrameSchema = z.strictObject({
  type: z.literal('device.list'),
  reqId: ReqId,
});

export const DeviceRevokeFrameSchema = z.strictObject({
  type: z.literal('device.revoke'),
  reqId: ReqId,
  deviceId: IdSchema,
});

export const ClientFrameSchema = z.discriminatedUnion('type', [
  HelloFrameSchema,
  ItemPushFrameSchema,
  SyncSinceFrameSchema,
  DeviceListFrameSchema,
  DeviceRevokeFrameSchema,
]);

// ---- server → client ------------------------------------------------------

export const WelcomeFrameSchema = z.strictObject({
  type: z.literal('welcome'),
  reqId: ReqId,
  protocolVersion: z.literal(PROTOCOL_VERSION),
  deviceId: IdSchema,
  spaceId: IdSchema,
  serverTime: TimestampMsSchema,
});

export const ItemAckFrameSchema = z.strictObject({
  type: z.literal('item.ack'),
  reqId: ReqId,
  id: UlidSchema,
});

export const ItemNewFrameSchema = z.strictObject({
  type: z.literal('item.new'),
  item: WireSyncItemSchema,
});

export const SyncBatchFrameSchema = z.strictObject({
  type: z.literal('sync.batch'),
  reqId: ReqId,
  items: z.array(WireSyncItemSchema).max(MAX_SYNC_BATCH_ITEMS),
  /** True if more items are available; the client should send another `sync.since`. */
  hasMore: z.boolean(),
});

export const DeviceInfoSchema = z.strictObject({
  deviceId: IdSchema,
  createdAt: TimestampMsSchema,
  lastSeenAt: TimestampMsSchema.nullable(),
});

export const DeviceListResultFrameSchema = z.strictObject({
  type: z.literal('device.list.result'),
  reqId: ReqId,
  devices: z.array(DeviceInfoSchema).max(1000),
});

export const DeviceRevokedFrameSchema = z.strictObject({
  type: z.literal('device.revoked'),
  reqId: ReqId,
  deviceId: IdSchema,
});

export const ERROR_CODES = [
  'bad_request',
  'unsupported_protocol_version',
  'unauthorized',
  'forbidden',
  'not_found',
  'payload_too_large',
  'rate_limited',
  'internal',
] as const;

export const ErrorCodeSchema = z.enum(ERROR_CODES);
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

export const ErrorFrameSchema = z.strictObject({
  type: z.literal('error'),
  reqId: ReqId,
  code: ErrorCodeSchema,
  /** Human-readable, must never contain plaintext or secrets. */
  message: z.string().max(1024),
});

export const ServerFrameSchema = z.discriminatedUnion('type', [
  WelcomeFrameSchema,
  ItemAckFrameSchema,
  ItemNewFrameSchema,
  SyncBatchFrameSchema,
  DeviceListResultFrameSchema,
  DeviceRevokedFrameSchema,
  ErrorFrameSchema,
]);

export const FrameSchema = z.union([ClientFrameSchema, ServerFrameSchema]);

export type HelloFrame = z.infer<typeof HelloFrameSchema>;
export type ItemPushFrame = z.infer<typeof ItemPushFrameSchema>;
export type SyncSinceFrame = z.infer<typeof SyncSinceFrameSchema>;
export type DeviceListFrame = z.infer<typeof DeviceListFrameSchema>;
export type DeviceRevokeFrame = z.infer<typeof DeviceRevokeFrameSchema>;
export type ClientFrame = z.infer<typeof ClientFrameSchema>;

export type WelcomeFrame = z.infer<typeof WelcomeFrameSchema>;
export type ItemAckFrame = z.infer<typeof ItemAckFrameSchema>;
export type ItemNewFrame = z.infer<typeof ItemNewFrameSchema>;
export type SyncBatchFrame = z.infer<typeof SyncBatchFrameSchema>;
export type DeviceInfo = z.infer<typeof DeviceInfoSchema>;
export type DeviceListResultFrame = z.infer<typeof DeviceListResultFrameSchema>;
export type DeviceRevokedFrame = z.infer<typeof DeviceRevokedFrameSchema>;
export type ErrorFrame = z.infer<typeof ErrorFrameSchema>;
export type ServerFrame = z.infer<typeof ServerFrameSchema>;

export type Frame = ClientFrame | ServerFrame;
export type FrameType = Frame['type'];

function decodeWith<S extends z.ZodType>(schema: S, raw: string, label: string): z.infer<S> {
  if (typeof raw !== 'string') throw new ProtocolError(`${label} must be a string`);
  if (raw.length > MAX_FRAME_CHARS) throw new ProtocolError(`${label} exceeds MAX_FRAME_CHARS`);
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new ProtocolError(`${label} is not valid JSON`);
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) throw new ProtocolError(`invalid ${label}`, formatIssues(parsed.error));
  return parsed.data;
}

function encodeWith<S extends z.ZodType>(schema: S, frame: unknown, label: string): string {
  const parsed = schema.safeParse(frame);
  if (!parsed.success) throw new ProtocolError(`invalid ${label}`, formatIssues(parsed.error));
  const raw = JSON.stringify(parsed.data);
  if (raw.length > MAX_FRAME_CHARS) throw new ProtocolError(`${label} exceeds MAX_FRAME_CHARS`);
  return raw;
}

/** Validate and serialize a client → server frame. */
export const encodeClientFrame = (frame: ClientFrame): string =>
  encodeWith(ClientFrameSchema, frame, 'client frame');
/** Parse and validate a client → server frame (used by the relay). */
export const decodeClientFrame = (raw: string): ClientFrame =>
  decodeWith(ClientFrameSchema, raw, 'client frame');
/** Validate and serialize a server → client frame (used by the relay). */
export const encodeServerFrame = (frame: ServerFrame): string =>
  encodeWith(ServerFrameSchema, frame, 'server frame');
/** Parse and validate a server → client frame. */
export const decodeServerFrame = (raw: string): ServerFrame =>
  decodeWith(ServerFrameSchema, raw, 'server frame');
/** Validate and serialize any frame. */
export const encodeFrame = (frame: Frame): string => encodeWith(FrameSchema, frame, 'frame');
/** Parse and validate any frame. Prefer the direction-specific decoders. */
export const decodeFrame = (raw: string): Frame => decodeWith(FrameSchema, raw, 'frame');
