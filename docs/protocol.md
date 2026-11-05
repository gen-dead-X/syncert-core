# syncert relay protocol (v1)

This document describes how clients talk to the syncert relay
(`apps/server`, package `@syncert/server`). The frame schemas live in
[`@syncert/protocol`](../packages/protocol/src/frames.ts), and the
encryption that produces `payload`, `nonce` and `contentHash` lives in
[`@syncert/crypto`](../packages/crypto). Both packages are the source of truth.
If this document and the code disagree, the code wins, and the mismatch is a bug.

The relay is untrusted. It stores and forwards ciphertext plus the routing
metadata it needs (`spaceId`, `id`, `originDeviceId`, `kind`, `schemaVersion`,
`createdAt`, `contentHash`). It never sees space keys, pairing strings or
plaintext. Every metadata field is bound to the ciphertext as AEAD associated
data, so if the relay alters any of it, decryption fails.

## URLs

A pairing string carries the relay's **base URL** (`r`), for example
`wss://relay.example.com` or `wss://example.com/syncert`.

| Purpose   | URL                                                          |
| --------- | ------------------------------------------------------------ |
| WebSocket | `<base>/ws`                                                  |
| REST      | `<base>/<route>`, with `wss:` → `https:` and `ws:` → `http:` |

Example: base `wss://example.com/syncert` gives
`wss://example.com/syncert/ws` and `https://example.com/syncert/pair/join`.
Any path prefix must be stripped by your reverse proxy. Use `wss://`/`https://`
everywhere except on localhost. Device tokens travel in headers and frames, so
plain `ws://` exposes them on the network.

## Credentials

- **Device token**: an opaque 43-char base64url bearer secret, issued once by
  `POST /spaces` or `POST /pair/join`. The relay stores only its SHA-256.
  Store it in the platform keychain. When a device is revoked, its token stops
  working immediately.
- **Join token**: an opaque one-time secret, valid for `JOIN_TOKEN_TTL`
  (default 10 minutes). The relay stores only its SHA-256. Joining with it
  consumes it, and so does revoking the device that issued it.

## REST

All bodies are JSON. Errors look like `{"error": {"code", "message"}}`, where
`code` is one of the protocol error codes listed below. Request bodies are
limited to 4 KiB.

### `GET /health`

`200 {"status":"ok","version":"0.1.0","protocolVersion":1}`, or `503` when the
database is unavailable.

### `POST /spaces`

Creates a space and its first device. No body.

If the relay has `SPACE_CREATION_SECRET` set, the request must send
`Authorization: Bearer <secret>`; otherwise it gets `401`. Rate limited per
client IP (`REST_RATE_LIMIT_*`).

`201 {"spaceId", "deviceId", "deviceToken"}`

The client then generates the space key locally (`generateSpaceKey()`). It
never sends the key to the relay.

### `POST /pair/token`

`Authorization: Bearer <deviceToken>`. No body. Issues a join token for the
caller's space.

`201 {"joinToken", "expiresAt"}` (`expiresAt` is Unix ms)

The existing device then shows
`encodePairingPayload({ spaceKey, relayUrl: <base>, joinToken })` as a QR code.

### `POST /pair/join`

Body: `{"joinToken": "..."}`. No auth. Rate limited per client IP.

`201 {"spaceId", "deviceId", "deviceToken"}`, or `401` if the token is unknown,
expired or already used. The reply doesn't say which.

## WebSocket

Connect to `<base>/ws`. Each frame is one JSON text message. Frames above
1 MiB are dropped with close code `1009`. Requests may include a `reqId`
(`[A-Za-z0-9_-]{1,64}`), which the relay echoes on the matching response or
`error`.

### Handshake

1. The client sends `{"type":"hello","protocolVersion":1,"deviceToken":"..."}`.
   It must arrive within `HELLO_TIMEOUT` (10 s); otherwise the relay closes
   the socket with `4008`.
2. The relay replies
   `{"type":"welcome","protocolVersion":1,"deviceId","spaceId","serverTime"}`.

If the version is wrong, the relay sends
`error{code:"unsupported_protocol_version"}` and closes with `4002`. If the
token is bad or revoked, it sends `error{code:"unauthorized"}` and closes with
`4001`. Any frame other than `hello` before authentication gets
`error{code:"bad_request"}` and a close with `4000`.

### Pushing items

`{"type":"item.push","reqId?","item":WireSyncItem}`

- `item.spaceId` and `item.originDeviceId` must be the authenticated device's;
  otherwise the reply is `forbidden`.
- The ciphertext (`payload`, base64) can be at most `MAX_ITEM_PAYLOAD_BYTES`
  (256 KiB + 16-byte tag) once decoded. Larger payloads get
  `payload_too_large`.
- On success the relay stores the item, replies `{"type":"item.ack","id"}`, and
  sends `{"type":"item.new","item"}` to every _other_ connected device in the
  space. The sender doesn't get an echo.
- **Idempotency:** re-pushing an identical item (same `id` and the same
  content) is acked again but not fanned out again, so clients can safely retry
  any push that wasn't acked. Reusing an `id` for different content returns
  `bad_request`.

### Catching up

`{"type":"sync.since","reqId?","lastItemId": <ULID> | null}`
→ `{"type":"sync.batch","items":[...],"hasMore":bool}`

- Items come back in the order the relay _received_ them, at most 10 per batch.
  While `hasMore` is true, send `sync.since` again with the last returned `id`.
- `null` starts from the oldest buffered item.
- Items pushed by the requesting device are left out, but the cursor still
  advances past them.
- If `lastItemId` is unknown (for example expired, pruned, or never seen), the
  relay restarts from the oldest buffered item. Clients de-duplicate by `id`
  (and by `contentHash` if they want).
- Recommended client flow: after `welcome`, page through `sync.since` from your
  last stored `id`, then rely on `item.new`. Persist the newest `id` you have
  processed.

### Devices

- `{"type":"device.list"}` → `{"type":"device.list.result","devices":[{"deviceId","createdAt","lastSeenAt"}]}`
  lists the space's active (non-revoked) devices.
- `{"type":"device.revoke","deviceId"}` → `{"type":"device.revoked","deviceId"}`.
  The target's token is invalidated, its open sockets are closed with `4003`,
  and its unused join tokens are deleted. If the device doesn't exist in the
  caller's space, the reply is `not_found`. A device can revoke itself.

Revoking a device does **not** rotate the space key. If a lost device might be
compromised, create a new space and re-pair the devices you still trust.

### Liveness and back-pressure

- The relay sends a WebSocket ping every `HEARTBEAT_INTERVAL` (30 s). Any
  connection that hasn't answered the previous ping is terminated. Standard
  WebSocket clients answer pings automatically.
- Each device has a token bucket for frames (`RATE_LIMIT_BURST`,
  `RATE_LIMIT_PER_SEC`). Frames over the limit get `rate_limited`, and the
  connection stays open.
- A client that stops reading until more than 16 MiB is queued for it is
  closed with `4009`.
- When the relay shuts down, it closes sockets with `1001`. Reconnect with
  exponential backoff and jitter.

### Close codes

| Code | Meaning                            | Client action               |
| ---- | ---------------------------------- | --------------------------- |
| 1001 | Relay shutting down                | Reconnect with backoff      |
| 1009 | Frame too large                    | Fix the client              |
| 4000 | Malformed frame or `hello` missing | Fix the client              |
| 4001 | Unknown or revoked device token    | Re-pair; don't loop         |
| 4002 | Unsupported protocol version       | Update the app              |
| 4003 | This device was revoked            | Forget credentials, re-pair |
| 4008 | No `hello` in time                 | Reconnect                   |
| 4009 | Slow consumer                      | Reconnect                   |

### Error codes

`bad_request`, `unsupported_protocol_version`, `unauthorized`, `forbidden`,
`not_found`, `payload_too_large`, `rate_limited`, `internal`. After
authentication, errors don't close the connection.

## Retention

The relay is a short-term buffer, not a backup. An item is deleted
`ITEM_TTL` (default 24 h) after the relay _received_ it. A sweep runs every
`CLEANUP_INTERVAL`, and expired items are never served even between sweeps.
Each space keeps at most `MAX_ITEMS_PER_SPACE` items (default 500), and
the oldest are dropped first. Expired join tokens are swept as well. SQLite
`secure_delete` is on, so deleted ciphertext is overwritten on disk.

## What the relay logs

The relay writes structured JSON lines to stdout: event names plus ids, sizes,
kinds and counts. It never logs payloads, nonces, tokens, secrets or
plaintext. Any key that looks sensitive is redacted by the logger as a
defensive measure.
