# syncert-core

**syncert** is a cross-device, end-to-end-encrypted clipboard sync tool. Copy on
your Mac, paste on your phone, and the relay in the middle only ever sees
ciphertext.

This repository is a pnpm-workspaces monorepo holding the shared TypeScript
packages and the self-hostable relay server. The desktop app
([syncert-macos](https://github.com/gen-dead-X/syncert-macos), Tauri) and the
Android app ([syncert-android](https://github.com/gen-dead-X/syncert-android))
consume these packages.

> Status: milestone 2: protocol, crypto and the relay server. Client sync engine next.

## Architecture

```
 ┌────────────┐   item.push (ciphertext)   ┌─────────────┐   item.new (ciphertext)  ┌────────────┐
 │  Device A  │ ─────────────────────────► │    Relay    │ ───────────────────────► │  Device B  │
 │ (Mac/Tauri)│ ◄───────────────────────── │ apps/server │ ◄─────────────────────── │ (Android)  │
 └────────────┘        WebSocket/JSON      └─────────────┘                          └────────────┘
   space key                               stores opaque items,                      space key
   (never leaves devices)                  routes by spaceId
```

- A **space** is a group of devices that share a 256-bit **space key**. The key
  is created on the first device and handed to new devices via a QR-code
  pairing string (`syncert1:...`) that also carries the relay URL and a
  one-time join token. The relay never sees the key.
- Each clipboard change becomes a **SyncItem**: metadata (ULID `id`, `spaceId`,
  `originDeviceId`, `kind`, `schemaVersion`, `createdAt`) in the clear, plus an
  AES-256-GCM encrypted `payload`, its `nonce`, and a keyed `contentHash`.
- The metadata is bound to the ciphertext as AEAD associated data, so the relay
  can route and order items but can't alter or move them between spaces
  without detection.
- Content types are **kind plugins** (`clipboard.text` today; images and files
  later), so the engine and protocol stay content-agnostic.

### Cryptography (`@syncert/crypto`)

| What            | How                                                                                                                                                                                    |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Space key       | 32 random bytes (`crypto.getRandomValues`)                                                                                                                                             |
| Subkeys         | HKDF-SHA-256(spaceKey, salt `syncert/v1/hkdf-salt`, info `syncert/v1/item-encryption` / `syncert/v1/content-hash`)                                                                     |
| Item encryption | AES-256-GCM, fresh random 96-bit nonce per item, 128-bit tag                                                                                                                           |
| Associated data | `lp("syncert/v1/item-ad") ‖ lp(spaceId) ‖ lp(id) ‖ lp(originDeviceId) ‖ lp(kind) ‖ u32(schemaVersion) ‖ u64(createdAt)`, where `lp` is a u32 big-endian length followed by UTF-8 bytes |
| Content hash    | hex HMAC-SHA-256(contentHashKey, plaintext)                                                                                                                                            |
| Pairing string  | `syncert1:` + base64url(JSON `{"v":1,"k":<key>,"r":<relay wss url>,"t":<join token>}`)                                                                                                 |

- **Why AES-256-GCM via WebCrypto:** it ships with Node 20+, every modern
  browser and the Tauri webview, as well as CryptoKit (Swift) and JCA (Kotlin).
  So there are zero crypto dependencies and native clients interoperate
  trivially. Random 96-bit nonces are safe here: NIST SP 800-38D allows up to 2³²
  random-nonce messages per key, far beyond any clipboard history.
- **Why a keyed content hash:** devices use `contentHash` to de-duplicate
  (e.g. not echo back what they just copied). The relay stores it, so a plain
  SHA-256 would let the relay confirm guesses of low-entropy clipboard content
  such as PINs, OTPs or common passwords. An HMAC under a key derived from the
  space key removes that oracle. Receivers re-compute and verify it after
  decryption.
- **Test vectors:** [`packages/crypto/test-vectors/v1.json`](packages/crypto/test-vectors/v1.json)
  pins HKDF outputs, associated data, ciphertexts, content hashes, tampered
  items that must fail, and valid/invalid pairing strings. Future Swift/Kotlin
  clients should verify against it. It's also exported as
  `@syncert/crypto/test-vectors/v1.json`.

### Protocol (`@syncert/protocol`)

JSON frames over WebSocket, validated with zod on both ends. Binary fields are
standard base64. Optional `reqId` on requests is echoed on responses/errors.

| Client → relay                         | Relay → client                                             |
| -------------------------------------- | ---------------------------------------------------------- |
| `hello {protocolVersion, deviceToken}` | `welcome {protocolVersion, deviceId, spaceId, serverTime}` |
| `item.push {item}`                     | `item.ack {id}`                                            |
|                                        | `item.new {item}` (pushed from other devices)              |
| `sync.since {lastItemId \| null}`      | `sync.batch {items[], hasMore}`                            |
| `device.list`                          | `device.list.result {devices[]}`                           |
| `device.revoke {deviceId}`             | `device.revoked {deviceId}`                                |
|                                        | `error {code, message}`                                    |

Limits: `clipboard.text` plaintext ≤ 256 KiB (`MAX_TEXT_PAYLOAD_BYTES`), ≤ 10
items per batch, ≤ 4 MiB per frame. `PROTOCOL_VERSION = 1`.

The full relay protocol, including REST pairing, sync semantics, close codes
and retention, is documented in [`docs/protocol.md`](docs/protocol.md).

### Relay (`@syncert/server`)

Node + [Hono](https://hono.dev) (REST) + [`ws`](https://github.com/websockets/ws)
(WebSocket at `/ws`) + SQLite ([better-sqlite3](https://github.com/WiseLibs/better-sqlite3),
WAL, `secure_delete`). One process, one database file, and no other services.

- Stores only ciphertext and routing metadata, for `ITEM_TTL` (24 h by
  default). Device and join tokens are stored as SHA-256 hashes.
- Join tokens are single-use and expire after 10 minutes. Revoking a device
  kills its token and closes its sockets.
- Pushes are idempotent (keyed by item id), acked, and fanned out to the
  space's other devices. `sync.since` pages through missed items.
- Per-device token-bucket rate limit, per-IP limits on unauthenticated REST,
  size limits on every frame, heartbeats that clean up dead connections, and
  graceful shutdown.
- Logs are structured JSON lines with ids and sizes only. Payloads, tokens and
  secrets are never logged.

## Layout

```
packages/
  protocol/   @syncert/protocol: types, constants, zod frame schemas, encode/decode, base64/ULID helpers
  crypto/     @syncert/crypto: space keys, AES-256-GCM items, keyed content hash, pairing, test vectors
  core/       @syncert/core: SyncTransport + KindPlugin interfaces, PluginRegistry, clipboard.text plugin, StubTransport
apps/
  server/     @syncert/server: the relay (Hono + ws + SQLite). Only ever handles ciphertext.
docs/
  protocol.md relay protocol: REST pairing, WebSocket frames, sync semantics, close codes
```

Packages build to ESM + `.d.ts` in `dist/`. Inside the workspace, TypeScript and
vitest resolve `@syncert/*` straight to `src/` (via the `@syncert/source`
export condition / aliases), so typecheck and tests need no prior build.

## Self-hosting

The relay is a single small Node process with one SQLite file, so it fits on
any free-tier VM, a Raspberry Pi, or a home server.

### Docker (recommended)

```sh
git clone https://github.com/gen-dead-X/syncert-core && cd syncert-core
docker compose up -d          # builds the image, serves :8787, data in the `syncert-data` volume
curl http://localhost:8787/health
```

Or without compose:

```sh
docker build -f apps/server/Dockerfile -t syncert-server .
docker run -d --name syncert -p 8787:8787 -v syncert-data:/data --restart unless-stopped syncert-server
```

The image is `node:24-alpine`, runs as the non-root `node` user, keeps its
data in `/data`, and includes a `HEALTHCHECK`.

### Node (no Docker)

Requires Node ≥ 22.14 and pnpm (`corepack enable`):

```sh
pnpm install --frozen-lockfile
pnpm --filter @syncert/server... build
DATA_DIR=./data node apps/server/dist/cli.js      # or: pnpm --filter @syncert/server start
```

The package also exposes a `syncert-server` bin. It isn't published to npm yet,
so `npx syncert-server` will only work once it is.

### TLS

Clients should connect with `wss://`. Put the relay behind any TLS-terminating
reverse proxy and forward WebSocket upgrades. With
[Caddy](https://caddyserver.com), for example:

```
relay.example.com {
    reverse_proxy localhost:8787
}
```

Set `TRUST_PROXY=true` so per-IP rate limits use `X-Forwarded-For`. A
Cloudflare Tunnel works too and needs no open ports. Give clients the base URL
`wss://relay.example.com`. The WebSocket lives at `/ws`, and the REST routes sit
at the same host over `https://`.

For a relay reachable from the internet, set `SPACE_CREATION_SECRET` so that
strangers can't create spaces on it (pairing more devices into an existing
space still works without it).

### Configuration

All settings come from environment variables. Durations accept `ms`, `s`,
`m`, `h` or `d` suffixes (a bare number means seconds). Empty values fall back
to the default.

| Variable                  | Default                      | Description                                                                           |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------------------------- |
| `PORT`                    | `8787`                       | Listen port.                                                                          |
| `HOST`                    | `0.0.0.0`                    | Listen address.                                                                       |
| `DATA_DIR`                | `./data` (`/data` in Docker) | Directory for the database.                                                           |
| `DB_PATH`                 | `$DATA_DIR/syncert.db`       | SQLite file path (overrides `DATA_DIR`).                                              |
| `ITEM_TTL`                | `24h`                        | How long an item is kept after the relay receives it.                                 |
| `CLEANUP_INTERVAL`        | `60s`                        | How often expired items and join tokens are deleted.                                  |
| `MAX_ITEMS_PER_SPACE`     | `500`                        | Newest items kept per space; older ones are dropped first.                            |
| `JOIN_TOKEN_TTL`          | `10m`                        | Lifetime of a one-time pairing token.                                                 |
| `RATE_LIMIT_BURST`        | `60`                         | WebSocket frames a device may send in a burst.                                        |
| `RATE_LIMIT_PER_SEC`      | `10`                         | Sustained WebSocket frames per second per device.                                     |
| `REST_RATE_LIMIT_BURST`   | `20`                         | REST requests per IP (unauthenticated) or per device in a burst.                      |
| `REST_RATE_LIMIT_PER_MIN` | `20`                         | Sustained REST requests per minute per IP or device.                                  |
| `HEARTBEAT_INTERVAL`      | `30s`                        | WebSocket ping interval; connections that miss a ping are dropped.                    |
| `HELLO_TIMEOUT`           | `10s`                        | Time a new socket has to authenticate.                                                |
| `SPACE_CREATION_SECRET`   | _(unset: open)_              | If set (≥ 16 chars), `POST /spaces` requires `Authorization: Bearer <secret>`.        |
| `TRUST_PROXY`             | `false`                      | Use `X-Forwarded-For` for client IPs. Enable only behind a reverse proxy you control. |
| `LOG_LEVEL`               | `info`                       | `debug`, `info`, `warn`, `error` or `silent`.                                         |

Backups are optional. The relay only buffers ciphertext for a day, and devices
re-pair if the database is lost. To keep pairings anyway, copy
`syncert.db` while the relay is stopped.

## Development

CI: GitHub Actions workflow in `.github/workflows/ci.yml` runs install, typecheck, lint, format check, tests and build for every workspace package (including the relay) on Node 22 and 24, and builds and smoke-tests the Docker image.

Requires Node ≥ 22.14 (the relay's SQLite driver needs Node-API 10) and pnpm 10
(`corepack enable`).

```sh
pnpm install
pnpm -r typecheck
pnpm -r lint
pnpm -r test
pnpm -r build
pnpm lint && pnpm format:check
pnpm vectors:update   # regenerate crypto test vectors (any diff = wire-format change!)
```

## Security notes

- The relay must only ever see ciphertext and metadata. Never log plaintext,
  space keys, pairing strings or device tokens.
- Pairing strings contain the space key. Show them only as a QR code or text
  on a device the user controls, and never send them via the relay.

## License

[MIT](./LICENSE) © 2026 Joyrudra Biswas
