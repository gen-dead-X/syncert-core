# syncert-core

**syncert** is a cross-device, end-to-end-encrypted clipboard sync tool. Copy on
your Mac, paste on your phone, and the relay in the middle only ever sees
ciphertext.

This repository is a pnpm-workspaces monorepo holding the shared TypeScript
packages (and, later, the relay server). The desktop app
([syncert-macos](https://github.com/gen-dead-X/syncert-macos), Tauri) and the
Android app ([syncert-android](https://github.com/gen-dead-X/syncert-android))
consume these packages.

> Status: milestone 1, protocol and crypto. No relay or sync engine yet.

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

## Layout

```
packages/
  protocol/   @syncert/protocol: types, constants, zod frame schemas, encode/decode, base64/ULID helpers
  crypto/     @syncert/crypto: space keys, AES-256-GCM items, keyed content hash, pairing, test vectors
  core/       @syncert/core: SyncTransport + KindPlugin interfaces, PluginRegistry, clipboard.text plugin, StubTransport
apps/
  server/     (later) the relay. It only ever handles ciphertext and never logs plaintext.
```

Packages build to ESM + `.d.ts` in `dist/`. Inside the workspace, TypeScript and
vitest resolve `@syncert/*` straight to `src/` (via the `@syncert/source`
export condition / aliases), so typecheck and tests need no prior build.

## Development

CI: GitHub Actions workflow in `.github/workflows/ci.yml` runs install, typecheck, lint and tests on every push and PR.

Requires Node ≥ 22.12 and pnpm 10 (`corepack enable`).

```sh
pnpm install
pnpm -r typecheck
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
