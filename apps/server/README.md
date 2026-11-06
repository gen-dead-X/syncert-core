# @syncert/server

The syncert relay is a small Node service that stores and forwards end-to-end
encrypted clipboard items between the devices of a space. It never sees
plaintext or keys.

- Self-hosting, Docker and configuration: [root README](../../README.md#self-hosting)
- Wire protocol: [docs/protocol.md](../../docs/protocol.md)

```sh
pnpm --filter @syncert/server... build
node apps/server/dist/cli.js       # or the `syncert-server` bin
pnpm --filter @syncert/server test # integration tests (real sockets, temp SQLite)
```

It can also be embedded programmatically:

```ts
import { createRelay } from '@syncert/server';
const relay = createRelay({ config: { port: 8787, dbPath: './syncert.db' } });
await relay.listen();
// ...
await relay.close();
```

Source layout: `config.ts` (env parsing), `store.ts` (SQLite schema and
queries), `hub.ts` (WebSocket frame handling and fan-out), `http.ts` (REST
routes), `server.ts` (wiring, timers, shutdown), `cli.ts` (entry point).
