import { readFileSync, existsSync } from 'node:fs';
import { DecryptionError, decryptItem } from '@syncert/crypto';
import {
  MAX_ITEM_PAYLOAD_BYTES,
  MAX_SYNC_BATCH_ITEMS,
  PROTOCOL_VERSION,
  bytesToBase64,
  itemFromWire,
  ulid,
} from '@syncert/protocol';
import { afterEach, describe, expect, it } from 'vitest';
import { CloseCode } from '../src/hub.ts';
import {
  TestClient,
  api,
  createSpace,
  decryptText,
  encryptText,
  pairDevice,
  sleep,
  startRelay,
  type TestRelay,
} from './helpers.ts';

let t: TestRelay;
const clients: TestClient[] = [];
const track = <T extends { client: TestClient }>(x: T): T => {
  clients.push(x.client);
  return x;
};

afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await t?.stop();
});

describe('REST: spaces and pairing', () => {
  it('reports health', async () => {
    t = await startRelay();
    const res = await api(t, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok', protocolVersion: PROTOCOL_VERSION });
  });

  it('creates a space and pairs a second device with a single-use join token', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    expect(a.spaceId).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.deviceToken.length).toBeGreaterThanOrEqual(43);

    const b = await pairDevice(t, a);
    expect(b.spaceId).toBe(a.spaceId);
    expect(b.deviceId).not.toBe(a.deviceId);
    expect(b.spaceKey).toEqual(a.spaceKey);

    // Join tokens are single use.
    const tok = await api<{ joinToken: string }>(t, 'POST', '/pair/token', {
      token: b.deviceToken,
    });
    expect(tok.status).toBe(201);
    const first = await api(t, 'POST', '/pair/join', { body: { joinToken: tok.body.joinToken } });
    expect(first.status).toBe(201);
    const second = await api(t, 'POST', '/pair/join', { body: { joinToken: tok.body.joinToken } });
    expect(second.status).toBe(401);
    expect(second.body).toMatchObject({ error: { code: 'unauthorized' } });

    // Tokens are stored only as hashes.
    const rows = t.relay.store.db.prepare('SELECT token_hash FROM devices').all() as {
      token_hash: string;
    }[];
    expect(rows.map((r) => r.token_hash)).not.toContain(a.deviceToken);
    expect(JSON.stringify(rows)).not.toContain(a.deviceToken);
  });

  it('rejects expired join tokens and unauthenticated token requests', async () => {
    t = await startRelay({ joinTokenTtlMs: 10 * 60_000 });
    const a = await createSpace(t);
    const tok = await api<{ joinToken: string; expiresAt: number }>(t, 'POST', '/pair/token', {
      token: a.deviceToken,
    });
    expect(tok.body.expiresAt).toBe(t.clock.now + 10 * 60_000);
    t.clock.now += 10 * 60_000 + 1;
    const res = await api(t, 'POST', '/pair/join', { body: { joinToken: tok.body.joinToken } });
    expect(res.status).toBe(401);

    expect((await api(t, 'POST', '/pair/token')).status).toBe(401);
    expect((await api(t, 'POST', '/pair/token', { token: 'x'.repeat(43) })).status).toBe(401);
    expect((await api(t, 'POST', '/pair/join', { body: { nope: 1 } })).status).toBe(400);
  });

  it('can require a secret for space creation', async () => {
    t = await startRelay({ spaceCreationSecret: 's3cret-s3cret-s3cret' });
    expect((await api(t, 'POST', '/spaces')).status).toBe(401);
    expect((await api(t, 'POST', '/spaces', { token: 'wrong-wrong-wrong-wrong' })).status).toBe(
      401,
    );
    expect((await api(t, 'POST', '/spaces', { token: 's3cret-s3cret-s3cret' })).status).toBe(201);
  });

  it('rate limits unauthenticated REST endpoints per IP', async () => {
    t = await startRelay({ restRateLimitBurst: 3, restRateLimitPerMin: 1 });
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) statuses.push((await api(t, 'POST', '/spaces')).status);
    expect(statuses).toEqual([201, 201, 201, 429, 429]);
  });
});

describe('WebSocket relay', () => {
  it('relays an encrypted push from A to B only, and B decrypts it', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const b = await pairDevice(t, a);
    const { client: ca, welcome } = track(await TestClient.hello(t, a));
    expect(welcome).toMatchObject({ deviceId: a.deviceId, spaceId: a.spaceId, protocolVersion: 1 });
    const { client: cb } = track(await TestClient.hello(t, b));

    const text = 'hello from A 👋';
    const wire = await encryptText(a, text);
    ca.send({ type: 'item.push', reqId: 'p1', item: wire });

    expect(await ca.next('item.ack')).toEqual({ type: 'item.ack', reqId: 'p1', id: wire.id });
    const got = await cb.next('item.new');
    expect(got.item).toEqual(wire);
    expect(await decryptText(b, got.item)).toBe(text);
    await ca.expectNone('item.new');
  });

  it('lets an offline device catch up with paginated sync.since', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const b = await pairDevice(t, a);
    const c = await pairDevice(t, a);
    const { client: ca } = track(await TestClient.hello(t, a));
    const { client: cb } = track(await TestClient.hello(t, b));

    const texts = Array.from({ length: 23 }, (_, i) => `clip #${i}`);
    for (const text of texts) {
      ca.send({ type: 'item.push', item: await encryptText(a, text) });
      await ca.next('item.ack');
    }
    // B pushes one too; C must see it, B must not get its own item back via sync.
    cb.send({ type: 'item.push', item: await encryptText(b, 'from B') });
    await cb.next('item.ack');

    const { client: cc } = track(await TestClient.hello(t, c));
    const received: string[] = [];
    const pages: number[] = [];
    let cursor: string | null = null;
    for (;;) {
      cc.send({ type: 'sync.since', reqId: 's', lastItemId: cursor });
      const batch = await cc.next('sync.batch');
      expect(batch.reqId).toBe('s');
      expect(batch.items.length).toBeLessThanOrEqual(MAX_SYNC_BATCH_ITEMS);
      pages.push(batch.items.length);
      for (const item of batch.items) received.push(await decryptText(c, item));
      cursor = batch.items.at(-1)?.id ?? cursor;
      if (!batch.hasMore) break;
    }
    expect(pages).toEqual([10, 10, 4]);
    expect(received).toEqual([...texts, 'from B']);

    cb.send({ type: 'sync.since', lastItemId: null });
    const own = await cb.next('sync.batch');
    expect(own.items.map((i) => i.originDeviceId)).not.toContain(b.deviceId);
    expect(own.items).toHaveLength(10);
  });

  it('acks a duplicate push without storing or fanning it out twice', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const b = await pairDevice(t, a);
    const { client: ca } = track(await TestClient.hello(t, a));
    const { client: cb } = track(await TestClient.hello(t, b));

    const wire = await encryptText(a, 'only once');
    ca.send({ type: 'item.push', reqId: 'a', item: wire });
    ca.send({ type: 'item.push', reqId: 'b', item: wire });
    expect((await ca.next('item.ack')).reqId).toBe('a');
    expect((await ca.next('item.ack')).reqId).toBe('b');
    await cb.next('item.new');
    await cb.expectNone('item.new');
    expect(t.relay.store.countItems(a.spaceId)).toBe(1);

    // Same id, different content: rejected.
    const other = await encryptText(a, 'different', wire.id);
    ca.send({ type: 'item.push', reqId: 'c', item: other });
    expect(await ca.next('error')).toMatchObject({ reqId: 'c', code: 'bad_request' });
  });

  it('revocation closes the device socket immediately and blocks its token', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const b = await pairDevice(t, a);
    const { client: ca } = track(await TestClient.hello(t, a));
    const { client: cb } = track(await TestClient.hello(t, b));

    ca.send({ type: 'device.list', reqId: 'l1' });
    const list = await ca.next('device.list.result');
    expect(list.devices.map((d) => d.deviceId).sort()).toEqual([a.deviceId, b.deviceId].sort());

    ca.send({ type: 'device.revoke', reqId: 'r1', deviceId: b.deviceId });
    expect(await ca.next('device.revoked')).toEqual({
      type: 'device.revoked',
      reqId: 'r1',
      deviceId: b.deviceId,
    });
    expect(await cb.next('error')).toMatchObject({ code: 'unauthorized' });
    expect((await cb.closed).code).toBe(CloseCode.Revoked);

    // Token no longer works over WS or REST.
    const again = await TestClient.connect(t);
    clients.push(again);
    again.send({ type: 'hello', protocolVersion: PROTOCOL_VERSION, deviceToken: b.deviceToken });
    expect(await again.next('error')).toMatchObject({ code: 'unauthorized' });
    expect((await again.closed).code).toBe(CloseCode.Unauthorized);
    expect((await api(t, 'POST', '/pair/token', { token: b.deviceToken })).status).toBe(401);

    ca.send({ type: 'device.list' });
    expect((await ca.next('device.list.result')).devices.map((d) => d.deviceId)).toEqual([
      a.deviceId,
    ]);
    // Revoking again (or a device from another space) is not_found.
    ca.send({ type: 'device.revoke', reqId: 'r2', deviceId: b.deviceId });
    expect(await ca.next('error')).toMatchObject({ reqId: 'r2', code: 'not_found' });
  });

  it('rejects a bad device token', async () => {
    t = await startRelay();
    const c = await TestClient.connect(t);
    clients.push(c);
    c.send({
      type: 'hello',
      reqId: 'h',
      protocolVersion: PROTOCOL_VERSION,
      deviceToken: 'A'.repeat(43),
    });
    expect(await c.next('error')).toEqual({
      type: 'error',
      reqId: 'h',
      code: 'unauthorized',
      message: 'invalid device token',
    });
    expect((await c.closed).code).toBe(CloseCode.Unauthorized);
  });

  it('rejects an unsupported protocol version', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const c = await TestClient.connect(t);
    clients.push(c);
    c.send({ type: 'hello', protocolVersion: PROTOCOL_VERSION + 1, deviceToken: a.deviceToken });
    expect(await c.next('error')).toMatchObject({ code: 'unsupported_protocol_version' });
    expect((await c.closed).code).toBe(CloseCode.UnsupportedProtocolVersion);
  });

  it('rejects frames before hello and malformed frames', async () => {
    t = await startRelay();
    const c1 = await TestClient.connect(t);
    clients.push(c1);
    c1.send({ type: 'device.list' });
    expect(await c1.next('error')).toMatchObject({ code: 'unauthorized' });
    expect((await c1.closed).code).toBe(CloseCode.Unauthorized);

    const c2 = await TestClient.connect(t);
    clients.push(c2);
    c2.sendRaw('{not json');
    expect(await c2.next('error')).toMatchObject({ code: 'bad_request' });
    expect((await c2.closed).code).toBe(CloseCode.BadRequest);
  });

  it('closes sockets that never say hello', async () => {
    t = await startRelay({ helloTimeoutMs: 150 });
    const c = await TestClient.connect(t);
    clients.push(c);
    expect((await c.closed).code).toBe(CloseCode.HelloTimeout);
  });

  it('rejects oversize payloads and items for another space or device', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const b = await pairDevice(t, a);
    const other = await createSpace(t);
    const { client: ca } = track(await TestClient.hello(t, a));

    const wire = await encryptText(a, 'x');
    const huge = { ...wire, payload: bytesToBase64(new Uint8Array(MAX_ITEM_PAYLOAD_BYTES + 1)) };
    ca.sendRaw(JSON.stringify({ type: 'item.push', reqId: 'big', item: huge }));
    expect(await ca.next('error')).toMatchObject({ reqId: 'big', code: 'payload_too_large' });

    // Exactly at the limit is accepted (relay can't check the plaintext, only ciphertext size).
    const max = {
      ...wire,
      id: ulid(),
      payload: bytesToBase64(new Uint8Array(MAX_ITEM_PAYLOAD_BYTES)),
    };
    ca.send({ type: 'item.push', reqId: 'max', item: max });
    expect(await ca.next('item.ack')).toMatchObject({ reqId: 'max' });

    // Frames beyond the WebSocket limit are dropped by closing the socket.
    const bomb = await TestClient.hello(t, a);
    clients.push(bomb.client);
    bomb.client.sendRaw('"' + 'a'.repeat(2 * 1024 * 1024) + '"');
    expect((await bomb.client.closed).code).toBe(1009);

    const spoofDevice = { ...(await encryptText(a, 'y')), originDeviceId: b.deviceId };
    ca.send({ type: 'item.push', reqId: 'sd', item: spoofDevice });
    expect(await ca.next('error')).toMatchObject({ reqId: 'sd', code: 'forbidden' });
    const spoofSpace = { ...(await encryptText(a, 'z')), spaceId: other.spaceId };
    ca.send({ type: 'item.push', reqId: 'ss', item: spoofSpace });
    expect(await ca.next('error')).toMatchObject({ reqId: 'ss', code: 'forbidden' });

    // Socket still usable after rejected frames.
    ca.send({ type: 'item.push', reqId: 'ok', item: await encryptText(a, 'fine') });
    expect(await ca.next('item.ack')).toMatchObject({ reqId: 'ok' });
  });

  it('rate limits a chatty device', async () => {
    t = await startRelay({ rateLimitBurst: 5, rateLimitPerSec: 1 });
    const a = await createSpace(t);
    const { client: ca } = track(await TestClient.hello(t, a));
    for (let i = 0; i < 8; i++) ca.send({ type: 'sync.since', reqId: `q${i}`, lastItemId: null });
    for (let i = 0; i < 5; i++) await ca.next('sync.batch');
    for (let i = 0; i < 3; i++)
      expect(await ca.next('error')).toMatchObject({ code: 'rate_limited' });
    // Refill: one more token after a (fake) second.
    t.clock.now += 1000;
    ca.send({ type: 'device.list' });
    await ca.next('device.list.result');
  });

  it('expires buffered items after the TTL', async () => {
    t = await startRelay({ itemTtlMs: 24 * 3_600_000 });
    const a = await createSpace(t);
    const b = await pairDevice(t, a);
    const { client: ca } = track(await TestClient.hello(t, a));
    ca.send({ type: 'item.push', item: await encryptText(a, 'old') });
    await ca.next('item.ack');
    t.clock.now += 23 * 3_600_000;
    ca.send({ type: 'item.push', item: await encryptText(a, 'newer') });
    await ca.next('item.ack');

    expect(t.relay.cleanup().items).toBe(0);
    t.clock.now += 1 * 3_600_000 + 1;
    expect(t.relay.cleanup().items).toBe(1);
    expect(t.relay.store.countItems()).toBe(1);

    const { client: cb } = track(await TestClient.hello(t, b));
    cb.send({ type: 'sync.since', lastItemId: null });
    const batch = await cb.next('sync.batch');
    expect(await Promise.all(batch.items.map((i) => decryptText(b, i)))).toEqual(['newer']);
  });

  it('caps buffered items per space', async () => {
    t = await startRelay({ maxItemsPerSpace: 3 });
    const a = await createSpace(t);
    const { client: ca } = track(await TestClient.hello(t, a));
    for (let i = 0; i < 5; i++) {
      ca.send({ type: 'item.push', item: await encryptText(a, `n${i}`) });
      await ca.next('item.ack');
    }
    expect(t.relay.store.countItems(a.spaceId)).toBe(3);
  });

  it('terminates connections that stop answering pings', async () => {
    t = await startRelay({ heartbeatIntervalMs: 100 });
    const a = await createSpace(t);
    const dead = track(await TestClient.hello(t, a, { autoPong: false }));
    const live = track(await TestClient.hello(t, a));
    const { code } = await dead.client.closed;
    expect(code).toBe(1006); // terminated without a close frame
    expect(live.client.ws.readyState).toBe(live.client.ws.OPEN);
    for (let i = 0; i < 50 && t.relay.hub.connectionCount !== 1; i++) await sleep(10);
    expect(t.relay.hub.connectionCount).toBe(1);
  });

  it('never stores or logs plaintext, payloads or tokens', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const b = await pairDevice(t, a);
    const { client: ca } = track(await TestClient.hello(t, a));
    const { client: cb } = track(await TestClient.hello(t, b));
    const secret = 'CANARY-plaintext-4f9b2c-correct horse battery staple';
    const wire = await encryptText(a, secret.repeat(50));
    ca.send({ type: 'item.push', item: wire });
    await ca.next('item.ack');
    const got = await cb.next('item.new');
    expect(await decryptText(b, got.item)).toBe(secret.repeat(50));

    // A wrong key can't read what the relay stored.
    const stranger = await createSpace(t);
    await expect(decryptItem(stranger.keys, itemFromWire(got.item))).rejects.toBeInstanceOf(
      DecryptionError,
    );

    await Promise.all(clients.splice(0).map((c) => c.close()));
    const { dbPath, logs } = t;
    await t.relay.close(); // checkpoints the WAL into the main file
    const files = [dbPath, `${dbPath}-wal`, `${dbPath}-shm`].filter((f) => existsSync(f));
    const dump = Buffer.concat(files.map((f) => readFileSync(f)));
    expect(dump.length).toBeGreaterThan(0);
    expect(dump.includes(Buffer.from('CANARY-plaintext'))).toBe(false);
    expect(dump.includes(Buffer.from(a.deviceToken))).toBe(false);
    expect(dump.includes(Buffer.from(b.deviceToken))).toBe(false);
    // The ciphertext is there (as raw bytes), so the check above is meaningful.
    expect(dump.includes(Buffer.from(itemFromWire(wire).payload.slice(0, 64)))).toBe(true);

    const logText = logs.join('\n');
    expect(logs.length).toBeGreaterThan(5);
    expect(logText).not.toContain('CANARY');
    expect(logText).not.toContain(wire.payload.slice(0, 32));
    expect(logText).not.toContain(wire.nonce);
    expect(logText).not.toContain(a.deviceToken);
    expect(logText).not.toContain(b.deviceToken);
  });

  it('does not deliver after the relay shuts down and is safe to close twice', async () => {
    t = await startRelay();
    const a = await createSpace(t);
    const { client } = track(await TestClient.hello(t, a));
    await Promise.all([t.relay.close(), t.relay.close()]);
    expect((await client.closed).code).toBe(CloseCode.GoingAway);
    await sleep(10);
  });
});
