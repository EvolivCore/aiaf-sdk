import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { setClockForTests } from '../src/clock.mjs';
import { NonceStore, shardFor } from '../src/nonce-store.mjs';
import { TrustState } from '../src/trust-state.mjs';
import { FakeStorage, NOW_MS, VECTORS } from './helpers.mjs';

const KEY = 'a'.repeat(64);
const claim = (store, body) => store.fetch(new Request('https://nonce.internal/claim', {
  method: 'POST', body: JSON.stringify(body) })).then(async (r) => ({ status: r.status, ...(await r.json()) }));

describe('NonceStore', () => {
  it('a nonce is fresh once, then seen', async () => {
    const store = new NonceStore({ storage: new FakeStorage() });
    assert.equal((await claim(store, { key: KEY, ttl: 300 })).fresh, true);
    assert.equal((await claim(store, { key: KEY, ttl: 300 })).fresh, false);
  });

  it('concurrent claims for one nonce: exactly one is fresh', async () => {
    const store = new NonceStore({ storage: new FakeStorage() });
    const results = await Promise.all(Array.from({ length: 10 }, () => claim(store, { key: KEY, ttl: 300 })));
    // The claim is one synchronous SQLite upsert, so however the awaits interleave, only one
    // statement can write the row.
    assert.equal(results.filter((r) => r.fresh).length, 1);
  });

  it('an expired entry can be claimed again; a live one cannot be taken over', async () => {
    const storage = new FakeStorage();
    const store = new NonceStore({ storage });
    await claim(store, { key: KEY, ttl: 300 });
    assert.equal((await claim(store, { key: KEY, ttl: 300 })).fresh, false);
    storage.db.prepare('UPDATE nonces SET expires = ?').run(Date.now() - 1);
    assert.equal((await claim(store, { key: KEY, ttl: 300 })).fresh, true);
  });

  it('refuses malformed claims', async () => {
    const store = new NonceStore({ storage: new FakeStorage() });
    for (const body of [{ key: 'short', ttl: 300 }, { key: KEY, ttl: 0 }, { key: KEY, ttl: 99999 },
      { key: KEY.toUpperCase(), ttl: 300 }]) {
      assert.equal((await claim(store, body)).status, 400, JSON.stringify(body));
    }
  });

  it('arms a sweep, and the sweep deletes only expired entries', async () => {
    const storage = new FakeStorage();
    const store = new NonceStore({ storage });
    await claim(store, { key: KEY, ttl: 300 });
    assert.ok(storage.alarm > Date.now());
    storage.db.prepare('INSERT INTO nonces (key, expires) VALUES (?, ?)').run('b'.repeat(64), Date.now() - 1);
    await store.alarm();
    assert.deepEqual(storage.db.prepare('SELECT key FROM nonces').all().map((r) => r.key), [KEY]);
  });

  it('shards by the first byte of the key', () => {
    assert.equal(shardFor(`ff${'0'.repeat(62)}`), 'nonce-ff');
  });
});

describe('TrustState', () => {
  const suite = VECTORS.suites[0];
  const ISSUER = suite.issuer;
  let served;
  let requests;
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    setClockForTests(() => NOW_MS);
    requests = [];
    served = {
      discovery: { issuer: ISSUER, jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        revocation_delta_endpoint: `${ISSUER}/v1/revocations/delta` },
      jwks: suite.jwks,
      delta: suite.revocation.delta_before_revocation,
      status: 200,
    };
    globalThis.fetch = async (url) => {
      const { pathname, searchParams } = new URL(url);
      requests.push(pathname + (searchParams.size ? `?${searchParams}` : ''));
      if (served.status !== 200) return new Response('down', { status: served.status });
      if (pathname === '/.well-known/aiaf-registry') return Response.json(served.discovery);
      if (pathname === '/.well-known/jwks.json') return Response.json(served.jwks);
      if (pathname === '/v1/revocations/delta') return Response.json({ delta: served.delta });
      return new Response('not found', { status: 404 });
    };
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    setClockForTests(null);
  });

  const trustState = () => new TrustState({ storage: new FakeStorage() }, { AIDR_ISSUER: ISSUER });
  const snapshot = (state) => state.fetch(new Request('https://trust.internal/snapshot'));

  it('fetches, verifies and serves a complete snapshot, and arms its refresh alarm', async () => {
    const state = trustState();
    const response = await snapshot(state);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.issuer, ISSUER);
    assert.equal(body.delta, suite.revocation.delta_before_revocation);
    assert.ok(requests.includes('/v1/revocations/delta?since=0'));
    assert.ok(state.storage.alarm);
  });

  it("refuses trust material off the issuer's origin", async () => {
    served.discovery.jwks_uri = 'https://attacker.example/jwks.json';
    const response = await snapshot(trustState());
    assert.equal(response.status, 503);
    assert.match((await response.json()).reason, /issuer's origin/);
    assert.ok(!requests.some((r) => r.includes('attacker')));
  });

  it('a feed that does not verify is never stored', async () => {
    served.delta = VECTORS.suites[1].revocation.delta_before_revocation;   // signed by another key
    const state = trustState();
    assert.equal((await snapshot(state)).status, 503);
    assert.equal(await state.storage.get('snapshot'), undefined);
  });

  it('a failed refresh keeps serving the last good snapshot', async () => {
    const state = trustState();
    await snapshot(state);
    const stored = await state.storage.get('snapshot');
    stored.fetchedAt -= 5 * 60 * 1000;                      // due for refresh
    await state.storage.put('snapshot', stored);
    served.status = 502;
    const response = await snapshot(state);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).fetchedAt, stored.fetchedAt);  // the isolate judges its age
  });

  it('retries with fresh keys when the registry has rotated', async () => {
    const state = trustState();
    await snapshot(state);
    const rotated = VECTORS.suites[1];
    served.jwks = rotated.jwks;
    served.delta = rotated.revocation.delta_before_revocation;
    const before = requests.filter((r) => r === '/.well-known/jwks.json').length;
    await state.refresh({ forceKeys: false });
    assert.equal(requests.filter((r) => r === '/.well-known/jwks.json').length, before + 1);
    assert.deepEqual((await state.storage.get('snapshot')).jwks, rotated.jwks);
  });

  it('on-demand key refreshes are rate-limited', async () => {
    const state = trustState();
    await state.fetch(new Request('https://trust.internal/refresh-keys'));
    await state.fetch(new Request('https://trust.internal/refresh-keys'));
    assert.equal(requests.filter((r) => r === '/.well-known/jwks.json').length, 1);
  });

  it('the alarm refreshes and re-arms even when the refresh fails', async () => {
    const state = trustState();
    served.status = 500;
    await state.alarm();
    assert.ok(state.storage.alarm > Date.now());
  });
});
