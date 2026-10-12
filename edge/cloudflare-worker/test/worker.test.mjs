/**
 * The worker end to end, with the platform faked: the four outcomes, what reaches the origin, and
 * every way it must fail closed.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { verifyEdgeContext } from '../src/edge-context.mjs';
import { NonceStore } from '../src/nonce-store.mjs';
import worker, { _internal, setClockForTests } from '../src/worker.mjs';
import {
  FakeNamespace, NOW_MS, SECRET, VECTORS, caseNamed, executionContext, firstAllow, snapshotNamespace,
  header, tamper, withHeader,
} from './helpers.mjs';

const SUITE = VECTORS.suites[0];
const ALLOW = firstAllow(SUITE);
const ORIGIN = 'https://origin.internal';

let forwarded;
const realFetch = globalThis.fetch;

beforeEach(() => {
  _internal.resetForTests();
  setClockForTests(() => NOW_MS);
  forwarded = [];
  // The origin: accepts only requests whose edge context verifies, and echoes that context.
  globalThis.fetch = async (request) => {
    const context = await verifyEdgeContext(
      { method: request.method, url: request.url, headers: request.headers }, SECRET, { now: NOW_MS });
    forwarded.push({ request, context, headers: Object.fromEntries(request.headers) });
    return Response.json({ origin: 'ok', status: context.status });
  };
});

afterEach(() => {
  globalThis.fetch = realFetch;
  setClockForTests(null);
});

function envWith(overrides = {}, snapshot = undefined) {
  return {
    AIDR_ISSUER: SUITE.issuer,
    AIDR_EDGE_CONTEXT_SECRET: SECRET,
    AIDR_ORIGIN: ORIGIN,
    AIDR_BYPASS: '["/health", "/public/.*"]',
    NONCES: new FakeNamespace(NonceStore),
    TRUST: snapshotNamespace(snapshot ?? {
      issuer: SUITE.issuer, jwks: SUITE.jwks, delta: SUITE.revocation.delta_before_revocation,
      fetchedAt: Date.now(),
    }),
    ...overrides,
  };
}

async function send(env, testCase, { path = null, headers = null, method = null } = {}) {
  const url = new URL(testCase?.url ?? 'https://shop.example/api/products');
  if (path) url.pathname = path;
  const ctx = executionContext();
  const response = await worker.fetch(new Request(url, {
    method: method ?? testCase?.method ?? 'GET', headers: headers ?? testCase?.headers ?? {},
  }), env, ctx);
  await Promise.allSettled(ctx.pending);
  return { response, body: await response.json(), ctx };
}

describe('outcomes', () => {
  it('anonymous: no agent headers is forwarded with a signed anonymous context', async () => {
    const { response, body } = await send(envWith(), null);
    assert.equal(response.status, 200);
    assert.equal(body.status, 'anonymous');
    assert.equal(forwarded[0].context.status, 'anonymous');
    assert.equal(new URL(forwarded[0].request.url).origin, ORIGIN);
  });

  it('verified: a valid agent is forwarded with its identity in the context', async () => {
    const { response } = await send(envWith(), ALLOW);
    assert.equal(response.status, 200);
    const { context } = forwarded[0];
    assert.equal(context.status, 'verified');
    assert.equal(context.aid, SUITE.aid);
    assert.equal(context.organization, SUITE.organization);
    assert.deepEqual([context.agal, context.oal, context.kal],
      [SUITE.expected_agal, SUITE.expected_oal, SUITE.expected_kal]);
  });

  it("the agent's own headers are not passed to the origin by default", async () => {
    await send(envWith(), ALLOW);
    for (const name of ['agent-credential', 'signature', 'signature-input']) {
      assert.equal(forwarded[0].headers[name], undefined, name);
    }
  });

  for (const header of ['Agent-Credential', 'Signature', 'Signature-Input']) {
    it(`refused 401: ${header} alone is a claim to be an agent`, async () => {
      const { response, body } = await send(envWith(), ALLOW, { headers: { [header]: ALLOW.headers[header] } });
      assert.equal(response.status, 401);
      assert.equal(body.error, 'aidr.crypto.malformed_token');
      assert.equal(forwarded.length, 0);
    });
  }

  it('refused 403: below the AgAL floor, with the reason', async () => {
    const { response, body } = await send(envWith({ AIDR_MIN_AGAL: '2' }), ALLOW);
    assert.equal(response.status, 403);
    assert.equal(body.error, 'aidr.verify.assurance_too_low');
    assert.match(body.reason, /AgAL 1/);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });

  it('refused 403: OAL and KAL floors are separate', async () => {
    assert.equal((await send(envWith({ AIDR_MIN_OAL: '2' }), ALLOW)).response.status, 200);
    forwarded = [];
    const { response, body } = await send(envWith({ AIDR_MIN_KAL: '2' }), ALLOW);
    assert.equal(response.status, 403);
    assert.match(body.reason, /KAL/);
  });

  it('refused 403: a revoked agent', async () => {
    const env = envWith({}, { issuer: SUITE.issuer, jwks: SUITE.jwks,
      delta: SUITE.revocation.delta_after_revocation, fetchedAt: Date.now() });
    const { response, body } = await send(env, ALLOW);
    assert.equal(response.status, 403);
    assert.equal(body.error, 'aidr.verify.agent_revoked');
  });

  it('bypassed: never verified, forwarded with a bypassed context', async () => {
    const { response } = await send(envWith(), null,
      { path: '/health', headers: { Signature: 'sig1=:AAAA:' } });
    assert.equal(response.status, 200);
    assert.equal(forwarded[0].context.status, 'bypassed');
    assert.equal(forwarded[0].context.aid, undefined);
  });

  it('bypass rules cannot be walked around with an encoded dot segment', async () => {
    const { response } = await send(envWith(), null,
      { path: '/public/..%2fadmin', headers: { Signature: 'sig1=:AAAA:' } });
    assert.equal(response.status, 401);
  });
});

describe('verified-only mode', () => {
  it('anonymous traffic is refused with 401 and told where identities come from', async () => {
    const { response, body } = await send(envWith({ AIDR_MODE: 'verified-only' }), null);
    assert.equal(response.status, 401);
    assert.equal(body.error, 'aidr.edge.agent_required');
    assert.equal(response.headers.get('link'),
      `<${SUITE.issuer}/.well-known/aiaf-registry>; rel="aiaf-registry"`);
    assert.equal(forwarded.length, 0);
  });

  it('a verified agent passes', async () => {
    const { response } = await send(envWith({ AIDR_MODE: 'verified-only' }), ALLOW);
    assert.equal(response.status, 200);
    assert.equal(forwarded[0].context.status, 'verified');
  });

  it('an invalid agent is still refused for what it is, not as anonymous', async () => {
    const { response, body } = await send(envWith({ AIDR_MODE: 'verified-only', AIDR_MIN_AGAL: '3' }), ALLOW);
    assert.equal(response.status, 403);
    assert.equal(body.error, 'aidr.verify.assurance_too_low');
  });

  it('bypassed paths stay open', async () => {
    const { response } = await send(envWith({ AIDR_MODE: 'verified-only' }), null, { path: '/health' });
    assert.equal(response.status, 200);
    assert.equal(forwarded[0].context.status, 'bypassed');
  });

  it('scoped to some paths: people keep the rest of the site', async () => {
    const env = envWith({ AIDR_MODE: 'verified-only', AIDR_VERIFIED_ONLY_PATHS: '["/api/.*"]' });
    assert.equal((await send(env, null, { path: '/api/products' })).response.status, 401);
    const { response } = await send(env, null, { path: '/catalogue' });
    assert.equal(response.status, 200);
    assert.equal(forwarded[0].context.status, 'anonymous');
  });

  it('a path that cannot be normalised counts as protected (fails closed)', async () => {
    const env = envWith({ AIDR_MODE: 'verified-only', AIDR_VERIFIED_ONLY_PATHS: '["/api/.*"]' });
    const { response } = await send(env, null, { path: '/docs/..%2fapi/products' });
    assert.equal(response.status, 401);
    assert.equal(forwarded.length, 0);
  });

  it('a mistyped mode is a configuration error, never an open site', async () => {
    for (const overrides of [{ AIDR_MODE: 'verified_only' }, { AIDR_VERIFIED_ONLY_PATHS: '["/api/.*"]' },
      { AIDR_MODE: 'verified-only', AIDR_VERIFIED_ONLY_PATHS: '[]' }]) {
      _internal.resetForTests();
      const { response, body } = await send(envWith(overrides), null);
      assert.equal(response.status, 503, JSON.stringify(overrides));
      assert.equal(body.error, 'aidr.edge.misconfigured');
    }
  });
});

describe('an origin behind a service binding', () => {
  it('is reached through the binding, not the internet, with the same signed context', async () => {
    const viaBinding = [];
    const ORIGIN_BINDING = { fetch: async (request) => {
      const context = await verifyEdgeContext(
        { method: request.method, url: request.url, headers: request.headers }, SECRET, { now: NOW_MS });
      viaBinding.push(context);
      return Response.json({ origin: 'bound', status: context.status });
    } };
    const { response, body } = await send(envWith({ ORIGIN: ORIGIN_BINDING }), ALLOW);
    assert.equal(response.status, 200);
    assert.equal(body.origin, 'bound');
    assert.equal(viaBinding[0].aid, SUITE.aid);
    assert.equal(forwarded.length, 0);   // global fetch never used
  });
});

describe('the origin hop', () => {
  it('client-sent x-aidr-* headers never reach the origin', async () => {
    await send(envWith(), null, { headers: {
      'X-AIDR-Context': 'forged', 'X-AIDR-Context-Signature': 'forged', 'X-AIDR-Org': 'acme-corp' } });
    assert.equal(forwarded[0].headers['x-aidr-org'], undefined);
    assert.equal(forwarded[0].context.status, 'anonymous');
  });

  it('a context is bound to its request: another path is refused at the origin', async () => {
    await send(envWith(), null);
    const { request } = forwarded[0];
    await assert.rejects(verifyEdgeContext({ method: 'GET', url: `${ORIGIN}/admin`, headers: request.headers },
      SECRET, { now: NOW_MS }), { code: 'aidr.edge.context_invalid' });
  });
});

describe('replay protection', () => {
  it('a replayed request is refused', async () => {
    const env = envWith();
    assert.equal((await send(env, ALLOW)).response.status, 200);
    const replay = await send(env, ALLOW);
    assert.equal(replay.response.status, 401);
    assert.equal(replay.body.error, 'aidr.verify.replay_detected');
  });

  it('a forged request does not consume the genuine nonce', async () => {
    const env = envWith();
    const forged = { ...ALLOW, headers: withHeader(ALLOW.headers, 'Signature', tamper(header(ALLOW.headers, 'Signature'))) };
    assert.equal((await send(env, forged)).response.status, 401);
    assert.equal((await send(env, ALLOW)).response.status, 200);
  });

  it('nonces are sharded across Durable Objects by key', async () => {
    const env = envWith();
    await send(env, ALLOW);
    assert.equal(env.NONCES.calls.length, 1);
    assert.match(env.NONCES.calls[0].id, /^nonce-[0-9a-f]{2}$/);
  });

  it('an unreachable replay store fails closed', async () => {
    const env = envWith({ NONCES: { idFromName: (n) => n,
      get: () => ({ fetch: async () => { throw new Error('connection reset'); } }) } });
    const { response, body } = await send(env, ALLOW);
    assert.equal(response.status, 503);
    assert.equal(body.error, 'aidr.registry.unavailable');
  });
});

describe('trust and configuration fail closed', () => {
  it('no snapshot: agents get 503, anonymous traffic still flows', async () => {
    const env = envWith({ TRUST: snapshotNamespace(() => Response.json({}, { status: 503 })) });
    assert.equal((await send(env, ALLOW)).response.status, 503);
    assert.equal((await send(env, null)).response.status, 200);
  });

  it('a snapshot the registry has not refreshed for over 11 minutes is refused', async () => {
    const env = envWith({}, { issuer: SUITE.issuer, jwks: SUITE.jwks,
      delta: SUITE.revocation.delta_before_revocation, fetchedAt: Date.now() - 12 * 60 * 1000 });
    const { response, body } = await send(env, ALLOW);
    assert.equal(response.status, 503);
    assert.match(body.reason, /too old/);
  });

  it('a snapshot for another issuer is refused', async () => {
    const env = envWith({}, { issuer: 'https://impostor.example', jwks: SUITE.jwks,
      delta: SUITE.revocation.delta_before_revocation, fetchedAt: Date.now() });
    assert.equal((await send(env, ALLOW)).response.status, 503);
  });

  it('an unknown kid asks the trust object for a key refresh without waiting on it', async () => {
    const other = VECTORS.suites[1];
    const env = envWith({}, { issuer: SUITE.issuer, jwks: other.jwks,
      delta: other.revocation.delta_before_revocation, fetchedAt: Date.now() });
    // Different issuers' keys: the suites share an issuer, so the ES256 JWKS lacks the Ed25519 kid.
    const { response, body } = await send(env, ALLOW);
    assert.equal(response.status, 401);
    assert.equal(body.error, 'aidr.verify.unknown_issuer');
    assert.ok(env.TRUST.calls.includes('/refresh-keys'));
  });

  for (const [name, overrides] of [
    ['a short context secret', { AIDR_EDGE_CONTEXT_SECRET: 'short' }],
    ['a non-https issuer', { AIDR_ISSUER: 'http://registry.example' }],
    ['an invalid bypass list', { AIDR_BYPASS: '"not-an-array"' }],
    ['a missing Durable Object binding', { NONCES: undefined }],
    ['an out-of-range floor', { AIDR_MIN_AGAL: '9' }],
  ]) {
    it(`misconfiguration refuses every request: ${name}`, async () => {
      const { response, body } = await send(envWith(overrides), null);
      assert.equal(response.status, 503);
      assert.equal(body.error, 'aidr.edge.misconfigured');
      assert.equal(forwarded.length, 0);
    });
  }
});

describe('vector cases through the worker', () => {
  for (const testCase of SUITE.cases) {
    it(testCase.name, async () => {
      const env = envWith({
        AIDR_MIN_AGAL: String(testCase.min_assurance ?? 0),
        ...(testCase.expected_audience ? { AIDR_EXPECTED_AUDIENCE: testCase.expected_audience } : {}),
      });
      const { response, body } = await send(env, testCase);
      if (testCase.expect === 'allow') {
        assert.equal(response.status, 200, JSON.stringify(body));
      } else {
        assert.ok([401, 403].includes(response.status), `${response.status} ${JSON.stringify(body)}`);
        if (testCase.expect_code) assert.equal(body.error, testCase.expect_code);
      }
    });
  }

  it('the tampered-signature case is the same nonce as the valid one', () => {
    // Precondition for the "forged request does not consume the genuine nonce" test above.
    const nonce = (c) => /nonce="([^"]+)"/.exec(header(c.headers, 'Signature-Input'))[1];
    assert.equal(nonce(caseNamed(SUITE, 'tampered signature is refused')), nonce(ALLOW));
  });
});
