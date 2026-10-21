/**
 * aidr() end to end: a fake registry serving the shared vectors' real keys and signed revocation
 * feeds through the discovery document, and the middleware driven like Express drives it.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  aidr, expressMiddleware, AgentVerifier, buildTrustStore, normalisePath,
  ENFORCE_PUBLIC_ORIGIN, PublicOriginRequired, isLoopbackHost, originResolver,
} from '../index.mjs';
import { resetOriginWarning } from '../src/origin.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TESTDATA = resolve(HERE, '../../testdata');
const VECTORS = JSON.parse(readFileSync(process.env.AIDR_VECTORS || resolve(TESTDATA, 'vectors.json'), 'utf8'));
const PATHS = JSON.parse(readFileSync(resolve(TESTDATA, 'path-normalisation.json'), 'utf8'));
const NOW = new Date(VECTORS.evaluate_at * 1000);
const SUITE = VECTORS.suites[0];
const ALLOW = SUITE.cases.find((c) => c.expect === 'allow' && !c.expected_audience && !c.min_assurance);

function registry(suite, { revoked = false, discovery = {} } = {}) {
  const calls = [];
  const fetchImpl = async (url) => {
    const target = new URL(url);
    calls.push(target.pathname + target.search);
    const json = (body) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    if (target.pathname === '/.well-known/aiaf-registry') {
      return json({ issuer: suite.issuer, jwks_uri: `${suite.issuer}/.well-known/jwks.json`,
        revocation_delta_endpoint: `${suite.issuer}/v1/revocations/delta`, ...discovery });
    }
    if (target.pathname === '/.well-known/jwks.json') return json(suite.jwks);
    if (target.pathname === '/v1/revocations/delta') {
      return json({ delta: suite.revocation[revoked ? 'delta_after_revocation' : 'delta_before_revocation'] });
    }
    return new Response('not found', { status: 404 });
  };
  return { fetch: fetchImpl, calls };
}

/** Drive the middleware the way Express does: (req, res, next). */
async function call(middleware, testCase, { path = null, headers = null } = {}) {
  const url = new URL(testCase?.url ?? 'https://shop.example/api/products');
  if (path) url.pathname = path;
  const req = { method: testCase?.method ?? 'GET', originalUrl: url.pathname + url.search,
    headers: { host: url.host, ...(headers ?? testCase?.headers ?? {}) } };
  const res = { statusCode: 200, headers: {}, body: null,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    end(body) { this.body = JSON.parse(body); } };
  let passed = false;
  middleware(req, res, () => { passed = true; });
  return { passed, req, res };
}

async function site(options = {}, registryOptions = {}) {
  const fake = registry(SUITE, registryOptions);
  const middleware = aidr({ issuer: SUITE.issuer, publicOrigin: 'https://shop.example', fetch: fake.fetch, clock: () => NOW,
    ...options });
  await middleware.ready;
  return { middleware, calls: fake.calls };
}

describe('aidr(): one line, three outcomes', () => {
  it('anonymous traffic passes, marked anonymous', async () => {
    const { middleware } = await site();
    const { passed, req } = await call(middleware, null);
    assert.equal(passed, true);
    assert.deepEqual(req.aidr, { status: 'anonymous' });
    assert.equal(req.agent, null);
    middleware.close();
  });

  it('a valid agent passes with its identity', async () => {
    const { middleware } = await site();
    const { passed, req } = await call(middleware, ALLOW);
    assert.equal(passed, true);
    assert.equal(req.aidr.status, 'verified');
    assert.equal(req.agent.aid, SUITE.aid);
    assert.equal(req.agent.organization, SUITE.organization);
    middleware.close();
  });

  it('a garbage credential is refused, never treated as anonymous', async () => {
    const { middleware } = await site();
    const { passed, res } = await call(middleware, null, { headers: { 'agent-credential': 'garbage' } });
    assert.equal(passed, false);
    assert.equal(res.statusCode, 401);
    middleware.close();
  });

  it('a replayed request is refused', async () => {
    const { middleware } = await site();
    assert.equal((await call(middleware, ALLOW)).passed, true);
    const replay = await call(middleware, ALLOW);
    assert.equal(replay.res.statusCode, 401);
    assert.equal(replay.res.body.error, 'aidr.verify.replay_detected');
    middleware.close();
  });

  it('a revoked agent is refused with 403', async () => {
    const { middleware } = await site({}, { revoked: true });
    const { res } = await call(middleware, ALLOW);
    assert.equal(res.statusCode, 403);
    assert.equal(res.body.error, 'aidr.verify.agent_revoked');
    middleware.close();
  });

  it('floors: AgAL, OAL and KAL each refuse with 403', async () => {
    for (const floor of ['minAgal', 'minOal', 'minKal']) {
      const { middleware } = await site({ [floor]: 3 });
      const { res } = await call(middleware, ALLOW);
      assert.equal(res.statusCode, 403, floor);
      middleware.close();
    }
  });
});

describe('every shared vector case through the middleware', () => {
  for (const suite of VECTORS.suites) {
    for (const testCase of suite.cases) {
      it(`${suite.algorithm}: ${testCase.name}`, async () => {
        const fake = registry(suite);
        // The site the case visits is the one its URL names (its own origin), or — for a case with an
        // explicit audience — a site at that audience.
        const middleware = aidr({ issuer: suite.issuer, fetch: fake.fetch, clock: () => NOW,
          minAgal: testCase.min_assurance ?? 0,
          publicOrigin: testCase.expected_audience ?? new URL(testCase.url).origin });
        await middleware.ready;
        // A case with an explicit audience is a site at that origin, verifying a request signed
        // for another: the signature then fails, which is still a refusal.
        const { passed, res } = await call(middleware, testCase);
        assert.equal(passed, testCase.expect === 'allow', `${res.statusCode} ${JSON.stringify(res.body)}`);
        if (testCase.expect === 'deny' && testCase.expect_code && !testCase.expected_audience) {
          assert.equal(res.body.error, testCase.expect_code);
        }
        middleware.close();
      });
    }
  }
});

describe('verified-only mode', () => {
  it('refuses anonymous traffic with 401 and points to the registry', async () => {
    const { middleware } = await site({ mode: 'verified-only' });
    const { passed, res } = await call(middleware, null);
    assert.equal(passed, false);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'aidr.edge.agent_required');
    assert.equal(res.headers.link, `<${SUITE.issuer}/.well-known/aiaf-registry>; rel="aiaf-registry"`);
    middleware.close();
  });

  it('scoped to paths, people keep the rest; an unnormalisable path is protected', async () => {
    const { middleware } = await site({ mode: 'verified-only', verifiedOnlyPaths: ['/api/.*'] });
    assert.equal((await call(middleware, null, { path: '/catalogue' })).passed, true);
    assert.equal((await call(middleware, null, { path: '/api/products' })).res.statusCode, 401);
    assert.equal((await call(middleware, null, { path: '/docs/%252e%252e/api/x' })).res.statusCode, 401);
    middleware.close();
  });

  it('bypassed paths are never verified', async () => {
    const { middleware } = await site({ mode: 'verified-only', bypass: ['/health'] });
    const { passed, req } = await call(middleware, null, { path: '/health', headers: { signature: 'x' } });
    assert.equal(passed, true);
    assert.deepEqual(req.aidr, { status: 'bypassed' });
    middleware.close();
  });

  it('a mistyped mode is an error at start-up, never an open site', () => {
    assert.throws(() => aidr({ issuer: SUITE.issuer, mode: 'verified_only' }), /mode/);
    assert.throws(() => aidr({ issuer: SUITE.issuer, verifiedOnlyPaths: ['/api/.*'] }), /verified-only/);
  });
});

describe('trust sync', () => {
  it('an agent arriving while the first trust load is in flight waits for it, then is verified', async () => {
    const fake = registry(SUITE);
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const slowFetch = async (url) => { await gate; return fake.fetch(url); };
    const middleware = aidr({ issuer: SUITE.issuer, publicOrigin: 'https://shop.example', fetch: slowFetch, clock: () => NOW });
    const url = new URL(ALLOW.url);
    const req = { method: ALLOW.method, originalUrl: url.pathname, headers: { host: url.host, ...ALLOW.headers } };
    const res = { statusCode: 200, setHeader() {}, end(body) { this.body = body; } };
    const passed = new Promise((resolve) => middleware(req, res, () => resolve(true)));
    release();
    assert.equal(await passed, true);
    assert.equal(req.aidr.status, 'verified');
    middleware.close();
  });

  it('before trust is loaded, agents get 503 and anonymous traffic still flows', async () => {
    const down = async () => new Response('', { status: 502 });
    const middleware = aidr({ issuer: SUITE.issuer, publicOrigin: 'https://shop.example', fetch: down, clock: () => NOW });
    assert.equal(await middleware.ready, false);
    assert.equal((await call(middleware, null)).passed, true);
    const { res } = await call(middleware, ALLOW);
    assert.equal(res.statusCode, 503);
    assert.equal(res.headers['retry-after'], '15');
    middleware.close();
  });

  it('refuses a discovery document that points off the issuer origin', async () => {
    const { middleware } = await site({}, { discovery: { jwks_uri: 'https://evil.example/jwks.json' } });
    assert.equal(middleware.health().ready, false);
    assert.match(middleware.health().lastError, /off the issuer's origin/);
    middleware.close();
  });

  it('loads keys and the complete revocation set from the discovered endpoints', async () => {
    const { middleware, calls } = await site();
    assert.deepEqual(calls, ['/.well-known/aiaf-registry', '/.well-known/jwks.json',
      '/v1/revocations/delta?since=0']);
    assert.equal(middleware.health().ready, true);
    middleware.close();
  });
});

describe('the older expressMiddleware', () => {
  it('optional: a garbage credential is refused, not passed as anonymous', () => {
    const trust = buildTrustStore(SUITE.jwks, { deltaToken: SUITE.revocation.delta_before_revocation,
      expectedIssuer: SUITE.issuer });
    const middleware = expressMiddleware(new AgentVerifier(trust), { optional: true, publicOrigin: 'https://shop.example' });
    const res = { statusCode: 200, setHeader() {}, end() {} };
    let passed = false;
    middleware({ method: 'GET', url: '/', headers: { host: 'shop.example', 'agent-credential': 'x' } },
      res, () => { passed = true; });
    assert.equal(passed, false);
    assert.equal(res.statusCode, 401);
  });
});

describe('path normalisation — the shared table', () => {
  for (const { raw, normalised } of PATHS.cases) {
    it(`${JSON.stringify(raw)} → ${JSON.stringify(normalised)}`, () => {
      assert.equal(normalisePath(raw), normalised);
    });
  }
});

// ---- whose origin: the Host-header replay (found 2026-10-10; src/origin.mjs) ----------------------

describe('aidr(): a request is judged as this site, not as the Host the client sent', () => {
  // Signed for https://other.example/api/products, then sent to this site claiming that Host.
  const crossHost = SUITE.cases.find((c) => c.name === 'replay from another host is refused');
  const asOther = { ...crossHost, url: 'https://other.example/api/products' };

  it('with publicOrigin, a request signed for another host is refused even with that Host', async () => {
    const { middleware } = await site({ publicOrigin: 'https://shop.example' });
    const { passed, res } = await call(middleware, asOther);
    assert.equal(passed, false);
    assert.equal(res.statusCode, 401);
    middleware.close();
  });

  it('with publicOrigin, this site\'s own agents still pass, whatever Host the proxy forwards', async () => {
    const { middleware } = await site({ publicOrigin: 'https://shop.example' });
    const { passed } = await call(middleware, ALLOW, { headers: { ...ALLOW.headers, host: 'internal:8080' } });
    assert.equal(passed, true);
    middleware.close();
  });

  it('several origins: the one the Host names, else the first', async () => {
    const resolve = originResolver({ publicOrigin: ['https://shop.example', 'https://www.shop.example'], env: {} });
    assert.equal(resolve('www.shop.example'), 'https://www.shop.example');
    assert.equal(resolve('other.example'), 'https://shop.example');
    assert.equal(originResolver({ publicOrigin: null, env: { AIDR_PUBLIC_ORIGIN: 'https://a.example,https://b.example' } })('b.example'),
      'https://b.example');
  });

  it('without an origin, localhost is judged by its Host and nothing is said', () => {
    const warnings = [];
    const resolve = originResolver({ env: {}, warn: (m) => warnings.push(m), enforce: true });
    for (const host of ['localhost:3000', '127.0.0.1:8080', '[::1]:3000', 'app.localhost']) {
      assert.equal(new URL(resolve(host)).host, new URL(`https://${host}`).host);
    }
    assert.deepEqual(warnings, []);
    assert.equal(isLoopbackHost('127.evil.example'), false);
    assert.equal(isLoopbackHost('localhost.evil.example'), false);
  });

  it('0.1.x: without an origin, another host is used as before — with one warning per process', () => {
    resetOriginWarning();
    const warnings = [];
    const resolve = originResolver({ env: {}, warn: (m) => warnings.push(m), enforce: false });
    assert.equal(resolve('other.example'), 'https://other.example');
    resolve('shop.example');
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /publicOrigin is not set/);
  });

  it('from 0.2.0: without an origin, an agent at another host is refused — people are not', async () => {
    const resolve = originResolver({ env: {}, enforce: true });
    assert.throws(() => resolve('shop.example'), PublicOriginRequired);
    assert.equal(ENFORCE_PUBLIC_ORIGIN, true, 'enforced from 0.2.0');
  });
});
