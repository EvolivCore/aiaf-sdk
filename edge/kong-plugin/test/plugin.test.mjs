/**
 * The Kong plugin against the shared AIAF vectors, through a fake Kong PDK that records what the
 * plugin asked Kong to do (exit with a status, set or clear upstream headers). A fake registry
 * serves the vectors' real keys and signed revocation feeds; the SDK is this repository's copy.
 *
 *   node --test test/
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { after, beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const plugin = require('../aidr.js');

const HERE = dirname(fileURLToPath(import.meta.url));
const SDK = resolve(HERE, '../../../sdk/node/index.mjs');
const VECTORS = JSON.parse(readFileSync(resolve(HERE, '../../../sdk/testdata/vectors.json'), 'utf8'));
const NOW = new Date(VECTORS.evaluate_at * 1000);
const SUITE = VECTORS.suites[0];
const VALID = SUITE.cases.find((c) => c.name === 'valid request verifies');

function registry(suite, { revoked = false } = {}) {
  return async (url) => {
    const target = new URL(url);
    const json = (body) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    if (target.pathname === '/.well-known/aiaf-registry') {
      return json({ issuer: suite.issuer, jwks_uri: `${suite.issuer}/.well-known/jwks.json`,
        revocation_delta_endpoint: `${suite.issuer}/v1/revocations/delta` });
    }
    if (target.pathname === '/.well-known/jwks.json') return json(suite.jwks);
    if (target.pathname === '/v1/revocations/delta') {
      return json({ delta: suite.revocation[revoked ? 'delta_after_revocation' : 'delta_before_revocation'] });
    }
    return new Response('not found', { status: 404 });
  };
}

function useRegistry(suite = SUITE, options = {}) {
  plugin._hooks({ loadSdk: () => import(`file://${SDK.replace(/\\/g, '/')}`), fetch: registry(suite, options),
    clock: () => NOW });
}

/** A Kong PDK with the calls the plugin makes; records the outcome. */
function fakeKong(testCase, extraHeaders = {}) {
  const url = new URL(testCase?.url ?? 'https://shop.example/api/products');
  const record = { exit: null, upstream: {}, cleared: [] };
  const kong = {
    request: {
      getHeaders: async () => ({ host: url.host, ...(testCase?.headers ?? {}), ...extraHeaders }),
      getMethod: async () => testCase?.method ?? 'GET',
      getRawPath: async () => url.pathname,
      getRawQuery: async () => url.search.slice(1),
    },
    response: { exit: async (status, body, headers) => { record.exit = { status, body, headers }; } },
    service: { request: {
      setHeader: async (name, value) => { record.upstream[name] = value; },
      clearHeader: async (name) => { record.cleared.push(name); },
    } },
    log: { err: async () => {} },
  };
  return { kong, record };
}

async function run(config, testCase, extraHeaders) {
  const { kong, record } = fakeKong(testCase, extraHeaders);
  await new plugin.Plugin({ public_origin: 'https://shop.example', issuer: SUITE.issuer, ...config }).access(kong);
  return record;
}

beforeEach(() => useRegistry());
after(() => plugin._hooks({}));

describe('every shared vector case through the plugin', () => {
  for (const suite of VECTORS.suites) {
    for (const testCase of suite.cases) {
      it(`${suite.algorithm}: ${testCase.name}`, async () => {
        useRegistry(suite);
        const record = await run({
          issuer: suite.issuer, min_agal: testCase.min_assurance ?? 0,
          public_origin: testCase.expected_audience ?? new URL(testCase.url).origin,
        }, testCase);
        if (testCase.expect === 'allow') {
          assert.equal(record.exit, null, JSON.stringify(record.exit));
          assert.equal(record.upstream['X-AIDR-Status'], 'verified');
          assert.equal(record.upstream['X-AIDR-Agent'], suite.aid);
          assert.equal(record.upstream['X-AIDR-Organization'], suite.organization);
        } else {
          assert.ok(record.exit, 'a refused request must not reach the service');
          assert.ok([401, 403].includes(record.exit.status));
          if (testCase.expect_code && !testCase.expected_audience) assert.equal(record.exit.body.error, testCase.expect_code);
        }
      });
    }
  }
});

describe('people, policy, replays and spoofed headers', () => {
  it('a person is proxied, marked anonymous', async () => {
    const record = await run({}, null);
    assert.equal(record.exit, null);
    assert.equal(record.upstream['X-AIDR-Status'], 'anonymous');
  });

  it('X-AIDR headers a client sends are removed before the service sees them', async () => {
    const record = await run({}, null, { 'x-aidr-agent': 'aid:v1:famous-ai-lab:forged', 'X-AIDR-Status': 'verified' });
    assert.deepEqual(record.cleared.sort(), ['x-aidr-agent', 'x-aidr-status']);
    assert.equal(record.upstream['X-AIDR-Status'], 'anonymous');
    assert.equal(record.upstream['X-AIDR-Agent'], undefined);
  });

  it('verified-only paths refuse people with 401 and a link to the registry', async () => {
    const record = await run({ mode: 'verified-only', verified_only_paths: ['/api/.*'] }, null);
    assert.equal(record.exit.status, 401);
    assert.equal(record.exit.body.error, 'aidr.edge.agent_required');
    assert.match(record.exit.headers.Link, /aiaf-registry/);
    const page = await run({ mode: 'verified-only', verified_only_paths: ['/api/.*'] }, { url: 'https://shop.example/about', headers: {} });
    assert.equal(page.exit, null);
  });

  it('a replayed request is refused', async () => {
    assert.equal((await run({}, VALID)).exit, null);
    const again = await run({}, VALID);
    assert.equal(again.exit.status, 401);
    assert.equal(again.exit.body.error, 'aidr.verify.replay_detected');
  });

  it('a revoked agent is refused with 403', async () => {
    useRegistry(SUITE, { revoked: true });
    const record = await run({}, VALID);
    assert.deepEqual([record.exit.status, record.exit.body.error], [403, 'aidr.verify.agent_revoked']);
  });

  it('without a public origin, agents are refused (503) and people still pass', async () => {
    const agent = await run({ public_origin: '' }, VALID);
    assert.equal(agent.exit.status, 503);
    const person = await run({ public_origin: '' }, null);
    assert.equal(person.exit, null);
  });
});

describe('the plugin as Kong loads it', () => {
  it('exports a schema, a version and a priority above rate limiting', () => {
    assert.equal(typeof plugin.Plugin, 'function');
    assert.ok(plugin.Schema.some((field) => field.public_origin?.required));
    assert.ok(plugin.Priority > 910);
  });
});
