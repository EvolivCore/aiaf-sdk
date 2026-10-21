/**
 * The authorizer against the shared AIAF vectors, as API Gateway would call it: REST API events
 * (IAM policy answers) and HTTP API events (payload 2.0, simple answers). A fake registry serves
 * the vectors' real keys and signed revocation feeds; the SDK is this repository's own copy.
 *
 *   node --test test/
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { createHandler, dynamoNonceClaimer } from '../index.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SDK = resolve(HERE, '../../../sdk/node/index.mjs');
const VECTORS = JSON.parse(readFileSync(resolve(HERE, '../../../sdk/testdata/vectors.json'), 'utf8'));
const NOW = new Date(VECTORS.evaluate_at * 1000);
const SUITE = VECTORS.suites[0];
const VALID = SUITE.cases.find((c) => c.name === 'valid request verifies');
const loadSdk = () => import(`file://${SDK.replace(/\\/g, '/')}`);

function registry(suite, { revoked = false } = {}) {
  const calls = [];
  const fetchImpl = async (url) => {
    const target = new URL(url);
    calls.push(target.pathname);
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
  return { fetch: fetchImpl, calls };
}

function authorizer(suite = SUITE, env = {}, options = {}) {
  const fake = registry(suite, options.registry);
  const handler = createHandler({
    env: { AIDR_ISSUER: suite.issuer, AIDR_PUBLIC_ORIGIN: 'https://shop.example', ...env },
    loadSdk, fetch: fake.fetch, clock: () => NOW, claimNonce: options.claimNonce,
  });
  return { handler, calls: fake.calls };
}

/** A REST API REQUEST-authorizer event, as API Gateway sends it on a custom domain. */
function restEvent(testCase) {
  const url = new URL(testCase?.url ?? 'https://shop.example/api/products');
  const headers = { Host: url.host, ...(testCase?.headers ?? {}) };
  return {
    type: 'REQUEST', methodArn: 'arn:aws:execute-api:eu-west-1:123456789012:abc123/prod/GET/api/products',
    resource: url.pathname, path: url.pathname, httpMethod: testCase?.method ?? 'GET', headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, [v]])),
    queryStringParameters: null, multiValueQueryStringParameters: null,
    requestContext: { path: url.pathname, httpMethod: testCase?.method ?? 'GET', stage: 'prod' },
  };
}

/** An HTTP API (payload 2.0) event: headers lower-cased, the raw path. */
function httpEvent(testCase) {
  const url = new URL(testCase?.url ?? 'https://shop.example/api/products');
  const headers = Object.fromEntries(Object.entries({ host: url.host, ...(testCase?.headers ?? {}) })
    .map(([k, v]) => [k.toLowerCase(), v]));
  return {
    version: '2.0', type: 'REQUEST', routeArn: 'arn:aws:execute-api:eu-west-1:123456789012:abc123/$default/GET/api/products',
    rawPath: url.pathname, rawQueryString: url.search.slice(1), headers,
    requestContext: { domainName: url.host, http: { method: testCase?.method ?? 'GET', path: url.pathname } },
  };
}

/** What API Gateway would do with an answer: allow, or the status it returns. */
async function outcome(handler, event) {
  try {
    const answer = await handler(event);
    if (event.version === '2.0') return { allowed: answer.isAuthorized, context: answer.context };
    return { allowed: answer.policyDocument.Statement[0].Effect === 'Allow', context: answer.context,
      resource: answer.policyDocument.Statement[0].Resource };
  } catch (error) {
    assert.equal(error.message, 'Unauthorized');
    return { allowed: false, status: 401 };
  }
}

for (const [format, toEvent] of [['REST API', restEvent], ['HTTP API', httpEvent]]) {
  describe(`${format}: every shared vector case`, () => {
    for (const suite of VECTORS.suites) {
      for (const testCase of suite.cases) {
        it(`${suite.algorithm}: ${testCase.name}`, async () => {
          const { handler } = authorizer(suite, {
            AIDR_MIN_AGAL: String(testCase.min_assurance ?? 0),
            AIDR_PUBLIC_ORIGIN: testCase.expected_audience ?? new URL(testCase.url).origin,
          });
          const result = await outcome(handler, toEvent(testCase));
          assert.equal(result.allowed, testCase.expect === 'allow', JSON.stringify(result));
          if (testCase.expect === 'allow') {
            assert.equal(result.context.aidr_status, 'verified');
            assert.equal(result.context.aidr_aid, suite.aid);
            assert.equal(result.context.aidr_org, suite.organization);
          } else if (testCase.expect_code && !testCase.expected_audience && result.context) {
            assert.equal(result.context.aidr_error, testCase.expect_code);
          }
          await handler.close();
        });
      }
    }
  });

  describe(`${format}: people, policy and replays`, () => {
    it('a person (no agent headers) is allowed, marked anonymous', async () => {
      const { handler } = authorizer();
      const result = await outcome(handler, toEvent(null));
      assert.deepEqual([result.allowed, result.context.aidr_status], [true, 'anonymous']);
      await handler.close();
    });

    it('verified-only paths refuse people, and only those paths', async () => {
      const { handler } = authorizer(SUITE, { AIDR_MODE: 'verified-only', AIDR_VERIFIED_ONLY_PATHS: '["/api/.*"]' });
      assert.equal((await outcome(handler, toEvent(null))).allowed, false);
      const page = toEvent({ url: 'https://shop.example/about', headers: {} });
      assert.equal((await outcome(handler, page)).allowed, true);
      await handler.close();
    });

    it('a replayed request is refused by the same instance', async () => {
      const { handler } = authorizer();
      assert.equal((await outcome(handler, toEvent(VALID))).allowed, true);
      const again = await outcome(handler, toEvent(VALID));
      assert.equal(again.allowed, false);
      await handler.close();
    });

    it('a revoked agent is refused (403, not 401)', async () => {
      const { handler } = authorizer(SUITE, {}, { registry: { revoked: true } });
      const result = await outcome(handler, toEvent(VALID));
      assert.equal(result.allowed, false);
      assert.equal(result.context.aidr_error, 'aidr.verify.agent_revoked');
      await handler.close();
    });
  });
}

describe('replay protection across Lambda instances (DynamoDB)', () => {
  /** A table that behaves like DynamoDB's conditional put. */
  function fakeTable() {
    const items = new Set();
    class PutItemCommand { constructor(input) { this.input = input; } }
    const client = {
      async send(command) {
        const key = command.input.Item.pk.S;
        assert.equal(command.input.ConditionExpression, 'attribute_not_exists(pk)');
        if (items.has(key)) throw Object.assign(new Error('exists'), { name: 'ConditionalCheckFailedException' });
        items.add(key);
      },
    };
    return { items, claimer: dynamoNonceClaimer('aidr-nonces', { client, loadSdk: async () => ({ PutItemCommand }) }) };
  }

  it('the same request on a second instance is refused', async () => {
    const table = fakeTable();
    const first = authorizer(SUITE, {}, { claimNonce: table.claimer });
    const second = authorizer(SUITE, {}, { claimNonce: table.claimer });
    assert.equal((await outcome(first.handler, restEvent(VALID))).allowed, true);
    const replay = await outcome(second.handler, restEvent(VALID));
    assert.equal(replay.allowed, false);
    assert.equal(replay.context.aidr_error, 'aidr.verify.replay_detected');
    assert.equal(table.items.size, 1);
    await first.handler.close();
    await second.handler.close();
  });

  it('a table that cannot answer refuses, never allows', async () => {
    const broken = async () => { throw new Error('throttled'); };
    const { handler } = authorizer(SUITE, {}, { claimNonce: broken });
    const result = await outcome(handler, restEvent(VALID));
    assert.deepEqual([result.allowed, result.context.aidr_error], [false, 'aidr.registry.unavailable']);
    await handler.close();
  });
});

describe('configuration', () => {
  it('refuses to start without the public origin', async () => {
    const handler = createHandler({ env: { AIDR_ISSUER: SUITE.issuer }, loadSdk, fetch: registry(SUITE).fetch });
    await assert.rejects(handler(restEvent(null)), /AIDR_PUBLIC_ORIGIN is required/);
  });
});
