/**
 * The agent end to end against a fake registry that checks what the real one checks: the
 * enrollment token, the proof of possession (aiaf-pop-v1) and, on every credential request, an
 * RFC 9421 signature with the agent's own key — verified by the separate Node verifier (sdk/node).
 */

import assert from 'node:assert/strict';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { verifyRequestSignature } from '../../node/src/crypto.mjs';
import {
  Agent, AgentIdentity, FileKeyStore, NotAllowed, RegistryError, createSignedFetch, enroll, generateKey, tokenId,
} from '../index.mjs';
import { aidrHttpTools, OriginNotAllowed } from '../src/ai.mjs';

const REGISTRY = 'https://registry.test';
const TOKEN = 'aidr_et_etk_01TESTTOKEN_secretpart';

function fakeRegistry({ audiences = [], credentialFor = (audience) => `cred-for-${audience ?? 'any'}` } = {}) {
  const state = { agents: new Map(), issued: [], calls: [] };
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const fetchImpl = async (url, init = {}) => {
    const target = new URL(url);
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    const body = init.body ? JSON.parse(init.body) : {};
    state.calls.push(`${init.method ?? 'GET'} ${target.pathname}`);
    if (target.pathname === '/v1/enroll') {
      if (headers.authorization !== `AIDR-Enrollment ${TOKEN}`) {
        return json(401, { error: { code: 'aidr.enroll.token_invalid', message: 'not a valid token' } });
      }
      assert.equal(headers['aidr-pop-context'], 'aiaf-pop-v1');
      const aid = `aid:v1:acme:01AGENT${state.agents.size}:x`;
      state.agents.set(aid, { jwk: body.public_key_jwk, proven: false, challenge: 'aiaf-pop-v1:challenge-123' });
      return json(201, { agent: { aid }, challenge: { challenge_id: 'ch_1', sign_this: 'aiaf-pop-v1:challenge-123' },
        allowed_audiences: body.audiences ?? audiences });
    }
    const proof = target.pathname.match(/^\/v1\/enroll\/(.+)\/proof$/);
    if (proof) {
      const agent = state.agents.get(proof[1]);
      const key = createPublicKey({ key: agent.jwk, format: 'jwk' });
      const signature = Buffer.from(body.signature, 'base64url');
      const ok = agent.jwk.kty === 'OKP' ? cryptoVerify(null, Buffer.from(agent.challenge), key, signature)
        : cryptoVerify('sha256', Buffer.from(agent.challenge), { key, dsaEncoding: 'ieee-p1363' }, signature);
      if (!ok) return json(400, { error: { code: 'aidr.crypto.signature_invalid', message: 'proof failed' } });
      agent.proven = true;
      return json(200, { agent: { aid: proof[1], status: 'active' } });
    }
    if (target.pathname === '/v1/credentials') {
      const agent = state.agents.get(body.aid);
      verifyRequestSignature({ method: 'POST', url, headers, resolvePublicKey: () => agent.jwk, expectedKeyid: body.aid });
      state.issued.push(body.audience ?? null);
      return json(200, { credential: credentialFor(body.audience), renew_after: 600, expires_in: 900 });
    }
    return json(404, { error: { code: 'aidr.not_found', message: 'no such endpoint' } });
  };
  return { fetch: fetchImpl, state };
}

async function enrolled(options = {}) {
  const registry = fakeRegistry(options);
  const identity = await enroll(TOKEN, { name: 'bot', registry: REGISTRY, fetch: registry.fetch, audiences: options.request ?? null });
  return { registry, identity };
}

describe('enrollment', () => {
  it('generates the key here, registers it with the token and proves it', async () => {
    const { registry, identity } = await enrolled({ request: ['https://shop.example'] });
    assert.match(identity.aid, /^aid:v1:acme:/);
    assert.deepEqual(identity.audiences, ['https://shop.example']);
    assert.equal(registry.state.agents.get(identity.aid).proven, true);
    assert.deepEqual(registry.state.calls, ['POST /v1/enroll', `POST /v1/enroll/${identity.aid}/proof`]);
    // Only the public half went to the registry.
    assert.equal('d' in registry.state.agents.get(identity.aid).jwk, false);
  });

  it('an ES256 key enrolls too', async () => {
    const registry = fakeRegistry();
    const identity = await enroll(TOKEN, { name: 'bot', registry: REGISTRY, fetch: registry.fetch, privateKey: generateKey('ES256') });
    assert.equal(registry.state.agents.get(identity.aid).proven, true);
  });

  it('a refusal carries the registry\'s code; a non-token is refused before any request', async () => {
    const registry = fakeRegistry();
    await assert.rejects(enroll('aidr_et_etk_01OTHER_wrong', { name: 'bot', registry: REGISTRY, fetch: registry.fetch }),
      (error) => error instanceof RegistryError && error.code === 'aidr.enroll.token_invalid' && error.status === 401);
    await assert.rejects(enroll('not-a-token', { name: 'bot', registry: REGISTRY, fetch: registry.fetch }), /enrollment token/);
    assert.equal(registry.state.calls.length, 1);
  });

  it('the token\'s id is shown, never its secret', () => {
    assert.equal(tokenId(TOKEN), 'etk_01TESTTOKEN');
    assert.equal(tokenId('nope'), '(not an enrollment token)');
  });
});

describe('Agent.loadOrEnroll', () => {
  it('enrolls on the first run with the token, then loads the saved identity without it', async () => {
    const registry = fakeRegistry();
    const store = new FileKeyStore(mkdtempSync(join(tmpdir(), 'aidr-agent-')));
    const first = await Agent.loadOrEnroll('bot', { keyStore: store, registryFetch: registry.fetch,
      env: { AIDR_ENROLLMENT_TOKEN: TOKEN, AIDR_REGISTRY_URL: REGISTRY } });
    const again = await Agent.loadOrEnroll('bot', { keyStore: store, registryFetch: registry.fetch, env: {} });
    assert.equal(again.aid, first.aid);
    assert.equal(registry.state.agents.size, 1);
  });

  it('without a saved identity or a token, it says what to do', async () => {
    const store = new FileKeyStore(mkdtempSync(join(tmpdir(), 'aidr-agent-')));
    await assert.rejects(Agent.loadOrEnroll('bot', { keyStore: store, env: {} }), /AIDR_ENROLLMENT_TOKEN/);
  });
});

describe('signing decisions', () => {
  it('signs for the allowed audiences only; elsewhere unsigned, or refused', async () => {
    const { registry, identity } = await enrolled({ request: ['https://shop.example'] });
    const agent = new Agent(identity, { registryFetch: registry.fetch });
    assert.equal(agent.shouldSign('https://shop.example/x'), true);
    assert.equal(agent.shouldSign('https://other.example/x'), false);
    assert.deepEqual(await agent.signHeaders('GET', 'https://other.example/x'), {});
    const strict = new Agent(identity, { registryFetch: registry.fetch, onUnlisted: 'refuse' });
    await assert.rejects(strict.signHeaders('GET', 'https://other.example/x'), NotAllowed);
    assert.throws(() => new Agent(identity, { signFor: ['https://bank.example'] }), NotAllowed);
  });

  it('never signs plain http, except to localhost', async () => {
    const { identity } = await enrolled();
    const agent = new Agent(identity);
    assert.equal(agent.shouldSign('http://shop.example/'), false);
    assert.equal(agent.shouldSign('http://localhost:3000/'), true);
    assert.equal(agent.shouldSign('http://127.0.0.1:8080/'), true);
    assert.equal(agent.shouldSign('https://any.example/'), true);   // unrestricted agent
  });

  it('credentials: one per audience for a bound agent, one in all for an unrestricted one, cached', async () => {
    const bound = await enrolled({ request: ['https://a.example', 'https://b.example'] });
    const agent = new Agent(bound.identity, { registryFetch: bound.registry.fetch });
    await agent.signHeaders('GET', 'https://a.example/1');
    await agent.signHeaders('GET', 'https://a.example/2');
    await agent.signHeaders('GET', 'https://b.example/1');
    assert.deepEqual(bound.registry.state.issued, ['https://a.example', 'https://b.example']);

    const open = await enrolled();
    const free = new Agent(open.identity, { registryFetch: open.registry.fetch });
    await Promise.all([free.signHeaders('GET', 'https://x.example/'), free.signHeaders('GET', 'https://y.example/')]);
    assert.deepEqual(open.registry.state.issued, [null]);
  });
});

describe('createSignedFetch', () => {
  it('adds the credential and a signature the verifier accepts, for the request as sent', async () => {
    const { registry, identity } = await enrolled({ request: ['https://shop.example'] });
    const agent = new Agent(identity, { registryFetch: registry.fetch });
    let seen = null;
    const signedFetch = createSignedFetch(agent, { fetch: async (request) => { seen = request; return new Response('ok'); } });
    await signedFetch('https://shop.example/api/products?page=2', { method: 'POST', body: '{"q":1}',
      headers: { 'content-type': 'application/json' } });
    const headers = Object.fromEntries(seen.headers.entries());
    assert.equal(headers['agent-credential'], 'cred-for-https://shop.example');
    assert.equal(seen.redirect, 'manual');
    assert.equal(await seen.text(), '{"q":1}');
    verifyRequestSignature({ method: 'POST', url: seen.url, headers, resolvePublicKey: () => identity.publicJwk() });
  });

  it('leaves requests to other sites untouched', async () => {
    const { registry, identity } = await enrolled({ request: ['https://shop.example'] });
    let seen = null;
    const signedFetch = createSignedFetch(new Agent(identity, { registryFetch: registry.fetch }),
      { fetch: async (request) => { seen = request; return new Response('ok'); } });
    await signedFetch('https://other.example/');
    assert.equal(seen.headers.get('signature'), null);
    assert.equal(seen.headers.get('agent-credential'), null);
  });
});

describe('Vercel AI SDK tools', () => {
  // The AI SDK's `tool` and `jsonSchema` are identity-like helpers; stand-ins keep this suite offline.
  const ai = { tool: (definition) => definition, jsonSchema: (schema) => ({ jsonSchema: schema }) };

  it('httpGet and httpPost reach only the allowed sites, signed, with responses cut short', async () => {
    const { registry, identity } = await enrolled({ request: ['https://shop.example'] });
    const agent = new Agent(identity, { registryFetch: registry.fetch });
    const requests = [];
    const tools = await aidrHttpTools(agent, { ai, maxChars: 10, fetch: async (request) => {
      requests.push(request);
      return new Response('x'.repeat(50), { status: 200 });
    } });
    assert.deepEqual(Object.keys(tools), ['httpGet', 'httpPost']);
    assert.match(tools.httpGet.description, /https:\/\/shop\.example/);
    assert.ok(tools.httpGet.inputSchema && tools.httpGet.parameters);

    const out = await tools.httpGet.execute({ url: 'https://shop.example/p' });
    assert.match(out, /^HTTP 200\nxxxxxxxxxx\n…\[truncated, 50 characters in all\]$/);
    assert.ok(requests[0].headers.get('signature'));
    await tools.httpPost.execute({ url: 'https://shop.example/orders', body: { id: 7 } });
    assert.equal(await requests[1].text(), '{"id":7}');

    await assert.rejects(tools.httpGet.execute({ url: 'https://evil.example/' }), OriginNotAllowed);
    await assert.rejects(tools.httpGet.execute({ url: 'http://169.254.169.254/latest' }), OriginNotAllowed);
    assert.equal(requests.length, 2);
  });

  it('an unrestricted agent must be told which sites its tools may reach', async () => {
    const { identity } = await enrolled();
    await assert.rejects(aidrHttpTools(new Agent(identity), { ai }), /name the origins/);
    const tools = await aidrHttpTools(new Agent(identity), { ai, origins: ['https://a.example'], methods: ['GET'] });
    assert.deepEqual(Object.keys(tools), ['httpGet']);
  });
});

describe('the identity is never printed by accident', () => {
  it('the private key is not an enumerable property', async () => {
    const { identity } = await enrolled();
    assert.equal(JSON.stringify(identity).includes('"d"'), false);
    assert.equal(Object.keys(identity).includes('privateKey'), false);
    assert.ok(AgentIdentity.fromPortable(identity.toPortable()).privateKey);
  });
});
