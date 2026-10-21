/**
 * Web Bot Auth (src/webbotauth.mjs), pinned to published values. The cross-implementation proof is
 * the Web Bot Auth suite of sdk/testdata/vectors.json, which this SDK signs in CI (--signer
 * node-agent) and every AIDR verifier replays.
 */

import assert from 'node:assert/strict';
import { createPrivateKey, verify } from 'node:crypto';
import { describe, it } from 'node:test';

import { Agent, AgentIdentity, generateKey, webBotAuth } from '../index.mjs';

// RFC 9421 appendix B.1.4, test-key-ed25519: the key of the Web Bot Auth drafts' test vector.
const RFC9421_ED25519 = createPrivateKey(
  '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n');
const DRAFT_KEYID = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';
const URL_ = 'https://shop.example/api/products';

describe('Web Bot Auth', () => {
  it('thumbprints match RFC 8037 A.3 and the draft test vector', () => {
    assert.equal(webBotAuth.jwkThumbprint({ crv: 'Ed25519', kty: 'OKP', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }),
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
    const x = RFC9421_ED25519.export({ format: 'jwk' }).x;
    assert.equal(webBotAuth.jwkThumbprint({ crv: 'Ed25519', kty: 'OKP', x }), DRAFT_KEYID);
  });

  it('an agent in Web Bot Auth mode signs once, in the shape Cloudflare verifies', async () => {
    const identity = new AgentIdentity({ aid: 'aid:v1:acme:01TEST:abcd', name: 't', registry: 'https://r.example',
      privateKey: RFC9421_ED25519 });
    const agent = new Agent(identity, { webBotAuth: 'https://agents.example.com/' });
    agent.credentials = { get: async () => 'the-credential' };
    const headers = await agent.signHeaders('GET', URL_);
    assert.equal(headers['Signature-Agent'], '"https://agents.example.com"');
    assert.equal(headers['Agent-Credential'], 'the-credential');
    const input = headers['Signature-Input'];
    assert.match(input, /^wba=\("@authority" "@method" "@path" "signature-agent"\);created=\d+;expires=\d+;keyid="[^"]+";alg="ed25519";nonce="[^"]+";tag="web-bot-auth"$/);
    assert.ok(input.includes(`keyid="${DRAFT_KEYID}"`));
    assert.ok(!headers.Signature.includes(','), 'one signature, not two');
  });

  it('the signed directory verifies with the key, over the request authority', () => {
    const { headers, body } = webBotAuth.signedDirectory(RFC9421_ED25519, 'Agents.Example.com', { created: new Date(1790000000000) });
    assert.equal(headers['Content-Type'], 'application/http-message-signatures-directory+json');
    const params = headers['Signature-Input'].replace(/^sig1=/, '');
    const base = `"@authority";req: agents.example.com\n"@signature-params": ${params}`;
    const signature = Buffer.from(headers.Signature.replace(/^sig1=:/, '').replace(/:$/, ''), 'base64');
    assert.ok(verify(null, Buffer.from(base), RFC9421_ED25519, signature));
    assert.equal(JSON.parse(body).keys[0].kid, DRAFT_KEYID);
  });

  it('Ed25519 and https only', () => {
    assert.throws(() => webBotAuth.signRequest({ method: 'GET', url: URL_, privateKey: generateKey('ES256'),
      signatureAgent: 'https://a.example' }), /Ed25519/);
    assert.throws(() => webBotAuth.signRequest({ method: 'GET', url: URL_, privateKey: RFC9421_ED25519,
      signatureAgent: 'http://a.example' }), /https/);
  });
});
