/**
 * One identity, two languages: the Python SDK's identity file and signatures, read and reproduced
 * here (sdk/testdata/agent-identity.json, made by scripts/generate_agent_identity_fixture.py).
 * Signatures are also checked by the separate Node verifier (sdk/node), not by this package.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { verifyRequestSignature } from '../../node/src/crypto.mjs';
import {
  AgentIdentity, EnvKeyStore, FileKeyStore, IdentityError, generateKey, normalizeOrigin, publicJwk, signRequest,
} from '../index.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(readFileSync(resolve(HERE, '../../testdata/agent-identity.json'), 'utf8'));
const REQ = FIXTURE.request;
const CREATED = new Date(REQ.created * 1000);

function verify(headers, jwk, url = REQ.url, method = REQ.method) {
  return verifyRequestSignature({ method, url, headers, resolvePublicKey: () => jwk, now: CREATED });
}

describe('an identity the Python SDK wrote', () => {
  for (const c of FIXTURE.cases) {
    it(`${c.algorithm}: loads from the file document and from the one-line form`, () => {
      for (const identity of [AgentIdentity.fromDocument(c.document), AgentIdentity.fromPortable(c.portable)]) {
        assert.equal(identity.aid, c.document.aid);
        assert.deepEqual(identity.audiences, ['https://shop.example']);
        assert.deepEqual(identity.publicJwk(), c.public_jwk);
      }
    });

    it(`${c.algorithm}: written back, it is the same document`, () => {
      assert.deepEqual(AgentIdentity.fromDocument(c.document).toDocument(), c.document);
    });

    it(`${c.algorithm}: the Python signature verifies, and so does ours`, () => {
      const identity = AgentIdentity.fromDocument(c.document);
      verify(c.headers, c.public_jwk);
      const ours = signRequest({ method: REQ.method, url: REQ.url, privateKey: identity.privateKey, keyid: identity.aid,
        created: CREATED, nonce: REQ.nonce });
      assert.equal(ours['Signature-Input'], c.headers['Signature-Input']);
      verify(ours, c.public_jwk);
      if (c.algorithm === 'Ed25519') {
        // Deterministic: the same key and bytes give the same signature, to the byte.
        assert.equal(ours.Signature, c.headers.Signature);
      }
    });
  }

  it('a signature is bound to its method, host and path', () => {
    const identity = AgentIdentity.fromDocument(FIXTURE.cases[0].document);
    const jwk = FIXTURE.cases[0].public_jwk;
    const signed = signRequest({ method: 'GET', url: REQ.url, privateKey: identity.privateKey, keyid: identity.aid,
      created: CREATED });
    assert.throws(() => verify(signed, jwk, 'https://other.example/api/products'));
    assert.throws(() => verify(signed, jwk, REQ.url, 'POST'));
    assert.throws(() => verify(signed, jwk, 'https://shop.example/api/admin'));
  });

  it('every new signature has its own nonce', () => {
    const key = generateKey();
    const one = signRequest({ method: 'GET', url: 'https://a.example/', privateKey: key, keyid: 'x' });
    const two = signRequest({ method: 'GET', url: 'https://a.example/', privateKey: key, keyid: 'x' });
    assert.notEqual(one['Signature-Input'], two['Signature-Input']);
  });

  it('ES256 keys sign 64-byte JOSE signatures the verifier accepts', () => {
    const key = generateKey('ES256');
    const headers = signRequest({ method: 'POST', url: 'https://a.example/x', privateKey: key, keyid: 'k', created: CREATED });
    assert.equal(Buffer.from(headers.Signature.split(':')[1], 'base64').length, 64);
    assert.match(headers['Signature-Input'], /alg="ecdsa-p256-sha256"/);
    verify(headers, publicJwk(key), 'https://a.example/x', 'POST');
  });
});

describe('key stores', () => {
  const identity = AgentIdentity.fromDocument(FIXTURE.cases[0].document);

  it('a file store keeps the Python path and format, readable by the owner only', () => {
    const home = mkdtempSync(join(tmpdir(), 'aidr-agent-'));
    const store = new FileKeyStore(home);
    store.save(identity);
    const path = join(home, identity.name, 'identity.json');
    assert.equal(store.path(identity.name), path);
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), identity.toDocument());
    if (process.platform !== 'win32') assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(store.load(identity.name).aid, identity.aid);
    assert.equal(store.load('someone-else'), null);
  });

  it('a key file other users can read is refused', { skip: process.platform === 'win32' }, () => {
    const home = mkdtempSync(join(tmpdir(), 'aidr-agent-'));
    const store = new FileKeyStore(home);
    store.save(identity);
    chmodSync(store.path(identity.name), 0o644);
    assert.throws(() => store.load(identity.name), /readable by other users/);
  });

  it('names that would escape the directory are refused', () => {
    const store = new FileKeyStore(tmpdir());
    for (const bad of ['', '.', '..', 'a/b', 'a\\b']) assert.throws(() => store.path(bad), IdentityError);
  });

  it('the environment store reads one line, refuses another agent\'s, and cannot be written', () => {
    const store = new EnvKeyStore('AIDR_AGENT_IDENTITY', { AIDR_AGENT_IDENTITY: FIXTURE.cases[0].portable });
    assert.equal(store.load(identity.name).aid, identity.aid);
    assert.throws(() => store.load('another-agent'), /holds agent/);
    assert.throws(() => store.save(identity), /read-only/);
    assert.equal(new EnvKeyStore('AIDR_AGENT_IDENTITY', {}).load(identity.name), null);
  });

  it('a damaged identity is a clear error', () => {
    assert.throws(() => AgentIdentity.fromPortable('not-base64-json'), IdentityError);
    assert.throws(() => AgentIdentity.fromDocument({ format: 'something-else' }), IdentityError);
    const home = mkdtempSync(join(tmpdir(), 'aidr-agent-'));
    const store = new FileKeyStore(home);
    store.save(identity);
    writeFileSync(store.path(identity.name), '{ not json', { mode: 0o600 });
    assert.throws(() => store.load(identity.name), /unreadable/);
  });

  it('origins normalise as the registry normalises them', () => {
    assert.equal(normalizeOrigin('https://Shop.Example:443/path?x=1'), 'https://shop.example');
    assert.equal(normalizeOrigin('https://shop.example.:8443/'), 'https://shop.example:8443');
    assert.equal(normalizeOrigin('http://localhost:3000'), 'http://localhost:3000');
    assert.throws(() => normalizeOrigin('not a url'));
  });
});
