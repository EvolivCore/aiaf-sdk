import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

import { signEdgeContext, verifyEdgeContext } from '../src/edge-context.mjs';
import { SECRET, TESTDATA } from './helpers.mjs';

const NOW = 1_800_000_000_000;
const URL_ = 'https://origin.internal/api/products?page=2';

async function signed(overrides = {}) {
  const { context, signature } = await signEdgeContext(
    { status: 'anonymous', method: 'GET', target: '/api/products?page=2', iat: NOW / 1000, ...overrides },
    SECRET);
  return { 'x-aidr-context': context, 'x-aidr-context-signature': signature };
}

const verify = (headers, { method = 'GET', url = URL_, now = NOW, secret = SECRET } = {}) =>
  verifyEdgeContext({ method, url, headers }, secret, { now });

describe('edge context', () => {
  it('round-trips', async () => {
    assert.equal((await verify(await signed())).status, 'anonymous');
  });

  it('refuses a request that did not come through the edge', async () => {
    await assert.rejects(verify({}), { code: 'aidr.edge.context_invalid' });
  });

  it('refuses an altered context', async () => {
    const headers = await signed();
    const forged = await signed({ status: 'verified', aid: 'aid:v1:acme:x', agal: 3 });
    headers['x-aidr-context'] = forged['x-aidr-context'];
    await assert.rejects(verify(headers), /does not verify/);
  });

  it('refuses a context signed with another secret', async () => {
    await assert.rejects(verify(await signed(), { secret: 'x'.repeat(40) }), /does not verify/);
  });

  it('refuses a stale context, and one from the future', async () => {
    const headers = await signed();
    await assert.rejects(verify(headers, { now: NOW + 61_000 }), /validity window/);
    await assert.rejects(verify(headers, { now: NOW - 61_000 }), /validity window/);
  });

  it('refuses a context re-used for another method or target', async () => {
    const headers = await signed();
    await assert.rejects(verify(headers, { method: 'POST' }), /different request/);
    await assert.rejects(verify(headers, { url: 'https://origin.internal/api/products?page=3' }),
      /different request/);
  });

  it('refuses a short secret', async () => {
    await assert.rejects(signEdgeContext({}, 'short'), /at least 32/);
  });

  it('matches the known-answer vector shared with the Python origin helper', async () => {
    const vector = JSON.parse(readFileSync(resolve(TESTDATA, 'edge-context.json'), 'utf8'));
    const { context, signature } = await signEdgeContext(vector.context, vector.secret);
    assert.equal(context, vector.header_context);
    assert.equal(signature, vector.header_signature);
  });
});
