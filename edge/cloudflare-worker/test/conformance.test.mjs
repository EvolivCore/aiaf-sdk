/**
 * The shared conformance vectors, replayed against the WebCrypto port. It must reach the same
 * verdict, with the same error code, as the Python, Node and Go SDKs.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { MAX_REVOCATION_AGE_SECONDS, TrustStore, verifyAgent } from '../src/verifier.mjs';
import { NOW_MS, VECTORS, firstAllow } from './helpers.mjs';

const NOW = new Date(NOW_MS);

async function trustFor(suite, delta = 'delta_before_revocation') {
  const trust = new TrustStore(suite.jwks, { expectedIssuer: suite.issuer });
  await trust.ingestSnapshot(suite.revocation[delta], { now: NOW });
  return trust;
}

function run(trust, suite, testCase, seen = new Set()) {
  return verifyAgent(trust, {
    expectedIssuer: suite.issuer,
    expectedAudience: testCase.expected_audience ?? null,
    minAgal: testCase.min_assurance ?? 0,
  }, {
    method: testCase.method, url: testCase.url, headers: testCase.headers,
    now: testCase.evaluate_at ? new Date(testCase.evaluate_at * 1000) : NOW,
    claimNonce: async (aid, nonce) => {
      const key = `${aid}\u001f${nonce}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  });
}

async function verdict(promise) {
  try {
    return { result: await promise, error: null };
  } catch (error) {
    return { result: null, error };
  }
}

for (const suite of VECTORS.suites) {
  describe(`conformance — ${suite.algorithm}`, () => {
    // freshness_cases: trust loaded at NOW, each verified at its own, later instant.
    for (const testCase of [...suite.cases, ...suite.freshness_cases]) {
      it(testCase.name, async () => {
        const { result, error } = await verdict(run(await trustFor(suite), suite, testCase));
        if (testCase.expect === 'allow') {
          assert.equal(error, null, `expected allow, got ${error?.code}: ${error?.message}`);
          assert.equal(result.aid, suite.aid);
          assert.equal(result.organization, suite.organization);
          assert.deepEqual([result.agal, result.oal, result.kal],
            [suite.expected_agal, suite.expected_oal, suite.expected_kal]);
        } else {
          assert.notEqual(error, null, 'expected a denial, got an acceptance');
          if (testCase.expect_code) assert.equal(error.code, testCase.expect_code, error.message);
        }
      });
    }

    it('a stored snapshot is rebuilt after its delta exp; its age is judged from iat', async () => {
      const later = new Date(NOW.getTime() + 600_000);
      await assert.rejects(new TrustStore(suite.jwks, { expectedIssuer: suite.issuer })
        .ingestSnapshot(suite.revocation.delta_before_revocation, { now: later }));
      const trust = new TrustStore(suite.jwks, { expectedIssuer: suite.issuer });
      await trust.ingestSnapshot(suite.revocation.delta_before_revocation, { now: later, stored: true });
      // Judged from the delta's own signed iat.
      const signedAt = JSON.parse(Buffer.from(suite.revocation.delta_before_revocation.split('.')[1], 'base64url')).iat;
      assert.equal(trust.issuedAt, signedAt * 1000);
      assert.equal(suite.max_revocation_age_seconds, MAX_REVOCATION_AGE_SECONDS);
    });

    for (const sequence of suite.sequences) {
      it(`sequence: ${sequence.name}`, async () => {
        const trust = await trustFor(suite);
        const seen = new Set();
        for (const step of sequence.steps) {
          const testCase = suite.cases.find((c) => c.name === step.case);
          const { error } = await verdict(run(trust, suite, testCase, seen));
          if (step.expect === 'allow') assert.equal(error, null, `${step.case}: ${error?.code}`);
          else {
            assert.notEqual(error, null, `${step.case}: expected a denial`);
            if (step.expect_code) assert.equal(error.code, step.expect_code);
          }
        }
      });
    }

    it('refuses a revoked agent', async () => {
      const trust = await trustFor(suite, 'delta_after_revocation');
      const { error } = await verdict(run(trust, suite, firstAllow(suite)));
      assert.equal(error?.code, 'aidr.verify.agent_revoked');
    });

    it('refuses a revocation feed with a gap as a snapshot', async () => {
      const trust = new TrustStore(suite.jwks, { expectedIssuer: suite.issuer });
      await assert.rejects(trust.ingestSnapshot(suite.revocation.delta_with_gap, { now: NOW }),
        { code: 'aidr.registry.unavailable' });
    });

    it('fails closed without revocation state', async () => {
      const trust = new TrustStore(suite.jwks, { expectedIssuer: suite.issuer });
      const { error } = await verdict(run(trust, suite, firstAllow(suite)));
      assert.equal(error?.code, 'aidr.registry.unavailable');
    });

    it('does not claim a nonce for a request refused by policy', async () => {
      const trust = await trustFor(suite);
      const seen = new Set();
      const below = { ...firstAllow(suite), min_assurance: 3 };
      assert.equal((await verdict(run(trust, suite, below, seen))).error?.code,
        'aidr.verify.assurance_too_low');
      assert.equal(seen.size, 0);
      assert.equal((await verdict(run(trust, suite, firstAllow(suite), seen))).error, null);
    });
  });
}
