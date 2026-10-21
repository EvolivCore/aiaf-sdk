/**
 * Trust material and agent verification, for the edge.
 *
 * Deliberately narrower than the SDKs: the edge holds only an EXACT revocation set (a verified
 * delta from serial 0), never a bloom filter, and has no soft-fail option. Anything it cannot
 * answer definitively it refuses; the worker turns that into a 503.
 */

import {
  CREDENTIAL_HEADER,
  importPublicKey,
  jwkThumbprint,
  verifyCompact,
  verifyRequestSignature,
} from './crypto.mjs';
import {
  AgentRevoked,
  AssuranceTooLow,
  CapabilityDenied,
  CredentialExpired,
  CredentialNotYetValid,
  MalformedToken,
  PolicyViolation,
  RegistryUnavailable,
  UnknownIssuer,
} from './errors.mjs';

const DELTA_TYP = 'aidr-crl+jwt';
const LEEWAY_SECONDS = 60;

function checkTime(claims, now, { requireExp }) {
  const t = now.getTime();
  if (claims.exp === undefined) {
    if (requireExp) {
      throw new MalformedToken("credential has no 'exp' claim — non-expiring credentials are refused");
    }
  } else if (t > Number(claims.exp) * 1000 + LEEWAY_SECONDS * 1000) {
    throw new CredentialExpired('credential has expired');
  }
  if (claims.nbf !== undefined && t < Number(claims.nbf) * 1000 - LEEWAY_SECONDS * 1000) {
    throw new CredentialNotYetValid('credential is not yet valid');
  }
}

export class TrustStore {
  /** @param {object} jwks the registry's JWKS document */
  constructor(jwks, { expectedIssuer }) {
    const keys = new Map();
    for (const jwk of Array.isArray(jwks?.keys) ? jwks.keys : []) {
      if (typeof jwk?.kid !== 'string') continue;
      if ('d' in jwk) throw new MalformedToken('JWKS contains private key material — refusing it');
      keys.set(jwk.kid, jwk);
    }
    if (keys.size === 0) throw new MalformedToken('JWKS document contains no usable keys');
    this.keys = keys;
    this.expectedIssuer = expectedIssuer;
    this.revoked = new Set();
    this.serial = 0;
    this.exact = false;
    /** When the registry signed the revocation data held (its `iat`, ms), or null. */
    this.issuedAt = null;
  }

  resolveKey(kid) {
    return this.keys.get(kid) ?? null;
  }

  /**
   * Ingest a complete revocation snapshot (a signed delta from serial 0).
   *
   * `stored: true` rebuilds from a snapshot this edge already verified when it fetched it: the
   * signature and issuer are checked again, but not the delta's short `exp`. How old the data may
   * be is the verifier's MAX_REVOCATION_AGE_SECONDS rule, judged from the signed `iat`.
   */
  async ingestSnapshot(deltaToken, { now = new Date(), stored = false } = {}) {
    const { payload } = await verifyCompact(deltaToken, (kid) => this.resolveKey(kid),
      { expectedTyp: DELTA_TYP });
    if (payload.iss !== this.expectedIssuer) {
      throw new UnknownIssuer(`revocation feed issued by ${payload.iss}, expected ${this.expectedIssuer}`);
    }
    if (!stored) checkTime(payload, now, { requireExp: false });
    if (Number(payload.since ?? 0) !== 0 || payload.complete === false) {
      throw new RegistryUnavailable('revocation snapshot is not complete (since != 0)');
    }
    for (const entry of payload.revocations ?? []) {
      if (typeof entry?.subject_id === 'string') this.revoked.add(entry.subject_id);
    }
    this.serial = Number(payload.serial ?? 0);
    this.issuedAt = Number.isFinite(Number(payload.iat)) ? Number(payload.iat) * 1000 : null;
    this.exact = true;
    return this.serial;
  }
}

/**
 * The oldest revocation data agents may be verified against: one 60 s refresh plus 600 s of grace
 * (11 minutes). The same limit in every AIDR verifier; sdk/testdata/vectors.json pins it.
 */
export const MAX_REVOCATION_AGE_SECONDS = 660;

export const DEFAULT_POLICY = {
  expectedIssuer: null,
  expectedAudience: null,
  minAgal: 0,
  minOal: 0,
  minKal: 0,
  requiredCapabilities: [],
  maxUpheldAbuseReports: null,
  maxSignatureAgeSeconds: 300,
  maxRevocationAgeSeconds: MAX_REVOCATION_AGE_SECONDS,
};

/**
 * Verify one request. Throws an AidrError on any failure.
 *
 * `claimNonce(aid, nonce, created)` is consulted only after everything else has verified.
 */
export async function verifyAgent(trust, policyOverrides, { method, url, headers, now, claimNonce }) {
  const policy = { ...DEFAULT_POLICY, ...policyOverrides };
  const normalised = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
  );

  // 1. credential present
  let raw = normalised[CREDENTIAL_HEADER];
  if (!raw) throw new MalformedToken('request carries no Agent-Credential header');
  if (String(raw).toLowerCase().startsWith('bearer ')) raw = String(raw).slice(7).trim();

  // 2. the registry's signature over it
  const { payload: claims } = await verifyCompact(raw, (kid) => trust.resolveKey(kid));

  // 3. validity window
  checkTime(claims, now, { requireExp: true });

  // 4. issuer and audience
  if (claims.iss !== policy.expectedIssuer) {
    throw new UnknownIssuer(`credential issued by ${claims.iss}, expected ${policy.expectedIssuer}`);
  }
  if (claims.aud !== undefined && claims.aud !== null) {
    const allowed = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    // Not configured: the site being visited (the request signature covers @authority).
    const expected = policy.expectedAudience ?? new URL(url).origin;
    if (!allowed.includes(expected)) {
      throw new PolicyViolation(
        `credential is bound to ${JSON.stringify(claims.aud)}, not to ${expected}`);
    }
  }
  const aid = claims.sub;
  if (typeof aid !== 'string' || !aid) throw new MalformedToken('credential has no subject');

  // 5. revocation — exact state or nothing
  if (!trust.exact) {
    throw new RegistryUnavailable('revocation state not loaded; refusing rather than guessing');
  }
  const limit = policy.maxRevocationAgeSeconds;
  if (limit !== null && limit !== undefined && trust.issuedAt !== null) {
    const age = (new Date(now ?? Date.now()).getTime() - trust.issuedAt) / 1000;
    if (age > limit) {
      throw new RegistryUnavailable(
        `revocation data is ${Math.floor(age)} s old (limit ${limit} s): agents are refused until it is refreshed`);
    }
  }
  if (trust.revoked.has(aid)) throw new AgentRevoked('agent identity has been revoked', { aid });

  // 6. the sender holds the credential's key, for THIS request
  const agentJwk = claims.cnf?.jwk;
  if (!agentJwk || typeof agentJwk !== 'object') {
    throw new MalformedToken("credential carries no key confirmation ('cnf.jwk')");
  }
  await importPublicKey(agentJwk);
  const verified = await verifyRequestSignature({
    method, url, headers, now,
    resolvePublicKey: () => agentJwk,
    maxAgeSeconds: policy.maxSignatureAgeSeconds,
    // The credential's own key: its identifier, or (Web Bot Auth) the thumbprint of cnf.jwk.
    expectedKeyid: [aid, await jwkThumbprint(agentJwk)],
    // Policy is checked before the nonce is claimed, so a refused request never occupies one.
    claimNonce: claimNonce
      ? async (nonce, created) => {
        applyPolicy(policy, identityFrom(claims, aid));
        return claimNonce(aid, nonce, created);
      }
      : null,
  });

  const identity = identityFrom(claims, aid, verified.created);
  applyPolicy(policy, identity);
  return identity;
}

function identityFrom(claims, aid, signatureCreatedAt = null) {
  // AgAL never falls back to the legacy `assurance` claim, which is OAL only.
  return {
    aid,
    organization: claims.org ?? '',
    orgDomains: Array.isArray(claims.org_domains) ? claims.org_domains : [],
    agal: Number(claims.agal ?? 0),
    oal: Number(claims.oal ?? claims.assurance ?? 0),
    kal: Number(claims.kal ?? 0),
    capabilities: Array.isArray(claims.capabilities) ? claims.capabilities : [],
    scopes: Array.isArray(claims.scopes) ? claims.scopes : [],
    standing: claims.standing ?? {},
    declared: claims.declared ?? {},
    credentialExpiresAt: claims.exp ? Number(claims.exp) : null,
    signatureCreatedAt,
  };
}

function applyPolicy(policy, identity) {
  for (const [axis, have, need] of [['AgAL', identity.agal, policy.minAgal],
    ['OAL', identity.oal, policy.minOal], ['KAL', identity.kal, policy.minKal]]) {
    if (have < need) {
      throw new AssuranceTooLow(`agent ${axis} ${have} is below this site's required ${need}`,
        { aid: identity.aid, axis, have, required: need });
    }
  }
  const missing = policy.requiredCapabilities.filter((c) => !identity.capabilities.includes(c));
  if (missing.length > 0) {
    throw new CapabilityDenied(`agent lacks required capabilities: ${missing.join(', ')}`);
  }
  const limit = policy.maxUpheldAbuseReports;
  if (limit !== null && limit !== undefined) {
    const upheld = Number(identity.standing?.abuse_reports_upheld ?? 0);
    if (upheld > limit) {
      throw new PolicyViolation(`agent has ${upheld} upheld abuse reports, above the limit of ${limit}`);
    }
  }
}
