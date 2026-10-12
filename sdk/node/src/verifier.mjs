/**
 * The relying-party verifier: check an agent's identity without calling the registry.
 *
 * Mirrors the Python SDK exactly, including the fail-closed revocation default. The two are held
 * to the same behaviour by shared test vectors in `sdk/testdata/vectors.json`, generated from the
 * Python implementation and replayed here.
 *
 *     import { AgentVerifier, buildTrustStore, NonceCache } from '@aidr/verifier';
 *
 *     const trust = buildTrustStore(jwks, { deltaToken, expectedIssuer: 'https://registry.aidr.example' });
 *     const verifier = new AgentVerifier(trust, { policy: { minAssurance: 1 }, nonceSeen: new NonceCache() });
 *     const result = verifier.verify({ method: req.method, url, headers: req.headers });
 *
 * The checks, cheapest first so a malformed request is rejected before any cryptography:
 *
 *   1. the `Agent-Credential` header is present and well-formed;
 *   2. the credential was signed by a key in the locally cached JWKS;
 *   3. the credential is inside its validity window, with clock-skew tolerance;
 *   4. issuer — and audience, when bound — are the expected ones;
 *   5. the agent identifier is not revoked;
 *   6. the request signature verifies against the key *inside the credential*, and covers the
 *      method, authority and path actually received;
 *   7. the site's own policy.
 *
 * Step 6 is what makes a credential non-transferable. The credential says "this identifier holds
 * this public key"; the signature proves the sender holds the matching private key, for this
 * request. Without it, a credential captured from any request would be reusable by anyone.
 */

import {
  AgentRevoked,
  AidrError,
  AssuranceTooLow,
  CapabilityDenied,
  CredentialExpired,
  CredentialNotYetValid,
  MalformedToken,
  PolicyViolation,
  RegistryUnavailable,
  UnknownIssuer,
} from './util.mjs';
import {
  CREDENTIAL_HEADER,
  REQUIRED_COMPONENTS,
  effectiveRequestUri,
  importPublicKey,
  verifyCompact,
  verifyRequestSignature,
} from './crypto.mjs';
import { PublicOriginRequired, originResolver } from './origin.mjs';

/**
 * Clock skew tolerance, in seconds. Larger than feels necessary because unsynchronised clocks are
 * the most common cause of spurious failures in the field; 60 s absorbs a drifting VM without
 * meaningfully extending a stolen credential's life.
 */
const DEFAULT_LEEWAY_SECONDS = 60;

/**
 * The oldest revocation data agents may be verified against: one 60 s refresh plus 600 s of grace
 * (11 minutes). The same limit in every AIDR verifier; sdk/testdata/vectors.json pins it.
 */
export const MAX_REVOCATION_AGE_SECONDS = 660;

export const DEFAULT_POLICY = {
  /** Minimum composite assurance (AgAL). AgAL is min(OAL, KAL): a floor on the weaker axis. */
  minAssurance: 0,
  /**
   * Minimum **key** assurance (KAL), independent of AgAL.
   *
   * A site that cares specifically about key protection cannot express that through AgAL, because
   * a high AgAL can be reached with a strong operator and a merely adequate key. KAL2 means
   * attested non-exportability; KAL3 adds an attested runtime.
   */
  minKal: 0,
  requiredCapabilities: [],
  maxSignatureAgeSeconds: 300,
  requireNonce: true,
  expectedIssuer: null,
  /** For audience-bound credentials. null: the origin of the URL being verified (set it behind a
   *  proxy that changes the host). */
  expectedAudience: null,
  maxUpheldAbuseReports: null,
  /**
   * What to do when revocation state cannot give a definitive answer.
   *
   * Defaults to **deny**. Soft-failing on unknown revocation is the mistake the web PKI spent two
   * decades regretting: it makes revocation optional for anyone who can block a fetch. A site that
   * would rather stay available supplies `onlineRevocationCheck`, or sets this deliberately.
   */
  allowUnknownRevocation: false,
  /**
   * Refuse agents (503 aidr.registry.unavailable) when the newest revocation data held was signed
   * by the registry longer ago than this. Judged from the delta's signed `iat` (AIAF §6.3), so a
   * replayed feed cannot pass for a fresh one. null disables it.
   */
  maxRevocationAgeSeconds: MAX_REVOCATION_AGE_SECONDS,
  onlineRevocationCheck: null,
  leewaySeconds: DEFAULT_LEEWAY_SECONDS,
  requiredComponents: REQUIRED_COMPONENTS,
};

export class AgentVerifier {
  constructor(trustStore, { policy = {}, nonceSeen = null } = {}) {
    this.trust = trustStore;
    this.policy = { ...DEFAULT_POLICY, ...policy };
    if (this.policy.expectedIssuer === null && trustStore.expectedIssuer) {
      this.policy.expectedIssuer = trustStore.expectedIssuer;
    }
    this.nonceSeen = nonceSeen;
  }

  /**
   * Verify a request. Throws on any failure.
   *
   * Throws rather than returning a verdict so a dropped result cannot be mistaken for a pass.
   * Sites wanting a boolean use `tryVerify`.
   */
  verify({ method, url, headers, now = new Date() }) {
    const warnings = [];
    const normalised = Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
    );

    // 1. credential present
    let rawCredential = normalised[CREDENTIAL_HEADER];
    if (!rawCredential) {
      throw new MalformedToken(
        'request carries no Agent-Credential header — the agent is unidentified',
      );
    }
    if (String(rawCredential).toLowerCase().startsWith('bearer ')) {
      rawCredential = String(rawCredential).slice(7).trim();
    }

    // 2. the registry's signature over the credential
    const { payload: claims } = verifyCompact(rawCredential, (kid) => this.trust.resolveKey(kid));

    // 3. validity window
    this.#validateTimeClaims(claims, now);

    // 4. issuer and audience
    this.#checkIssuerAndAudience(claims, url);

    const aid = claims.sub;
    if (typeof aid !== 'string' || !aid) throw new MalformedToken('credential has no subject');

    // 5. revocation: fresh enough to rely on, then the identifier itself
    this.#checkRevocationAge(now);
    warnings.push(...this.#checkRevocation(aid));

    // 6. proof that the sender holds the credential's key, for THIS request
    const agentJwk = claims.cnf?.jwk;
    if (!agentJwk || typeof agentJwk !== 'object') {
      throw new MalformedToken("credential carries no key confirmation ('cnf.jwk')");
    }
    importPublicKey(agentJwk);          // validate structurally before use

    const verified = verifyRequestSignature({
      method,
      url,
      headers,
      resolvePublicKey: () => agentJwk,
      requiredComponents: this.policy.requiredComponents,
      maxAgeSeconds: this.policy.maxSignatureAgeSeconds,
      now,
      nonceSeen: this.policy.requireNonce && this.nonceSeen
        ? (nonce) => this.nonceSeen.check(nonce)
        : null,
      // The signature's keyid must be the identifier the credential was issued for. Without this,
      // a valid credential for agent A could be paired with a signature made by agent B's key.
      expectedKeyid: aid,
    });

    // 7. the site's own policy
    // AgAL never falls back to the legacy `assurance` claim: that claim is OAL only, and reading
    // it as AgAL overstates any agent whose key assurance is below its operator's. OAL may fall
    // back to it, because OAL is exactly what it carries.
    const agal = Number(claims.agal ?? 0);
    const result = {
      aid,
      organization: claims.org ?? '',
      // The composite level a site should act on: equal to `agal`.
      assurance: agal,
      agal,
      oal: Number(claims.oal ?? claims.assurance ?? 0),
      kal: Number(claims.kal ?? 0),
      dal: Number(claims.dal ?? 0),
      // Trust decisions should key on (issuer, verified domain), never on the namespace string.
      orgDomains: claims.org_domains ?? [],
      capabilities: claims.capabilities ?? [],
      scopes: claims.scopes ?? [],
      keyId: claims.cnf?.kid ?? '',
      credentialJti: claims.jti ?? '',
      credentialExpiresAt: claims.exp ? new Date(claims.exp * 1000) : null,
      signatureCreatedAt: verified.created,
      /**
       * Self-asserted by the owner and NOT verified by the registry. Kept in its own property so
       * no site can mistake it for a checked fact: the registry can prove who owns the agent, not
       * what model it runs.
       */
      declared: claims.declared ?? {},
      standing: claims.standing ?? {},
      warnings,
    };
    this.#applyPolicy(result);

    if (this.trust.keySet.isStale()) warnings.push('registry key set is stale — refresh JWKS');
    if (this.trust.revocation.isStale()) {
      warnings.push('revocation state is stale — refresh the delta feed');
    }
    return result;
  }

  /** Non-throwing form: returns `{ result, error }`. */
  tryVerify(options) {
    try {
      return { result: this.verify(options), error: null };
    } catch (error) {
      // Catches the whole AidrError taxonomy, not one branch of it: a malformed credential and a
      // revoked agent are different diagnoses but the same outcome for the caller.
      if (error instanceof AidrError) return { result: null, error };
      throw error;
    }
  }

  /**
   * Convenience wrapper for a Node HTTP request.
   *
   * The URI is built from this site's own origin (`publicOrigin`, or AIDR_PUBLIC_ORIGIN) — never
   * from anything inside the signature, and not from the client's Host header, except on
   * localhost (src/origin.mjs).
   */
  verifyIncoming(request, { scheme = 'https', publicOrigin = null, ...options } = {}) {
    const origin = new URL(originResolver({ publicOrigin, scheme })(request.headers.host));
    return this.verify({
      method: request.method,
      url: effectiveRequestUri(origin.protocol.replace(':', ''), origin.host, request.url ?? '/'),
      headers: request.headers,
      ...options,
    });
  }

  #validateTimeClaims(claims, now) {
    const leeway = this.policy.leewaySeconds * 1000;

    if (claims.exp === undefined) {
      // A non-expiring credential defeats the architecture's safety argument: bounded blast
      // radius from a stolen credential even when revocation fails.
      throw new MalformedToken(
        "credential has no 'exp' claim — non-expiring credentials are refused",
      );
    }
    const expiresAt = Number(claims.exp) * 1000;
    if (now.getTime() > expiresAt + leeway) {
      throw new CredentialExpired('credential has expired', {
        expiredAt: new Date(expiresAt).toISOString(),
        secondsAgo: Math.round((now.getTime() - expiresAt) / 1000),
      });
    }

    if (claims.nbf !== undefined) {
      const notBefore = Number(claims.nbf) * 1000;
      if (now.getTime() < notBefore - leeway) {
        throw new CredentialNotYetValid('credential is not yet valid',
          { notBefore: new Date(notBefore).toISOString() });
      }
    }
  }

  #checkIssuerAndAudience(claims, url) {
    if (this.policy.expectedIssuer && claims.iss !== this.policy.expectedIssuer) {
      throw new UnknownIssuer(
        `credential issued by ${claims.iss}, expected ${this.policy.expectedIssuer}`,
        { issuer: claims.iss },
      );
    }

    if (claims.aud !== undefined && claims.aud !== null) {
      // An audience-bound credential is valid only at the named site. Ignoring the claim would
      // silently undo a binding the issuer deliberately applied.
      // Not configured: the site being visited (the request signature covers @authority).
      const expected = this.policy.expectedAudience ?? new URL(url).origin;
      const allowed = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!allowed.includes(expected)) {
        throw new PolicyViolation(
          `credential is bound to ${JSON.stringify(claims.aud)}, not to ${expected}`,
          { audience: claims.aud, expected },
        );
      }
    }
  }

  #checkRevocationAge(now) {
    const limit = this.policy.maxRevocationAgeSeconds;
    const issued = this.trust.revocation.issuedAt;
    if (limit === null || limit === undefined || issued === null || issued === undefined) return;
    const age = (new Date(now).getTime() - issued) / 1000;
    if (age > limit) {
      throw new RegistryUnavailable(
        `revocation data is ${Math.floor(age)} s old (limit ${limit} s): agents are refused until it is refreshed`,
        { ageSeconds: Math.floor(age), limitSeconds: limit },
      );
    }
  }

  #checkRevocation(aid) {
    const warnings = [];
    const { revoked, definitive } = this.trust.revocation.contains(aid);

    if (revoked && definitive) throw new AgentRevoked('agent identity has been revoked', { aid });
    if (definitive) return warnings;

    const check = this.policy.onlineRevocationCheck;
    if (check) {
      try {
        if (check(aid)) throw new AgentRevoked('agent identity has been revoked', { aid });
        return warnings;
      } catch (error) {
        if (error instanceof AgentRevoked) throw error;
        if (!this.policy.allowUnknownRevocation) {
          throw new RegistryUnavailable(
            `online revocation check failed and the policy is fail-closed: ${error.message}`,
            { aid },
          );
        }
        warnings.push(`online revocation check failed: ${error.message}`);
        return warnings;
      }
    }

    if (!this.policy.allowUnknownRevocation) {
      throw new RegistryUnavailable(
        'revocation state is inconclusive for this identifier and no online check is configured; '
        + 'policy is fail-closed',
        { aid, revocationExact: this.trust.revocation.exact },
      );
    }
    warnings.push('revocation status unverified — local state is not authoritative');
    return warnings;
  }

  #applyPolicy(result) {
    if (result.agal < this.policy.minAssurance) {
      throw new AssuranceTooLow(
        `agent assurance AgAL${result.agal} is below the required AgAL${this.policy.minAssurance}`,
        { aid: result.aid, agal: result.agal, oal: result.oal, kal: result.kal,
          required: this.policy.minAssurance },
      );
    }

    if (result.kal < this.policy.minKal) {
      throw new AssuranceTooLow(
        `agent key assurance KAL${result.kal} is below the required KAL${this.policy.minKal} `
        + '— this endpoint requires a hardware-protected key',
        { aid: result.aid, kal: result.kal, requiredKal: this.policy.minKal },
      );
    }

    const missing = this.policy.requiredCapabilities.filter(
      (capability) => !result.capabilities.includes(capability),
    );
    if (missing.length > 0) {
      throw new CapabilityDenied(
        `agent lacks required capabilities: ${missing.join(', ')}`,
        { aid: result.aid, missing, granted: result.capabilities },
      );
    }

    const limit = this.policy.maxUpheldAbuseReports;
    if (limit !== null && limit !== undefined) {
      const upheld = Number(result.standing?.abuse_reports_upheld ?? 0);
      if (upheld > limit) {
        throw new PolicyViolation(
          `agent has ${upheld} upheld abuse reports, above this site's limit of ${limit}`,
          { aid: result.aid, upheld, limit },
        );
      }
    }
  }
}

/**
 * Express / Connect middleware over a verifier you keep current yourself. Attaches `req.agent` on
 * success. Prefer `aidr()` (src/middleware.mjs), which also keeps the trust material current.
 */
export function expressMiddleware(verifier, { scheme = 'https', optional = false, publicOrigin = null } = {}) {
  const agentHeaders = ['agent-credential', 'signature', 'signature-input'];
  const originFor = originResolver({ publicOrigin, scheme });
  return (req, res, next) => {
    // Unidentified only when no agent header at all is present. A request that claims to be an
    // agent with a credential that does not parse is refused, never waved through as anonymous.
    if (optional && !agentHeaders.some((name) => Object.keys(req.headers ?? {})
      .some((header) => header.toLowerCase() === name))) {
      req.agent = null;
      return next();
    }
    let origin;
    try {
      origin = new URL(originFor(req.headers.host));
    } catch (error) {
      if (!(error instanceof PublicOriginRequired)) throw error;
      res.statusCode = 503;
      res.setHeader?.('content-type', 'application/json');
      return res.end(JSON.stringify({ error: error.code, reason: error.message }));
    }
    const { result, error } = verifier.tryVerify({
      method: req.method,
      url: effectiveRequestUri(origin.protocol.replace(':', ''), origin.host, req.originalUrl ?? req.url ?? '/'),
      headers: req.headers,
    });

    if (result) {
      req.agent = result;
      return next();
    }
    // Distinguish "not valid" from "could not determine": 401 versus 503. A site's retry and
    // alerting behaviour differs between them, and collapsing both into 401 hides an outage.
    const status = error?.code === 'aidr.registry.unavailable' ? 503 : 401;
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({ error: { code: error?.code, message: error?.message } }));
  };
}
