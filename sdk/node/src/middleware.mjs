/**
 * `aidr()` — verify AI agents in one line, for Express, Connect and Node's own `http` server:
 *
 *   import { aidr } from '@evoliv/aidr-verifier';
 *   app.use(aidr({ issuer: 'https://api.evolivcore.com' }));
 *   // then req.aidr.status is 'anonymous', 'bypassed' or 'verified' (with the agent's identity)
 *
 * The same three outcomes as the Cloudflare Worker and the Python middleware:
 *
 * - anonymous — none of Agent-Credential, Signature, Signature-Input: passed on (a person, or a bot
 *   that did not identify itself), unless the path is verified-only;
 * - verified  — the identity was proven and meets this site's floors: passed on, with
 *   `req.aidr` (and `req.agent`) holding it;
 * - refused   — it claims to be an agent and is not a valid one (401), is revoked or outside policy
 *   (403), or cannot be checked right now (503). JSON `{ error, reason }`.
 *
 * Keys and revocations are kept current in the background (TrustSync); nothing on the request path
 * calls the registry. Replay protection is in memory, which is right for one process; several
 * processes behind a balancer share a `nonceStore` (anything with `check(nonce)` returning false
 * on a repeat).
 */

import { effectiveRequestUri, CREDENTIAL_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER } from './crypto.mjs';
import { PublicOriginRequired, originResolver } from './origin.mjs';
import { compileBypass, isBypassed, normalisePath } from './path.mjs';
import { TrustSync } from './sync.mjs';
import { NonceCache } from './trust.mjs';
import {
  AgentRevoked, AidrError, AssuranceTooLow, CapabilityDenied, PolicyViolation, RegistryUnavailable,
  UnknownIssuer,
} from './util.mjs';
import { AgentVerifier, MAX_REVOCATION_AGE_SECONDS } from './verifier.mjs';

const AGENT_HEADERS = [CREDENTIAL_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER].map((h) => h.toLowerCase());
const FORBIDDEN = [AgentRevoked, AssuranceTooLow, CapabilityDenied, PolicyViolation];

/**
 * @param {object} options
 * @param {string} options.issuer            the registry, e.g. https://api.evolivcore.com
 * @param {string|string[]} [options.publicOrigin]  this site's origin(s) as agents see them, e.g.
 *                                           https://shop.example (or AIDR_PUBLIC_ORIGIN). Without it,
 *                                           only localhost is judged by its Host header safely; see
 *                                           src/origin.mjs (required from 0.2.0)
 * @param {'open'|'verified-only'} [options.mode]  default 'open'
 * @param {string[]} [options.verifiedOnlyPaths]   in verified-only mode, only these (regexes, whole path)
 * @param {string[]} [options.bypass]        paths never verified (regexes, whole path)
 * @param {number} [options.minAgal] @param {number} [options.minOal] @param {number} [options.minKal]
 * @param {string[]} [options.requiredCapabilities]
 * @param {'https'|'http'} [options.scheme]  when publicOrigin is not set; default 'https'
 */
export function aidr({
  issuer, publicOrigin = null, mode = 'open', verifiedOnlyPaths = null, bypass = [],
  minAgal = 0, minOal = 0, minKal = 0, requiredCapabilities = [], scheme = 'https',
  nonceStore = null, sync = null, fetch: fetchImpl = undefined, clock = () => new Date(),
  maxRevocationAgeSeconds = MAX_REVOCATION_AGE_SECONDS,
} = {}) {
  if (!issuer) throw new Error('aidr(): issuer is required, e.g. https://api.evolivcore.com');
  if (mode !== 'open' && mode !== 'verified-only') throw new Error('aidr(): mode must be "open" or "verified-only"');
  if (verifiedOnlyPaths && mode !== 'verified-only') throw new Error('aidr(): verifiedOnlyPaths needs mode "verified-only"');
  for (const [name, value] of [['minAgal', minAgal], ['minOal', minOal], ['minKal', minKal]]) {
    if (!Number.isInteger(value) || value < 0 || value > 3) throw new Error(`aidr(): ${name} must be 0-3`);
  }
  const originFor = originResolver({ publicOrigin, scheme });
  const bypassRules = compileBypass(bypass);
  const protectedRules = verifiedOnlyPaths ? compileBypass(verifiedOnlyPaths) : null;
  const isVerifiedOnly = (path) => {
    if (mode !== 'verified-only') return false;
    if (!protectedRules) return true;
    const normalised = normalisePath(path);
    // Fail closed: a path that cannot be normalised counts as protected.
    return normalised === null || protectedRules.some((rule) => rule.test(normalised));
  };

  const trustSync = sync ?? new TrustSync(issuer, fetchImpl ? { fetch: fetchImpl } : {});
  const nonces = nonceStore ?? new NonceCache();
  let verifier = null;
  const started = trustSync.start();
  let startSettled = false;
  started.finally(() => { startSettled = true; });

  const middleware = (req, res, next) => {
    const rawPath = (req.originalUrl ?? req.url ?? '/').split('?')[0];
    const pass = (identity) => {
      req.aidr = identity;
      req.agent = identity.status === 'verified' ? identity : null;
      if (typeof next === 'function') next();
    };
    const refuse = (status, code, reason, extraHeaders = {}) => {
      res.statusCode = status;
      res.setHeader('content-type', 'application/json');
      res.setHeader('cache-control', 'no-store');
      for (const [name, value] of Object.entries(extraHeaders)) res.setHeader(name, value);
      res.end(JSON.stringify({ error: code, reason }));
    };

    if (isBypassed(bypassRules, rawPath)) return pass({ status: 'bypassed' });

    const headers = {};
    for (const [name, value] of Object.entries(req.headers ?? {})) headers[name.toLowerCase()] = value;
    if (!AGENT_HEADERS.some((name) => name in headers)) {
      if (isVerifiedOnly(rawPath)) {
        return refuse(401, 'aidr.edge.agent_required',
          'this resource is for verified AI agents: present an AIDR credential and a signed request',
          { link: `<${trustSync.issuer}/.well-known/aiaf-registry>; rel="aiaf-registry"` });
      }
      return pass({ status: 'anonymous' });
    }

    if (!trustSync.ready && !startSettled) {
      // The first trust load is still in flight (the server began listening before it finished):
      // an agent's request waits for it rather than being told to come back. Only the first one.
      started.finally(() => middleware(req, res, next));
      return undefined;
    }
    if (!trustSync.ready) {
      return refuse(503, 'aidr.registry.unavailable', 'agent verification is not ready yet; try again shortly',
        { 'retry-after': '15' });
    }
    if (!verifier || verifier.trust !== trustSync.trust) {
      verifier = new AgentVerifier(trustSync.trust, {
        policy: { expectedIssuer: trustSync.issuer, minAssurance: minAgal, minKal, requiredCapabilities,
          maxRevocationAgeSeconds },
        nonceSeen: nonces,
      });
    }
    let base;
    try {
      base = new URL(originFor(headers.host));
    } catch (error) {
      if (error instanceof PublicOriginRequired) return refuse(503, error.code, error.message);
      throw error;
    }
    const url = effectiveRequestUri(base.protocol.replace(':', ''), base.host, req.originalUrl ?? req.url ?? '/');
    const { result, error } = verifier.tryVerify({ method: req.method, url, headers, now: clock() });
    if (result && result.oal < minOal) {
      return refuse(403, 'aidr.verify.assurance_too_low',
        `this site requires OAL ${minOal}; the agent's organisation is at OAL ${result.oal}`);
    }
    if (result) return pass({ status: 'verified', ...result });

    if (error instanceof UnknownIssuer && error.context?.kid) trustSync.requestKeyRefresh();
    let status = 401;
    if (error instanceof RegistryUnavailable) status = 503;
    else if (FORBIDDEN.some((type) => error instanceof type)) status = 403;
    return refuse(status, error instanceof AidrError ? error.code : 'aidr.crypto.malformed_token',
      error?.message ?? 'request could not be verified');
  };

  /** Resolves once the first trust load finished (true if it succeeded). */
  middleware.ready = started;
  middleware.health = () => trustSync.health();
  middleware.close = () => trustSync.stop();
  return middleware;
}
