/**
 * AIDR edge verifier for Cloudflare Workers.
 *
 * Every request ends in exactly one of these outcomes:
 *
 * - bypassed  — the normalised path fully matches a bypass rule. Not verified; forwarded.
 * - anonymous — none of Agent-Credential / Signature / Signature-Input is present. Forwarded: a
 *               person, or a bot that did not identify itself — unless the path is verified-only
 *               (AIDR_MODE), where it is refused with 401 aidr.edge.agent_required.
 * - verified  — the agent's identity was proven and meets policy. Forwarded.
 * - refused   — it claims to be an agent and is not a valid one (401), is revoked or outside
 *               policy (403, with a reason code), or cannot be checked right now (503).
 *
 * Whatever is forwarded carries a signed X-AIDR-Context stating which outcome it was; client-sent
 * x-aidr-* headers are removed first. The origin verifies that context on every request
 * (edge-context.mjs, or aidr_verifier.edge for Python), so it can neither be reached around the
 * edge nor told a different story.
 *
 * Configuration (wrangler.toml [vars], and secrets):
 *   AIDR_ISSUER                 registry issuer URL (https), exactly as in credentials' `iss`
 *   AIDR_EDGE_CONTEXT_SECRET    secret, >= 32 chars, shared with the origin   (wrangler secret put)
 *   AIDR_MIN_AGAL / _OAL / _KAL assurance floors (default 0)
 *   AIDR_REQUIRED_CAPABILITIES  comma-separated
 *   AIDR_BYPASS                 JSON array of regular expressions, each matched against the whole path
 *   AIDR_EXPECTED_AUDIENCE      default: the request's own origin
 *   AIDR_ORIGIN                 optional origin base URL; default: pass through to the zone's origin
 *   ORIGIN (service binding)    optional: an origin that is itself a Worker, reached through a
 *                               service binding rather than the internet (it then needs no public
 *                               URL at all). The context is bound to the same target either way
 *   AIDR_FORWARD_AGENT_HEADERS  "true" to pass the agent's own headers on (default: stripped)
 *   AIDR_MODE                   "open" (default): anonymous traffic is forwarded. "verified-only":
 *                               only verified agents reach the origin — people included are refused,
 *                               so scope it with AIDR_VERIFIED_ONLY_PATHS unless that is the intent
 *   AIDR_VERIFIED_ONLY_PATHS    JSON array of regular expressions (whole path); in verified-only
 *                               mode, only these paths are verified-only. Default: every path
 * Bindings: NONCES (NonceStore), TRUST (TrustState).
 */

import { nowMs, setClockForTests } from './clock.mjs';
import { CREDENTIAL_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER } from './crypto.mjs';
import { CONTEXT_HEADER, CONTEXT_SIGNATURE_HEADER, MIN_SECRET_LENGTH, signEdgeContext, targetOf }
  from './edge-context.mjs';
import { sha256Hex } from './encoding.mjs';
import {
  AgentRevoked, AidrError, AssuranceTooLow, CapabilityDenied, PolicyViolation, RegistryUnavailable,
  UnknownIssuer,
} from './errors.mjs';
import { NonceStore, shardFor } from './nonce-store.mjs';
import { compileBypass, isBypassed, normalisePath } from './path.mjs';
import { TrustState } from './trust-state.mjs';
import { TrustStore, verifyAgent } from './verifier.mjs';

export { NonceStore, TrustState };

const AGENT_HEADERS = [CREDENTIAL_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER];
const FORBIDDEN = [AgentRevoked, AssuranceTooLow, CapabilityDenied, PolicyViolation];

/** How long an isolate uses a loaded snapshot before reloading it (in the background). */
const RELOAD_AFTER_MS = 60 * 1000;
/** A snapshot the registry has not refreshed for this long is too old to decide revocation. */
const MAX_SNAPSHOT_AGE_MS = 11 * 60 * 1000;

const clock = nowMs;
export { setClockForTests };

// ---- configuration, parsed once per isolate ---------------------------------------------------

let configCache = { env: null, config: null, error: null };

function loadConfig(env) {
  if (configCache.env === env) {
    if (configCache.error) throw configCache.error;
    return configCache.config;
  }
  try {
    const issuer = String(env.AIDR_ISSUER ?? '').replace(/\/+$/, '');
    if (!/^https:\/\//.test(issuer)) throw new Error('AIDR_ISSUER must be an https:// URL');
    const secret = env.AIDR_EDGE_CONTEXT_SECRET;
    if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) {
      throw new Error(`AIDR_EDGE_CONTEXT_SECRET must be set, at least ${MIN_SECRET_LENGTH} characters`);
    }
    if (!env.NONCES || !env.TRUST) throw new Error('NONCES and TRUST Durable Object bindings are required');
    const int = (name) => {
      const value = Number.parseInt(env[name] ?? '0', 10);
      if (!Number.isInteger(value) || value < 0 || value > 3) throw new Error(`${name} must be 0-3`);
      return value;
    };
    const bypass = JSON.parse(env.AIDR_BYPASS ?? '[]');
    if (!Array.isArray(bypass)) throw new Error('AIDR_BYPASS must be a JSON array');
    const config = {
      issuer,
      secret,
      minAgal: int('AIDR_MIN_AGAL'),
      minOal: int('AIDR_MIN_OAL'),
      minKal: int('AIDR_MIN_KAL'),
      requiredCapabilities: String(env.AIDR_REQUIRED_CAPABILITIES ?? '')
        .split(',').map((s) => s.trim()).filter(Boolean),
      bypass: compileBypass(bypass),
      expectedAudience: env.AIDR_EXPECTED_AUDIENCE || null,
      origin: env.AIDR_ORIGIN ? new URL(env.AIDR_ORIGIN) : null,
      forwardAgentHeaders: env.AIDR_FORWARD_AGENT_HEADERS === 'true',
      verifiedOnly: verifiedOnlyRule(env),
      originService: env.ORIGIN ?? null,
    };
    configCache = { env, config, error: null };
    return config;
  } catch (error) {
    configCache = { env, config: null, error };
    throw error;
  }
}

/** null in open mode; otherwise a predicate on the normalised path. */
function verifiedOnlyRule(env) {
  const mode = String(env.AIDR_MODE ?? 'open');
  if (mode === 'open') {
    if (env.AIDR_VERIFIED_ONLY_PATHS) throw new Error('AIDR_VERIFIED_ONLY_PATHS needs AIDR_MODE = "verified-only"');
    return null;
  }
  if (mode !== 'verified-only') throw new Error('AIDR_MODE must be "open" or "verified-only"');
  if (!env.AIDR_VERIFIED_ONLY_PATHS) return () => true;
  const paths = JSON.parse(env.AIDR_VERIFIED_ONLY_PATHS);
  if (!Array.isArray(paths) || paths.length === 0) {
    throw new Error('AIDR_VERIFIED_ONLY_PATHS must be a non-empty JSON array');
  }
  const compiled = compileBypass(paths);
  // Fail closed: a path that cannot be normalised (an encoded dot segment…) counts as protected.
  return (path) => {
    const normalised = normalisePath(path);
    return normalised === null || compiled.some((rule) => rule.test(normalised));
  };
}

// ---- trust, cached per isolate ------------------------------------------------------------------

// Plain data only. No promise is shared across requests: Workers forbid one request from awaiting
// I/O begun by another, so concurrent cold requests each load for themselves.
let trustCache = { issuer: null, trust: null, loadedAt: 0, snapshotAt: 0, reloadingSince: 0 };

async function loadTrust(env, config) {
  const stub = env.TRUST.get(env.TRUST.idFromName('trust'));
  const response = await stub.fetch('https://trust.internal/snapshot');
  if (!response.ok) throw new RegistryUnavailable(`trust snapshot unavailable (HTTP ${response.status})`);
  const snapshot = await response.json();
  if (snapshot.issuer !== config.issuer) throw new RegistryUnavailable('trust snapshot is for another issuer');
  const trust = new TrustStore(snapshot.jwks, { expectedIssuer: config.issuer });
  await trust.ingestSnapshot(snapshot.delta, { now: new Date(clock()), stored: true });
  trustCache = { issuer: config.issuer, trust, loadedAt: Date.now(), snapshotAt: snapshot.fetchedAt,
    reloadingSince: 0 };
  return trustCache;
}

async function currentTrust(env, config, ctx) {
  const now = Date.now();
  let cached = trustCache.issuer === config.issuer ? trustCache : null;
  if (cached && now - cached.loadedAt >= RELOAD_AFTER_MS && now - cached.snapshotAt < MAX_SNAPSHOT_AGE_MS) {
    // Still usable: serve from it and reload in the background, one reload at a time.
    if (now - cached.reloadingSince > 30_000) {
      trustCache.reloadingSince = now;
      ctx.waitUntil(loadTrust(env, config).catch((error) => {
        console.warn(JSON.stringify({ aidr: 'trust_reload_failed', error: error.message }));
      }));
    }
    return cached.trust;
  }
  if (!cached || now - cached.snapshotAt >= MAX_SNAPSHOT_AGE_MS) cached = await loadTrust(env, config);
  if (Date.now() - cached.snapshotAt >= MAX_SNAPSHOT_AGE_MS) {
    throw new RegistryUnavailable('revocation data is too old to rely on; refusing agent requests');
  }
  return cached.trust;
}

// ---- nonce claims -------------------------------------------------------------------------------

async function claimNonce(env, aid, nonce, created, maxAgeSeconds) {
  const key = await sha256Hex(`${aid}\u001f${nonce}`);
  // Remember the nonce exactly as long as its signature could still be accepted.
  const ttl = Math.max(1, Math.ceil(created + maxAgeSeconds - clock() / 1000) + 1);
  let response;
  try {
    const stub = env.NONCES.get(env.NONCES.idFromName(shardFor(key)));
    response = await stub.fetch('https://nonce.internal/claim', {
      method: 'POST', body: JSON.stringify({ key, ttl }), headers: { 'content-type': 'application/json' },
    });
  } catch (error) {
    throw new RegistryUnavailable(`replay store unreachable: ${error.message}`);
  }
  if (!response.ok) throw new RegistryUnavailable(`replay store refused the claim (HTTP ${response.status})`);
  return (await response.json()).fresh === true;
}

// ---- the request path ---------------------------------------------------------------------------

function refusal(status, code, reason) {
  const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
  if (status === 503) headers['retry-after'] = '30';
  return new Response(JSON.stringify({ error: code, reason }), { status, headers });
}

function log(fields) {
  // Never the Signature header or the credential: a logged pair is a replayable request.
  console.log(JSON.stringify({ aidr: 'decision', ...fields }));
}

async function forward(request, config, identity, url) {
  const headers = new Headers(request.headers);
  // Nothing the client sends may look like it came from the edge.
  for (const name of [...headers.keys()]) if (name.startsWith('x-aidr-')) headers.delete(name);
  if (!config.forwardAgentHeaders) for (const name of AGENT_HEADERS) headers.delete(name);

  const target = config.origin ? new URL(url.pathname + url.search, config.origin) : url;
  const method = request.method.toUpperCase();
  const { context, signature } = await signEdgeContext({
    ...identity, method, target: targetOf(target.toString()), iat: Math.floor(clock() / 1000),
  }, config.secret);
  headers.set(CONTEXT_HEADER, context);
  headers.set(CONTEXT_SIGNATURE_HEADER, signature);

  const hasBody = !['GET', 'HEAD'].includes(method);
  const upstream = new Request(target.toString(), {
    method, headers, redirect: 'manual',
    body: hasBody ? request.body : null,
    ...(hasBody ? { duplex: 'half' } : {}),
  });
  return config.originService ? config.originService.fetch(upstream) : fetch(upstream);
}

async function handle(request, env, ctx) {
  let config;
  try {
    config = loadConfig(env);
  } catch (error) {
    console.error(JSON.stringify({ aidr: 'misconfigured', error: error.message }));
    return refusal(503, 'aidr.edge.misconfigured', 'the AIDR edge is not configured correctly');
  }

  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const path = url.pathname;

  if (isBypassed(config.bypass, path)) {
    return forward(request, config, { status: 'bypassed' }, url);
  }
  const headers = Object.fromEntries(request.headers);
  if (!AGENT_HEADERS.some((name) => name in headers)) {
    if (config.verifiedOnly?.(path)) {
      log({ outcome: 'refused', status: 401, code: 'aidr.edge.agent_required', method, path });
      const response = refusal(401, 'aidr.edge.agent_required',
        'this resource is for verified AI agents: present an AIDR credential and a signed request');
      // Where an agent finds out who to get an identity from.
      response.headers.set('link', `<${config.issuer}/.well-known/aiaf-registry>; rel="aiaf-registry"`);
      return response;
    }
    return forward(request, config, { status: 'anonymous' }, url);
  }

  const now = new Date(clock());
  try {
    const trust = await currentTrust(env, config, ctx);
    const identity = await verifyAgent(trust, {
      expectedIssuer: config.issuer,
      expectedAudience: config.expectedAudience ?? url.origin,
      minAgal: config.minAgal,
      minOal: config.minOal,
      minKal: config.minKal,
      requiredCapabilities: config.requiredCapabilities,
    }, {
      method, url: request.url, headers, now,
      claimNonce: (aid, nonce, created) => claimNonce(env, aid, nonce, created, 300),
    });
    log({ outcome: 'verified', aid: identity.aid, method, path });
    return forward(request, config, {
      status: 'verified', aid: identity.aid, organization: identity.organization,
      org_domains: identity.orgDomains, agal: identity.agal, oal: identity.oal, kal: identity.kal,
      capabilities: identity.capabilities, declared: identity.declared,
    }, url);
  } catch (error) {
    if (!(error instanceof AidrError)) {
      console.error(JSON.stringify({ aidr: 'unexpected_error', error: String(error?.message ?? error) }));
      // Never a pass and never a 500: an input we did not anticipate is an unverified request.
      return refusal(401, 'aidr.crypto.malformed_token', 'request could not be verified');
    }
    if (error instanceof UnknownIssuer && error.context?.kid) {
      // Perhaps the registry rotated its key. Ask for a (rate-limited) refresh; never wait on it.
      ctx.waitUntil(env.TRUST.get(env.TRUST.idFromName('trust'))
        .fetch('https://trust.internal/refresh-keys').catch(() => {}));
    }
    let status = 401;
    if (error instanceof RegistryUnavailable) status = 503;
    else if (FORBIDDEN.some((type) => error instanceof type)) status = 403;
    log({ outcome: 'refused', status, code: error.code, method, path });
    return refusal(status, error.code, error.message);
  }
}

export default {
  async fetch(request, env, ctx) {
    return handle(request, env, ctx);
  },
};

export const _internal = { resetForTests() {
  configCache = { env: null, config: null, error: null };
  trustCache = { issuer: null, trust: null, loadedAt: 0, snapshotAt: 0, reloadingSince: 0 };
} };
