'use strict';

/**
 * AIDR verification for Kong Gateway: the `aidr` plugin, for Kong's JavaScript plugin server
 * (kong-js-pdk). It runs the published verifier, @evoliv/aidr-verifier, unchanged: the code that
 * passes the shared AIAF conformance vectors. Nothing here re-implements cryptography.
 *
 * Why JavaScript, not Lua: verifying an agent is two signatures, the issuer's keys, revocation,
 * replay and clock windows. A Lua copy would be a fourth implementation to keep in step with the
 * standard; this plugin is a thin adapter over the one that is already tested.
 *
 * Per request, in the access phase:
 *   anonymous  no Agent-Credential, Signature or Signature-Input: proxied (unless a verified-only
 *              path), with X-AIDR-Status: anonymous;
 *   verified   proxied, with X-AIDR-Status: verified and the identity in X-AIDR-* headers;
 *   refused    401 / 403 / 503 with JSON {error, reason}; never reaches the service.
 * X-AIDR-* headers a client sent are always removed first, so the service can trust them.
 *
 * Keys (hourly) and the signed revocation list (every 60 s) are refreshed in the background;
 * nothing on the request path calls the registry. Replay protection is in memory, shared by every
 * worker of this Kong node (one plugin server per node). Several Kong nodes: see README.md.
 */

const AGENT_HEADERS = ['agent-credential', 'signature', 'signature-input'];
const IDENTITY_HEADERS = {
  'X-AIDR-Agent': (id) => id.aid,
  'X-AIDR-Organization': (id) => id.organization,
  'X-AIDR-Org-Domains': (id) => (id.orgDomains ?? []).join(','),
  'X-AIDR-AgAL': (id) => String(id.agal),
  'X-AIDR-OAL': (id) => String(id.oal),
  'X-AIDR-KAL': (id) => String(id.kal),
  'X-AIDR-Capabilities': (id) => (id.capabilities ?? []).join(','),
};

// One verifier per distinct configuration, shared by every request that uses it, so the key and
// revocation refresh runs once per configuration rather than once per request.
const verifiers = new Map();
let hooks = { loadSdk: () => import('@evoliv/aidr-verifier'), fetch: undefined, clock: () => new Date() };

function verifierFor(config) {
  const key = JSON.stringify(config);
  if (!verifiers.has(key)) {
    const ready = (async () => {
      const sdk = await hooks.loadSdk();
      const origins = String(config.public_origin ?? '').split(',').map((o) => o.trim()).filter(Boolean);
      if (origins.length === 0) throw new Error('aidr: public_origin is required (this API\'s origin as agents call it)');
      const middleware = sdk.aidr({
        issuer: config.issuer || 'https://api.evolivcore.com',
        publicOrigin: origins,
        mode: config.mode || 'open',
        verifiedOnlyPaths: config.verified_only_paths?.length ? config.verified_only_paths : null,
        bypass: config.bypass ?? [],
        minAgal: config.min_agal ?? 0,
        minOal: config.min_oal ?? 0,
        minKal: config.min_kal ?? 0,
        requiredCapabilities: config.required_capabilities ?? [],
        ...(hooks.fetch ? { fetch: hooks.fetch } : {}),
        clock: hooks.clock,
      });
      await middleware.ready;
      return middleware;
    })();
    ready.catch(() => verifiers.delete(key));   // a failed start is retried by the next request
    verifiers.set(key, ready);
  }
  return verifiers.get(key);
}

/** Run the verifier the way a Node server would, and report what it decided. */
function decide(middleware, method, target, headers) {
  return new Promise((resolve) => {
    const req = { method, originalUrl: target, url: target, headers };
    const res = {
      statusCode: 200, headers: {},
      setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
      end(body) {
        let parsed = {};
        try { parsed = JSON.parse(body); } catch { /* not JSON */ }
        resolve({ refused: true, status: this.statusCode, body: parsed, headers: this.headers });
      },
    };
    middleware(req, res, () => resolve({ refused: false, identity: req.aidr }));
  });
}

class AidrPlugin {
  constructor(config) {
    this.config = config;
  }

  async access(kong) {
    const raw = await kong.request.getHeaders();
    const headers = {};
    for (const [name, value] of Object.entries(raw ?? {})) {
      headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
    }
    for (const name of Object.keys(headers)) {
      if (name.startsWith('x-aidr-')) await kong.service.request.clearHeader(name);
    }

    const isAgent = AGENT_HEADERS.some((name) => name in headers);
    let middleware;
    try {
      middleware = await verifierFor(this.config);
    } catch (error) {
      await kong.log.err(`aidr: ${error.message}`);
      if (!isAgent && (this.config.mode || 'open') === 'open') {
        await kong.service.request.setHeader('X-AIDR-Status', 'anonymous');
        return;
      }
      return kong.response.exit(503, { error: 'aidr.registry.unavailable', reason: 'agent verification is not available' },
        { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    }

    // The path and query exactly as the client sent them: that is what its signature covers.
    const path = await kong.request.getRawPath();
    const query = await kong.request.getRawQuery();
    const method = await kong.request.getMethod();
    const outcome = await decide(middleware, method, query ? `${path}?${query}` : path, headers);

    if (outcome.refused) {
      const extra = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
      if (outcome.headers['retry-after']) extra['Retry-After'] = outcome.headers['retry-after'];
      if (outcome.headers.link) extra.Link = outcome.headers.link;
      return kong.response.exit(outcome.status, outcome.body, extra);
    }

    const identity = outcome.identity;
    await kong.service.request.setHeader('X-AIDR-Status', identity.status);
    if (identity.status === 'verified') {
      for (const [name, read] of Object.entries(IDENTITY_HEADERS)) {
        await kong.service.request.setHeader(name, read(identity));
      }
    }
  }
}

module.exports = {
  Plugin: AidrPlugin,
  Schema: [
    { public_origin: { type: 'string', required: true } },
    { issuer: { type: 'string', default: 'https://api.evolivcore.com' } },
    { mode: { type: 'string', default: 'open', one_of: ['open', 'verified-only'] } },
    { verified_only_paths: { type: 'array', elements: { type: 'string' }, default: [] } },
    { bypass: { type: 'array', elements: { type: 'string' }, default: [] } },
    { min_agal: { type: 'integer', default: 0, between: [0, 3] } },
    { min_oal: { type: 'integer', default: 0, between: [0, 3] } },
    { min_kal: { type: 'integer', default: 0, between: [0, 3] } },
    { required_capabilities: { type: 'array', elements: { type: 'string' }, default: [] } },
  ],
  Version: '0.1.0',
  // Before rate limiting and request transformation, with Kong's other authentication plugins.
  Priority: 1100,
  /** For tests: replace how the SDK is loaded and the registry fetched, and the clock. */
  _hooks(overrides) {
    hooks = { ...hooks, ...overrides };
    for (const ready of verifiers.values()) ready.then((m) => m.close(), () => {});
    verifiers.clear();
  },
};
