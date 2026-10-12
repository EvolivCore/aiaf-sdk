/**
 * Live check: the worker on workerd (via miniflare), real SQLite Durable Objects, trust synced from
 * a real registry, requests signed by the CLI mock agent (scripts/staging_agent.py).
 *
 *   NODE_EXTRA_CA_CERTS=deploy/terraform/staging/staging-edge.pem \
 *   AIDR_ISSUER=https://evolivcore.com AGENT_KEY=/state/agent-key.json AGENT_AID=aid:v1:... \
 *   node edge/cloudflare-worker/test/integration/live-staging.mjs
 *
 * Needs `miniflare` resolvable (NODE_PATH) and python3 with `cryptography` for the mock agent.
 * The origin is played by this script: it accepts only requests whose edge context verifies.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { verifyEdgeContext } from '../../src/edge-context.mjs';

// MINIFLARE_FROM=/opt/mf resolves miniflare from an install outside the repo.
const miniflareEntry = process.env.MINIFLARE_FROM
  ? pathToFileURL(createRequire(join(process.env.MINIFLARE_FROM, 'noop.js')).resolve('miniflare')).href
  : 'miniflare';
const { Miniflare, Response: MfResponse } = await import(miniflareEntry);

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = resolve(HERE, '../..');
const REPO = resolve(WORKER, '../..');
const ISSUER = process.env.AIDR_ISSUER;
const KEY = process.env.AGENT_KEY;
const AID = process.env.AGENT_AID;
const SITE = 'https://shop.example';
const SECRET = 'live-check-edge-context-secret-0123456789';

const results = [];
const check = (name, ok, detail) => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ${detail}`); };

// ---- the mock agent ------------------------------------------------------------------------------
const work = mkdtempSync(join(tmpdir(), 'aidr-live-'));
function signedHeaders(method, url) {
  const out = join(work, 'sig.txt');
  execFileSync('python3', [join(REPO, 'scripts/staging_agent.py'), 'sign', KEY, AID, method, url, out]);
  return Object.fromEntries(readFileSync(out, 'utf8').trim().split('\n').map((line) => {
    const index = line.indexOf(': ');
    return [line.slice(0, index), line.slice(index + 2)];
  }));
}

async function freshCredential() {
  const url = `${ISSUER}/v1/credentials`;
  const response = await fetch(url, {
    method: 'POST', headers: { ...signedHeaders('POST', url), 'content-type': 'application/json' },
    body: JSON.stringify({ aid: AID }),
  });
  const body = await response.json();
  if (!body.credential) throw new Error(`credential issuance failed: ${JSON.stringify(body)}`);
  return body.credential;
}

// ---- the origin, and the registry passthrough ---------------------------------------------------
const originSaw = [];
async function outbound(request) {
  const url = new URL(request.url);
  if (url.hostname === 'origin.internal') {
    try {
      const context = await verifyEdgeContext(
        { method: request.method, url: request.url, headers: request.headers }, SECRET);
      originSaw.push({ context, headers: Object.fromEntries(request.headers) });
      return new MfResponse(JSON.stringify({ origin: 'ok', context }), {
        headers: { 'content-type': 'application/json' } });
    } catch (error) {
      return new MfResponse(JSON.stringify({ error: error.code, reason: error.message }), { status: 401 });
    }
  }
  // Everything else (the registry) goes out for real, trusting NODE_EXTRA_CA_CERTS.
  const upstream = await fetch(request.url, { method: request.method, headers: request.headers,
    redirect: 'manual' });
  return new MfResponse(await upstream.arrayBuffer(), { status: upstream.status, headers: upstream.headers });
}

function edge(extraBindings = {}) {
  return new Miniflare({
    modules: true,
    scriptPath: join(WORKER, 'src/worker.mjs'),
    modulesRoot: WORKER,
    modulesRules: [{ type: 'ESModule', include: ['**/*.mjs'] }],
    compatibilityDate: '2025-09-01',
    bindings: {
      AIDR_ISSUER: ISSUER, AIDR_EDGE_CONTEXT_SECRET: SECRET, AIDR_ORIGIN: 'https://origin.internal',
      AIDR_BYPASS: '["/health"]', ...extraBindings,
    },
    durableObjects: {
      NONCES: { className: 'NonceStore', useSQLite: true },
      TRUST: { className: 'TrustState', useSQLite: true },
    },
    outboundService: outbound,
  });
}

async function call(mf, path, headers = {}) {
  const response = await mf.dispatchFetch(`${SITE}${path}`, { headers });
  return { status: response.status, body: await response.json() };
}

// ---- the run ----------------------------------------------------------------------------------------
const credential = await freshCredential();
console.log(`credential issued for ${AID}`);
const agent = (path) => ({ ...signedHeaders('GET', `${SITE}${path}`), 'Agent-Credential': credential });

let mf = edge();
try {
  let r = await call(mf, '/whoami');
  check('anonymous is forwarded as anonymous', r.status === 200 && r.body.context?.status === 'anonymous',
    `${r.status} ${r.body.context?.status}`);

  const headers = agent('/whoami');
  r = await call(mf, '/whoami', headers);
  const seen = originSaw.at(-1);
  check('verified agent reaches the origin with its identity',
    r.status === 200 && r.body.context?.status === 'verified' && r.body.context?.aid === AID,
    `${r.status} ${r.body.context?.aid} AgAL${r.body.context?.agal} ${JSON.stringify(r.body.context?.org_domains)}`);
  check("the agent's own headers are stripped before the origin",
    !('agent-credential' in seen.headers) && !('signature' in seen.headers), '');

  r = await call(mf, '/whoami', headers);
  check('replayed request is refused (Durable Object nonce store)',
    r.status === 401 && r.body.error === 'aidr.verify.replay_detected', `${r.status} ${r.body.error}`);

  r = await call(mf, '/whoami', { 'Agent-Credential': credential });
  check('credential without a signature is refused', r.status === 401, `${r.status} ${r.body.error}`);

  r = await call(mf, '/health', { Signature: 'sig1=:AAAA:' });
  check('bypassed path is never verified', r.status === 200 && r.body.context?.status === 'bypassed',
    `${r.status} ${r.body.context?.status}`);

  r = await call(mf, '/whoami', { 'X-AIDR-Context': 'forged', 'X-AIDR-Org': 'acme-corp' });
  check('client-sent x-aidr-* headers never reach the origin',
    r.status === 200 && r.body.context?.status === 'anonymous' && !('x-aidr-org' in originSaw.at(-1).headers),
    `${r.status}`);
} finally {
  await mf.dispose();
}

mf = edge({ AIDR_MIN_AGAL: '2' });
try {
  const r = await call(mf, '/whoami', agent('/whoami'));
  check('valid agent below an AgAL floor of 2 is refused 403',
    r.status === 403 && r.body.error === 'aidr.verify.assurance_too_low', `${r.status} ${r.body.reason}`);
} finally {
  await mf.dispose();
}

const direct = await outbound(new Request('https://origin.internal/whoami'));
check('a request straight to the origin (no edge) is refused', direct.status === 401, `${direct.status}`);

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} live checks passed`);
process.exit(failed ? 1 : 0);
