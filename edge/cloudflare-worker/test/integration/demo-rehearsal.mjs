/**
 * Rehearse the Phase 1 demo on this machine: the edge (demo settings, verified agents only) and the
 * demo origin, both on workerd via miniflare, the origin behind a service binding, trust synced from
 * the real registry. Serves http://127.0.0.1:8787 until stopped; run the agent against it with
 * sdk/python/examples/worker_demo.py. scripts/rehearse_worker_demo.sh runs both in containers.
 *
 *   MINIFLARE_FROM=/opt/mf AIDR_ISSUER=https://api.evolivcore.com node demo-rehearsal.mjs
 */

import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const miniflareEntry = process.env.MINIFLARE_FROM
  ? pathToFileURL(createRequire(join(process.env.MINIFLARE_FROM, 'noop.js')).resolve('miniflare')).href
  : 'miniflare';
const { Miniflare } = await import(miniflareEntry);

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = resolve(HERE, '../..');
const SECRET = 'demo-rehearsal-edge-context-secret-0123456789';
const PORT = Number(process.env.PORT ?? 8787);

const common = {
  modules: true,
  modulesRoot: WORKER,
  modulesRules: [{ type: 'ESModule', include: ['**/*.mjs'] }],
  compatibilityDate: '2025-09-01',
};

const mf = new Miniflare({
  host: '0.0.0.0',
  port: PORT,
  workers: [
    {
      ...common,
      name: 'aidr-edge-demo',
      scriptPath: join(WORKER, 'src/worker.mjs'),
      // The same settings as [env.demo] in wrangler.toml.
      bindings: {
        AIDR_ISSUER: process.env.AIDR_ISSUER ?? 'https://api.evolivcore.com',
        AIDR_EDGE_CONTEXT_SECRET: SECRET,
        AIDR_MODE: 'verified-only',
        AIDR_VERIFIED_ONLY_PATHS: '["/agents/.*"]',
        AIDR_BYPASS: '[]',
        AIDR_MIN_AGAL: '0', AIDR_MIN_OAL: '0', AIDR_MIN_KAL: '0',
      },
      serviceBindings: { ORIGIN: 'aidr-demo-origin' },
      durableObjects: {
        NONCES: { className: 'NonceStore', useSQLite: true },
        TRUST: { className: 'TrustState', useSQLite: true },
      },
    },
    {
      ...common,
      name: 'aidr-demo-origin',
      scriptPath: join(WORKER, 'demo/origin.mjs'),
      bindings: { AIDR_EDGE_CONTEXT_SECRET: SECRET },
    },
  ],
});

const url = await mf.ready;
console.log(`demo edge listening on ${url} (verified agents only below /agents/)`);
process.on('SIGTERM', async () => { await mf.dispose(); process.exit(0); });
