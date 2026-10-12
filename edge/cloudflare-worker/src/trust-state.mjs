/**
 * The registry's trust material, fetched once for the whole deployment.
 *
 * One Durable Object ("trust") fetches the JWKS (hourly) and a complete revocation snapshot (every
 * 60 s, on its own alarm — no cron needed) and serves the last verified snapshot to isolates.
 * Isolates re-verify what they load: storage is ours, but a snapshot that does not verify is never
 * used, and a signed revocation feed is the only kind that cannot be silently stripped.
 *
 * Where to fetch from comes from the registry's discovery document, and every endpoint it names
 * must be on the issuer's own origin. The JWKS itself is not signed; its authenticity rests on TLS
 * to the issuer, and a discovery document pointing elsewhere would hand that trust to someone else.
 */

import { nowMs } from './clock.mjs';
import { RegistryUnavailable } from './errors.mjs';
import { TrustStore } from './verifier.mjs';

const REVOCATION_REFRESH_MS = 60 * 1000;
const JWKS_REFRESH_MS = 60 * 60 * 1000;
const KEY_REFRESH_MIN_INTERVAL_MS = 60 * 1000;

const originOf = (url) => {
  const parsed = new URL(url);
  return `${parsed.protocol}//${parsed.host}`.toLowerCase();
};

async function getJson(url, what) {
  const response = await fetch(url, { redirect: 'manual', headers: { accept: 'application/json' } });
  if (response.status !== 200) {
    throw new RegistryUnavailable(`${what}: GET ${url} returned HTTP ${response.status}`);
  }
  const body = await response.json();
  if (typeof body !== 'object' || body === null) throw new RegistryUnavailable(`${what}: not a JSON object`);
  return body;
}

export class TrustState {
  constructor(state, env) {
    this.storage = state.storage;
    this.issuer = String(env.AIDR_ISSUER ?? '').replace(/\/+$/, '');
  }

  async fetch(request) {
    const { pathname } = new URL(request.url);
    try {
      if (pathname === '/snapshot') {
        let snapshot = await this.storage.get('snapshot');
        if (!snapshot || Date.now() - snapshot.fetchedAt > REVOCATION_REFRESH_MS) {
          try {
            snapshot = await this.refresh({ forceKeys: false });
          } catch (error) {
            // Serve the last verified snapshot; the isolate decides whether it is too old.
            if (!snapshot) throw error;
            console.warn(JSON.stringify({ aidr: 'trust_refresh_failed', error: error.message }));
          }
        }
        await this.ensureAlarm();
        return Response.json(snapshot);
      }
      if (pathname === '/refresh-keys') {
        const last = (await this.storage.get('keysRequestedAt')) ?? 0;
        if (Date.now() - last >= KEY_REFRESH_MIN_INTERVAL_MS) {
          await this.storage.put('keysRequestedAt', Date.now());
          await this.refresh({ forceKeys: true });
        }
        return Response.json({ ok: true });
      }
      return new Response('not found', { status: 404 });
    } catch (error) {
      return Response.json({ error: 'aidr.registry.unavailable', reason: error.message },
        { status: 503 });
    }
  }

  async alarm() {
    try {
      await this.refresh({ forceKeys: false });
    } catch (error) {
      console.warn(JSON.stringify({ aidr: 'trust_refresh_failed', error: error.message }));
    } finally {
      await this.storage.setAlarm(Date.now() + REVOCATION_REFRESH_MS);
    }
  }

  async ensureAlarm() {
    if ((await this.storage.getAlarm()) === null) {
      await this.storage.setAlarm(Date.now() + REVOCATION_REFRESH_MS);
    }
  }

  async endpoints() {
    if (!/^https:\/\//.test(this.issuer)) {
      throw new RegistryUnavailable('AIDR_ISSUER must be an https:// URL');
    }
    const document = await getJson(`${this.issuer}/.well-known/aiaf-registry`, 'discovery');
    if (String(document.issuer ?? '').replace(/\/+$/, '') !== this.issuer) {
      throw new RegistryUnavailable('discovery document names a different issuer');
    }
    const found = { jwks: String(document.jwks_uri ?? ''),
      delta: String(document.revocation_delta_endpoint ?? '') };
    for (const url of Object.values(found)) {
      let origin;
      try { origin = originOf(url); } catch { origin = null; }
      if (origin !== originOf(this.issuer)) {
        throw new RegistryUnavailable("discovery points trust material off the issuer's origin; refusing it");
      }
    }
    return found;
  }

  /** Fetch, verify, and only then store. A failed refresh never replaces a good snapshot. */
  async refresh({ forceKeys }) {
    const previous = await this.storage.get('snapshot');
    const endpoints = await this.endpoints();
    const now = Date.now();

    let { jwks, jwksFetchedAt } = previous ?? {};
    if (forceKeys || !jwks || now - jwksFetchedAt > JWKS_REFRESH_MS) {
      jwks = await getJson(endpoints.jwks, 'jwks');
      jwksFetchedAt = now;
    }
    const deltaUrl = new URL(endpoints.delta);
    deltaUrl.searchParams.set('since', '0');
    const { delta } = await getJson(deltaUrl.toString(), 'revocation');

    let trust;
    try {
      trust = new TrustStore(jwks, { expectedIssuer: this.issuer });
      await trust.ingestSnapshot(delta, { now: new Date(nowMs()) });
    } catch (error) {
      if (forceKeys) throw error;
      // Perhaps the registry rotated its key: try once more with fresh keys.
      return this.refresh({ forceKeys: true });
    }

    const snapshot = { issuer: this.issuer, jwks, jwksFetchedAt, delta, serial: trust.serial,
      fetchedAt: now };
    await this.storage.put('snapshot', snapshot);
    return snapshot;
  }
}
