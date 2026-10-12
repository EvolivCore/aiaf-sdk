/**
 * Keep a TrustStore current in the background: the registry's JWKS hourly (and, rate-limited, on
 * demand when a credential names a kid we have not seen, which is what a key rotation looks like),
 * and the signed revocation delta every 60 seconds from the serial we hold. A delta that would
 * leave a gap triggers a rebuild from serial 0 rather than being skipped.
 *
 * Where things come from is the registry's discovery document, and every endpoint it names must be
 * on the issuer's own origin: the JWKS is not itself signed, so its authenticity rests on TLS to
 * the issuer. Same protocol as the Python SDK (aidr_verifier.sync). Nothing here is on the request
 * path, and the timers are unref'd, so they never keep a process alive by themselves.
 */

import {
  JWKS_REFRESH_SECONDS, KeySet, REVOCATION_REFRESH_SECONDS, RevocationState, TrustStore,
} from './trust.mjs';
import { MalformedToken, RegistryUnavailable } from './util.mjs';

export const DISCOVERY_PATH = '/.well-known/aiaf-registry';
/** How soon to retry after a failed fetch: a failed revocation fetch is time spent not learning. */
export const RETRY_SECONDS = 15;
/** At most one out-of-schedule JWKS fetch per this interval, however many unknown kids arrive. */
export const UNKNOWN_KID_REFRESH_SECONDS = 60;

export class TrustSync {
  /**
   * @param {string} issuer the registry, exactly as in credentials' `iss`
   * @param {{ fetch?: typeof fetch, jwksInterval?: number, revocationInterval?: number,
   *           timeoutMs?: number }} [options]
   */
  constructor(issuer, { fetch: fetchImpl = globalThis.fetch, jwksInterval = JWKS_REFRESH_SECONDS,
    revocationInterval = REVOCATION_REFRESH_SECONDS, timeoutMs = 10_000 } = {}) {
    this.issuer = String(issuer).replace(/\/+$/, '');
    if (!/^https?:\/\//.test(this.issuer)) throw new Error('issuer must be an https:// URL');
    this.fetch = fetchImpl;
    this.jwksInterval = jwksInterval;
    this.revocationInterval = revocationInterval;
    this.timeoutMs = timeoutMs;
    this.trust = null;
    this.lastError = null;
    this.endpoints = null;
    this.timers = [];
    this.lastKidRefresh = 0;
    this.kidRefresh = null;
  }

  /** Trust is usable: keys loaded and an exact revocation set. */
  get ready() {
    return Boolean(this.trust && this.trust.revocation.exact);
  }

  /** First load (awaited), then the two background loops. Resolves false if the first load failed. */
  async start() {
    let ok = true;
    try {
      await this.refreshAll();
    } catch (error) {
      ok = false;
      this.lastError = `${error.name}: ${error.message}`;
    }
    this.#loop(() => this.refreshJwks(), this.jwksInterval);
    this.#loop(() => this.refreshRevocations(), this.revocationInterval);
    return ok;
  }

  stop() {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers = [];
  }

  #loop(refresh, intervalSeconds) {
    const schedule = (seconds) => {
      const timer = setTimeout(async () => {
        this.timers = this.timers.filter((t) => t !== timer);
        let next = intervalSeconds;
        try {
          await refresh();
          this.lastError = null;
        } catch (error) {
          this.lastError = `${error.name}: ${error.message}`;
          next = Math.min(intervalSeconds, RETRY_SECONDS);
        }
        schedule(next);
      }, seconds * 1000);
      timer.unref?.();
      this.timers.push(timer);
    };
    schedule(intervalSeconds);
  }

  async #getJson(url, params = {}) {
    const target = new URL(url);
    for (const [key, value] of Object.entries(params)) target.searchParams.set(key, String(value));
    let response;
    try {
      response = await this.fetch(target, { signal: AbortSignal.timeout(this.timeoutMs),
        headers: { accept: 'application/json' } });
    } catch (error) {
      throw new RegistryUnavailable(`GET ${target} failed: ${error.message}`);
    }
    if (response.status !== 200) throw new RegistryUnavailable(`GET ${target} returned HTTP ${response.status}`);
    const body = await response.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new MalformedToken(`GET ${target} did not return a JSON object`);
    }
    return body;
  }

  async #endpoints() {
    if (this.endpoints) return this.endpoints;
    const document = await this.#getJson(this.issuer + DISCOVERY_PATH);
    if (String(document.issuer ?? '').replace(/\/+$/, '') !== this.issuer) {
      throw new RegistryUnavailable('discovery document names a different issuer');
    }
    const found = { jwks: String(document.jwks_uri ?? ''),
      revocationDelta: String(document.revocation_delta_endpoint ?? '') };
    const origin = new URL(this.issuer).origin;
    for (const url of Object.values(found)) {
      let sameOrigin = false;
      try { sameOrigin = new URL(url).origin === origin; } catch { sameOrigin = false; }
      if (!sameOrigin) {
        throw new RegistryUnavailable("discovery points trust material off the issuer's origin; refusing it");
      }
    }
    this.endpoints = found;
    return found;
  }

  async refreshAll() {
    await this.refreshJwks();
    await this.refreshRevocations();
  }

  async refreshJwks() {
    const document = await this.#getJson((await this.#endpoints()).jwks);
    // fromJwks throws on an unusable document, leaving the keys we hold: a bad fetch never wipes trust.
    const keySet = KeySet.fromJwks(document);
    if (this.trust) this.trust.keySet = keySet;
    else this.trust = new TrustStore(keySet, { expectedIssuer: this.issuer });
  }

  async refreshRevocations() {
    if (!this.trust) await this.refreshJwks();
    const url = (await this.#endpoints()).revocationDelta;
    const state = this.trust.revocation;
    if (!state.exact) return this.#rebuild(url);
    const body = await this.#getJson(url, { since: state.serial });
    try {
      this.trust.ingestDelta(String(body.delta ?? ''));
    } catch (error) {
      if (!(error instanceof RegistryUnavailable)) throw error;
      // A gap between our serial and the delta: start again from zero rather than guess.
      await this.#rebuild(url);
    }
  }

  async #rebuild(url) {
    const body = await this.#getJson(url, { since: 0 });
    const fresh = new TrustStore(this.trust.keySet,
      { revocation: new RevocationState(), expectedIssuer: this.issuer });
    fresh.ingestDelta(String(body.delta ?? ''));
    // Swap only a complete, verified state in: readers never see a half-built one.
    this.trust.revocation = fresh.revocation;
  }

  /** A credential named an unknown kid. Rate-limited, never awaited by the request. */
  requestKeyRefresh() {
    const now = Date.now();
    if (now - this.lastKidRefresh < UNKNOWN_KID_REFRESH_SECONDS * 1000 || this.kidRefresh) return;
    this.lastKidRefresh = now;
    this.kidRefresh = this.refreshJwks()
      .catch((error) => { this.lastError = `${error.name}: ${error.message}`; })
      .finally(() => { this.kidRefresh = null; });
  }

  health() {
    return { ...(this.trust?.health() ?? {}), ready: this.ready, lastError: this.lastError };
  }
}
