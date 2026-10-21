/**
 * The agent: load its identity or enroll once, then sign the requests it is allowed to sign.
 *
 * `signFor` — the origins this process presents the identity to — defaults to the audiences the
 * registry allows. An agent without audiences is unrestricted at the registry; this SDK then signs
 * for any https origin. Requests elsewhere go out unsigned (anonymous), or are refused with
 * `onUnlisted: 'refuse'`. Plain http is never signed except to localhost: a credential sent in
 * clear text is a credential given away.
 */

import { DEFAULT_REGISTRY, normalizeOrigin } from './identity.mjs';
import { EnvKeyStore, FileKeyStore } from './keystore.mjs';
import { CredentialCache, enroll, tokenId } from './registry.mjs';
import { CREDENTIAL_HEADER, signRequest } from './signatures.mjs';
import { signRequest as signWebBotAuth, signedDirectory } from './webbotauth.mjs';

/** The key directory URL that turns Web Bot Auth signing on (see `webBotAuth`). */
export const WEB_BOT_AUTH_ENV = 'AIDR_WEB_BOT_AUTH';

export const TOKEN_ENV = 'AIDR_ENROLLMENT_TOKEN';
export const REGISTRY_ENV = 'AIDR_REGISTRY_URL';

/** The agent was asked to identify itself to a site it is not allowed to (`onUnlisted: 'refuse'`). */
export class NotAllowed extends Error {}

export class Agent {
  /**
   * @param {import('./identity.mjs').AgentIdentity} identity
   * @param {object} [options]
   * @param {string[]} [options.signFor]    origins to identify to; default the registry's audiences
   * @param {'unsigned'|'refuse'} [options.onUnlisted]
   * @param {typeof fetch} [options.registryFetch]  for the registry only (a proxy, a private CA)
   * @param {() => Date} [options.clock]
   * @param {string} [options.webBotAuth]  the https URL of the key directory this agent's operator
   *   hosts (`webBotAuthDirectory`); default AIDR_WEB_BOT_AUTH. With it, each request is signed once
   *   in the Web Bot Auth profile, which Web Bot Auth verifiers such as Cloudflare's edge check,
   *   and AIDR verifiers 0.2.1 and later accept. Earlier AIDR verifiers refuse it: turn it on only
   *   where the sites you call run 0.2.1 or later. Ed25519 keys only.
   */
  constructor(identity, { signFor = null, onUnlisted = 'unsigned', registryFetch = fetch, clock = () => new Date(),
    webBotAuth = process.env[WEB_BOT_AUTH_ENV] || null } = {}) {
    this.identity = identity;
    this.webBotAuth = webBotAuth || null;
    const allowed = signFor === null ? identity.audiences : signFor.map(normalizeOrigin);
    if (identity.audiences.length && !allowed.every((o) => identity.audiences.includes(o))) {
      throw new NotAllowed(`the registry issues credentials only for ${identity.audiences.join(', ')}`);
    }
    this.signFor = new Set(allowed);
    if (onUnlisted !== 'unsigned' && onUnlisted !== 'refuse') throw new Error("onUnlisted must be 'unsigned' or 'refuse'");
    this.onUnlisted = onUnlisted;
    this.clock = clock;
    this.credentials = new CredentialCache(identity, { fetch: registryFetch });
  }

  get aid() { return this.identity.aid; }

  /**
   * The identity saved for `name`, or — first run only — enroll with the token (`token` or
   * AIDR_ENROLLMENT_TOKEN). After that the saved identity is enough; remove the token.
   */
  static async loadOrEnroll(name, { audiences = null, token = null, registry = null, keyStore = null, description = '',
    onUnlisted = 'unsigned', registryFetch = fetch, log = () => {}, env = process.env,
    webBotAuth = env[WEB_BOT_AUTH_ENV] || null } = {}) {
    const stores = keyStore ? [keyStore] : [new EnvKeyStore(undefined, env), new FileKeyStore()];
    for (const store of stores) {
      const identity = store.load(name);
      if (identity) {
        if (token || env[TOKEN_ENV]) log(`agent ${name} is already enrolled (${identity.aid}); ${TOKEN_ENV} is no longer needed`);
        return new Agent(identity, { onUnlisted, registryFetch, webBotAuth });
      }
    }
    const presented = token ?? env[TOKEN_ENV];
    if (!presented) {
      throw new Error(`agent ${JSON.stringify(name)} is not enrolled here and no enrollment token was given `
        + `(set ${TOKEN_ENV}, or pass token)`);
    }
    const target = registry ?? env[REGISTRY_ENV] ?? DEFAULT_REGISTRY;
    const writable = stores.find((s) => !(s instanceof EnvKeyStore));
    if (!writable) throw new Error('no writable key store to keep the new identity in');
    log(`enrolling agent ${name} at ${target} with token ${tokenId(presented)}`);
    const identity = await enroll(presented, { name, registry: target, description, fetch: registryFetch,
      audiences: audiences ? audiences.map(normalizeOrigin) : null });
    writable.save(identity);
    log(`enrolled ${identity.aid}`);
    return new Agent(identity, { onUnlisted, registryFetch, webBotAuth });
  }

  shouldSign(url) {
    const origin = normalizeOrigin(url);
    const [scheme, rest] = origin.split('://');
    const host = rest.split(':')[0];
    if (scheme !== 'https' && !(scheme === 'http' && (host === 'localhost' || host === '127.0.0.1'))) return false;
    return this.signFor.size ? this.signFor.has(origin) : true;
  }

  /** The headers that identify this agent on one request, or `{}` when it should not. */
  async signHeaders(method, url) {
    if (!this.shouldSign(url)) {
      if (this.onUnlisted === 'refuse') throw new NotAllowed(`${normalizeOrigin(url)} is not an origin this agent identifies to`);
      return {};
    }
    const credential = await this.credentials.get(normalizeOrigin(url));
    const signed = this.webBotAuth
      ? signWebBotAuth({ method, url, privateKey: this.identity.privateKey, signatureAgent: this.webBotAuth, created: this.clock() })
      : signRequest({ method, url, privateKey: this.identity.privateKey, keyid: this.identity.aid, created: this.clock() });
    return { ...signed, [CREDENTIAL_HEADER]: credential };
  }

  /**
   * The signed key directory to serve at https://<authority>/.well-known/
   * http-message-signatures-directory (and register with Cloudflare): `{ headers, body }`. It
   * expires after a day; serve a fresh one from a scheduled job.
   */
  webBotAuthDirectory(authority) {
    return signedDirectory(this.identity.privateKey, authority, { created: this.clock() });
  }
}
