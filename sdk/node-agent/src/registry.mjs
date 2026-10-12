/**
 * The two conversations an agent has with the registry: enrolling once (authenticated by the
 * enrollment token) and asking for credentials (authenticated by an RFC 9421 signature with the
 * agent's own key). The token is never needed again after enrollment.
 */

import { AgentIdentity } from './identity.mjs';
import { b64url, generateKey, publicJwk, signRaw } from './keys.mjs';
import { signRequest } from './signatures.mjs';

export const POP_CONTEXT = 'aiaf-pop-v1';
export const TOKEN_PREFIX = 'aidr_et_';

/** The registry refused, with its own error code (`aidr.…`) where it gave one. */
export class RegistryError extends Error {
  constructor(status, code, message) {
    super(`${message} (${code})`);
    this.status = status;
    this.code = code;
  }
}

async function refusal(response) {
  let error = {};
  try {
    error = (await response.json())?.error ?? {};
  } catch { /* not JSON */ }
  return new RegistryError(response.status, error.code ?? 'aidr.unknown',
    error.message ?? `the registry answered HTTP ${response.status}`);
}

/** The non-secret part of a token, for messages and logs: `etk_…`. */
export function tokenId(token) {
  if (!token.startsWith(TOKEN_PREFIX)) return '(not an enrollment token)';
  const parts = token.slice(TOKEN_PREFIX.length).split('_');
  return parts.length >= 3 ? `${parts[0]}_${parts[1]}` : '(not an enrollment token)';
}

/** Generate a key here, register the agent with the token, and prove the key. Two requests. */
export async function enroll(token, { name, registry, audiences = null, description = '', fetch: fetchImpl = fetch,
  privateKey = null } = {}) {
  if (!token?.startsWith(TOKEN_PREFIX)) throw new Error('that is not an enrollment token (they start with aidr_et_)');
  const key = privateKey ?? generateKey();
  const base = registry.replace(/\/+$/, '');
  const headers = { authorization: `AIDR-Enrollment ${token}`, 'aidr-pop-context': POP_CONTEXT,
    'content-type': 'application/json' };
  const body = { name, description, public_key_jwk: publicJwk(key), ...(audiences !== null ? { audiences } : {}) };

  const started = await fetchImpl(`${base}/v1/enroll`, { method: 'POST', headers, body: JSON.stringify(body) });
  if (started.status !== 201) throw await refusal(started);
  const registration = await started.json();
  const { challenge } = registration;
  if (!challenge?.sign_this?.startsWith(`${POP_CONTEXT}:`)) {
    throw new RegistryError(0, 'aidr.client.bad_challenge', 'the registry asked for a signature this SDK does not make');
  }
  const aid = registration.agent.aid;
  const proven = await fetchImpl(`${base}/v1/enroll/${aid}/proof`, { method: 'POST', headers,
    body: JSON.stringify({ challenge_id: challenge.challenge_id,
      signature: b64url(signRaw(key, Buffer.from(challenge.sign_this, 'utf8'))) }) });
  if (proven.status !== 200) throw await refusal(proven);
  return new AgentIdentity({ aid, name, registry: base, privateKey: key,
    audiences: registration.allowed_audiences ?? [] });
}

/**
 * Short-lived credentials (15 minutes or less), one per audience, renewed early. An agent with
 * allowed audiences gets a credential bound to each site; an unrestricted agent one unbound
 * credential (one issuance instead of one per site — issuance is what is billed).
 */
export class CredentialCache {
  constructor(identity, { fetch: fetchImpl = fetch, now = () => performance.now() / 1000 } = {}) {
    this.identity = identity;
    this.fetch = fetchImpl;
    this.now = now;
    this.cache = new Map();
    this.pending = new Map();
  }

  keyFor(origin) { return this.identity.audiences.length ? origin : null; }

  async get(origin) {
    const key = this.keyFor(origin);
    const cached = this.cache.get(key);
    if (cached && this.now() < cached.renewAt) return cached.token;
    // Concurrent requests for one audience share a single issuance.
    if (!this.pending.has(key)) {
      this.pending.set(key, this.#issue(key).finally(() => this.pending.delete(key)));
    }
    return this.pending.get(key);
  }

  async #issue(audience) {
    const url = `${this.identity.registry}/v1/credentials`;
    const headers = { ...signRequest({ method: 'POST', url, privateKey: this.identity.privateKey, keyid: this.identity.aid }),
      'content-type': 'application/json' };
    const body = JSON.stringify({ aid: this.identity.aid, ...(audience ? { audience } : {}) });
    const response = await this.fetch(url, { method: 'POST', headers, body });
    if (response.status !== 200) throw await refusal(response);
    const issued = await response.json();
    const now = this.now();
    this.cache.set(audience, { token: issued.credential, renewAt: now + issued.renew_after, expiresAt: now + issued.expires_in });
    return issued.credential;
  }

  /** Drop cached credentials (after a relying party refuses one: it may be revoked). */
  forget(origin = undefined) {
    if (origin === undefined) this.cache.clear();
    else this.cache.delete(this.keyFor(origin));
  }
}
