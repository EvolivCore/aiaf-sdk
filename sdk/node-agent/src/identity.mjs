/**
 * An agent's identity: its identifier, where it is registered, what it may sign for, and its key.
 * The same document as the Python SDK (`aidr-agent-identity/1`), so an identity enrolled from
 * either language is used by the other.
 */

import { privateJwk, privateKeyFromJwk, publicJwk } from './keys.mjs';

export const DEFAULT_REGISTRY = 'https://api.evolivcore.com';
export const FORMAT = 'aidr-agent-identity/1';

export class IdentityError extends Error {}

/** `https://Shop.Example:443/path` → `https://shop.example` (the registry's normalisation). */
export function normalizeOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`not a URL: ${value}`);
  }
  if (!url.hostname) throw new Error(`not a URL: ${value}`);
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  return `${url.protocol}//${host}${url.port ? `:${url.port}` : ''}`;
}

export class AgentIdentity {
  constructor({ aid, name, registry, privateKey, audiences = [] }) {
    Object.assign(this, { aid, name, registry, audiences: [...audiences] });
    Object.defineProperty(this, 'privateKey', { value: privateKey, enumerable: false });  // never in logs
  }

  publicJwk() { return publicJwk(this.privateKey); }

  /** Everything, private key included. Treat the result as a secret. */
  toDocument() {
    return { format: FORMAT, aid: this.aid, name: this.name, registry: this.registry,
      audiences: [...this.audiences], private_jwk: privateJwk(this.privateKey) };
  }

  static fromDocument(document) {
    if (document?.format !== FORMAT) throw new IdentityError(`not an ${FORMAT} document`);
    try {
      return new AgentIdentity({ aid: document.aid, name: document.name, registry: document.registry,
        audiences: document.audiences ?? [], privateKey: privateKeyFromJwk(document.private_jwk) });
    } catch (error) {
      throw new IdentityError(`malformed identity: ${error.message}`);
    }
  }

  /** One line for a secret store: base64url(JSON). A secret — it holds the private key. */
  toPortable() {
    return Buffer.from(JSON.stringify(this.toDocument())).toString('base64url');
  }

  static fromPortable(value) {
    try {
      return AgentIdentity.fromDocument(JSON.parse(Buffer.from(value.trim(), 'base64url').toString('utf8')));
    } catch (error) {
      if (error instanceof IdentityError) throw error;
      throw new IdentityError('AIDR_AGENT_IDENTITY is not a valid identity');
    }
  }
}
