/**
 * Web Bot Auth: the IETF webbotauth profile of RFC 9421, as Cloudflare verifies it. The same
 * output, byte for byte in structure, as aidr_crypto.web_bot_auth in Python.
 *
 * With it on (`new Agent(identity, { webBotAuth: 'https://agent.example.com' })` or
 * AIDR_WEB_BOT_AUTH), an agent signs each request once, in this profile:
 *
 *   Signature-Agent: "https://agent.example.com"
 *   Signature-Input: wba=("@authority" "@method" "@path" "signature-agent");created=…;expires=…;
 *       keyid="<JWK thumbprint>";alg="ed25519";nonce="…";tag="web-bot-auth"
 *
 * AIDR verifiers 0.2.1 and later accept it (the keyid names the credential's own key), and Web Bot
 * Auth verifiers check it through the key directory at Signature-Agent. One signature, not two:
 * Cloudflare's verifier refuses a request with several unless told which to check.
 *
 * Where the drafts and Cloudflare differ, Cloudflare wins: Signature-Agent is a bare quoted string
 * (Cloudflare rejects the dictionary form), and `signature-agent` is covered without a `key`
 * parameter (Cloudflare does not support it). Ed25519 only: the one algorithm Cloudflare verifies.
 */

import { createHash, randomBytes } from 'node:crypto';

import { algorithmOf, publicJwk, signRaw } from './keys.mjs';

export const TAG = 'web-bot-auth';
export const DIRECTORY_TAG = 'http-message-signatures-directory';
export const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
export const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';
export const LABEL = 'wba';
export const COMPONENTS = ['@authority', '@method', '@path', 'signature-agent'];
/** The age AIDR verifiers accept. Cloudflare sets no maximum and suggests short lifetimes. */
export const DEFAULT_LIFETIME_SECONDS = 300;

/** The base64url SHA-256 JWK thumbprint (RFC 7638; RFC 8037 appendix A.3 for OKP keys). */
export function jwkThumbprint(jwk) {
  const members = { OKP: ['crv', 'kty', 'x'], EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'] }[jwk?.kty];
  if (!members || members.some((name) => typeof jwk[name] !== 'string')) {
    throw new Error(`cannot take the thumbprint of a ${jwk?.kty} key`);
  }
  const canonical = `{${members.map((name) => `"${name}":${JSON.stringify(jwk[name])}`).join(',')}}`;
  return createHash('sha256').update(canonical).digest('base64url');
}

function ed25519Jwk(privateKey) {
  if (algorithmOf(privateKey) !== 'Ed25519') {
    throw new Error('Web Bot Auth signatures need an Ed25519 key (the one algorithm Cloudflare verifies)');
  }
  return publicJwk(privateKey);
}

function signatureAgentValue(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new Error(`Signature-Agent must be an https:// URL, not ${url}`);
  return String(url).replace(/\/+$/, '');
}

/**
 * The headers of one request's Web Bot Auth signature: Signature-Agent, Signature-Input, Signature.
 * `created` (a Date), `lifetimeSeconds` and `nonce` exist for tests and vectors.
 */
export function signRequest({ method, url, privateKey, signatureAgent, created = new Date(),
  lifetimeSeconds = DEFAULT_LIFETIME_SECONDS, nonce = randomBytes(64).toString('base64') }) {
  const agentHeader = `"${signatureAgentValue(signatureAgent)}"`;
  const target = new URL(url);
  const createdAt = Math.floor(created.getTime() / 1000);
  const params = [
    `(${COMPONENTS.map((c) => `"${c}"`).join(' ')})`,
    `;created=${createdAt}`,
    `;expires=${createdAt + lifetimeSeconds}`,
    `;keyid="${jwkThumbprint(ed25519Jwk(privateKey))}"`,
    ';alg="ed25519"',
    `;nonce="${nonce}"`,
    `;tag="${TAG}"`,
  ].join('');
  const values = {
    '@authority': target.host,          // WHATWG URL: host lower-cased, default port dropped
    '@method': method.toUpperCase(),
    '@path': target.pathname || '/',
    'signature-agent': agentHeader,
  };
  const base = [...COMPONENTS.map((c) => `"${c}": ${values[c]}`), `"@signature-params": ${params}`].join('\n');
  const signature = signRaw(privateKey, Buffer.from(base, 'utf8'));
  return {
    'Signature-Agent': agentHeader,
    'Signature-Input': `${LABEL}=${params}`,
    Signature: `${LABEL}=:${Buffer.from(signature).toString('base64')}:`,
  };
}

/**
 * The key directory an agent's operator serves at https://<authority>/.well-known/
 * http-message-signatures-directory and registers with Cloudflare: `{ headers, body }`, signed by
 * the key itself as Cloudflare requires (tag http-message-signatures-directory, covering the
 * request's @authority). It expires after `lifetimeSeconds` (a day); serve a fresh one.
 */
export function signedDirectory(privateKey, authority, { created = new Date(), lifetimeSeconds = 86400 } = {}) {
  const jwk = ed25519Jwk(privateKey);
  const keyid = jwkThumbprint(jwk);
  const body = JSON.stringify({ keys: [{ kty: jwk.kty, crv: jwk.crv, x: jwk.x, kid: keyid, use: 'sig' }] });
  const createdAt = Math.floor(created.getTime() / 1000);
  const params = `("@authority";req);created=${createdAt};expires=${createdAt + lifetimeSeconds};`
    + `keyid="${keyid}";alg="ed25519";tag="${DIRECTORY_TAG}"`;
  const base = `"@authority";req: ${String(authority).toLowerCase()}\n"@signature-params": ${params}`;
  const signature = signRaw(privateKey, Buffer.from(base, 'utf8'));
  return {
    headers: {
      'Content-Type': DIRECTORY_MEDIA_TYPE,
      'Cache-Control': 'max-age=300',
      'Signature-Input': `sig1=${params}`,
      Signature: `sig1=:${Buffer.from(signature).toString('base64')}:`,
    },
    body,
  };
}
