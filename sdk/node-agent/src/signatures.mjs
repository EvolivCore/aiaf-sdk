/**
 * RFC 9421 request signatures, made exactly as the Python reference makes them
 * (aidr_crypto.signatures.sign_request): label `sig1`, components `@method @authority @path`,
 * parameters created, keyid, alg, nonce, tag="aidr" — in that order, byte for byte. The shared
 * conformance vectors, signed through this SDK, must pass every verifier (docs/13).
 */

import { randomBytes } from 'node:crypto';

import { ALGORITHMS, algorithmOf, signRaw } from './keys.mjs';

export const COMPONENTS = ['@method', '@authority', '@path'];
export const LABEL = 'sig1';
export const TAG = 'aidr';
export const SIGNATURE_INPUT_HEADER = 'Signature-Input';
export const SIGNATURE_HEADER = 'Signature';
export const CREDENTIAL_HEADER = 'Agent-Credential';

export function generateNonce() {
  return randomBytes(16).toString('base64url');
}

function component(name, url, method) {
  if (name === '@method') return method.toUpperCase();
  // WHATWG URL already lowercases the host and drops a default port, as RFC 9421 asks.
  if (name === '@authority') return url.host;
  if (name === '@path') return url.pathname || '/';
  throw new Error(`component ${name} is not signed by this SDK`);
}

/**
 * The headers that sign one request: `{ 'Signature-Input', 'Signature' }`. `created` (a Date)
 * and `nonce` exist for tests and vectors; leave them out.
 */
export function signRequest({ method, url, privateKey, keyid, created = new Date(), nonce = generateNonce() }) {
  const target = new URL(url);
  const params = [
    `(${COMPONENTS.map((c) => `"${c}"`).join(' ')})`,
    `;created=${Math.floor(created.getTime() / 1000)}`,
    `;keyid="${keyid}"`,
    `;alg="${ALGORITHMS[algorithmOf(privateKey)].httpAlg}"`,
    `;nonce="${nonce}"`,
    `;tag="${TAG}"`,
  ].join('');
  const base = [...COMPONENTS.map((c) => `"${c}": ${component(c, target, method)}`), `"@signature-params": ${params}`]
    .join('\n');
  const signature = signRaw(privateKey, Buffer.from(base, 'utf8'));
  return {
    [SIGNATURE_INPUT_HEADER]: `${LABEL}=${params}`,
    [SIGNATURE_HEADER]: `${LABEL}=:${Buffer.from(signature).toString('base64')}:`,
  };
}
