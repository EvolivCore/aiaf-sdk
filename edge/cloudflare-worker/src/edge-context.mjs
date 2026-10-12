/**
 * The edge → origin hop: a signed statement of what the edge decided about a request.
 *
 * Every request the worker forwards carries `X-AIDR-Context` (base64url JSON) and
 * `X-AIDR-Context-Signature` (base64url HMAC-SHA256 over "aidr-edge-context-v1\n" + context),
 * under a secret shared only by the worker and the origin. The origin refuses any request without
 * a valid pair — which is what makes the edge unskippable: a request sent straight to the origin,
 * or one whose context was forged or altered, is refused there.
 *
 * The context is bound to the request's method and path (with query) and to a 60-second window,
 * so a captured context cannot be re-used for another request or kept for later.
 *
 * Works in Workers and in Node 18+ (both have WebCrypto). The Python origin helper
 * (aidr_verifier.edge) implements the same format; sdk/testdata/edge-context.json pins it.
 */

import { b64urlDecode, b64urlEncode, utf8Decode, utf8Encode } from './encoding.mjs';
import { EdgeContextInvalid } from './errors.mjs';

export const CONTEXT_HEADER = 'x-aidr-context';
export const CONTEXT_SIGNATURE_HEADER = 'x-aidr-context-signature';
export const CONTEXT_VERSION = 1;
const DOMAIN = 'aidr-edge-context-v1\n';
export const MIN_SECRET_LENGTH = 32;
export const DEFAULT_MAX_AGE_SECONDS = 60;

const keys = new Map();
async function hmacKey(secret) {
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) {
    throw new EdgeContextInvalid(`edge context secret must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  let key = keys.get(secret);
  if (!key) {
    key = await crypto.subtle.importKey('raw', utf8Encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    keys.set(secret, key);
  }
  return key;
}

/** Path plus query exactly as the request URL carries it. */
export function targetOf(url) {
  const parsed = new URL(url);
  return parsed.pathname + parsed.search;
}

export async function signEdgeContext(context, secret) {
  const encoded = b64urlEncode(utf8Encode(JSON.stringify({ v: CONTEXT_VERSION, ...context })));
  const mac = await crypto.subtle.sign('HMAC', await hmacKey(secret), utf8Encode(DOMAIN + encoded));
  return { context: encoded, signature: b64urlEncode(new Uint8Array(mac)) };
}

/**
 * Verify the context on a request received at the origin. Returns the context object, or throws
 * EdgeContextInvalid. `headers` may be a Headers object or a plain object.
 */
export async function verifyEdgeContext({ method, url, headers }, secret,
  { now = Date.now(), maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS } = {}) {
  const get = (name) => (typeof headers.get === 'function' ? headers.get(name) : headers[name]);
  const encoded = get(CONTEXT_HEADER);
  const signature = get(CONTEXT_SIGNATURE_HEADER);
  if (!encoded || !signature) {
    throw new EdgeContextInvalid('request did not come through the AIDR edge');
  }

  let mac;
  try {
    mac = b64urlDecode(signature);
  } catch {
    throw new EdgeContextInvalid('edge context signature is not base64url');
  }
  // subtle.verify compares in constant time.
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), mac, utf8Encode(DOMAIN + encoded));
  if (!ok) throw new EdgeContextInvalid('edge context signature does not verify');

  let context;
  try {
    context = JSON.parse(utf8Decode(b64urlDecode(encoded)));
  } catch {
    throw new EdgeContextInvalid('edge context is not valid JSON');
  }
  if (context?.v !== CONTEXT_VERSION) throw new EdgeContextInvalid('unsupported edge context version');
  const age = now / 1000 - Number(context.iat);
  if (!Number.isFinite(age) || age > maxAgeSeconds || age < -maxAgeSeconds) {
    throw new EdgeContextInvalid('edge context is outside its validity window');
  }
  if (context.method !== String(method).toUpperCase() || context.target !== targetOf(url)) {
    throw new EdgeContextInvalid('edge context was issued for a different request');
  }
  return context;
}
