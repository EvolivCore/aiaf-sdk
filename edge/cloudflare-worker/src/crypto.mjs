/**
 * JWS credentials and RFC 9421 request signatures, over WebCrypto.
 *
 * A port of sdk/node/src/crypto.mjs for runtimes without node:crypto (Cloudflare Workers). The
 * checks and their order are the same; the difference is that WebCrypto is asynchronous. It must
 * reach the same verdicts as the other SDKs on sdk/testdata/vectors.json.
 *
 * ES256 needs no conversion here: WebCrypto's ECDSA takes the fixed-width R‖S form, which is
 * exactly what JOSE and RFC 9421 use.
 */

import { b64urlDecode, b64urlEncode, base64Decode, utf8Decode, utf8Encode } from './encoding.mjs';
import {
  CoveredComponentMismatch,
  InvalidKey,
  MalformedToken,
  ReplayDetected,
  SignatureInvalid,
  SignatureTooOld,
  UnknownIssuer,
  UnsupportedAlgorithm,
} from './errors.mjs';

/** Components every AIDR signature must cover. Dropping any one re-enables a real attack. */
export const REQUIRED_COMPONENTS = ['@method', '@authority', '@path'];

export const SIGNATURE_INPUT_HEADER = 'signature-input';
export const SIGNATURE_HEADER = 'signature';
export const CREDENTIAL_HEADER = 'agent-credential';

const ALGORITHMS = {
  EdDSA: {
    kty: 'OKP', crv: 'Ed25519', httpAlg: 'ed25519',
    importAlg: { name: 'Ed25519' }, verifyAlg: { name: 'Ed25519' },
  },
  ES256: {
    kty: 'EC', crv: 'P-256', httpAlg: 'ecdsa-p256-sha256',
    importAlg: { name: 'ECDSA', namedCurve: 'P-256' }, verifyAlg: { name: 'ECDSA', hash: 'SHA-256' },
  },
};

const BY_HTTP_ALG = Object.fromEntries(
  Object.entries(ALGORITHMS).map(([jose, spec]) => [spec.httpAlg, jose]),
);

/** Resolve the algorithm from the key's own kty/crv — never from its attacker-supplied `alg`. */
export function algorithmForJwk(jwk) {
  for (const [jose, spec] of Object.entries(ALGORITHMS)) {
    if (jwk?.kty === spec.kty && jwk?.crv === spec.crv) return jose;
  }
  throw new UnsupportedAlgorithm(`unsupported key type kty=${jwk?.kty} crv=${jwk?.crv}`);
}

// Imported keys, so a busy isolate does not re-import the registry's key on every request.
const KEY_CACHE_LIMIT = 1000;
const keyCache = new Map();

export async function importPublicKey(jwk) {
  if (!jwk || typeof jwk !== 'object') throw new InvalidKey('JWK must be an object');
  if ('d' in jwk) throw new InvalidKey('a private key was supplied where a public key is required');

  const jose = algorithmForJwk(jwk);
  const spec = ALGORITHMS[jose];
  let clean;
  if (spec.kty === 'OKP') {
    if (b64urlDecode(jwk.x).length !== 32) throw new InvalidKey('Ed25519 public key must be 32 bytes');
    clean = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  } else {
    // Fixed-width coordinates (RFC 7518 §6.2.1.2): otherwise one key has several encodings.
    if (b64urlDecode(jwk.x).length !== 32 || b64urlDecode(jwk.y).length !== 32) {
      throw new InvalidKey('P-256 coordinates must be exactly 32 bytes each');
    }
    clean = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }

  const cacheKey = `${jose}:${clean.x}:${clean.y ?? ''}`;
  const cached = keyCache.get(cacheKey);
  if (cached) return { key: cached, jose };

  let key;
  try {
    // Only the members that define the key are passed: `alg`, `use` or `key_ops` from an
    // untrusted JWK must not be able to change how it is imported.
    key = await crypto.subtle.importKey('jwk', clean, spec.importAlg, false, ['verify']);
  } catch (error) {
    // Includes an off-curve point: an invalid-curve attack or a corrupt key.
    throw new InvalidKey(`could not import public key: ${error.message}`);
  }
  if (keyCache.size >= KEY_CACHE_LIMIT) keyCache.clear();
  keyCache.set(cacheKey, key);
  return { key, jose };
}

export async function verifySignature(key, jose, signature, data) {
  const spec = ALGORITHMS[jose];
  if (!spec) throw new UnsupportedAlgorithm(`unsupported algorithm ${jose}`);
  if (signature.length !== 64) {
    throw new SignatureInvalid(`${jose} signature must be 64 bytes, got ${signature.length}`);
  }
  let ok = false;
  try {
    ok = await crypto.subtle.verify(spec.verifyAlg, key, signature, data);
  } catch {
    ok = false;
  }
  if (!ok) throw new SignatureInvalid('signature verification failed');
}

// ===============================================================================================
// Compact JWS
// ===============================================================================================

function decodeJsonPart(part, what) {
  let value;
  try {
    value = JSON.parse(utf8Decode(b64urlDecode(part)));
  } catch (error) {
    throw new MalformedToken(`JWS ${what} is not valid JSON: ${error.message}`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MalformedToken(`JWS ${what} must be a JSON object`);
  }
  return value;
}

/** Verify a compact JWS and return `{ header, payload }`. There is no parse-without-verify path. */
export async function verifyCompact(token, resolveKey, { expectedTyp = 'aidr-cred+jwt' } = {}) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new MalformedToken('compact JWS must have three parts');
  const [headerB64, payloadB64, signatureB64] = parts;
  const header = decodeJsonPart(headerB64, 'header');

  // Refused before any key lookup: alg=none, HS256 confusion, RS256 and everything else.
  if (!ALGORITHMS[header.alg]) {
    throw new UnsupportedAlgorithm(`unsupported or unsafe JWS algorithm ${header.alg}`);
  }
  if (expectedTyp && header.typ !== expectedTyp) {
    throw new MalformedToken(`unexpected token type ${header.typ}; expected ${expectedTyp}`);
  }
  if (typeof header.kid !== 'string' || !header.kid) {
    throw new MalformedToken("JWS header is missing 'kid'");
  }

  const jwk = resolveKey(header.kid);
  if (!jwk) throw new UnknownIssuer(`no trusted key for kid ${header.kid}`, { kid: header.kid });

  const { key, jose } = await importPublicKey(jwk);
  if (jose !== header.alg) {
    throw new UnsupportedAlgorithm(
      `header declares ${header.alg} but the trusted key for kid ${header.kid} is ${jose}`);
  }
  await verifySignature(key, jose, b64urlDecode(signatureB64),
    utf8Encode(`${headerB64}.${payloadB64}`));

  return { header, payload: decodeJsonPart(payloadB64, 'payload') };
}

// ===============================================================================================
// RFC 9421 structured fields — the narrow subset AIDR emits and accepts
// ===============================================================================================

function splitTopLevel(text, separator) {
  const parts = [];
  let current = '';
  let inQuotes = false;
  let escaped = false;
  let depth = 0;

  for (const char of text) {
    if (escaped) { current += char; escaped = false; continue; }
    if (char === '\\' && inQuotes) { current += char; escaped = true; continue; }
    if (char === '"') { inQuotes = !inQuotes; current += char; continue; }
    if (!inQuotes) {
      if (char === '(') depth += 1;
      else if (char === ')') {
        depth -= 1;
        if (depth < 0) throw new MalformedToken("unbalanced ')' in structured field");
      } else if (char === separator && depth === 0) {
        parts.push(current.trim());
        current = '';
        continue;
      }
    }
    current += char;
  }
  if (inQuotes) throw new MalformedToken('unterminated quoted string in structured field');
  if (depth !== 0) throw new MalformedToken('unbalanced parentheses in structured field');
  parts.push(current.trim());
  return parts.filter(Boolean);
}

function unquote(token) {
  if (token.length >= 2 && token.startsWith('"') && token.endsWith('"')) {
    return token.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return token;
}

function parseParams(text) {
  const params = {};
  for (const item of splitTopLevel(text, ';')) {
    const index = item.indexOf('=');
    if (index === -1) { params[item.trim()] = true; continue; }
    const key = item.slice(0, index).trim();
    const raw = item.slice(index + 1).trim();
    if (raw.startsWith('"')) params[key] = unquote(raw);
    else if (/^-?\d+$/.test(raw)) params[key] = Number.parseInt(raw, 10);
    else params[key] = raw;
  }
  return params;
}

export function parseSignatureInput(headerValue) {
  const entries = {};
  for (const member of splitTopLevel(headerValue, ',')) {
    const index = member.indexOf('=');
    const label = member.slice(0, index).trim();
    const value = member.slice(index + 1).trim();
    if (index === -1 || !label || !value.startsWith('(')) {
      throw new MalformedToken(`malformed Signature-Input member: ${member.slice(0, 64)}`);
    }
    const close = value.indexOf(')');
    const inner = value.slice(1, close).trim();
    const paramsText = value.slice(close + 1).replace(/^;/, '');
    entries[label] = {
      label,
      components: inner ? splitTopLevel(inner, ' ').map(unquote) : [],
      params: paramsText ? parseParams(paramsText) : {},
      // Verbatim: re-serialising risks a canonicalisation mismatch that looks like a forgery.
      rawValue: value,
    };
  }
  if (Object.keys(entries).length === 0) {
    throw new MalformedToken('Signature-Input header contains no signatures');
  }
  return entries;
}

export function parseSignatureHeader(headerValue) {
  const signatures = {};
  for (const member of splitTopLevel(headerValue, ',')) {
    const index = member.indexOf('=');
    const label = member.slice(0, index).trim();
    const value = member.slice(index + 1).trim();
    if (index === -1 || !(value.startsWith(':') && value.endsWith(':') && value.length >= 2)) {
      throw new MalformedToken(`malformed Signature member for label ${label}`);
    }
    const encoded = value.slice(1, -1);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
      throw new MalformedToken(`signature for ${label} is not valid base64`);
    }
    try {
      signatures[label] = base64Decode(encoded);
    } catch {
      throw new MalformedToken(`signature for ${label} is not valid base64`);
    }
  }
  if (Object.keys(signatures).length === 0) {
    throw new MalformedToken('Signature header contains no signatures');
  }
  return signatures;
}

function deriveComponent(name, { method, url, headers }) {
  const parsed = new URL(url);
  switch (name) {
    case '@method': return method.toUpperCase();
    case '@target-uri': return url;
    case '@authority': {
      // Lowercase, default port omitted: https://HOST:443/ and https://host/ are one origin.
      let authority = parsed.host.toLowerCase();
      if (parsed.protocol === 'https:' && authority.endsWith(':443')) authority = authority.slice(0, -4);
      if (parsed.protocol === 'http:' && authority.endsWith(':80')) authority = authority.slice(0, -3);
      return authority;
    }
    case '@scheme': return parsed.protocol.replace(':', '').toLowerCase();
    case '@path': return parsed.pathname || '/';
    case '@query': return parsed.search ? parsed.search : '?';
    default: break;
  }
  if (name.startsWith('@')) {
    throw new UnsupportedAlgorithm(`derived component ${name} is not supported`);
  }
  const value = headers[name.toLowerCase()];
  if (value === undefined) {
    throw new CoveredComponentMismatch(`signature covers header ${name}, which is absent`);
  }
  return String(value).split(/\s+/).filter(Boolean).join(' ');
}

export function buildSignatureBase(components, signatureParams, request) {
  const lines = components.map((name) => `"${name.toLowerCase()}": ${deriveComponent(name, request)}`);
  lines.push(`"@signature-params": ${signatureParams}`);
  return utf8Encode(lines.join('\n'));
}

/**
 * Verify an RFC 9421 signature on a received request.
 *
 * Cheapest checks first, so garbage is refused before any cryptography — with one exception:
 * `claimNonce` runs LAST, after the signature has verified. It records what it is asked about, so
 * running it earlier would let a forged request occupy a genuine request's nonce.
 *
 * `claimNonce(nonce, created)` resolves to `true` if this is the nonce's first use.
 */
/**
 * Which signature to verify when a request carries several: the first, in header order, whose
 * keyid is one the credential names; otherwise the first, which then fails on its keyid.
 */
function chooseLabel(entries, accepted) {
  const labels = Object.keys(entries);
  if (accepted) {
    const match = labels.find((name) => accepted.includes(entries[name].params.keyid));
    if (match) return match;
  }
  return labels[0];
}

/** The base64url SHA-256 JWK thumbprint (RFC 7638; RFC 8037 A.3): a Web Bot Auth keyid. */
export async function jwkThumbprint(jwk) {
  const members = { OKP: ['crv', 'kty', 'x'], EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'] }[jwk?.kty];
  if (!members || members.some((name) => typeof jwk[name] !== 'string')) {
    throw new InvalidKey(`cannot take the thumbprint of a ${jwk?.kty} key`);
  }
  const canonical = `{${members.map((name) => `"${name}":${JSON.stringify(jwk[name])}`).join(',')}}`;
  return b64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(canonical))));
}

export async function verifyRequestSignature({
  method,
  url,
  headers,
  resolvePublicKey,
  requiredComponents = REQUIRED_COMPONENTS,
  maxAgeSeconds = 300,
  now = new Date(),
  claimNonce = null,
  expectedKeyid = null,
}) {
  const normalised = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
  );
  const rawInput = normalised[SIGNATURE_INPUT_HEADER];
  const rawSignature = normalised[SIGNATURE_HEADER];
  if (!rawInput || !rawSignature) {
    throw new MalformedToken('request is missing Signature-Input or Signature headers');
  }

  const entries = parseSignatureInput(rawInput);
  const signatures = parseSignatureHeader(rawSignature);
  const accepted = expectedKeyid === null ? null : [].concat(expectedKeyid);
  const chosen = chooseLabel(entries, accepted);
  const entry = entries[chosen];
  const signature = signatures[chosen];
  if (!signature) throw new MalformedToken(`no Signature member labelled ${chosen}`);

  const declaredAlg = entry.params.alg ? BY_HTTP_ALG[entry.params.alg] : null;
  if (entry.params.alg && !declaredAlg) {
    throw new UnsupportedAlgorithm(`unsupported signature algorithm ${entry.params.alg}`);
  }

  const keyid = entry.params.keyid;
  if (typeof keyid !== 'string' || !keyid) {
    throw new MalformedToken("signature parameters are missing 'keyid'");
  }
  if (accepted !== null && !accepted.includes(keyid)) {
    throw new CoveredComponentMismatch('signature keyid does not match the presented credential');
  }

  const created = entry.params.created;
  if (typeof created !== 'number') {
    throw new MalformedToken("signature parameters are missing 'created'");
  }
  const ageSeconds = (now.getTime() - created * 1000) / 1000;
  if (ageSeconds > maxAgeSeconds) {
    throw new SignatureTooOld(`signature is ${Math.round(ageSeconds)}s old, older than ${maxAgeSeconds}s`);
  }
  if (ageSeconds < -maxAgeSeconds) {
    throw new SignatureTooOld('signature was created in the future beyond clock-skew tolerance');
  }
  if (typeof entry.params.expires === 'number' && now.getTime() > entry.params.expires * 1000) {
    throw new SignatureTooOld('signature has passed its stated expiry');
  }

  const covered = new Set(entry.components.map((name) => name.toLowerCase()));
  const missing = requiredComponents.filter((name) => !covered.has(name.toLowerCase()));
  if (missing.length > 0) {
    throw new CoveredComponentMismatch(
      `signature does not cover required components: ${missing.join(', ')}`);
  }

  const nonce = entry.params.nonce;
  if (claimNonce && (typeof nonce !== 'string' || !nonce)) {
    throw new MalformedToken('replay protection is enabled but the signature carries no nonce');
  }

  const jwk = resolvePublicKey(keyid);
  if (!jwk) throw new SignatureInvalid(`no public key available for keyid ${keyid}`);
  const { key, jose } = await importPublicKey(jwk);
  if (declaredAlg && declaredAlg !== jose) {
    throw new UnsupportedAlgorithm(`signature declares ${entry.params.alg} but the key is ${jose}`);
  }

  const base = buildSignatureBase(entry.components, entry.rawValue, { method, url, headers: normalised });
  await verifySignature(key, jose, signature, base);

  if (claimNonce && !(await claimNonce(nonce, created))) {
    throw new ReplayDetected('signature nonce has already been used');
  }
  return { keyid, created: new Date(created * 1000), nonce: nonce ?? null };
}
