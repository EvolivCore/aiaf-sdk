/**
 * Cryptographic verification: JWS credentials and RFC 9421 request signatures.
 *
 * Uses Node's built-in crypto only — no dependencies. That is deliberate: a relying party should
 * be able to adopt AIDR without taking on a supply-chain risk, and a verification library with a
 * dependency tree is a verification library that can be compromised without touching its own code.
 *
 * Two algorithms, matching the Python SDK: Ed25519 (default) and ECDSA P-256 (for FIPS-constrained
 * deployments). For ECDSA, `dsaEncoding: 'ieee-p1363'` is essential — JOSE uses the fixed-width
 * `R‖S` form, while Node's default is ASN.1 DER. Getting that wrong produces signatures that
 * verify in one language and nowhere else.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

import {
  CoveredComponentMismatch,
  InvalidKey,
  MalformedToken,
  ReplayDetected,
  SignatureInvalid,
  SignatureTooOld,
  UnknownIssuer,
  UnsupportedAlgorithm,
  b64urlDecode,
} from './util.mjs';

/** Components every AIDR signature must cover. Dropping any one re-enables a real attack. */
export const REQUIRED_COMPONENTS = ['@method', '@authority', '@path'];

export const SIGNATURE_INPUT_HEADER = 'signature-input';
export const SIGNATURE_HEADER = 'signature';
export const CREDENTIAL_HEADER = 'agent-credential';

const ALGORITHMS = {
  EdDSA: { kty: 'OKP', crv: 'Ed25519', httpAlg: 'ed25519', hash: null, dsaEncoding: undefined },
  ES256: { kty: 'EC', crv: 'P-256', httpAlg: 'ecdsa-p256-sha256', hash: 'sha256', dsaEncoding: 'ieee-p1363' },
};

const BY_HTTP_ALG = Object.fromEntries(
  Object.entries(ALGORITHMS).map(([jose, spec]) => [spec.httpAlg, jose]),
);

/**
 * Resolve the algorithm from the key's own `kty`/`crv`, never from its `alg` member.
 *
 * `alg` is a hint an attacker controls. Honouring it over the actual key material is precisely
 * the algorithm-confusion bug.
 */
export function algorithmForJwk(jwk) {
  for (const [jose, spec] of Object.entries(ALGORITHMS)) {
    if (jwk?.kty === spec.kty && jwk?.crv === spec.crv) return jose;
  }
  throw new UnsupportedAlgorithm(
    `unsupported key type kty=${jwk?.kty} crv=${jwk?.crv}`, { kty: jwk?.kty, crv: jwk?.crv },
  );
}

export function importPublicKey(jwk) {
  if (!jwk || typeof jwk !== 'object') throw new InvalidKey('JWK must be an object');
  if ('d' in jwk) throw new InvalidKey('a private key was supplied where a public key is required');

  const jose = algorithmForJwk(jwk);
  const spec = ALGORITHMS[jose];

  if (spec.kty === 'OKP') {
    const raw = b64urlDecode(jwk.x);
    if (raw.length !== 32) throw new InvalidKey(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  } else {
    // RFC 7518 §6.2.1.2 requires fixed-width coordinates: variable widths would give one key
    // several encodings and therefore several thumbprints.
    const x = b64urlDecode(jwk.x);
    const y = b64urlDecode(jwk.y);
    if (x.length !== 32 || y.length !== 32) {
      throw new InvalidKey('P-256 coordinates must be exactly 32 bytes each');
    }
  }

  try {
    return { key: createPublicKey({ key: jwk, format: 'jwk' }), jose };
  } catch (error) {
    // Node rejects an off-curve point here, which is an invalid-curve attack or a corrupt key.
    throw new InvalidKey(`could not import public key: ${error.message}`);
  }
}

export function verifySignature(publicKey, jose, signature, data) {
  const spec = ALGORITHMS[jose];
  if (!spec) throw new UnsupportedAlgorithm(`unsupported algorithm ${jose}`);
  if (signature.length !== 64) {
    throw new SignatureInvalid(`${jose} signature must be 64 bytes, got ${signature.length}`);
  }

  const ok = cryptoVerify(
    spec.hash, data,
    spec.dsaEncoding ? { key: publicKey, dsaEncoding: spec.dsaEncoding } : publicKey,
    signature,
  );
  if (!ok) throw new SignatureInvalid('signature verification failed');
}

// ===============================================================================================
// Compact JWS
// ===============================================================================================

/**
 * Read the header without verifying. The ONLY legitimate use is looking up which key to verify
 * with — nothing in the payload means anything until the signature has been checked.
 */
export function decodeUnverifiedHeader(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new MalformedToken('compact JWS must have three parts');
  try {
    const header = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
    if (typeof header !== 'object' || header === null) {
      throw new MalformedToken('JWS header must be a JSON object');
    }
    return header;
  } catch (error) {
    if (error instanceof MalformedToken) throw error;
    throw new MalformedToken(`JWS header is not valid JSON: ${error.message}`);
  }
}

/**
 * Verify a compact JWS and return `{ header, payload }`.
 *
 * Parse and verify are one function on purpose: there is no code path that returns claims without
 * having checked the signature, so no caller can accidentally trust an unverified payload.
 */
export function verifyCompact(token, resolveKey, { expectedTyp = 'aidr-cred+jwt' } = {}) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new MalformedToken('compact JWS must have three parts');
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = decodeUnverifiedHeader(token);

  // Refused before any key lookup: covers alg=none, HS256 confusion, RS256 and everything else.
  if (!ALGORITHMS[header.alg]) {
    throw new UnsupportedAlgorithm(`unsupported or unsafe JWS algorithm ${header.alg}`,
      { alg: header.alg });
  }
  if (expectedTyp && header.typ !== expectedTyp) {
    throw new MalformedToken(`unexpected token type ${header.typ}; expected ${expectedTyp}`);
  }
  if (typeof header.kid !== 'string' || !header.kid) {
    throw new MalformedToken("JWS header is missing 'kid'");
  }

  const jwk = resolveKey(header.kid);
  if (!jwk) throw new UnknownIssuer(`no trusted key for kid ${header.kid}`, { kid: header.kid });

  const { key, jose } = importPublicKey(jwk);
  // The header's algorithm must match the key we actually trust for this kid. Checking only one
  // side reintroduces algorithm confusion through the back door.
  if (jose !== header.alg) {
    throw new UnsupportedAlgorithm(
      `header declares ${header.alg} but the trusted key for kid ${header.kid} is ${jose}`,
    );
  }

  verifySignature(key, jose, b64urlDecode(signatureB64),
    Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'));

  try {
    const payload = JSON.parse(b64urlDecode(payloadB64).toString('utf8'));
    if (typeof payload !== 'object' || payload === null) {
      throw new MalformedToken('JWS payload must be a JSON object');
    }
    return { header, payload };
  } catch (error) {
    if (error instanceof MalformedToken) throw error;
    throw new MalformedToken(`JWS payload is not valid JSON: ${error.message}`);
  }
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
    if (!label || !value.startsWith('(')) {
      throw new MalformedToken(`malformed Signature-Input member: ${member.slice(0, 64)}`);
    }
    const close = value.indexOf(')');
    const inner = value.slice(1, close).trim();
    const paramsText = value.slice(close + 1).replace(/^;/, '');
    entries[label] = {
      label,
      components: inner ? splitTopLevel(inner, ' ').map(unquote) : [],
      params: paramsText ? parseParams(paramsText) : {},
      // Kept verbatim: re-serialising risks a canonicalisation mismatch, which would look
      // exactly like a forged signature.
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
    if (!(value.startsWith(':') && value.endsWith(':') && value.length >= 2)) {
      throw new MalformedToken(`malformed Signature member for label ${label}`);
    }
    const encoded = value.slice(1, -1);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
      throw new MalformedToken(`signature for ${label} is not valid base64`);
    }
    signatures[label] = Buffer.from(encoded, 'base64');
  }
  if (Object.keys(signatures).length === 0) {
    throw new MalformedToken('Signature header contains no signatures');
  }
  return signatures;
}

/** Derive one component's value from the request as it was actually received. */
function deriveComponent(name, { method, url, headers }) {
  const parsed = new URL(url);

  switch (name) {
    case '@method': return method.toUpperCase();
    case '@target-uri': return url;
    case '@authority': {
      // Lowercase with the default port omitted: https://HOST:443/ and https://host/ are the same
      // origin, and an agent must not have to guess which spelling the server will use.
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
    throw new UnsupportedAlgorithm(`derived component ${name} is not supported`, { component: name });
  }

  const value = headers[name.toLowerCase()];
  if (value === undefined) {
    throw new CoveredComponentMismatch(
      `signature covers header ${name}, which is absent from the request`, { component: name },
    );
  }
  return String(value).split(/\s+/).filter(Boolean).join(' ');
}

export function buildSignatureBase(components, signatureParams, request) {
  const lines = components.map((name) => `"${name.toLowerCase()}": ${deriveComponent(name, request)}`);
  lines.push(`"@signature-params": ${signatureParams}`);
  return Buffer.from(lines.join('\n'), 'utf8');
}

/**
 * Verify an RFC 9421 signature on a received request.
 *
 * Checks run cheapest-first, so a malformed or stale request is rejected before any cryptography.
 * That ordering is a small DoS mitigation: signature verification is the expensive step and an
 * attacker should not be able to force it by sending garbage.
 */
/**
 * Which signature to verify when a request carries several (RFC 9421 allows any number): the first,
 * in header order, whose keyid is one the credential names; otherwise the first, which then fails
 * on its keyid as it should. A signature for someone else beside it is ignored rather than
 * mistaken for the agent's.
 */
function chooseLabel(entries, accepted) {
  const labels = Object.keys(entries);
  if (accepted) {
    const match = labels.find((name) => accepted.includes(entries[name].params.keyid));
    if (match) return match;
  }
  return labels[0];
}

/**
 * The base64url SHA-256 JWK thumbprint (RFC 7638; RFC 8037 appendix A.3 for OKP keys): the keyid
 * of a Web Bot Auth signature.
 */
export function jwkThumbprint(jwk) {
  const members = { OKP: ['crv', 'kty', 'x'], EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'] }[jwk?.kty];
  if (!members || members.some((name) => typeof jwk[name] !== 'string')) {
    throw new InvalidKey(`cannot take the thumbprint of a ${jwk?.kty} key`);
  }
  const canonical = `{${members.map((name) => `"${name}":${JSON.stringify(jwk[name])}`).join(',')}}`;
  return createHash('sha256').update(canonical).digest('base64url');
}

export function verifyRequestSignature({
  method,
  url,
  headers,
  resolvePublicKey,
  requiredComponents = REQUIRED_COMPONENTS,
  maxAgeSeconds = 300,
  now = new Date(),
  nonceSeen = null,
  label = null,
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
  const chosen = label || chooseLabel(entries, accepted);
  const entry = entries[chosen];
  if (!entry) throw new MalformedToken(`no Signature-Input member labelled ${chosen}`);
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
    // The credential says one identity, the signature another. Almost always an attempt to pair
    // a stolen credential with a key the attacker actually controls.
    throw new CoveredComponentMismatch(
      'signature keyid does not match the presented credential',
      { signatureKeyid: keyid, credentialKeyid: accepted[0] },
    );
  }

  const created = entry.params.created;
  if (typeof created !== 'number') {
    throw new MalformedToken("signature parameters are missing 'created'");
  }
  const ageSeconds = (now.getTime() - created * 1000) / 1000;
  if (ageSeconds > maxAgeSeconds) {
    throw new SignatureTooOldError(ageSeconds, maxAgeSeconds);
  }
  if (ageSeconds < -maxAgeSeconds) {
    throw new SignatureTooOldError(ageSeconds, maxAgeSeconds, true);
  }
  if (typeof entry.params.expires === 'number' && now.getTime() > entry.params.expires * 1000) {
    throw new SignatureTooOldError(ageSeconds, maxAgeSeconds);
  }

  const covered = new Set(entry.components.map((name) => name.toLowerCase()));
  const missing = requiredComponents.filter((name) => !covered.has(name.toLowerCase()));
  if (missing.length > 0) {
    throw new CoveredComponentMismatch(
      `signature does not cover required components: ${missing.join(', ')}`,
      { missing, covered: [...covered].sort() },
    );
  }

  const nonce = entry.params.nonce;
  if (nonceSeen && (typeof nonce !== 'string' || !nonce)) {
    throw new MalformedToken('replay protection is enabled but the signature carries no nonce');
  }

  const jwk = resolvePublicKey(keyid);
  if (!jwk) throw new SignatureInvalid(`no public key available for keyid ${keyid}`, { keyid });

  const { key, jose } = importPublicKey(jwk);
  if (declaredAlg && declaredAlg !== jose) {
    throw new UnsupportedAlgorithm(
      `signature declares ${entry.params.alg} but the key for ${keyid} is ${jose}`,
    );
  }

  const base = buildSignatureBase(entry.components, entry.rawValue, { method, url, headers: normalised });
  verifySignature(key, jose, signature, base);

  // The replay check comes last, after the signature has verified. `nonceSeen` records the nonce
  // it is asked about, so consulting it earlier would let a forged request occupy a nonce: the
  // genuine request would then be refused as a replay, and forgeries could fill the cache.
  if (nonceSeen && nonceSeen(nonce)) {
    throw new ReplayDetectedError(nonce);
  }

  return {
    label: chosen,
    keyid,
    created: new Date(created * 1000),
    nonce: entry.params.nonce ?? null,
    components: entry.components,
    tag: typeof entry.params.tag === 'string' ? entry.params.tag : null,
  };
}

function SignatureTooOldError(age, limit, future = false) {
  return new SignatureTooOld(
    future
      ? 'signature was created in the future beyond clock-skew tolerance'
      : `signature is ${Math.round(age)}s old, older than the ${limit}s limit`,
    { ageSeconds: Math.round(age) },
  );
}

function ReplayDetectedError(nonce) {
  return new ReplayDetected('signature nonce has already been used', { nonce });
}

/** Reconstruct the request URI a server actually received. */
export function effectiveRequestUri(scheme, hostHeader, pathWithQuery) {
  if (!hostHeader) throw new MalformedToken('cannot derive request URI without a Host header');
  const path = pathWithQuery.startsWith('/') ? pathWithQuery : `/${pathWithQuery}`;
  return `${scheme}://${hostHeader}${path}`;
}
