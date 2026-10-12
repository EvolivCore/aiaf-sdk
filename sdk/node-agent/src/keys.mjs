/**
 * Agent keys: generated here, kept here, never sent anywhere. Ed25519 by default; P-256 (ES256)
 * for keys that must live in hardware that only speaks P-256. The same algorithms, JWK forms and
 * signature encodings as the Python SDK (aidr_crypto), so one identity works from either language.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';

export const ALGORITHMS = {
  Ed25519: { httpAlg: 'ed25519', jwsAlg: 'EdDSA' },
  ES256: { httpAlg: 'ecdsa-p256-sha256', jwsAlg: 'ES256' },
};

export function generateKey(algorithm = 'Ed25519') {
  if (algorithm === 'Ed25519') return generateKeyPairSync('ed25519').privateKey;
  if (algorithm === 'ES256') return generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  throw new Error(`unsupported algorithm ${algorithm}: Ed25519 or ES256`);
}

/** The algorithm a key implies — never an `alg` member someone wrote down. */
export function algorithmOf(key) {
  if (key.asymmetricKeyType === 'ed25519') return 'Ed25519';
  if (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1') return 'ES256';
  throw new Error('unsupported key: Ed25519 or P-256 only');
}

/** The public half, as the registry receives it — the same members, in the same order, as Python's. */
export function publicJwk(privateKey) {
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
  const alg = ALGORITHMS[algorithmOf(privateKey)].jwsAlg;
  return jwk.kty === 'OKP'
    ? { kty: 'OKP', crv: 'Ed25519', x: jwk.x, alg, use: 'sig' }
    : { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, alg, use: 'sig' };
}

/** The whole key, as the identity file stores it. A secret. */
export function privateJwk(privateKey) {
  const jwk = privateKey.export({ format: 'jwk' });
  const alg = ALGORITHMS[algorithmOf(privateKey)].jwsAlg;
  return jwk.kty === 'OKP'
    ? { kty: 'OKP', crv: 'Ed25519', x: jwk.x, alg, use: 'sig', d: jwk.d }
    : { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, alg, use: 'sig', d: jwk.d };
}

export function privateKeyFromJwk(jwk) {
  if (!jwk || typeof jwk.d !== 'string') throw new Error('the identity holds no private key');
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d }, format: 'jwk' });
  }
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    return createPrivateKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d }, format: 'jwk' });
  }
  throw new Error(`unsupported key ${jwk.kty}/${jwk.crv}: Ed25519 or P-256 only`);
}

/** A signature in JOSE form: 64 raw bytes for both algorithms, never DER. */
export function signRaw(privateKey, data) {
  return algorithmOf(privateKey) === 'Ed25519'
    ? sign(null, data, privateKey)
    : sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
}

export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
