/**
 * Trust material a relying party holds locally: the key set, and the revocation state.
 *
 * A website keeps two things in memory and refreshes them in the background — the registry's JWKS
 * (hourly) and the revocation state (every 60 s). That is two background requests per minute,
 * regardless of how much agent traffic the site sees, and nothing in the request path ever
 * contacts the registry.
 *
 * Everything fetched is signed and verified before it is trusted. An unsigned revocation feed
 * would let anyone who can interpose on the fetch silently strip their own agent's revocation;
 * against a signed feed the worst an interceptor can do is serve a stale one, which `isStale()`
 * makes visible.
 */

import { createHash } from 'node:crypto';

import { MalformedToken, RegistryUnavailable, UnknownIssuer } from './util.mjs';
import { verifyCompact } from './crypto.mjs';

export const JWKS_REFRESH_SECONDS = 3600;
export const REVOCATION_REFRESH_SECONDS = 60;
const STALENESS_GRACE_SECONDS = 600;

// The bloom index arithmetic is defined modulo 2^64 so that every language agrees.
const UINT64_MASK = (1n << 64n) - 1n;

const DELTA_TYP = 'aidr-crl+jwt';
const FILTER_TYP = 'aidr-crl-filter+jwt';

/**
 * Revocation bloom filter. The construction must match the Python and Go SDKs byte for byte:
 *
 *   digest = SHA-256(identifier as UTF-8)
 *   h1 = digest[0..8) big-endian, h2 = digest[8..16) big-endian
 *   bit i = ((h1 + i*h2 + i*i) mod 2^64) mod m
 *   bit b lives in byte b >> 3, at position b & 7 from the least significant bit
 *
 * BigInt throughout: the hash values are 64-bit and JavaScript numbers lose precision above 2^53,
 * which would silently produce different bit positions from the other SDKs.
 *
 * The `mod 2^64` is load-bearing. BigInt does not wrap, a Go uint64 does; without the explicit
 * mask the two select different bits once the sum exceeds 2^64, and a revoked agent verifies as
 * healthy in one SDK while being refused in another.
 */
export class BloomFilter {
  constructor(m, k, bits) {
    this.m = BigInt(m);
    this.k = k;
    this.bits = bits;
  }

  static fromJSON(data) {
    if (data?.format !== 1) throw new MalformedToken(`unsupported bloom filter format ${data?.format}`);
    const bits = Buffer.from(data.bits, 'base64');
    if (bits.length * 8 !== data.m) {
      throw new MalformedToken('bloom filter bit length does not match declared size');
    }
    return new BloomFilter(data.m, data.k, bits);
  }

  /** `true` means *possibly* present; `false` means *definitely* absent. */
  has(item) {
    const digest = createHash('sha256').update(item, 'utf8').digest();
    const h1 = digest.readBigUInt64BE(0);
    const h2 = digest.readBigUInt64BE(8);

    for (let i = 0; i < this.k; i += 1) {
      const sum = (h1 + BigInt(i) * h2 + BigInt(i) * BigInt(i)) & UINT64_MASK;
      const index = Number(sum % this.m);
      if ((this.bits[index >> 3] & (1 << (index & 7))) === 0) return false;
    }
    return true;
  }
}

/** Locally held revocation knowledge. */
export class RevocationState {
  constructor() {
    this.revoked = new Set();
    this.filter = null;
    this.serial = 0;
    /**
     * False until a full snapshot has been ingested. A fresh store knows nothing and must not
     * claim that an unknown identifier is definitively healthy.
     */
    this.exact = false;
    this.fetchedAt = Date.now();
    /** When the registry signed the newest revocation data held (its `iat`, ms), or null. */
    this.issuedAt = null;
  }

  /**
   * @returns {{revoked: boolean, definitive: boolean}}
   *   `{true, true}`   — revoked, no doubt.
   *   `{false, true}`  — not revoked, no doubt.
   *   `{true, false}`  — possibly revoked; the caller's policy decides.
   */
  contains(subjectId) {
    if (this.revoked.has(subjectId)) return { revoked: true, definitive: true };
    if (this.filter && this.filter.has(subjectId)) {
      // A bloom hit with an exact set present means the exact set already said no, so this is a
      // false positive and the exact answer wins.
      return this.exact ? { revoked: false, definitive: true } : { revoked: true, definitive: false };
    }
    return { revoked: false, definitive: this.exact };
  }

  isStale(now = Date.now()) {
    return (now - this.fetchedAt) / 1000 > REVOCATION_REFRESH_SECONDS + STALENESS_GRACE_SECONDS;
  }
}

export class KeySet {
  constructor(keys) {
    this.keys = keys;
    this.fetchedAt = Date.now();
  }

  static fromJwks(document) {
    const entries = document?.keys;
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new MalformedToken('JWKS document contains no keys');
    }

    const keys = new Map();
    for (const jwk of entries) {
      if (typeof jwk?.kid !== 'string') continue;   // cannot be selected deterministically
      if ('d' in jwk) {
        // The registry must never publish private material. If it appears, something is badly
        // wrong upstream and the key must not be used.
        throw new MalformedToken('JWKS contains private key material — refusing to trust it');
      }
      keys.set(jwk.kid, jwk);
    }
    if (keys.size === 0) throw new MalformedToken('JWKS document contains no usable keys');
    return new KeySet(keys);
  }

  resolve(kid) {
    return this.keys.get(kid) ?? null;
  }

  isStale(now = Date.now()) {
    return (now - this.fetchedAt) / 1000 > JWKS_REFRESH_SECONDS + STALENESS_GRACE_SECONDS;
  }
}

export class TrustStore {
  constructor(keySet, { revocation = new RevocationState(), expectedIssuer = null } = {}) {
    this.keySet = keySet;
    this.revocation = revocation;
    this.expectedIssuer = expectedIssuer;
  }

  static fromJwks(jwks, options = {}) {
    return new TrustStore(KeySet.fromJwks(jwks), options);
  }

  resolveKey(kid) {
    return this.keySet.resolve(kid);
  }

  /** Verify and apply a signed revocation delta. Returns the new serial. */
  ingestDelta(deltaToken) {
    const { payload } = verifyCompact(deltaToken, (kid) => this.resolveKey(kid),
      { expectedTyp: DELTA_TYP });
    this.#checkIssuer(payload);

    const since = Number(payload.since ?? 0);
    if (since > this.revocation.serial) {
      // A delta starting after our serial would leave revocations between the two unlearned, and
      // the gap would never be noticed. Refuse and let the caller re-request from its own serial.
      throw new RegistryUnavailable(
        'revocation delta starts beyond the local serial — a gap would go unnoticed',
        { localSerial: this.revocation.serial, deltaSince: since },
      );
    }

    for (const entry of payload.revocations ?? []) {
      if (typeof entry?.subject_id === 'string') this.revocation.revoked.add(entry.subject_id);
    }
    this.revocation.serial = Math.max(this.revocation.serial, Number(payload.serial ?? 0));
    this.revocation.fetchedAt = Date.now();
    if (Number.isFinite(Number(payload.iat))) this.revocation.issuedAt = Number(payload.iat) * 1000;

    // Only a delta from serial 0 delivers the complete set. Marking the state exact after an
    // incremental delta would be wrong in a specific and dangerous way: a site that bootstrapped
    // from a bloom filter and then applied an empty incremental delta would hold an empty "exact"
    // set and report every revoked agent as healthy.
    if (since === 0 && payload.complete !== false) this.revocation.exact = true;

    return this.revocation.serial;
  }

  /** Verify and install a signed revocation bloom filter. */
  ingestFilter(filterToken) {
    const { payload } = verifyCompact(filterToken, (kid) => this.resolveKey(kid),
      { expectedTyp: FILTER_TYP });
    this.#checkIssuer(payload);

    this.revocation.filter = BloomFilter.fromJSON(payload.filter);
    this.revocation.serial = Math.max(this.revocation.serial, Number(payload.serial ?? 0));
    this.revocation.fetchedAt = Date.now();
    // A filter is supplementary and never makes the state exact.
    return this.revocation.serial;
  }

  #checkIssuer(payload) {
    if (this.expectedIssuer && payload.iss !== this.expectedIssuer) {
      throw new UnknownIssuer(
        `artefact issued by ${payload.iss}, expected ${this.expectedIssuer}`,
        { issuer: payload.iss },
      );
    }
  }

  /** Export for the site's own monitoring. A stale store still verifies, but learns nothing new. */
  health() {
    return {
      keys: this.keySet.keys.size,
      keysStale: this.keySet.isStale(),
      revocationSerial: this.revocation.serial,
      revocationEntries: this.revocation.revoked.size,
      revocationExact: this.revocation.exact,
      revocationStale: this.revocation.isStale(),
      hasFilter: this.revocation.filter !== null,
      // When the registry signed the newest revocation data held (Unix seconds). Verifiers refuse
      // agents once it is MAX_REVOCATION_AGE_SECONDS (660) old: alert well before.
      revocationIssuedAt: this.revocation.issuedAt === null ? null
        : Math.floor(this.revocation.issuedAt / 1000),
    };
  }
}

/**
 * In-process replay cache for signature nonces.
 *
 * Sufficient for a single process. A multi-instance deployment must back this with a shared store
 * (Redis `SET NX` with a TTL matching the maximum signature age) — otherwise a captured request
 * simply replays against another instance and the nonce check becomes decorative.
 *
 * The default TTL is twice the maximum signature age: a signature may be dated up to 300 s in the
 * future (clock skew) and stays acceptable until 300 s after that. When full of live entries the
 * cache throws `RegistryUnavailable` rather than evicting: forgetting a live nonce re-opens replay
 * for exactly that request.
 */
export class NonceCache {
  constructor({ ttlSeconds = 600, maxEntries = 100_000 } = {}) {
    this.ttl = ttlSeconds * 1000;
    this.maxEntries = maxEntries;
    this.seen = new Map();
  }

  /** Returns `true` if the nonce has been seen. Records it either way. */
  check(nonce) {
    const now = Date.now();
    const previous = this.seen.get(nonce);
    if (previous !== undefined && now - previous < this.ttl) return true;
    if (this.seen.size >= this.maxEntries) {
      for (const [seenNonce, at] of this.seen) {
        if (now - at >= this.ttl) this.seen.delete(seenNonce);
      }
      if (this.seen.size >= this.maxEntries) {
        throw new RegistryUnavailable(
          'replay cache is full of live nonces; refusing rather than forgetting one',
          { maxEntries: this.maxEntries },
        );
      }
    }
    this.seen.set(nonce, now);
    return false;
  }

  get size() {
    return this.seen.size;
  }
}

/** Convenience constructor for the usual bootstrap: JWKS plus initial revocation state. */
export function buildTrustStore(jwks, { deltaToken = null, filterToken = null, expectedIssuer = null } = {}) {
  const store = TrustStore.fromJwks(jwks, { expectedIssuer });
  if (filterToken) store.ingestFilter(filterToken);
  if (deltaToken) store.ingestDelta(deltaToken);
  return store;
}
