package aidr

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	JWKSRefreshSeconds       = 3600
	RevocationRefreshSeconds = 60
	stalenessGraceSeconds    = 600
)

// BloomFilter is the revocation filter published by the registry.
//
// The construction must match the Python and Node SDKs byte for byte:
//
//	digest = SHA-256(identifier as UTF-8)
//	h1 = digest[0:8] big-endian, h2 = digest[8:16] big-endian
//	bit i = ((h1 + i*h2 + i*i) mod 2^64) mod m
//	bit b lives in byte b>>3, at position b&7 from the least significant bit
//
// The mod 2^64 is what uint64 arithmetic does natively here, and the Python and Node SDKs mask
// explicitly to match. Without it they would select different bits once the sum exceeds 2^64, and
// a revoked agent would verify as healthy in one SDK while being refused in another.
//
// The error direction is the whole point: a miss is definitive, a hit is only "possibly revoked".
// A filter of *valid* identifiers would let a false positive admit a revoked agent, and would be
// unusable here. Anyone modifying this must preserve that direction.
type BloomFilter struct {
	m    uint64
	k    int
	bits []byte
}

type bloomDocument struct {
	Format int    `json:"format"`
	M      int    `json:"m"`
	K      int    `json:"k"`
	Bits   string `json:"bits"`
}

func bloomFromDocument(document bloomDocument) (*BloomFilter, error) {
	if document.Format != 1 {
		return nil, newError(CodeMalformedToken,
			fmt.Sprintf("unsupported bloom filter format %d", document.Format), nil)
	}
	bits, err := base64.StdEncoding.DecodeString(document.Bits)
	if err != nil {
		return nil, newError(CodeMalformedToken, "bloom filter bits are not valid base64", nil)
	}
	if len(bits)*8 != document.M {
		return nil, newError(CodeMalformedToken,
			"bloom filter bit length does not match declared size", nil)
	}
	return &BloomFilter{m: uint64(document.M), k: document.K, bits: bits}, nil
}

// Has reports whether the item is *possibly* present. False means definitely absent.
func (f *BloomFilter) Has(item string) bool {
	digest := sha256.Sum256([]byte(item))
	h1 := binary.BigEndian.Uint64(digest[0:8])
	h2 := binary.BigEndian.Uint64(digest[8:16])

	for i := 0; i < f.k; i++ {
		index := (h1 + uint64(i)*h2 + uint64(i)*uint64(i)) % f.m
		if f.bits[index>>3]&(1<<(index&7)) == 0 {
			return false
		}
	}
	return true
}

// RevocationState is the revocation knowledge a relying party holds locally.
type RevocationState struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
	filter  *BloomFilter
	serial  int64
	// Exact is false until a full snapshot has been ingested. A fresh store knows nothing and must
	// not claim that an unknown identifier is definitively healthy.
	exact     bool
	fetchedAt time.Time
	// issuedAt is when the registry signed the newest revocation data held (its iat); zero if none.
	issuedAt time.Time
}

func newRevocationState() *RevocationState {
	return &RevocationState{revoked: map[string]struct{}{}, fetchedAt: time.Now()}
}

// Contains reports (revoked, definitive):
//
//	(true, true)   revoked, no doubt
//	(false, true)  not revoked, no doubt
//	(true, false)  possibly revoked; the caller's policy decides
func (s *RevocationState) Contains(subjectID string) (bool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.revoked[subjectID]; ok {
		return true, true
	}
	if s.filter != nil && s.filter.Has(subjectID) {
		// A bloom hit with an exact set present means the exact set already said no, so this is a
		// false positive and the exact answer wins.
		if s.exact {
			return false, true
		}
		return true, false
	}
	return false, s.exact
}

func (s *RevocationState) IsStale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.fetchedAt) >
		time.Duration(RevocationRefreshSeconds+stalenessGraceSeconds)*time.Second
}

// IssuedAt is when the registry signed the newest revocation data held; zero if none yet.
func (s *RevocationState) IssuedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.issuedAt
}

func (s *RevocationState) Serial() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serial
}

// KeySet holds the registry's published public keys.
type KeySet struct {
	keys      map[string]JWK
	fetchedAt time.Time
}

type jwksDocument struct {
	Keys []JWK `json:"keys"`
}

// NewKeySet builds a key set from a JWKS document.
func NewKeySet(document jwksDocument) (*KeySet, error) {
	if len(document.Keys) == 0 {
		return nil, newError(CodeMalformedToken, "JWKS document contains no keys", nil)
	}

	keys := map[string]JWK{}
	for _, jwk := range document.Keys {
		if jwk.Kid == "" {
			continue // cannot be selected deterministically
		}
		if jwk.D != "" {
			// The registry must never publish private material. If it appears, something is badly
			// wrong upstream and the key must not be used.
			return nil, newError(CodeMalformedToken,
				"JWKS contains private key material — refusing to trust it", nil)
		}
		keys[jwk.Kid] = jwk
	}
	if len(keys) == 0 {
		return nil, newError(CodeMalformedToken, "JWKS document contains no usable keys", nil)
	}
	return &KeySet{keys: keys, fetchedAt: time.Now()}, nil
}

func (k *KeySet) Resolve(kid string) (JWK, bool) {
	jwk, ok := k.keys[kid]
	return jwk, ok
}

func (k *KeySet) IsStale() bool {
	return time.Since(k.fetchedAt) >
		time.Duration(JWKSRefreshSeconds+stalenessGraceSeconds)*time.Second
}

// TrustStore is everything a relying party needs to verify offline.
type TrustStore struct {
	KeySet         *KeySet
	Revocation     *RevocationState
	ExpectedIssuer string
}

// TrustOptions configures the bootstrap.
type TrustOptions struct {
	DeltaToken     string
	FilterToken    string
	ExpectedIssuer string
}

// BuildTrustStore performs the usual bootstrap: JWKS plus initial revocation state.
func BuildTrustStore(jwksJSON []byte, options TrustOptions) (*TrustStore, error) {
	var document jwksDocument
	if err := jsonUnmarshal(jwksJSON, &document); err != nil {
		return nil, newError(CodeMalformedToken, "JWKS document is not valid JSON", nil)
	}
	keySet, err := NewKeySet(document)
	if err != nil {
		return nil, err
	}

	store := &TrustStore{
		KeySet: keySet, Revocation: newRevocationState(),
		ExpectedIssuer: options.ExpectedIssuer,
	}
	if options.FilterToken != "" {
		if _, err := store.IngestFilter(options.FilterToken); err != nil {
			return nil, err
		}
	}
	if options.DeltaToken != "" {
		if _, err := store.IngestDelta(options.DeltaToken); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (t *TrustStore) resolve(kid string) (JWK, bool) { return t.KeySet.Resolve(kid) }

// IngestDelta verifies and applies a signed revocation delta, returning the new serial.
func (t *TrustStore) IngestDelta(token string) (int64, error) {
	claims, err := verifyCompact(token, t.resolve, deltaTyp)
	if err != nil {
		return 0, err
	}
	if err := t.checkIssuer(claims); err != nil {
		return 0, err
	}

	since := int64(asFloat(claims["since"]))
	t.Revocation.mu.Lock()
	defer t.Revocation.mu.Unlock()

	if since > t.Revocation.serial {
		// A delta starting past the local serial would leave the revocations in between
		// unlearned, and the gap would never be noticed.
		return 0, newError(CodeRegistryUnavailable,
			"revocation delta starts beyond the local serial — a gap would go unnoticed", nil)
	}

	if entries, ok := claims["revocations"].([]any); ok {
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if subject, ok := entry["subject_id"].(string); ok {
				t.Revocation.revoked[subject] = struct{}{}
			}
		}
	}

	if serial := int64(asFloat(claims["serial"])); serial > t.Revocation.serial {
		t.Revocation.serial = serial
	}
	t.Revocation.fetchedAt = time.Now()
	if iat := asFloat(claims["iat"]); iat > 0 {
		t.Revocation.issuedAt = time.Unix(int64(iat), 0)
	}

	// Only a delta from serial 0 delivers the complete set. Marking the state exact after an
	// incremental delta would be wrong in a specific and dangerous way: a site that bootstrapped
	// from a bloom filter and then applied an empty incremental delta would hold an empty "exact"
	// set and report every revoked agent as healthy.
	complete, hasComplete := claims["complete"].(bool)
	if since == 0 && (!hasComplete || complete) {
		t.Revocation.exact = true
	}
	return t.Revocation.serial, nil
}

// IngestFilter verifies and installs a signed revocation bloom filter.
func (t *TrustStore) IngestFilter(token string) (int64, error) {
	claims, err := verifyCompact(token, t.resolve, filterTyp)
	if err != nil {
		return 0, err
	}
	if err := t.checkIssuer(claims); err != nil {
		return 0, err
	}

	raw, ok := claims["filter"].(map[string]any)
	if !ok {
		return 0, newError(CodeMalformedToken, "revocation filter payload is malformed", nil)
	}
	document := bloomDocument{
		Format: int(asFloat(raw["format"])),
		M:      int(asFloat(raw["m"])),
		K:      int(asFloat(raw["k"])),
	}
	document.Bits, _ = raw["bits"].(string)

	filter, err := bloomFromDocument(document)
	if err != nil {
		return 0, err
	}

	t.Revocation.mu.Lock()
	defer t.Revocation.mu.Unlock()
	t.Revocation.filter = filter
	if serial := int64(asFloat(claims["serial"])); serial > t.Revocation.serial {
		t.Revocation.serial = serial
	}
	t.Revocation.fetchedAt = time.Now()
	// A filter is supplementary and never makes the state exact.
	return t.Revocation.serial, nil
}

func (t *TrustStore) checkIssuer(claims map[string]any) error {
	if t.ExpectedIssuer == "" {
		return nil
	}
	issuer, _ := claims["iss"].(string)
	if issuer != t.ExpectedIssuer {
		return newError(CodeUnknownIssuer,
			fmt.Sprintf("artefact issued by %q, expected %q", issuer, t.ExpectedIssuer), nil)
	}
	return nil
}

// Health exports the trust store's state for the site's own monitoring. A stale store still
// verifies correctly but is no longer learning about revoked agents.
func (t *TrustStore) Health() map[string]any {
	t.Revocation.mu.RLock()
	defer t.Revocation.mu.RUnlock()
	// revocation_issued_at: when the registry signed the newest revocation data held (Unix
	// seconds, 0 if none). Verifiers refuse agents once it is MaxRevocationAgeDefault old.
	var issuedAt int64
	if !t.Revocation.issuedAt.IsZero() {
		issuedAt = t.Revocation.issuedAt.Unix()
	}
	return map[string]any{
		"revocation_issued_at": issuedAt,
		"keys":                 len(t.KeySet.keys),
		"keys_stale":           t.KeySet.IsStale(),
		"revocation_serial":    t.Revocation.serial,
		"revocation_entries":   len(t.Revocation.revoked),
		"revocation_exact":     t.Revocation.exact,
		"revocation_stale":     t.Revocation.IsStale(),
		"has_filter":           t.Revocation.filter != nil,
	}
}

// NonceCache is an in-process replay cache for signature nonces.
//
// Sufficient for a single process. A multi-instance deployment must back this with a shared store
// (Redis SET NX with a TTL matching the maximum signature age) — otherwise a captured request
// simply replays against another instance and the nonce check becomes decorative.
//
// The default TTL is twice the maximum signature age: a signature may be dated up to 300 s in the
// future (clock skew) and stays acceptable until 300 s after that. When full of live entries the
// cache refuses with a registry-unavailable error rather than evicting: forgetting a live nonce
// re-opens replay for exactly that request.
type NonceCache struct {
	mu         sync.Mutex
	seen       map[string]time.Time
	ttl        time.Duration
	maxEntries int
}

// NewNonceCache returns a cache; zero values select the defaults (600 s, 100 000 entries). A
// negative ttl means entries expire immediately, which is only useful in tests.
func NewNonceCache(ttl time.Duration, maxEntries int) *NonceCache {
	if ttl == 0 {
		ttl = 600 * time.Second
	}
	if maxEntries == 0 {
		maxEntries = 100000
	}
	return &NonceCache{seen: map[string]time.Time{}, ttl: ttl, maxEntries: maxEntries}
}

// Check reports whether the nonce has been seen, recording it either way. It returns an error,
// and records nothing, when the cache is full of live nonces.
func (c *NonceCache) Check(nonce string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if at, ok := c.seen[nonce]; ok && now.Sub(at) < c.ttl {
		return true, nil
	}
	if len(c.seen) >= c.maxEntries {
		for seenNonce, at := range c.seen {
			if now.Sub(at) >= c.ttl {
				delete(c.seen, seenNonce)
			}
		}
		if len(c.seen) >= c.maxEntries {
			return false, newError(CodeRegistryUnavailable,
				"replay cache is full of live nonces; refusing rather than forgetting one",
				map[string]any{"max_entries": c.maxEntries})
		}
	}
	c.seen[nonce] = now
	return false, nil
}

func (c *NonceCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func asFloat(value any) float64 {
	if number, ok := value.(float64); ok {
		return number
	}
	return 0
}
