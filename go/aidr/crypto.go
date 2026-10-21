package aidr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Components every AIDR signature must cover. Dropping any one re-enables a real attack: without
// @method a GET signature replays as a DELETE, without @authority it replays against another
// site, without @path against another endpoint on the same site.
var RequiredComponents = []string{"@method", "@authority", "@path"}

const (
	HeaderSignatureInput = "signature-input"
	HeaderSignature      = "signature"
	HeaderCredential     = "agent-credential"

	credentialTyp = "aidr-cred+jwt"
	deltaTyp      = "aidr-crl+jwt"
	filterTyp     = "aidr-crl-filter+jwt"
)

// JWK is the subset of RFC 7517 that AIDR uses.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"` // must never be present in a published key set
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
}

type algorithm struct {
	joseAlg string
	httpAlg string
}

var (
	algEd25519 = algorithm{joseAlg: "EdDSA", httpAlg: "ed25519"}
	algES256   = algorithm{joseAlg: "ES256", httpAlg: "ecdsa-p256-sha256"}
)

func algorithmForJWK(jwk JWK) (algorithm, error) {
	// Resolved from kty/crv, never from the alg member: alg is a hint an attacker controls, and
	// honouring it over the actual key material is precisely the algorithm-confusion bug.
	switch {
	case jwk.Kty == "OKP" && jwk.Crv == "Ed25519":
		return algEd25519, nil
	case jwk.Kty == "EC" && jwk.Crv == "P-256":
		return algES256, nil
	default:
		return algorithm{}, newError(CodeUnsupportedAlg,
			fmt.Sprintf("unsupported key type kty=%s crv=%s", jwk.Kty, jwk.Crv), nil)
	}
}

func algorithmByHTTPName(name string) (algorithm, bool) {
	switch name {
	case algEd25519.httpAlg:
		return algEd25519, true
	case algES256.httpAlg:
		return algES256, true
	default:
		return algorithm{}, false
	}
}

// b64urlDecode decodes unpadded base64url, rejecting anything outside the alphabet.
func b64urlDecode(text string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(text, "="))
	if err != nil {
		return nil, newError(CodeInvalidKey, "invalid base64url encoding", nil)
	}
	return decoded, nil
}

type publicKey struct {
	alg      algorithm
	ed25519  ed25519.PublicKey
	ecdsaKey *ecdsa.PublicKey
}

func importPublicKey(jwk JWK) (publicKey, error) {
	if jwk.D != "" {
		return publicKey{}, newError(CodeInvalidKey,
			"a private key was supplied where a public key is required", nil)
	}

	alg, err := algorithmForJWK(jwk)
	if err != nil {
		return publicKey{}, err
	}

	x, err := b64urlDecode(jwk.X)
	if err != nil {
		return publicKey{}, err
	}

	if alg == algEd25519 {
		if len(x) != ed25519.PublicKeySize {
			return publicKey{}, newError(CodeInvalidKey,
				fmt.Sprintf("Ed25519 public key must be 32 bytes, got %d", len(x)), nil)
		}
		return publicKey{alg: alg, ed25519: ed25519.PublicKey(x)}, nil
	}

	y, err := b64urlDecode(jwk.Y)
	if err != nil {
		return publicKey{}, err
	}
	// RFC 7518 §6.2.1.2 requires fixed-width coordinates: variable widths would give one key
	// several encodings and therefore several thumbprints.
	if len(x) != 32 || len(y) != 32 {
		return publicKey{}, newError(CodeInvalidKey,
			"P-256 coordinates must be exactly 32 bytes each", nil)
	}

	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	// An off-curve point is an invalid-curve attack or a corrupt key; it must never reach a
	// verification call.
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return publicKey{}, newError(CodeInvalidKey, "point is not on the P-256 curve", nil)
	}
	return publicKey{alg: alg, ecdsaKey: key}, nil
}

func (k publicKey) verify(signature, data []byte) error {
	if len(signature) != 64 {
		return newError(CodeSignatureInvalid,
			fmt.Sprintf("%s signature must be 64 bytes, got %d", k.alg.joseAlg, len(signature)), nil)
	}

	if k.alg == algEd25519 {
		if !ed25519.Verify(k.ed25519, data, signature) {
			return newError(CodeSignatureInvalid, "signature verification failed", nil)
		}
		return nil
	}

	// JOSE uses the fixed-width R‖S form, not ASN.1 DER. Getting this wrong produces signatures
	// that verify in one language and nowhere else.
	digest := sha256.Sum256(data)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(k.ecdsaKey, digest[:], r, s) {
		return newError(CodeSignatureInvalid, "signature verification failed", nil)
	}
	return nil
}

var _ = crypto.SHA256 // keep the crypto import meaningful across Go versions

// ===============================================================================================
// Compact JWS
// ===============================================================================================

type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// KeyResolver maps a kid to a JWK the caller already trusts. Returning false means "not trusted".
type KeyResolver func(kid string) (JWK, bool)

// verifyCompact verifies a compact JWS and returns its claims.
//
// Parse and verify are one function on purpose: there is no code path that returns claims without
// having checked the signature, so no caller can accidentally trust an unverified payload.
func verifyCompact(token string, resolve KeyResolver, expectedTyp string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, newError(CodeMalformedToken, "compact JWS must have three parts", nil)
	}

	headerBytes, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, newError(CodeMalformedToken, "JWS header is not valid base64url", nil)
	}
	var header jwsHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, newError(CodeMalformedToken, "JWS header is not valid JSON", nil)
	}

	// Refused before any key lookup: covers alg=none, HS256 confusion, RS256 and everything else.
	if header.Alg != algEd25519.joseAlg && header.Alg != algES256.joseAlg {
		return nil, newError(CodeUnsupportedAlg,
			fmt.Sprintf("unsupported or unsafe JWS algorithm %q", header.Alg), nil)
	}
	if expectedTyp != "" && header.Typ != expectedTyp {
		return nil, newError(CodeMalformedToken,
			fmt.Sprintf("unexpected token type %q; expected %q", header.Typ, expectedTyp), nil)
	}
	if header.Kid == "" {
		return nil, newError(CodeMalformedToken, "JWS header is missing 'kid'", nil)
	}

	jwk, ok := resolve(header.Kid)
	if !ok {
		return nil, newError(CodeUnknownIssuer,
			fmt.Sprintf("no trusted key for kid %q", header.Kid), nil)
	}

	key, err := importPublicKey(jwk)
	if err != nil {
		return nil, err
	}
	// The header's algorithm must match the key we actually trust for this kid. Checking only one
	// side reintroduces algorithm confusion through the back door.
	if key.alg.joseAlg != header.Alg {
		return nil, newError(CodeUnsupportedAlg,
			fmt.Sprintf("header declares %s but the trusted key is %s", header.Alg, key.alg.joseAlg), nil)
	}

	signature, err := b64urlDecode(parts[2])
	if err != nil {
		return nil, newError(CodeMalformedToken, "JWS signature is not valid base64url", nil)
	}
	if err := key.verify(signature, []byte(parts[0]+"."+parts[1])); err != nil {
		return nil, err
	}

	payloadBytes, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, newError(CodeMalformedToken, "JWS payload is not valid base64url", nil)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, newError(CodeMalformedToken, "JWS payload is not valid JSON", nil)
	}
	return claims, nil
}

// ===============================================================================================
// RFC 9421 structured fields — the narrow subset AIDR emits and accepts
// ===============================================================================================

type signatureEntry struct {
	label      string
	position   int // where it appeared in Signature-Input: header order, which a map loses
	components []string
	params     map[string]any
	// Kept verbatim: re-serialising risks a canonicalisation mismatch, which would look exactly
	// like a forged signature.
	rawValue string
}

func splitTopLevel(text string, separator rune) ([]string, error) {
	var parts []string
	var current strings.Builder
	inQuotes, escaped, depth := false, false, 0

	for _, char := range text {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' && inQuotes {
			current.WriteRune(char)
			escaped = true
			continue
		}
		if char == '"' {
			inQuotes = !inQuotes
			current.WriteRune(char)
			continue
		}
		if !inQuotes {
			switch char {
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					return nil, newError(CodeMalformedToken, "unbalanced ')' in structured field", nil)
				}
			case separator:
				if depth == 0 {
					parts = append(parts, strings.TrimSpace(current.String()))
					current.Reset()
					continue
				}
			}
		}
		current.WriteRune(char)
	}
	if inQuotes {
		return nil, newError(CodeMalformedToken, "unterminated quoted string in structured field", nil)
	}
	if depth != 0 {
		return nil, newError(CodeMalformedToken, "unbalanced parentheses in structured field", nil)
	}
	parts = append(parts, strings.TrimSpace(current.String()))

	filtered := parts[:0]
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return filtered, nil
}

func unquote(token string) string {
	if len(token) >= 2 && strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`) {
		inner := token[1 : len(token)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		return strings.ReplaceAll(inner, `\\`, `\`)
	}
	return token
}

func parseParams(text string) (map[string]any, error) {
	params := map[string]any{}
	items, err := splitTopLevel(text, ';')
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		index := strings.Index(item, "=")
		if index < 0 {
			params[strings.TrimSpace(item)] = true
			continue
		}
		key := strings.TrimSpace(item[:index])
		raw := strings.TrimSpace(item[index+1:])
		switch {
		case strings.HasPrefix(raw, `"`):
			params[key] = unquote(raw)
		default:
			if number, err := strconv.ParseInt(raw, 10, 64); err == nil {
				params[key] = number
			} else {
				params[key] = raw
			}
		}
	}
	return params, nil
}

// ParseSignatureInput parses a Signature-Input header into label → entry.
func parseSignatureInput(headerValue string) (map[string]signatureEntry, error) {
	entries := map[string]signatureEntry{}
	members, err := splitTopLevel(headerValue, ',')
	if err != nil {
		return nil, err
	}

	for _, member := range members {
		index := strings.Index(member, "=")
		if index < 0 {
			return nil, newError(CodeMalformedToken, "malformed Signature-Input member", nil)
		}
		label := strings.TrimSpace(member[:index])
		value := strings.TrimSpace(member[index+1:])
		if label == "" || !strings.HasPrefix(value, "(") {
			return nil, newError(CodeMalformedToken, "malformed Signature-Input member", nil)
		}

		close := strings.Index(value, ")")
		if close < 0 {
			return nil, newError(CodeMalformedToken, "unterminated component list", nil)
		}
		inner := strings.TrimSpace(value[1:close])
		paramsText := strings.TrimPrefix(value[close+1:], ";")

		var components []string
		if inner != "" {
			tokens, err := splitTopLevel(inner, ' ')
			if err != nil {
				return nil, err
			}
			for _, token := range tokens {
				components = append(components, unquote(token))
			}
		}

		params := map[string]any{}
		if paramsText != "" {
			if params, err = parseParams(paramsText); err != nil {
				return nil, err
			}
		}

		entries[label] = signatureEntry{
			label: label, position: len(entries), components: components, params: params, rawValue: value,
		}
	}

	if len(entries) == 0 {
		return nil, newError(CodeMalformedToken, "Signature-Input header contains no signatures", nil)
	}
	return entries, nil
}

func parseSignatureHeader(headerValue string) (map[string][]byte, error) {
	signatures := map[string][]byte{}
	members, err := splitTopLevel(headerValue, ',')
	if err != nil {
		return nil, err
	}

	for _, member := range members {
		index := strings.Index(member, "=")
		if index < 0 {
			return nil, newError(CodeMalformedToken, "malformed Signature member", nil)
		}
		label := strings.TrimSpace(member[:index])
		value := strings.TrimSpace(member[index+1:])
		if len(value) < 2 || !strings.HasPrefix(value, ":") || !strings.HasSuffix(value, ":") {
			return nil, newError(CodeMalformedToken, "malformed Signature member", nil)
		}
		decoded, err := base64.StdEncoding.DecodeString(value[1 : len(value)-1])
		if err != nil {
			return nil, newError(CodeMalformedToken,
				fmt.Sprintf("signature for %q is not valid base64", label), nil)
		}
		signatures[label] = decoded
	}

	if len(signatures) == 0 {
		return nil, newError(CodeMalformedToken, "Signature header contains no signatures", nil)
	}
	return signatures, nil
}

func deriveComponent(name, method, requestURL string, headers map[string]string) (string, error) {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", newError(CodeMalformedToken, "request URL is not parseable", nil)
	}

	switch name {
	case "@method":
		return strings.ToUpper(method), nil
	case "@target-uri":
		return requestURL, nil
	case "@authority":
		// Lowercase with the default port omitted: https://HOST:443/ and https://host/ are the
		// same origin, and an agent must not have to guess which spelling the server will use.
		authority := strings.ToLower(parsed.Host)
		if parsed.Scheme == "https" {
			authority = strings.TrimSuffix(authority, ":443")
		}
		if parsed.Scheme == "http" {
			authority = strings.TrimSuffix(authority, ":80")
		}
		return authority, nil
	case "@scheme":
		return strings.ToLower(parsed.Scheme), nil
	case "@path":
		if parsed.Path == "" {
			return "/", nil
		}
		return parsed.Path, nil
	case "@query":
		if parsed.RawQuery == "" {
			return "?", nil
		}
		return "?" + parsed.RawQuery, nil
	}

	if strings.HasPrefix(name, "@") {
		return "", newError(CodeUnsupportedAlg,
			fmt.Sprintf("derived component %q is not supported", name), nil)
	}

	value, ok := headers[strings.ToLower(name)]
	if !ok {
		return "", newError(CodeComponentMismatch,
			fmt.Sprintf("signature covers header %q, which is absent from the request", name), nil)
	}
	return strings.Join(strings.Fields(value), " "), nil
}

func buildSignatureBase(components []string, signatureParams, method, requestURL string,
	headers map[string]string) ([]byte, error) {
	lines := make([]string, 0, len(components)+1)
	for _, name := range components {
		value, err := deriveComponent(name, method, requestURL, headers)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fmt.Sprintf("%q: %s", strings.ToLower(name), value))
	}
	lines = append(lines, fmt.Sprintf("%q: %s", "@signature-params", signatureParams))
	return []byte(strings.Join(lines, "\n")), nil
}

// VerifiedSignature describes an accepted RFC 9421 signature.
type VerifiedSignature struct {
	Label      string
	KeyID      string
	Created    time.Time
	Nonce      string
	Components []string
	Tag        string
}

type signatureVerifyOptions struct {
	method             string
	url                string
	headers            map[string]string
	resolve            func(keyid string) (JWK, bool)
	requiredComponents []string
	maxAge             time.Duration
	now                time.Time
	nonceSeen          func(string) (bool, error)
	// The keyids that name the credential's own key: its identifier, and the thumbprint of its
	// cnf.jwk (a Web Bot Auth signature). Empty: any.
	expectedKeyIDs []string
}

// chooseSignature picks the signature to verify when a request carries several (RFC 9421 allows
// any number): the first, in header order, whose keyid is one the credential names; otherwise the
// first in header order that has a signature value, which then fails on its keyid as it should.
// Map order is random in Go, so header order is restored from each entry's position.
func chooseSignature(entries map[string]signatureEntry, signatures map[string][]byte,
	accepted []string) (signatureEntry, []byte) {
	ordered := make([]signatureEntry, 0, len(entries))
	for _, entry := range entries {
		ordered = append(ordered, entry)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].position < ordered[j].position })
	if len(accepted) > 0 {
		for _, entry := range ordered {
			keyid, _ := entry.params["keyid"].(string)
			if sig, ok := signatures[entry.label]; ok && containsString(accepted, keyid) {
				return entry, sig
			}
		}
	}
	for _, entry := range ordered {
		if sig, ok := signatures[entry.label]; ok {
			return entry, sig
		}
	}
	return signatureEntry{}, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// JWKThumbprint is the base64url SHA-256 JWK thumbprint (RFC 7638; RFC 8037 appendix A.3 for OKP
// keys): the keyid of a Web Bot Auth signature.
func JWKThumbprint(jwk JWK) (string, error) {
	var canonical string
	switch jwk.Kty {
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%s,"kty":"OKP","x":%s}`, quoteJSON(jwk.Crv), quoteJSON(jwk.X))
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%s,"kty":"EC","x":%s,"y":%s}`,
			quoteJSON(jwk.Crv), quoteJSON(jwk.X), quoteJSON(jwk.Y))
	default:
		return "", newError(CodeInvalidKey, fmt.Sprintf("cannot take the thumbprint of a %q key", jwk.Kty), nil)
	}
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func quoteJSON(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// verifyRequestSignature checks an RFC 9421 signature on a received request.
//
// Checks run cheapest-first, so a malformed or stale request is rejected before any cryptography.
// That ordering is a small DoS mitigation: verification is the expensive step and an attacker
// should not be able to force it by sending garbage.
func verifyRequestSignature(options signatureVerifyOptions) (VerifiedSignature, error) {
	rawInput, ok := options.headers[HeaderSignatureInput]
	if !ok {
		return VerifiedSignature{}, newError(CodeMalformedToken,
			"request is missing Signature-Input or Signature headers", nil)
	}
	rawSignature, ok := options.headers[HeaderSignature]
	if !ok {
		return VerifiedSignature{}, newError(CodeMalformedToken,
			"request is missing Signature-Input or Signature headers", nil)
	}

	entries, err := parseSignatureInput(rawInput)
	if err != nil {
		return VerifiedSignature{}, err
	}
	signatures, err := parseSignatureHeader(rawSignature)
	if err != nil {
		return VerifiedSignature{}, err
	}

	entry, signature := chooseSignature(entries, signatures, options.expectedKeyIDs)
	if signature == nil {
		return VerifiedSignature{}, newError(CodeMalformedToken,
			"no Signature member matches any Signature-Input label", nil)
	}

	var declared algorithm
	hasDeclared := false
	if raw, ok := entry.params["alg"].(string); ok {
		declared, hasDeclared = algorithmByHTTPName(raw)
		if !hasDeclared {
			return VerifiedSignature{}, newError(CodeUnsupportedAlg,
				fmt.Sprintf("unsupported signature algorithm %q", raw), nil)
		}
	}

	keyid, _ := entry.params["keyid"].(string)
	if keyid == "" {
		return VerifiedSignature{}, newError(CodeMalformedToken,
			"signature parameters are missing 'keyid'", nil)
	}
	if len(options.expectedKeyIDs) > 0 && !containsString(options.expectedKeyIDs, keyid) {
		// The credential says one identity, the signature another. Almost always an attempt to
		// pair a stolen credential with a key the attacker actually controls.
		return VerifiedSignature{}, newError(CodeComponentMismatch,
			"signature keyid does not match the presented credential", nil)
	}

	createdRaw, ok := entry.params["created"].(int64)
	if !ok {
		return VerifiedSignature{}, newError(CodeMalformedToken,
			"signature parameters are missing 'created'", nil)
	}
	created := time.Unix(createdRaw, 0).UTC()
	age := options.now.Sub(created)
	if age > options.maxAge {
		return VerifiedSignature{}, newError(CodeSignatureTooOld,
			fmt.Sprintf("signature is %ds old, older than the %ds limit",
				int(age.Seconds()), int(options.maxAge.Seconds())), nil)
	}
	if age < -options.maxAge {
		return VerifiedSignature{}, newError(CodeSignatureTooOld,
			"signature was created in the future beyond clock-skew tolerance", nil)
	}
	if expires, ok := entry.params["expires"].(int64); ok && options.now.After(time.Unix(expires, 0)) {
		return VerifiedSignature{}, newError(CodeSignatureTooOld,
			"signature has passed its stated expiry", nil)
	}

	covered := map[string]bool{}
	for _, component := range entry.components {
		covered[strings.ToLower(component)] = true
	}
	var missing []string
	for _, required := range options.requiredComponents {
		if !covered[strings.ToLower(required)] {
			missing = append(missing, required)
		}
	}
	if len(missing) > 0 {
		return VerifiedSignature{}, newError(CodeComponentMismatch,
			"signature does not cover required components: "+strings.Join(missing, ", "), nil)
	}

	nonce, _ := entry.params["nonce"].(string)
	if options.nonceSeen != nil && nonce == "" {
		return VerifiedSignature{}, newError(CodeMalformedToken,
			"replay protection is enabled but the signature carries no nonce", nil)
	}

	jwk, ok := options.resolve(keyid)
	if !ok {
		return VerifiedSignature{}, newError(CodeSignatureInvalid,
			fmt.Sprintf("no public key available for keyid %q", keyid), nil)
	}
	key, err := importPublicKey(jwk)
	if err != nil {
		return VerifiedSignature{}, err
	}
	if hasDeclared && declared != key.alg {
		return VerifiedSignature{}, newError(CodeUnsupportedAlg,
			"signature declares an algorithm the key is not", nil)
	}

	base, err := buildSignatureBase(entry.components, entry.rawValue,
		options.method, options.url, options.headers)
	if err != nil {
		return VerifiedSignature{}, err
	}
	if err := key.verify(signature, base); err != nil {
		return VerifiedSignature{}, err
	}

	// The replay check comes last, after the signature has verified. nonceSeen records the nonce
	// it is asked about, so consulting it earlier would let a forged request occupy a nonce: the
	// genuine request would then be refused as a replay, and forgeries could fill the cache.
	if options.nonceSeen != nil {
		seen, err := options.nonceSeen(nonce)
		if err != nil {
			return VerifiedSignature{}, err
		}
		if seen {
			return VerifiedSignature{}, newError(CodeReplayDetected,
				"signature nonce has already been used", nil)
		}
	}

	tag, _ := entry.params["tag"].(string)
	return VerifiedSignature{
		Label: entry.label, KeyID: keyid, Created: created,
		Nonce: nonce, Components: entry.components, Tag: tag,
	}, nil
}

// EffectiveRequestURI reconstructs the request URI a server actually received.
//
// Must be built from what the server received, never from anything inside the signature, which is
// attacker-controlled. Behind a proxy, ensure the Host header and forwarded scheme are the
// trusted, rewritten ones.
func EffectiveRequestURI(scheme, hostHeader, pathWithQuery string) (string, error) {
	if hostHeader == "" {
		return "", newError(CodeMalformedToken, "cannot derive request URI without a Host header", nil)
	}
	if !strings.HasPrefix(pathWithQuery, "/") {
		pathWithQuery = "/" + pathWithQuery
	}
	return scheme + "://" + hostHeader + pathWithQuery, nil
}
