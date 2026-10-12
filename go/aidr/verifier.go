package aidr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Policy is what a site requires of an agent. Every field is the site's decision, not ours.
type Policy struct {
	// MinAssurance is the floor on composite assurance (AgAL), which is min(OAL, KAL).
	MinAssurance int

	// MinKAL is a floor on **key** assurance alone, independent of AgAL.
	//
	// A site that cares specifically about key protection cannot express that through AgAL: a
	// high AgAL can be reached with a strong operator and a merely adequate key. KAL2 means
	// attested non-exportability; KAL3 adds an attested runtime.
	MinKAL int

	RequiredCapabilities []string

	MaxSignatureAge time.Duration // zero means 300s
	RequireNonce    bool

	ExpectedIssuer string
	// PublicOrigins is this site's origin(s), e.g. "https://shop.example" (else AIDR_PUBLIC_ORIGIN).
	// VerifyRequest judges signatures against it, never against the client's Host header except on
	// localhost (origin.go). Required from 0.2.0.
	PublicOrigins []string
	// ExpectedAudience is for audience-bound credentials. Empty: the origin of the URL being
	// verified — the site being visited (the request signature covers @authority). Set it behind
	// a proxy that changes the host.
	ExpectedAudience string

	// MaxUpheldAbuseReports is nil to disable the check. A plain int cannot distinguish "a
	// limit of zero" from "unset", and the zero value would silently reject every agent carrying
	// a single upheld report.
	MaxUpheldAbuseReports *int

	// AllowUnknownRevocation decides what happens when revocation state is inconclusive.
	//
	// Defaults to false — deny. Soft-failing on unknown revocation is the mistake the web PKI
	// spent two decades regretting: it makes revocation optional for anyone who can block a
	// fetch. A site that would rather stay available supplies OnlineRevocationCheck, or sets this
	// deliberately and knowingly.
	AllowUnknownRevocation bool

	// OnlineRevocationCheck is called only when local state is inconclusive.
	OnlineRevocationCheck func(aid string) (bool, error)

	// MaxRevocationAge refuses agents (aidr.registry.unavailable) when the newest revocation data
	// held was signed by the registry longer ago than this, judged from the delta's signed iat
	// (AIAF 6.3). Zero means MaxRevocationAgeDefault (11 minutes, as in every AIDR verifier); a
	// negative value disables the check.
	MaxRevocationAge time.Duration

	Leeway             time.Duration // zero means 60s
	RequiredComponents []string      // zero means RequiredComponents
}

func (p Policy) withDefaults() Policy {
	if p.MaxSignatureAge == 0 {
		p.MaxSignatureAge = 300 * time.Second
	}
	if p.Leeway == 0 {
		p.Leeway = 60 * time.Second
	}
	if len(p.RequiredComponents) == 0 {
		p.RequiredComponents = RequiredComponents
	}
	return p
}

// Result is a verified agent identity plus what the site needs to decide.
type Result struct {
	AID          string
	Organization string
	Assurance    int

	// AIAF assurance axes. AgAL is min(OAL, KAL).
	AgAL int
	OAL  int
	KAL  int
	DAL  int

	// OrgDomains are domains the operator has proven control of (AIAF §4.2). Trust decisions
	// should key on (issuer, verified domain), never on the namespace string.
	OrgDomains   []string
	Capabilities []string
	Scopes       []string
	KeyID        string
	CredentialID string
	ExpiresAt    time.Time
	SignedAt     time.Time

	// Declared is self-asserted by the owner and NOT verified by the registry. Kept in its own
	// field so no site can mistake it for a checked fact: the registry can prove who owns the
	// agent, not what model it runs.
	Declared map[string]any

	// Standing holds registry-internal counts only — never who reported or what was said.
	Standing map[string]any

	// Warnings are non-fatal observations: stale trust material, soft-failed revocation. A site
	// running permanently with warnings is not verifying as well as it thinks.
	Warnings []string
}

func (r Result) HasCapability(capability string) bool {
	for _, granted := range r.Capabilities {
		if granted == capability {
			return true
		}
	}
	return false
}

// Verifier checks agent identity from HTTP request headers, entirely locally.
type Verifier struct {
	trust  *TrustStore
	policy Policy
	nonces *NonceCache
}

func NewVerifier(trust *TrustStore, policy Policy, nonces *NonceCache) *Verifier {
	policy = policy.withDefaults()
	if policy.ExpectedIssuer == "" {
		policy.ExpectedIssuer = trust.ExpectedIssuer
	}
	return &Verifier{trust: trust, policy: policy, nonces: nonces}
}

// VerifyRequest verifies an incoming *http.Request.
//
// The URI is built from this site's origin (Policy.PublicOrigins, or AIDR_PUBLIC_ORIGIN) and the
// request's path — not from the client's Host header, except on localhost (origin.go).
func (v *Verifier) VerifyRequest(request *http.Request) (Result, error) {
	scheme := "https"
	if request.TLS == nil && request.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	} else if forwarded := request.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}

	origin, err := resolveOrigin(v.policy.PublicOrigins, scheme, request.Host)
	if err != nil {
		if !hasAgentHeaders(request.Header) {
			// A person, not an agent: never refused for the site's configuration.
			return Result{}, newError(CodeMalformedToken, "no agent credential presented", nil)
		}
		return Result{}, err
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return Result{}, newError(CodePublicOriginRequired, "public origin is not a URL: "+origin, nil)
	}
	uri, err := EffectiveRequestURI(parsed.Scheme, parsed.Host, request.URL.RequestURI())
	if err != nil {
		return Result{}, err
	}

	headers := map[string]string{}
	for name, values := range request.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}
	return v.Verify(request.Method, uri, headers, time.Now())
}

// Verify checks a request. It returns an error on any failure rather than a verdict value, so a
// dropped result cannot be mistaken for a pass.
//
// The checks run cheapest-first, so a malformed or stale request is rejected before any
// cryptography: verification is the expensive step and an attacker should not be able to force it
// by sending garbage.
func (v *Verifier) Verify(method, requestURL string, headers map[string]string,
	now time.Time) (Result, error) {
	normalised := map[string]string{}
	for name, value := range headers {
		normalised[strings.ToLower(name)] = value
	}

	// 1. credential present
	rawCredential, ok := normalised[HeaderCredential]
	if !ok || rawCredential == "" {
		return Result{}, newError(CodeMalformedToken,
			"request carries no Agent-Credential header — the agent is unidentified", nil)
	}
	if strings.HasPrefix(strings.ToLower(rawCredential), "bearer ") {
		rawCredential = strings.TrimSpace(rawCredential[7:])
	}

	// 2. the registry's signature over the credential
	claims, err := verifyCompact(rawCredential, v.trust.resolve, credentialTyp)
	if err != nil {
		return Result{}, err
	}

	// 3. validity window
	if err := v.validateTimeClaims(claims, now); err != nil {
		return Result{}, err
	}

	// 4. issuer and audience
	if err := v.checkIssuerAndAudience(claims, requestURL); err != nil {
		return Result{}, err
	}

	aid, _ := claims["sub"].(string)
	if aid == "" {
		return Result{}, newError(CodeMalformedToken, "credential has no subject", nil)
	}

	// 5. revocation: fresh enough to rely on, then the identifier itself
	if err := v.checkRevocationAge(now); err != nil {
		return Result{}, err
	}
	warnings, err := v.checkRevocation(aid)
	if err != nil {
		return Result{}, err
	}

	// 6. proof that the sender holds the credential's key, for THIS request
	confirmation, ok := claims["cnf"].(map[string]any)
	if !ok {
		return Result{}, newError(CodeMalformedToken,
			"credential carries no key confirmation ('cnf.jwk')", nil)
	}
	agentJWK, err := jwkFromAny(confirmation["jwk"])
	if err != nil {
		return Result{}, err
	}

	var nonceSeen func(string) (bool, error)
	if v.policy.RequireNonce && v.nonces != nil {
		nonceSeen = v.nonces.Check
	}

	verified, err := verifyRequestSignature(signatureVerifyOptions{
		method:  method,
		url:     requestURL,
		headers: normalised,
		resolve: func(string) (JWK, bool) { return agentJWK, true },
		// The signature's keyid must be the identifier the credential was issued for. Without
		// this, a valid credential for agent A could be paired with a signature made by agent B.
		expectedKeyID:      aid,
		requiredComponents: v.policy.RequiredComponents,
		maxAge:             v.policy.MaxSignatureAge,
		now:                now,
		nonceSeen:          nonceSeen,
	})
	if err != nil {
		return Result{}, err
	}

	// 7. the site's own policy
	//
	// AgAL never falls back to the legacy `assurance` claim: that claim is OAL only, and reading it
	// as AgAL overstates any agent whose key assurance is below its operator's. OAL may fall back
	// to it, because OAL is exactly what it carries.
	agal := intClaim(claims, "agal", "")
	result := Result{
		AID:          aid,
		Organization: stringClaim(claims, "org"),
		Assurance:    agal, // the composite a site should act on
		AgAL:         agal,
		OAL:          intClaim(claims, "oal", "assurance"),
		KAL:          intClaim(claims, "kal", ""),
		DAL:          intClaim(claims, "dal", ""),
		OrgDomains:   stringSlice(claims["org_domains"]),
		Capabilities: stringSlice(claims["capabilities"]),
		Scopes:       stringSlice(claims["scopes"]),
		KeyID:        stringClaim(confirmation, "kid"),
		CredentialID: stringClaim(claims, "jti"),
		SignedAt:     verified.Created,
		Declared:     mapClaim(claims, "declared"),
		Standing:     mapClaim(claims, "standing"),
		Warnings:     warnings,
	}
	if exp := asFloat(claims["exp"]); exp > 0 {
		result.ExpiresAt = time.Unix(int64(exp), 0).UTC()
	}

	if err := v.applyPolicy(&result); err != nil {
		return Result{}, err
	}

	if v.trust.KeySet.IsStale() {
		result.Warnings = append(result.Warnings, "registry key set is stale — refresh JWKS")
	}
	if v.trust.Revocation.IsStale() {
		result.Warnings = append(result.Warnings,
			"revocation state is stale — refresh the delta feed")
	}
	return result, nil
}

func (v *Verifier) validateTimeClaims(claims map[string]any, now time.Time) error {
	exp, ok := claims["exp"]
	if !ok || exp == nil {
		// A non-expiring credential defeats the architecture's safety argument: bounded blast
		// radius from a stolen credential even when revocation fails.
		return newError(CodeMalformedToken,
			"credential has no 'exp' claim — non-expiring credentials are refused", nil)
	}
	expiresAt := time.Unix(int64(asFloat(exp)), 0)
	if now.After(expiresAt.Add(v.policy.Leeway)) {
		return newError(CodeCredentialExpired, "credential has expired",
			map[string]any{"seconds_ago": int(now.Sub(expiresAt).Seconds())})
	}

	if nbf, ok := claims["nbf"]; ok && nbf != nil {
		notBefore := time.Unix(int64(asFloat(nbf)), 0)
		if now.Before(notBefore.Add(-v.policy.Leeway)) {
			return newError(CodeCredentialNotYet, "credential is not yet valid", nil)
		}
	}
	return nil
}

func (v *Verifier) checkIssuerAndAudience(claims map[string]any, requestURL string) error {
	if v.policy.ExpectedIssuer != "" {
		if issuer := stringClaim(claims, "iss"); issuer != v.policy.ExpectedIssuer {
			return newError(CodeUnknownIssuer,
				fmt.Sprintf("credential issued by %q, expected %q", issuer, v.policy.ExpectedIssuer),
				nil)
		}
	}

	audience, present := claims["aud"]
	if !present || audience == nil {
		return nil
	}
	// An audience-bound credential is valid only at the named site. Ignoring the claim would
	// silently undo a binding the issuer deliberately applied.
	expected := v.policy.ExpectedAudience
	if expected == "" {
		expected = requestOrigin(requestURL)
	}
	for _, allowed := range stringSliceOrSingle(audience) {
		if allowed == expected {
			return nil
		}
	}
	return newError(CodePolicyViolation,
		fmt.Sprintf("credential is bound elsewhere, not to %q", expected), nil)
}

// requestOrigin is scheme://host[:port], the host lower-cased and the scheme's default port
// dropped: the form credentials are bound to.
func requestOrigin(requestURL string) string {
	parsed, err := url.Parse(requestURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	origin := parsed.Scheme + "://" + strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if port := parsed.Port(); port != "" &&
		!(parsed.Scheme == "https" && port == "443") && !(parsed.Scheme == "http" && port == "80") {
		origin += ":" + port
	}
	return origin
}

// MaxRevocationAgeDefault is the oldest revocation data agents may be verified against: one 60 s
// refresh plus 600 s of grace. sdk/testdata/vectors.json pins it for every AIDR verifier.
const MaxRevocationAgeDefault = 660 * time.Second

func (v *Verifier) checkRevocationAge(now time.Time) error {
	limit := v.policy.MaxRevocationAge
	if limit == 0 {
		limit = MaxRevocationAgeDefault
	}
	issued := v.trust.Revocation.IssuedAt()
	if limit < 0 || issued.IsZero() {
		return nil
	}
	if age := now.Sub(issued); age > limit {
		return newError(CodeRegistryUnavailable, fmt.Sprintf(
			"revocation data is %d s old (limit %d s): agents are refused until it is refreshed",
			int64(age.Seconds()), int64(limit.Seconds())), nil)
	}
	return nil
}

func (v *Verifier) checkRevocation(aid string) ([]string, error) {
	var warnings []string
	revoked, definitive := v.trust.Revocation.Contains(aid)

	if revoked && definitive {
		return nil, newError(CodeAgentRevoked, "agent identity has been revoked",
			map[string]any{"aid": aid})
	}
	if definitive {
		return warnings, nil
	}

	if check := v.policy.OnlineRevocationCheck; check != nil {
		isRevoked, err := check(aid)
		if err == nil {
			if isRevoked {
				return nil, newError(CodeAgentRevoked, "agent identity has been revoked",
					map[string]any{"aid": aid})
			}
			return warnings, nil
		}
		if !v.policy.AllowUnknownRevocation {
			return nil, newError(CodeRegistryUnavailable,
				"online revocation check failed and the policy is fail-closed", nil)
		}
		return append(warnings, "online revocation check failed: "+err.Error()), nil
	}

	if !v.policy.AllowUnknownRevocation {
		return nil, newError(CodeRegistryUnavailable,
			"revocation state is inconclusive for this identifier and no online check is "+
				"configured; policy is fail-closed", map[string]any{"aid": aid})
	}
	return append(warnings, "revocation status unverified — local state is not authoritative"), nil
}

func (v *Verifier) applyPolicy(result *Result) error {
	if result.AgAL < v.policy.MinAssurance {
		return newError(CodeAssuranceTooLow,
			fmt.Sprintf("agent assurance AgAL%d is below the required AgAL%d",
				result.AgAL, v.policy.MinAssurance), nil)
	}

	if result.KAL < v.policy.MinKAL {
		return newError(CodeAssuranceTooLow,
			fmt.Sprintf("agent key assurance KAL%d is below the required KAL%d — this endpoint "+
				"requires a hardware-protected key", result.KAL, v.policy.MinKAL), nil)
	}

	var missing []string
	for _, required := range v.policy.RequiredCapabilities {
		if !result.HasCapability(required) {
			missing = append(missing, required)
		}
	}
	if len(missing) > 0 {
		return newError(CodeCapabilityDenied,
			"agent lacks required capabilities: "+strings.Join(missing, ", "), nil)
	}

	if limit := v.policy.MaxUpheldAbuseReports; limit != nil {
		upheld := int(asFloat(result.Standing["abuse_reports_upheld"]))
		if upheld > *limit {
			return newError(CodePolicyViolation,
				fmt.Sprintf("agent has %d upheld abuse reports, above this site's limit of %d",
					upheld, *limit), nil)
		}
	}
	return nil
}

// Middleware wraps an http.Handler, verifying the agent and attaching the result to the request
// context under ContextKey.
//
// It distinguishes "not valid" (401) from "could not determine" (503). A site's retry and alerting
// behaviour differs between them, and collapsing both into 401 hides an outage.
func (v *Verifier) Middleware(next http.Handler, optional bool) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result, err := v.VerifyRequest(request)
		if err == nil {
			next.ServeHTTP(writer, request.WithContext(withResult(request.Context(), result)))
			return
		}
		if optional && Code(err) == CodeMalformedToken {
			// No credential at all: unidentified traffic, which a site may still choose to serve.
			next.ServeHTTP(writer, request)
			return
		}

		status := http.StatusUnauthorized
		if IsUnavailable(err) || Code(err) == CodePublicOriginRequired {
			status = http.StatusServiceUnavailable
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"error": map[string]string{"code": Code(err), "message": err.Error()},
		})
	})
}

// -- small helpers ------------------------------------------------------------------------------

func hasAgentHeaders(header http.Header) bool {
	for _, name := range []string{"Agent-Credential", "Signature", "Signature-Input"} {
		if header.Get(name) != "" {
			return true
		}
	}
	return false
}

func jsonUnmarshal(data []byte, target any) error { return json.Unmarshal(data, target) }

func jwkFromAny(value any) (JWK, error) {
	raw, ok := value.(map[string]any)
	if !ok {
		return JWK{}, newError(CodeMalformedToken,
			"credential carries no key confirmation ('cnf.jwk')", nil)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return JWK{}, newError(CodeInvalidKey, "key confirmation is not encodable", nil)
	}
	var jwk JWK
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		return JWK{}, newError(CodeInvalidKey, "key confirmation is not a valid JWK", nil)
	}
	return jwk, nil
}

// intClaim reads an integer claim, falling back to a legacy name when the primary is absent.
func intClaim(claims map[string]any, key, fallback string) int {
	if value, ok := claims[key]; ok {
		return int(asFloat(value))
	}
	if fallback != "" {
		return int(asFloat(claims[fallback]))
	}
	return 0
}

func stringClaim(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return value
}

func mapClaim(claims map[string]any, key string) map[string]any {
	value, _ := claims[key].(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return value
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringSliceOrSingle(value any) []string {
	if text, ok := value.(string); ok {
		return []string{text}
	}
	return stringSlice(value)
}
