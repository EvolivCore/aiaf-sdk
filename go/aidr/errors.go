// Package aidr verifies AI agent identity offline against the AIDR registry.
//
// Standard library only — no dependencies. A verification library with a dependency tree is a
// verification library that can be compromised without touching its own code.
//
// Typical use:
//
//	trust, err := aidr.BuildTrustStore(jwks, aidr.TrustOptions{
//		DeltaToken:     deltaToken,
//		ExpectedIssuer: "https://registry.aidr.example",
//	})
//	verifier := aidr.NewVerifier(trust, aidr.Policy{MinAssurance: 1}, aidr.NewNonceCache(0, 0))
//	result, err := verifier.VerifyRequest(r)
//
// Refresh the JWKS hourly and the revocation delta every 60 seconds in the background. Nothing in
// the request path contacts the registry.
package aidr

import "fmt"

// Error codes are identical across the Python, Node and Go SDKs. A relying party running more
// than one must be able to branch on a single set of codes; messages are for humans and may be
// reworded, codes are the contract.
const (
	CodeMalformedToken      = "aidr.crypto.malformed_token"
	CodeSignatureInvalid    = "aidr.crypto.signature_invalid"
	CodeUnsupportedAlg      = "aidr.crypto.unsupported_algorithm"
	CodeInvalidKey          = "aidr.crypto.invalid_key"
	CodeCredentialExpired   = "aidr.verify.credential_expired"
	CodeCredentialNotYet    = "aidr.verify.credential_not_yet_valid"
	CodeAgentRevoked        = "aidr.verify.agent_revoked"
	CodeUnknownIssuer       = "aidr.verify.unknown_issuer"
	CodeReplayDetected      = "aidr.verify.replay_detected"
	CodeSignatureTooOld     = "aidr.verify.signature_too_old"
	CodeComponentMismatch   = "aidr.verify.covered_component_mismatch"
	CodeAssuranceTooLow     = "aidr.verify.assurance_too_low"
	CodeCapabilityDenied    = "aidr.verify.capability_denied"
	CodePolicyViolation     = "aidr.registry.policy_violation"
	CodeRegistryUnavailable = "aidr.registry.unavailable"
)

// Error carries a stable machine-readable code alongside a human message.
type Error struct {
	Code    string
	Message string
	Context map[string]any
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func newError(code, message string, context map[string]any) *Error {
	return &Error{Code: code, Message: message, Context: context}
}

// IsDenial reports whether the error means "this identity is NOT valid".
//
// The distinction from [IsUnavailable] matters: a denial is a decision, an unavailability is a
// failure to decide, and the correct response differs. Collapsing both into 401 hides an outage.
func IsDenial(err error) bool {
	var e *Error
	if !asError(err, &e) {
		return false
	}
	return e.Code != CodeRegistryUnavailable
}

// IsUnavailable reports whether the verifier could not determine validity — a fail-closed
// refusal, not a statement about the agent.
func IsUnavailable(err error) bool {
	var e *Error
	if !asError(err, &e) {
		return false
	}
	return e.Code == CodeRegistryUnavailable
}

// Code returns the stable error code, or "" for a non-AIDR error.
func Code(err error) string {
	var e *Error
	if !asError(err, &e) {
		return ""
	}
	return e.Code
}

func asError(err error, target **Error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*Error); ok {
		*target = e
		return true
	}
	return false
}
