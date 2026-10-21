"""Error taxonomy for AIDR.

Every error carries a stable machine-readable ``code``. Relying parties and SDKs branch on the
code, never on the message text — messages are for humans and may be reworded at any time.

The distinction that matters most here is between errors that mean "this identity is not valid"
(:class:`VerificationError` and its subclasses) and errors that mean "we could not determine
whether this identity is valid" (:class:`RegistryUnavailable`). A relying party must be able to
tell those apart, because the correct response differs: the first is a denial, the second is a
policy decision about fail-open vs fail-closed that only the relying party can make.
"""

from __future__ import annotations


class AidrError(Exception):
    """Base class for every error raised by AIDR components."""

    code = "aidr.error"
    http_status = 500

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "context": self.context}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}({self.code!r}, {self.message!r})"


# --------------------------------------------------------------------------------------
# Identifier errors
# --------------------------------------------------------------------------------------

class InvalidAgentID(AidrError):
    code = "aidr.identifier.invalid"
    http_status = 400


class ChecksumMismatch(InvalidAgentID):
    """The identifier is well-formed but its checksum does not match.

    Almost always a transcription error rather than an attack — the checksum exists precisely so
    that a mistyped identifier fails loudly here instead of silently becoming a lookup miss.
    """

    code = "aidr.identifier.checksum_mismatch"


class InvalidNamespace(InvalidAgentID):
    code = "aidr.identifier.invalid_namespace"


class UnsupportedVersion(InvalidAgentID):
    code = "aidr.identifier.unsupported_version"


# --------------------------------------------------------------------------------------
# Cryptographic errors
# --------------------------------------------------------------------------------------

class CryptoError(AidrError):
    code = "aidr.crypto.error"
    http_status = 400


class InvalidKey(CryptoError):
    code = "aidr.crypto.invalid_key"


class UnsupportedAlgorithm(CryptoError):
    code = "aidr.crypto.unsupported_algorithm"


class SignatureInvalid(CryptoError):
    code = "aidr.crypto.signature_invalid"
    http_status = 401


class MalformedToken(CryptoError):
    code = "aidr.crypto.malformed_token"


# --------------------------------------------------------------------------------------
# Verification errors — "this identity is NOT valid"
# --------------------------------------------------------------------------------------

class VerificationError(AidrError):
    code = "aidr.verify.failed"
    http_status = 401


class CredentialExpired(VerificationError):
    code = "aidr.verify.credential_expired"


class CredentialNotYetValid(VerificationError):
    code = "aidr.verify.credential_not_yet_valid"


class CredentialRevoked(VerificationError):
    code = "aidr.verify.credential_revoked"


class AgentRevoked(VerificationError):
    code = "aidr.verify.agent_revoked"


class UnknownIssuer(VerificationError):
    code = "aidr.verify.unknown_issuer"


class ReplayDetected(VerificationError):
    code = "aidr.verify.replay_detected"


class SignatureTooOld(VerificationError):
    code = "aidr.verify.signature_too_old"


class CoveredComponentMismatch(VerificationError):
    """The signature is valid but does not cover the request actually received.

    This is the attack that naive implementations miss: a signature over a *different* method,
    host or path verifies perfectly well against the right key. The binding is what makes a
    captured signature useless somewhere else.
    """

    code = "aidr.verify.covered_component_mismatch"


class AssuranceTooLow(VerificationError):
    code = "aidr.verify.assurance_too_low"
    http_status = 403


class CapabilityDenied(VerificationError):
    code = "aidr.verify.capability_denied"
    http_status = 403


# --------------------------------------------------------------------------------------
# Registry / lifecycle errors
# --------------------------------------------------------------------------------------

class RegistryError(AidrError):
    code = "aidr.registry.error"


class NotFound(RegistryError):
    code = "aidr.registry.not_found"
    http_status = 404


class InvalidRequest(RegistryError):
    """The request is malformed in a way the schema cannot express (an unreadable cursor)."""

    code = "aidr.registry.invalid_request"
    http_status = 400


class AlreadyExists(RegistryError):
    code = "aidr.registry.already_exists"
    http_status = 409


class VersionConflict(RegistryError):
    """Optimistic concurrency check failed; the caller should re-read and retry."""

    code = "aidr.registry.version_conflict"
    http_status = 409


class InvalidState(RegistryError):
    """The operation is not legal from the record's current state."""

    code = "aidr.registry.invalid_state"
    http_status = 409


class LastOrgAdmin(InvalidState):
    """The change would leave the organisation with no active org_admin, and nobody able to
    invite, issue tokens or change roles."""

    code = "aidr.registry.last_admin"


class PasskeyResetUnavailable(RegistryError):
    """This deployment has no credential with which to reset a passkey (docs/16). Its own code so
    that a console can hide the action instead of offering one that cannot work."""

    code = "aidr.registry.passkey_reset_unavailable"
    http_status = 404


class ChallengeExpired(RegistryError):
    code = "aidr.registry.challenge_expired"
    http_status = 410


class ChallengeAlreadyUsed(RegistryError):
    code = "aidr.registry.challenge_already_used"
    http_status = 409


class DomainControlNotProven(RegistryError):
    """The domain-control check ran and did not find the expected token.

    Distinct from an expired or consumed challenge: this one is still live, and the caller may
    fix their DNS record or file and try again (within the rate limit).
    """

    code = "aidr.registry.domain_control_not_proven"
    http_status = 422


class QuotaExceeded(RegistryError):
    code = "aidr.registry.quota_exceeded"
    http_status = 429


class AgentQuotaExceeded(QuotaExceeded):
    """The organisation holds as many agents as its plan allows. Not a rate limit — retrying will
    not help — so 403, with the plan, the limit and how to free a place in the message."""

    http_status = 403


class MemberLimitReached(QuotaExceeded):
    """The organisation has as many members, counting pending invitations, as its plan allows.
    Like the agent limit, not a rate limit: 403, and its own code so a client can point at the
    plan page."""

    code = "aidr.registry.member_limit"
    http_status = 403


class PolicyViolation(RegistryError):
    code = "aidr.registry.policy_violation"
    http_status = 403


class OrganizationSuspended(PolicyViolation):
    """The organisation is suspended by Evoliv: its members can read, revoke and write to
    support, and change nothing else. Its own code so that a client can say so plainly."""

    code = "aidr.registry.organization_suspended"


class CompanySignInRequired(PolicyViolation):
    """The organisation requires its company sign-in (enterprise SSO, docs/18) for this person, who
    signed in another way. Its own code, so that a console can send them to the company sign-in."""

    code = "aidr.registry.sso_required"


class TermsNotAccepted(PolicyViolation):
    """The organisation has not accepted the current API terms, so it may not register agents or
    issue enrollment tokens. Its own code so that a client can send an admin to accept them."""

    code = "aidr.registry.terms_required"


class VerificationRequired(PolicyViolation):
    """The account has not been verified (or is awaiting review), so it may not register agents.

    Its own code so that a client — the dashboard, the desktop app — can send the person to the
    verification screen instead of showing a generic refusal.
    """

    code = "aidr.account.verification_required"


class EnrollmentTokenInvalid(RegistryError):
    """Malformed, unknown, or the wrong secret — one answer for all three, so the enrollment
    endpoint cannot be used to learn which token ids exist."""

    code = "aidr.enrollment.token_invalid"
    http_status = 401


class EnrollmentTokenInactive(RegistryError):
    """The secret matched, but the token is expired, exhausted or revoked. Its holder already has
    the secret, so saying which reveals nothing new."""

    code = "aidr.enrollment.token_inactive"
    http_status = 403


class RateLimited(QuotaExceeded):
    code = "aidr.registry.rate_limited"


# --------------------------------------------------------------------------------------
# Availability — "we could not determine validity". Never conflate with a denial.
# --------------------------------------------------------------------------------------

class RegistryUnavailable(AidrError):
    code = "aidr.registry.unavailable"
    http_status = 503


class LedgerIntegrityError(AidrError):
    """The audit ledger's hash chain does not verify.

    This is the loudest error in the system. It means either a bug or tampering, and it should
    page a human immediately — never be swallowed, retried, or degraded past.
    """

    code = "aidr.ledger.integrity_violation"
    http_status = 500
