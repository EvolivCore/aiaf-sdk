"""OAL3 enterprise onboarding: Responsible Officer, operating agreement, financial instrument.

AIAF §3.2 defines OAL3 as OAL2 **plus** a named Responsible Officer proofed to an IAL2 equivalent,
a signed operating agreement accepting responsibility for agent conduct, and a financial instrument
sized to the agent's authorised actions.

Three things shape this schema, and each one is a constraint rather than a preference:

**OAL3 is the highest-value forgery target in the system.** It is the level a payments layer will
rely on, so a forged grant is worth more than a forged anything-else. Every artefact therefore
carries a content digest that goes into the tamper-evident ledger: swapping a document after
approval must be detectable, not merely discouraged.

**We are now handling a natural person's identity.** Proofing a Responsible Officer to IAL2 means
government identity documents. This schema is built so the registry **does not hold them**: the
preferred path records an external identity-verification provider's *result* and reference, never
the documents. Holding passport scans for every enterprise customer creates a breach liability out
of all proportion to the value it adds, and the document-holding path exists only for jurisdictions
where an external provider is unavailable.

**None of this is permanent.** Contracts lapse, officers leave, insurance expires. An OAL3 grant
carries an expiry and re-verification cadence, and lapse **demotes** rather than revokes — the same
rule attestation follows, for the same reason: a paperwork lapse must not take an enterprise's
agents offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from .serde import utcnow

# ==============================================================================================
# Enumerations
# ==============================================================================================


class SubmissionStatus(str, Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    #: The reviewer needs something more. Distinct from rejection: the clock pauses, the
    #: submission stays open, and the operator is told exactly what is missing.
    INFORMATION_REQUESTED = "information_requested"
    #: A reviewer has assessed the evidence and recommends a grant. **Not yet granted** — a second
    #:, distinct person must approve (AIAF §8.16, WebTrust 4.1).
    RECOMMENDED = "recommended"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"


class EvidenceKind(str, Enum):
    OPERATING_AGREEMENT = "operating_agreement"
    FINANCIAL_INSTRUMENT = "financial_instrument"
    OFFICER_PROOFING = "officer_proofing"
    CORPORATE_REGISTRY_EXTRACT = "corporate_registry_extract"
    SUPPORTING = "supporting"
    # Account verification (aidr_core.verification). The identity kinds carry the short
    # proofing retention, like OFFICER_PROOFING.
    IDENTITY_DOCUMENT = "identity_document"
    IDENTITY_NUMBER = "identity_number"
    CERTIFICATE_OF_INCORPORATION = "certificate_of_incorporation"
    SIGNATORY_IDENTITY = "signatory_identity"


class ProofingMethod(str, Enum):
    #: **Preferred.** An accredited identity-verification provider proofs the officer and returns
    #: a result; the registry stores the outcome and a reference, never the documents.
    EXTERNAL_IDV = "external_idv"
    #: Fallback for jurisdictions without a usable provider. Documents are held encrypted under
    #: WORM with a short retention, and this path should be the exception.
    MANUAL_REVIEW = "manual_review"


class InstrumentKind(str, Enum):
    PROFESSIONAL_INDEMNITY = "professional_indemnity"
    CYBER_LIABILITY = "cyber_liability"
    SURETY_BOND = "surety_bond"
    ESCROW = "escrow"
    PARENT_GUARANTEE = "parent_guarantee"


class InstrumentVerification(str, Enum):
    #: The issuer confirmed the policy directly. The only method that survives a determined forger.
    ISSUER_CONFIRMED = "issuer_confirmed"
    BROKER_CONFIRMED = "broker_confirmed"
    #: A document was supplied and nobody independently confirmed it. **Insufficient for OAL3.**
    DOCUMENT_ONLY = "document_only"


class SignatureMethod(str, Enum):
    #: A detached JWS by the officer's registered key. Strongest, and machine-verifiable forever.
    CRYPTOGRAPHIC = "cryptographic"
    ESIGNATURE = "esignature"
    WET_INK_SCAN = "wet_ink_scan"


# ==============================================================================================
# Evidence
# ==============================================================================================


@dataclass
class EvidenceDocument:
    """A document held in write-once storage.

    ``sha256`` is the load-bearing field. It is recorded in the audit ledger at submission, so a
    document substituted after approval is detectable by anyone replaying the log — which is the
    difference between "we keep documents safely" and "we can prove which document was approved".
    """

    id: str
    kind: EvidenceKind
    #: Opaque pointer into WORM storage, including the immutable version identifier.
    storage_ref: str
    sha256: str
    content_type: str
    size_bytes: int
    filename: str = ""
    #: How the object is encrypted. Envelope encryption with the data key wrapped by Vault means
    #: the storage operator holds ciphertext and nothing else.
    encryption: str = "envelope-aes256gcm"
    #: Vault-wrapped data encryption key. Useless without the Transit key it was wrapped under.
    wrapped_key: str = ""
    uploaded_at: datetime = field(default_factory=utcnow)
    uploaded_by: str = ""
    #: WORM retention. Until this passes, the object cannot be deleted by anyone — including a
    #: root operator, which is the point.
    retention_until: datetime | None = None
    legal_hold: bool = False
    #: Crypto-shredded: the wrapped data key was destroyed, so the ciphertext still held under
    #: retention can never be decrypted again. The digest stays, so the ledger still verifies.
    shredded_at: datetime | None = None

    def is_retained(self, at: datetime | None = None) -> bool:
        if self.legal_hold:
            return True
        if self.retention_until is None:
            return False
        return (at or utcnow()) < self.retention_until


# ==============================================================================================
# Responsible Officer
# ==============================================================================================


@dataclass
class OfficerProofing:
    """The result of proofing a natural person, without the documents that produced it."""

    method: ProofingMethod
    #: The assurance the proofing achieved, in NIST SP 800-63A terms. Note this is one of the few
    #: places 800-63 genuinely applies: the Responsible Officer *is* a human being.
    achieved_level: str = "ial2"
    provider: str | None = None
    #: The provider's verification identifier. A reference to their record, not a copy of it.
    provider_reference: str | None = None
    proofed_at: datetime | None = None
    #: Set only on the MANUAL_REVIEW path. Absent on the preferred path, which is the point.
    evidence_id: str | None = None
    #: Who at the registry accepted the proofing, when it was reviewed by hand.
    reviewed_by: str | None = None

    def is_sufficient_for_oal3(self) -> bool:
        return self.achieved_level in {"ial2", "ial3"} and self.proofed_at is not None


@dataclass
class ResponsibleOfficer:
    """The named natural person accountable for an operator's agents.

    Personal data. Every field marked below is encrypted client-side (see
    ``aidr_db.encryption``), and none of it may enter the audit ledger.
    """

    id: str
    full_name: str                       # 🔐
    role_title: str
    email: str                           # 🔐
    phone: str | None = None             # 🔐
    #: Jurisdiction the officer is accountable in — which court would hear a claim.
    jurisdiction: str | None = None
    proofing: OfficerProofing | None = None
    #: When the officer personally accepted the responsibility, distinct from when the company
    #: signed the agreement. One is an institution's commitment; the other is a person's.
    accepted_responsibility_at: datetime | None = None
    #: Public key, when the officer signs cryptographically. Never a private key.
    signing_public_jwk: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=utcnow)
    #: Officers change. A superseded officer is retained for the audit trail rather than deleted,
    #: because a grant made on their accountability must remain explicable afterwards.
    superseded_at: datetime | None = None

    def is_active(self) -> bool:
        return self.superseded_at is None


# ==============================================================================================
# Operating agreement and financial instrument
# ==============================================================================================


@dataclass
class OperatingAgreement:
    """The contract in which an operator accepts responsibility for its agents' conduct."""

    version: str
    signed_at: datetime
    signatory_officer_id: str
    method: SignatureMethod
    evidence_id: str
    document_sha256: str
    #: Detached JWS over the document digest, for the cryptographic method. Machine-verifiable
    #: indefinitely, unlike a scanned signature which is only ever evidence for a human.
    signature_jws: str | None = None
    #: Agreements have terms. One that has lapsed does not support an OAL3 claim.
    effective_from: datetime | None = None
    expires_at: datetime | None = None

    def is_current(self, at: datetime | None = None) -> bool:
        moment = at or utcnow()
        if self.effective_from and moment < self.effective_from:
            return False
        return not (self.expires_at and moment >= self.expires_at)


@dataclass
class FinancialInstrument:
    """Insurance, bond, escrow or guarantee backing the operator's accountability.

    The registry cannot verify a PDF cryptographically; verifying an insurance certificate means
    contacting the issuer. ``verification`` records *how* that was done, and a document nobody
    independently confirmed does not support OAL3 — see :meth:`is_sufficient_for_oal3`.
    """

    kind: InstrumentKind
    provider_name: str
    policy_reference: str                # 🔐
    #: Minor units (pence, cents) to avoid float rounding on money.
    coverage_amount_minor: int
    coverage_currency: str
    effective_from: datetime
    expires_at: datetime
    verification: InstrumentVerification = InstrumentVerification.DOCUMENT_ONLY
    verified_by: str | None = None
    verified_at: datetime | None = None
    evidence_id: str | None = None
    #: Free-text record of the confirmation — who was spoken to, reference given.
    verification_note: str = ""           # 🔐

    def is_current(self, at: datetime | None = None) -> bool:
        moment = at or utcnow()
        return self.effective_from <= moment < self.expires_at

    def is_sufficient_for_oal3(self, *, minimum_coverage_minor: int,
                               at: datetime | None = None) -> bool:
        return (
            self.is_current(at)
            and self.verification in {InstrumentVerification.ISSUER_CONFIRMED,
                                      InstrumentVerification.BROKER_CONFIRMED}
            and self.coverage_amount_minor >= minimum_coverage_minor
        )


# ==============================================================================================
# Decision signature
# ==============================================================================================


@dataclass
class DecisionSignature:
    """A registry administrator's cryptographic sign-off on a decision.

    Recording "usr_alice approved" is an assertion by the system about itself. A signature over the
    canonical decision document is evidence that survives the system: an auditor can verify it
    without trusting our database, and an operator whose OAL3 was granted can be shown *what* was
    approved rather than merely that something was.

    The payload digest covers the whole decision — submission, organisation, evidence digests,
    level, expiry — so a signature cannot be lifted onto a different grant.
    """

    method: str                           # "ed25519_admin_key" | "webauthn"
    signer_id: str
    key_id: str
    signature: str                        # base64url
    payload_digest: str                   # sha256 hex of the canonical decision document
    signed_at: datetime = field(default_factory=utcnow)


# ==============================================================================================
# Submission and grant
# ==============================================================================================


#: How long an OAL3 grant stands before re-verification. Annual because that is the cadence at
#: which insurance renews and officers change, not because a year is inherently meaningful.
DEFAULT_OAL3_VALIDITY = timedelta(days=365)

#: Warn this far ahead of expiry, so renewal is a scheduled task rather than an incident.
OAL3_RENEWAL_WINDOW = timedelta(days=60)


@dataclass
class OAL3Submission:
    """An enterprise's application for OAL3."""

    id: str
    org_id: str
    status: SubmissionStatus = SubmissionStatus.DRAFT
    officer: ResponsibleOfficer | None = None
    operating_agreement: OperatingAgreement | None = None
    financial_instrument: FinancialInstrument | None = None
    evidence: list[EvidenceDocument] = field(default_factory=list)

    submitted_by: str | None = None
    submitted_at: datetime | None = None

    #: Review is separate from approval, and both are separate from submission. Three distinct
    #: parties in the strict case; two at minimum (AIAF §8.16).
    reviewer_id: str | None = None
    reviewed_at: datetime | None = None
    review_notes: str = ""                # 🔐
    information_requested: str = ""
    recommendation: str | None = None     # "grant" | "reject"

    #: The dual-control request that must be approved before a grant takes effect.
    approval_request_id: str | None = None
    #: Expiry fixed when the approval payload was prepared.
    #:
    #: Persisted so the bytes an approver signs are the bytes the server verifies. If
    #: the expiry were recomputed at approval time it would differ by microseconds from
    #: the prepared document, and no signature would ever verify.
    prepared_expires_at: datetime | None = None
    approver_id: str | None = None
    decision_signature: DecisionSignature | None = None

    granted_at: datetime | None = None
    expires_at: datetime | None = None
    rejection_reason: str = ""

    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    version: int = 1

    # -- completeness --------------------------------------------------------------------------

    def evidence_by_kind(self, kind: EvidenceKind) -> list[EvidenceDocument]:
        return [document for document in self.evidence if document.kind == kind]

    def missing_requirements(self, *, minimum_coverage_minor: int,
                             at: datetime | None = None) -> list[str]:
        """What still stands between this submission and a grant.

        Returned as a list rather than a boolean so the console can tell an operator exactly what
        to supply. "Your application is incomplete" generates a support ticket; naming the three
        missing items generates the three missing items.
        """
        missing: list[str] = []

        if self.officer is None:
            missing.append("a named Responsible Officer")
        else:
            if self.officer.proofing is None or not self.officer.proofing.is_sufficient_for_oal3():
                missing.append("identity proofing of the Responsible Officer to IAL2 or above")
            if self.officer.accepted_responsibility_at is None:
                missing.append("the Responsible Officer's personal acceptance of responsibility")

        agreement = self.operating_agreement
        if agreement is None:
            missing.append("a signed operating agreement")
        elif not agreement.is_current(at):
            missing.append("an operating agreement that is currently in force")

        instrument = self.financial_instrument
        if instrument is None:
            missing.append("a financial instrument")
        elif not instrument.is_current(at):
            missing.append("a financial instrument that has not expired")
        elif instrument.verification is InstrumentVerification.DOCUMENT_ONLY:
            missing.append(
                "independent confirmation of the financial instrument with its issuer or broker "
                "— a supplied document alone does not evidence cover")
        elif instrument.coverage_amount_minor < minimum_coverage_minor:
            missing.append(
                f"financial cover of at least "
                f"{minimum_coverage_minor / 100:,.0f} {instrument.coverage_currency}")

        return missing

    def is_complete(self, *, minimum_coverage_minor: int,
                    at: datetime | None = None) -> bool:
        return not self.missing_requirements(
            minimum_coverage_minor=minimum_coverage_minor, at=at)

    def evidence_digests(self) -> dict[str, str]:
        """Content digests of every attached document, for the decision signature and the ledger."""
        return {document.id: document.sha256 for document in sorted(
            self.evidence, key=lambda d: d.id)}


@dataclass
class OAL3Grant:
    """An active OAL3 grant held on the organisation record."""

    submission_id: str
    officer_id: str
    granted_at: datetime
    expires_at: datetime
    granted_by: str
    approved_by: str
    #: Digest of the decision the approver signed. Lets an auditor tie a live grant back to the
    #: exact evidence set it was made on.
    decision_digest: str
    instrument_expires_at: datetime | None = None
    agreement_expires_at: datetime | None = None

    def is_valid(self, at: datetime | None = None) -> bool:
        """Valid only while the grant *and* everything it rests on remain in force.

        An operator whose insurance lapsed in March does not have an accountable-entity grant in
        April, whatever the grant's own expiry says. Checking the components here means the
        earliest lapse governs, rather than the most convenient one.
        """
        moment = at or utcnow()
        if moment >= self.expires_at:
            return False
        if self.instrument_expires_at and moment >= self.instrument_expires_at:
            return False
        return not (self.agreement_expires_at and moment >= self.agreement_expires_at)

    def needs_renewal(self, at: datetime | None = None) -> bool:
        return (at or utcnow()) >= self.expires_at - OAL3_RENEWAL_WINDOW
