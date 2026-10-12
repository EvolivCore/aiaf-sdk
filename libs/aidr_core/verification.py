"""Account verification: who a person is (Personal), or which company they act for (Enterprise).

This grades an **account**, not an organisation. The organisation assurance levels (AIAF §3.2,
docs/05-ai-agent-identity-standard.md) are untouched by it:

* **Personal** — a solo developer's identity: a national ID card or passport, and its number,
  checked by a registry reviewer. It says "this person is who they claim to be". It is not OAL1
  (that is domain control) and not OAL2 (that is a legal entity).
* **Enterprise** — know-your-business: the company's certificate of incorporation, its registration
  number and jurisdiction, and the identity of the person signing for it. That is the evidence an
  OAL2 decision needs, but approving it here does **not** raise any organisation's level:
  ``organization.verify``, under dual control, still does that, and OAL3 keeps its own pipeline
  (aidr_core.onboarding).

What an approval does change is one thing (services/registry_api/verification.py): where the
deployment requires it, an account that is not approved may not register agents.

Identity numbers are personal data of the most sensitive kind. The number is never stored in the
record: it goes to the evidence store like a document (envelope-encrypted, Vault-wrapped key) and
the record keeps only the pointer. It never enters the audit ledger — not even as a digest, because
a digest of a short identifier can be reversed by enumeration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from aidr_core.onboarding import EvidenceDocument, EvidenceKind
from aidr_core.serde import utcnow


class AccountType(str, Enum):
    PERSONAL = "personal"
    ENTERPRISE = "enterprise"


class VerificationStatus(str, Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    INFORMATION_REQUESTED = "information_requested"
    APPROVED = "approved"
    REJECTED = "rejected"


class IdentityDocumentType(str, Enum):
    NATIONAL_ID = "national_id"
    PASSPORT = "passport"


#: The consent wording the applicant accepts before uploading, identified by date. Change the
#: identifier whenever the wording changes, so a record shows what exactly was agreed to.
CONSENT_VERSION = "2026-09-29"
CONSENT_TEXT = ("I consent to the secure processing and storage of these documents for identity "
                "verification purposes in accordance with the Privacy Policy.")

#: Statuses in which the applicant may still change what they submitted.
EDITABLE = frozenset({VerificationStatus.DRAFT, VerificationStatus.INFORMATION_REQUESTED})

#: The documents each account type must upload, in the order the console asks for them.
REQUIRED_DOCUMENTS: dict[AccountType, tuple[EvidenceKind, ...]] = {
    AccountType.PERSONAL: (EvidenceKind.IDENTITY_DOCUMENT,),
    AccountType.ENTERPRISE: (EvidenceKind.CERTIFICATE_OF_INCORPORATION,
                             EvidenceKind.SIGNATORY_IDENTITY),
}

#: Every kind an applicant may upload here. The identity number is not uploaded as a file; the
#: service stores it under IDENTITY_NUMBER itself.
UPLOADABLE: frozenset[EvidenceKind] = frozenset(
    kind for kinds in REQUIRED_DOCUMENTS.values() for kind in kinds)

#: Profile fields each account type must fill in (names as in VerificationProfile).
REQUIRED_FIELDS: dict[AccountType, tuple[str, ...]] = {
    AccountType.PERSONAL: ("full_name", "identity_document_type"),
    AccountType.ENTERPRISE: ("full_name", "job_title", "company_name", "registration_number",
                             "jurisdiction", "identity_document_type"),
}


@dataclass
class VerificationProfile:
    """What the applicant tells us. For Enterprise, the person is the authorised signatory."""

    full_name: str = ""
    identity_document_type: IdentityDocumentType | None = None
    job_title: str = ""
    company_name: str = ""
    registration_number: str = ""
    #: ISO 3166-1 alpha-2 country of incorporation.
    jurisdiction: str = ""


@dataclass
class AccountVerification:
    id: str
    #: The identity provider's subject for the account. One verification per account.
    subject: str
    email: str
    account_type: AccountType
    status: VerificationStatus = VerificationStatus.DRAFT
    profile: VerificationProfile = field(default_factory=VerificationProfile)
    evidence: list[EvidenceDocument] = field(default_factory=list)
    #: The encrypted identity number (EvidenceKind.IDENTITY_NUMBER); see the module docstring.
    identity_number_ref: EvidenceDocument | None = None

    #: When the applicant consented to the processing and storage of their documents, and to
    #: which wording (CONSENT_VERSION). No document is accepted before this is set.
    consented_at: datetime | None = None
    consent_version: str = ""
    #: When a rejected application's documents and identity number were crypto-shredded.
    purged_at: datetime | None = None

    submitted_at: datetime | None = None
    reviewer_id: str | None = None
    decided_at: datetime | None = None
    #: The reviewer's reasons. Shown to reviewers, and to the applicant when information is
    #: requested or the application is rejected.
    decision_notes: str = ""

    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    version: int = 1

    def current_document(self, kind: EvidenceKind) -> EvidenceDocument | None:
        """The latest upload of a kind. Earlier ones stay in WORM storage, and in the record."""
        matching = [document for document in self.evidence if document.kind is kind]
        return matching[-1] if matching else None

    def missing_requirements(self) -> list[str]:
        """What still has to be provided before this can be submitted. Empty means complete."""
        missing: list[str] = []
        for name in REQUIRED_FIELDS[self.account_type]:
            value = getattr(self.profile, name)
            if value is None or (isinstance(value, str) and not value.strip()):
                missing.append(name)
        if self.identity_number_ref is None:
            missing.append("identity_number")
        for kind in REQUIRED_DOCUMENTS[self.account_type]:
            if self.current_document(kind) is None:
                missing.append(kind.value)
        return missing
