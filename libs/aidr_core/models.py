"""Domain models for the AIDR registry (schema rev 2 — identity only).

These mirror ``docs/02-data-model.md``. Two rules govern what may be added here:

1. **No agent activity, ever.** There is no field for a destination host, a request path, a
   payload, or anything else describing what an agent did on someone else's site. If a future
   change wants one, that is a scope decision for the architecture document first, not a field
   added quietly to a dataclass.
2. **No private keys, ever.** :class:`AgentKey` holds a public JWK and nothing else. The registry
   cannot leak what it never receives.

Both rules are restated in the relevant class docstrings, because the place a rule gets broken is
the place someone is editing, not the place it was written down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, IntEnum
from typing import Any

from .serde import utcnow

# ==============================================================================================
# Enumerations
# ==============================================================================================


class OrgStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class OrgTier(str, Enum):
    FREE = "free"           # permanent and non-discriminatory — see docs/01-architecture.md §0.3
    PRO = "pro"
    ENTERPRISE = "enterprise"


class VerificationLevel(str, Enum):
    UNVERIFIED = "unverified"
    DOMAIN_VERIFIED = "domain_verified"
    VERIFIED_LEGAL_ENTITY = "verified_legal_entity"


class OwnerRole(str, Enum):
    ORG_ADMIN = "org_admin"
    AGENT_OPERATOR = "agent_operator"
    AUDITOR = "auditor"
    BILLING = "billing"


class AgentStatus(str, Enum):
    PENDING_PROOF = "pending_proof"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class KeyStatus(str, Enum):
    ACTIVE = "active"
    ROTATING = "rotating"
    RETIRED = "retired"
    COMPROMISED = "compromised"


class AgentType(str, Enum):
    AUTONOMOUS = "autonomous"
    SUPERVISED = "supervised"
    HUMAN_IN_LOOP = "human_in_loop"
    TOOL = "tool"


class AutonomyLevel(str, Enum):
    SUPERVISED = "supervised"
    SEMI_AUTONOMOUS = "semi_autonomous"
    FULLY_AUTONOMOUS = "fully_autonomous"


class ActsOnBehalfOf(str, Enum):
    ORGANIZATION = "organization"
    END_USER = "end_user"
    SELF = "self"


class AssuranceLevel(IntEnum):
    """How strongly the owning entity behind an agent has been verified.

    An integer so relying parties can express a policy as ``>= 2``. The ordering is the point:
    each level strictly subsumes the one below it.
    """

    SELF_ASSERTED = 0       # email + proof of key possession
    DOMAIN_VERIFIED = 1     # + DNS/well-known control of the operating domain
    LEGAL_ENTITY = 2        # + KYB, human review, reachable abuse contact
    HARDWARE_ATTESTED = 3   # the KAL reading of level 3

    #: Alias. This enum predates the AIAF split into separate operator and key axes, and
    #: level 3 means different things on each: a hardware-attested *key* (KAL3) and an
    #: *accountable entity* with a named officer, signed agreement and financial
    #: instrument (OAL3). Same number, different evidence. The alias lets each axis be
    #: named for what it actually asserts without renumbering a value that appears in
    #: issued credentials.
    ACCOUNTABLE_ENTITY = 3


class RevocationReason(str, Enum):
    KEY_COMPROMISE = "key_compromise"
    SUPERSEDED = "superseded"
    CESSATION = "cessation"
    ABUSE = "abuse"
    FRAUD = "fraud"
    OWNER_REQUEST = "owner_request"


class RevocationSubjectType(str, Enum):
    AGENT = "agent"
    KEY = "key"
    CREDENTIAL = "credential"
    ORGANIZATION = "organization"


class AbuseCategory(str, Enum):
    RATE_ABUSE = "rate_abuse"
    ROBOTS_VIOLATION = "robots_violation"
    IMPERSONATION = "impersonation"
    CREDENTIAL_SHARING = "credential_sharing"
    FRAUD = "fraud"
    UNDECLARED_PURPOSE = "undeclared_purpose"
    #: Unsolicited vulnerability or port scanning, or any offensive security probing the target
    #: did not authorise. Tier 1 (AIAF §7.6): upheld means revoked, and the operator is reviewed.
    UNSOLICITED_SCANNING = "unsolicited_scanning"
    OTHER = "other"


class AbuseStatus(str, Enum):
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    UPHELD = "upheld"
    DISMISSED = "dismissed"
    WITHDRAWN = "withdrawn"


class AbuseAction(str, Enum):
    NONE = "none"
    WARNING = "warning"
    ASSURANCE_DEMOTION = "assurance_demotion"
    SUSPENSION = "suspension"
    REVOCATION = "revocation"


class ChallengeType(str, Enum):
    PROOF_OF_POSSESSION = "proof_of_possession"
    DOMAIN_CONTROL = "domain_control"


class DomainProofMethod(str, Enum):
    """How an organisation proved control of a domain (AIAF §3.2, OAL1)."""

    DNS_TXT = "dns-txt"             # TXT at _aiaf-challenge.<domain>
    HTTP = "http"                   # http(s)://<domain>/.well-known/aiaf-challenge.txt


# ==============================================================================================
# Organisations and owners — "the parents"
# ==============================================================================================


@dataclass
class ContactInfo:
    email: str
    phone: str | None = None
    pgp_fingerprint: str | None = None
    sla_hours: int | None = None


@dataclass
class DomainProof:
    fqdn: str
    proof: str = "dns-txt"          # dns-txt | http — see DomainProofMethod
    verified_at: datetime | None = None
    last_rechecked: datetime | None = None


@dataclass
class OrgVerification:
    level: VerificationLevel = VerificationLevel.UNVERIFIED
    registry_id: str | None = None       # company number / LEI — encrypted at the storage layer
    jurisdiction: str | None = None
    verified_at: datetime | None = None
    verified_by: str | None = None       # the human reviewer, recorded for accountability
    evidence_ref: str | None = None      # pointer into WORM storage, never an inline blob


@dataclass
class OrgContacts:
    technical: ContactInfo | None = None
    abuse: ContactInfo | None = None     # mandatory in practice — see Organization.assurance_level
    legal: ContactInfo | None = None


@dataclass
class TermsAcceptance:
    """Which version of the API terms (aidr_core.terms) the organisation accepted, when and by whom.
    The ledger entry ``organization.terms.accept`` is the tamper-evident record of it."""

    version: str
    accepted_at: datetime
    accepted_by: str                         # owner id


@dataclass
class OrgLimits:
    #: Agents the organisation may hold (every one not revoked counts); None is unlimited. Set from
    #: the plan (aidr_core.plans) at self-service sign-up and whenever the plan changes.
    max_agents: int | None = 100
    max_issuance_per_hour: int = 100


@dataclass
class AccountabilityReview:
    """An operator under review because one of its agents committed a Tier 1 violation.

    AIAF §7.6: the enterprise answers for its agents' offensive actions. While a review is open
    the organisation's OAL is capped at 1, so every credential issued to any of its agents in the
    meantime says so — relying parties do not have to learn about the incident to be protected
    from its operator. Closing a review is a dual-controlled, AAL3 security-officer action.
    """

    id: str
    report_id: str
    aid: str
    category: str
    opened_at: datetime = field(default_factory=utcnow)
    status: str = "open"                 # open | resolved
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution: str | None = None


@dataclass
class Organization:
    """The legal entity behind a set of agents."""

    id: str
    namespace: str
    legal_name: str
    display_name: str = ""
    status: OrgStatus = OrgStatus.PENDING
    tier: OrgTier = OrgTier.FREE
    verification: OrgVerification = field(default_factory=OrgVerification)
    domains: list[DomainProof] = field(default_factory=list)
    contacts: OrgContacts = field(default_factory=OrgContacts)
    limits: OrgLimits = field(default_factory=OrgLimits)
    #: Active OAL3 grant, when the organisation has completed enterprise onboarding.
    #: Absent means OAL2 at best — and so does a *lapsed* grant, because accountability
    #: is a live property: an operator whose insurance expired is not an accountable
    #: entity this month, whatever it was last month.
    oal3_grant: Any | None = None
    accountability_reviews: list[AccountabilityReview] = field(default_factory=list)
    #: The API terms last accepted. Absent, or an older version: no new agents or enrollment
    #: tokens while AIDR_TERMS=required.
    terms: TermsAcceptance | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    version: int = 1

    def verified_domains(self) -> list[str]:
        """Domains this organisation has proven control of within the re-verification window.

        AIAF §4.2: a relying party must key trust on (issuer, verified domain), never on the
        namespace string — otherwise a squatter registering the same namespace at a permissive
        registry impersonates the real operator. Domain control is the only namespace anchor that
        already has an authority behind it, which is why the Web PKI uses it for the same purpose.
        """
        return [d.fqdn.lower() for d in self.domains if d.verified_at is not None]

    @property
    def assurance_level(self) -> AssuranceLevel:
        """Derive the operator assurance level (OAL) an agent of this organisation inherits.

        A verified legal entity with no reachable abuse contact is demoted to domain-verified.
        The registry's value proposition is that someone can be held accountable; an unreachable
        operator is an unaccountable one, so the claim is withdrawn automatically rather than
        depending on anyone remembering to withdraw it.

        OAL3 requires a *live* grant. The grant itself checks that the operating agreement and
        financial instrument underpinning it are still in force, so the earliest lapse governs
        rather than the most convenient one.

        An open accountability review (a Tier 1 violation by one of its agents) caps the level at
        DOMAIN_VERIFIED whatever the evidence says, until a security officer closes it.
        """
        earned = self._earned_assurance_level()
        if self.under_accountability_review():
            return AssuranceLevel(min(int(earned), int(AssuranceLevel.DOMAIN_VERIFIED)))
        return earned

    def under_accountability_review(self) -> bool:
        return any(review.status == "open" for review in self.accountability_reviews)

    def _earned_assurance_level(self) -> AssuranceLevel:
        if self.verification.level == VerificationLevel.VERIFIED_LEGAL_ENTITY:
            if self.contacts.abuse and self.contacts.abuse.email:
                if self.oal3_grant is not None and self.oal3_grant.is_valid():
                    return AssuranceLevel.ACCOUNTABLE_ENTITY
                return AssuranceLevel.LEGAL_ENTITY
            return AssuranceLevel.DOMAIN_VERIFIED
        if self.verification.level == VerificationLevel.DOMAIN_VERIFIED:
            return AssuranceLevel.DOMAIN_VERIFIED
        return AssuranceLevel.SELF_ASSERTED

    def is_operational(self) -> bool:
        return self.status == OrgStatus.ACTIVE


@dataclass
class MFASettings:
    enrolled: bool = False
    methods: list[str] = field(default_factory=list)
    hardware_required: bool = False


@dataclass
class OwnerAuth:
    method: str = "oidc"            # oidc | mtls_cert | api_key
    oidc_subject: str | None = None
    mfa: MFASettings = field(default_factory=MFASettings)


@dataclass
class Owner:
    """A human or service principal who administers agents."""

    id: str
    org_id: str
    email: str
    display_name: str = ""
    role: OwnerRole = OwnerRole.AGENT_OPERATOR
    status: str = "active"
    auth: OwnerAuth = field(default_factory=OwnerAuth)
    last_login_at: datetime | None = None
    created_at: datetime = field(default_factory=utcnow)

    def requires_hardware_mfa(self) -> bool:
        """Privileged roles require a hardware authenticator, with no TOTP fallback.

        A phishable second factor on an account that can mint identities is not a second factor.
        """
        return self.role == OwnerRole.ORG_ADMIN


class InvitationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REVOKED = "revoked"


@dataclass
class Invitation:
    """An organisation's invitation for one email address to join it as an operator.

    Joining is the only way besides sign-up to bind a person's account to an organisation, so it
    carries the same guarantee: whoever accepts must hold a *verified* email at a domain the
    organisation has *proven* (OAL1). The invitation token is shown once and stored only as its
    SHA-256; the registry cannot re-send it, only issue a new one.
    """

    id: str
    org_id: str
    email: str
    role: OwnerRole
    token_hash: str
    invited_by: str
    expires_at: datetime
    status: InvitationStatus = InvitationStatus.PENDING
    accepted_at: datetime | None = None
    accepted_subject: str | None = None
    owner_id: str | None = None
    revoked_at: datetime | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    version: int = 1

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at


class EnrollmentTokenStatus(str, Enum):
    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class EnrollmentToken:
    """Permission, delegated by an org_admin, for code to register agents with no person present.

    Presented as ``aidr_et_<id>_<secret>``; only the secret's SHA-256 is stored, and the token is
    shown once. It enrolls new agents and does nothing else — it never authenticates an agent that
    exists. Every agent it enrolls is owned by ``issued_by``, the admin answerable for it.
    ``uses + reserved`` never exceeds ``max_uses``: an enrollment reserves a use when it starts
    and converts it when its proof of possession succeeds.
    """

    id: str
    org_id: str
    issued_by: str                           # owner id of the issuing org_admin
    issued_by_subject: str                   # their identity-provider subject, for the gate
    secret_hash: str
    expires_at: datetime
    label: str = ""
    max_uses: int = 1
    uses: int = 0
    reserved: int = 0
    name_prefix: str | None = None
    scopes: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    audiences: list[str] = field(default_factory=list)
    status: EnrollmentTokenStatus = EnrollmentTokenStatus.ACTIVE
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    version: int = 1

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at

    def current_status(self, now: datetime | None = None) -> EnrollmentTokenStatus:
        """The stored status, with expiry computed now (it is written back on the next touch)."""
        if self.status == EnrollmentTokenStatus.ACTIVE and self.is_expired(now):
            return EnrollmentTokenStatus.EXPIRED
        return self.status


@dataclass
class EnrolledVia:
    """How an agent registered with an enrollment token came to exist (a copy for display; the
    ledger's agent.register entry is authoritative)."""

    token_id: str
    issued_by: str


# ==============================================================================================
# Agents
# ==============================================================================================


@dataclass
class KeyAttestation:
    """Evidence that an agent key lives in a protected module (AIAF §3.3).

    Note what is *not* here: the raw module identifier. A TPM Endorsement Key certificate or a
    Nitro module id is a permanent, globally unique hardware identifier, and storing it would give
    the registry a device fingerprint linkable across every organisation that ever used that
    machine. ``module_identity_hash`` is salted per deployment — enough to notice one module
    attesting for implausibly many operators, not enough to build the graph.
    """

    profile: str                              # "aws-nitro" | "tpm2-certify" | ...
    evidence_class: str                       # "cryptographic" | "third_party_assertion"
    attested_kal: int
    module_identity_hash: str
    module_vendor: str
    module_class: str                         # "enclave" | "discrete_tpm" | "hsm" | ...
    verified_at: datetime
    expires_at: datetime
    challenge_id: str
    measurement_digest: str | None = None
    measurement_baseline_matched: bool = False

    def is_valid(self, at: datetime | None = None) -> bool:
        return (at or utcnow()) < self.expires_at


@dataclass
class AgentKey:
    """A public key bound to an agent.

    There is deliberately no private-key field, in this class or anywhere else in the schema.
    Owners generate keys locally and send us only the public half. That single constraint means a
    total compromise of the registry database yields no ability to impersonate any agent.
    """

    kid: str
    alg: str                                 # Ed25519 | ES256 ; ML-DSA-65 reserved for aid:v2
    public_key_jwk: dict[str, Any]
    status: KeyStatus = KeyStatus.ACTIVE
    proof_challenge_id: str | None = None
    proof_verified_at: datetime | None = None
    #: Hardware attestation, once verified. Absent means KAL1 — and so does an *expired*
    #: attestation, because assurance is a live property rather than a historical one.
    attestation: KeyAttestation | None = None
    created_at: datetime = field(default_factory=utcnow)
    not_after: datetime | None = None
    retired_at: datetime | None = None

    def is_usable(self, at: datetime | None = None) -> bool:
        moment = at or utcnow()
        if self.status not in (KeyStatus.ACTIVE, KeyStatus.ROTATING):
            return False
        if self.proof_verified_at is None:
            return False        # a key that never proved possession was never really bound
        if self.not_after and moment >= self.not_after:
            return False
        return True


@dataclass
class AgentProfile:
    name: str
    description: str = ""
    agent_type: AgentType = AgentType.AUTONOMOUS
    homepage: str | None = None
    user_agent_string: str | None = None


@dataclass
class AgentSpecification:
    """The agent and model specification, **as declared by the owner**.

    Every field here is self-asserted and unverifiable over the wire. The registry must never
    present these as verified facts — doing so would be the fastest available way to destroy its
    credibility. What is verifiable is who declared it, which makes a false declaration
    attributable to a named, contactable legal entity. That is the accountability mechanism; the
    declaration itself is not evidence.
    """

    model_family: str | None = None
    model_version: str | None = None
    capabilities_declared: list[str] = field(default_factory=list)
    autonomy_level: AutonomyLevel = AutonomyLevel.SUPERVISED
    human_oversight: bool = True
    declared_at: datetime = field(default_factory=utcnow)

    #: Field names that are self-asserted. Serialised into credentials so a relying party can
    #: tell declared claims from verified ones without consulting documentation.
    SELF_ASSERTED_FIELDS = ("model_family", "model_version", "capabilities_declared",
                            "autonomy_level", "human_oversight")


@dataclass
class AgentDeclaration:
    """What the owner commits their agent will do. A commitment, not a control."""

    purposes: list[str] = field(default_factory=list)
    acts_on_behalf_of: ActsOnBehalfOf = ActsOnBehalfOf.ORGANIZATION
    respects_robots_txt: bool = True
    training_data_collection: bool = False
    max_request_rate: int | None = None
    contact_for_abuse: str | None = None


@dataclass
class AgentAssurance:
    #: Snapshot of the inherited level at registration, kept for display and history.
    #: **Not** used to compute the credential: see AgentAssurance.demotions.
    level: AssuranceLevel = AssuranceLevel.SELF_ASSERTED

    #: Agent-specific demotions, applied against the organisation's *current* level.
    #:
    #: Counting demotions rather than freezing a level is what lets an organisation's
    #: upgrade reach the agents it already has. Storing the level directly made it a
    #: snapshot: an operator who completed OAL3 onboarding would have seen every agent
    #: registered beforehand keep reporting the old level, which is the opposite of what
    #: the grant is for.
    demotions: int = 0
    attestation_type: str = "none"          # none | nitro | tpm2 | hsm

    #: Expected runtime measurements, declared by the operator **before** any attestation
    #: is presented (AIAF §3.3). Recording it in advance is what makes KAL3 meaningful:
    #: comparing an attestation against a baseline taken from that same attestation
    #: proves nothing at all.
    measurement_baseline: dict[str, str] = field(default_factory=dict)
    #: Profile the operator intends to use, declared at the same time.
    attestation_profile: str | None = None


@dataclass
class AgentStanding:
    """Trust signals derived **only** from registry-internal facts.

    No traffic data feeds this, because the registry observes no traffic. Every input is either
    something we did (a suspension) or something someone formally reported to us (an abuse
    report). That constraint is what keeps a reputation signal from becoming a surveillance
    product.
    """

    abuse_reports_open: int = 0
    abuse_reports_upheld: int = 0
    suspensions: int = 0
    key_compromises: int = 0
    last_evaluated_at: datetime | None = None

    def is_clean(self) -> bool:
        return self.abuse_reports_upheld == 0 and self.suspensions == 0 and self.key_compromises == 0


@dataclass
class AgentCounters:
    credentials_issued: int = 0
    last_credential_issued_at: datetime | None = None
    # Note what is absent: no request counts, no destinations, no last-seen-on-site. Issuance is
    # our own event and reveals volume but never destination.


@dataclass
class Agent:
    """An agent identity record — the heart of the registry."""

    id: str                                  # the full canonical aid: string
    org_id: str
    owner_id: str
    namespace: str
    profile: AgentProfile
    specification: AgentSpecification = field(default_factory=AgentSpecification)
    declaration: AgentDeclaration = field(default_factory=AgentDeclaration)
    capabilities: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    keys: list[AgentKey] = field(default_factory=list)
    status: AgentStatus = AgentStatus.PENDING_PROOF
    status_reason: str | None = None
    assurance: AgentAssurance = field(default_factory=AgentAssurance)
    standing: AgentStanding = field(default_factory=AgentStanding)
    counters: AgentCounters = field(default_factory=AgentCounters)
    #: Origins this agent may obtain credentials for; empty = unrestricted (issuance enforces it).
    allowed_audiences: list[str] = field(default_factory=list)
    #: Set only for agents registered with an enrollment token.
    enrolled_via: EnrolledVia | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    version: int = 1

    def active_key(self) -> AgentKey | None:
        """The key to use for new credentials: the newest usable one.

        Newest-first matters during rotation, when an agent legitimately holds two usable keys and
        should be migrating to the newer.
        """
        usable = [k for k in self.keys if k.is_usable()]
        return max(usable, key=lambda k: k.created_at) if usable else None

    def key_by_id(self, kid: str) -> AgentKey | None:
        return next((k for k in self.keys if k.kid == kid), None)

    def is_active(self) -> bool:
        return self.status == AgentStatus.ACTIVE

    def can_issue_credentials(self) -> bool:
        return self.is_active() and self.active_key() is not None


# ==============================================================================================
# Credentials, revocations, challenges
# ==============================================================================================


@dataclass
class CredentialRecord:
    """Metadata about a credential we issued. The credential body is never stored.

    We keep exactly enough to revoke and to audit, and deliberately not enough to impersonate.
    There is no audience or destination field: an issuance record can say "this agent asked us for
    a valid identity at 14:32" and can never say where the agent then went.
    """

    id: str
    jti: str
    aid: str
    kid: str
    issued_at: datetime
    expires_at: datetime
    signing_key_id: str
    capabilities_snapshot: list[str] = field(default_factory=list)
    status: str = "active"                   # active | revoked | expired

    def is_expired(self, at: datetime | None = None) -> bool:
        return (at or utcnow()) >= self.expires_at


@dataclass
class Revocation:
    """A revocation record. Small, hot, and replicated to every edge."""

    id: str
    subject_type: RevocationSubjectType
    subject_id: str
    reason: RevocationReason
    serial: int                              # monotonic — clients fetch deltas with ?since=
    revoked_at: datetime = field(default_factory=utcnow)
    effective_at: datetime = field(default_factory=utcnow)
    revoked_by: str | None = None
    cascade: bool = True
    audit_ref: str | None = None


@dataclass
class Challenge:
    """A single-use, short-lived nonce the owner must sign to prove key possession."""

    id: str
    type: ChallengeType
    nonce: str
    subject: str                             # the aid: or domain the challenge is about
    expires_at: datetime
    created_at: datetime = field(default_factory=utcnow)
    consumed_at: datetime | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def is_expired(self, at: datetime | None = None) -> bool:
        return (at or utcnow()) >= self.expires_at

    def is_consumed(self) -> bool:
        return self.consumed_at is not None


@dataclass
class DomainCheckAttempt:
    """One outbound domain-control check the registry performed, kept for rate limiting only.

    Every verification request makes the registry send DNS queries and HTTP requests to a host
    the *caller* named. Unlimited, that is a free reflector: sign up, claim a victim's domain, and
    have the registry hammer it. These records are what the limits count. They hold the domain
    and the organisation that asked — nothing about any agent — and expire after a day.
    """

    id: str
    org_id: str
    fqdn: str
    challenge_id: str
    method: DomainProofMethod
    at: datetime = field(default_factory=utcnow)
    succeeded: bool = False


@dataclass
class AbuseReport:
    """A report filed *to* the registry about an agent.

    The registry is a mailbox here, not a sensor: evidence is supplied by the reporter and never
    collected by us. This is how "is this agent trustworthy" becomes answerable without observing
    any traffic — the same way a national registry learns a document was misused by being told.
    """

    id: str
    aid: str
    category: AbuseCategory
    reporter_type: str = "relying_party"     # relying_party | registered_org | public | internal
    reporter_id: str | None = None
    reporter_contact: str | None = None
    reporter_domain: str | None = None    # sensitive: a real site↔agent link. Never exposed.
    description: str = ""
    evidence_ref: str | None = None
    status: AbuseStatus = AbuseStatus.SUBMITTED
    resolution_outcome: str | None = None
    resolution_action: AbuseAction = AbuseAction.NONE
    resolved_at: datetime | None = None
    reviewer_id: str | None = None
    owner_notified_at: datetime | None = None
    owner_response: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    def public_view(self) -> dict[str, Any]:
        """What may be exposed outside the registry: counts and category only.

        Never the reporter, never the description, never the evidence. Exposing reporters would
        turn the registry into a tool for competitors to smear each other, and reporter domains
        would leak exactly the site↔agent relationships the rev-2 scope was designed to eliminate.
        """
        return {"category": self.category.value, "status": self.status.value,
                "created_at": self.created_at}


# ==============================================================================================
# Audit ledger
# ==============================================================================================


@dataclass
class AuditActor:
    type: str                                # user | service | system
    id: str | None = None
    ip: str | None = None                 # truncated to a prefix before it reaches here
    session_id: str | None = None


@dataclass
class StaffNotification:
    """An item in the registry operators' inbox on the admin console (docs/11, step 4): a new
    organisation, an account verification waiting for review. Identifiers only — who is waiting is
    for the review screens, not the inbox. ``read_by`` holds the operator ids that have read it."""

    id: str
    kind: str                                # organization.signup | account.verification.submit
    org_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    read_by: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class AuditEntry:
    """One appended entry in the tamper-evident ledger of registry operations.

    Subject matter is what our operators and customers did to identity records — never what an
    agent did on someone's website. ``before_hash``/``after_hash`` are digests rather than
    documents, which is what lets the right to erasure and an immutable audit trail coexist: the
    personal data can be deleted while the proof that a change occurred remains.
    """

    id: str
    seq: int
    ts: datetime
    actor: AuditActor
    action: str                              # agent.create | agent.revoke | abuse.uphold | ...
    target_type: str
    target_id: str
    prev_hash: str
    entry_hash: str
    before_hash: str | None = None
    after_hash: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    tree_head_ref: str | None = None


@dataclass
class SignedTreeHead:
    """A signed commitment to the ledger's contents at a point in time.

    Published externally every few minutes. Anyone holding last week's head can verify that this
    week's tree still contains it, which proves we did not rewrite history in between. That is the
    difference between tamper-*evident* — provable — and tamper-*proof*, which is marketing.
    """

    id: str
    tree_size: int
    root_hash: str
    timestamp: datetime
    signature: str
    signing_key_id: str


# ==============================================================================================
# Credential payload (the wire format relying parties actually see)
# ==============================================================================================

DEFAULT_CREDENTIAL_TTL = timedelta(minutes=15)
DEFAULT_CERTIFICATE_TTL = timedelta(days=90)


@dataclass
class CredentialClaims:
    """The JWS payload presented to a website in the ``Agent-Credential`` header.

    Self-contained by design: everything a relying party needs to make a decision travels in the
    credential, so verification requires no call to us. The declared/verified split is explicit —
    ``declared`` is what the owner asserted, ``assurance`` is what we checked.
    """

    iss: str                                 # the registry, e.g. "https://registry.aidr.example"
    sub: str                                 # the aid: identifier
    jti: str
    iat: datetime
    exp: datetime
    nbf: datetime
    org: str                                 # owning organisation namespace
    assurance: int                           # AssuranceLevel — VERIFIED by us
    capabilities: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    cnf: dict[str, Any] = field(default_factory=dict)      # RFC 7800 key confirmation: {"jwk": ...}
    declared: dict[str, Any] = field(default_factory=dict)  # self-asserted, clearly fenced off
    aud: str | None = None                # set only when the relying party is known in advance

    def ttl_seconds(self) -> int:
        return int((self.exp - self.iat).total_seconds())
