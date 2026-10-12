"""AIAF assurance levels for an agent, derived from evidence at the moment they are asked for.

One implementation for everything that states them: issuance, which puts them in credentials, and
the registry, which shows them to the agent's organisation. Two copies would eventually disagree,
and an admin would be shown a level the agent's credentials do not carry.

    OAL  §3.2  the operator's assurance: its organisation's level, less agent-specific demotions
    KAL  §3.3  how well the agent's key is protected, from proof of possession and attestation
    AgAL §3.5  min(OAL, KAL)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aidr_core.models import Agent, AssuranceLevel


def operator_assurance(agent: Agent, organization: Any) -> AssuranceLevel:
    """Operator assurance (OAL) for this agent: the organisation's current level, less any
    agent-specific demotion.

    Derived from the organisation *now*, not from a value copied onto the agent when it was
    registered. Both directions matter: demoting an organisation — after its abuse contact goes
    dark, say — must immediately lower every agent it owns, and upgrading one to OAL3 must reach
    the agents it already had. A stored snapshot gets the first right and the second wrong.
    """
    level = int(organization.assurance_level) - agent.assurance.demotions
    return AssuranceLevel(max(0, min(3, level)))


def key_assurance(agent: Agent, now: datetime | None = None) -> int:
    """AIAF §3.3 Key Assurance Level, derived from evidence rather than assertion.

    KAL0 no proof of possession · KAL1 possession proven · KAL2 attested non-exportability ·
    KAL3 KAL2 plus a runtime measurement matched to a pre-declared baseline.

    An **expired** attestation yields KAL1, not the level it once evidenced. Assurance is a live
    property: an agent whose attestation has lapsed is not lying, but it is no longer
    demonstrating what it claimed, and the credential must say so. AIAF §3.3 requires demotion
    rather than revocation here, so that an attestation-service outage cannot become a mass
    identity outage.
    """
    key = agent.active_key()
    if key is None or key.proof_verified_at is None:
        return 0
    attestation = key.attestation
    if attestation is None or not attestation.is_valid(now):
        return 1
    return max(1, min(3, attestation.attested_kal))


def agent_assurance(agent: Agent, organization: Any, now: datetime | None = None) -> int:
    """AIAF §3.5: ``AgAL = min(OAL, KAL)``."""
    return min(int(operator_assurance(agent, organization)), key_assurance(agent, now))


@dataclass(frozen=True)
class AssuranceSummary:
    """What an organisation's admin sees for one agent: the levels, and what bounds them."""

    agal: int
    oal: int
    kal: int
    #: When the attestation behind KAL2/KAL3 lapses (KAL then falls to 1); None without one.
    attestation_expires_at: datetime | None
    #: The axis holding AgAL down, or None when both are equal.
    limited_by: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"agal": self.agal, "oal": self.oal, "kal": self.kal,
                "attestation_expires_at": None if self.attestation_expires_at is None
                else self.attestation_expires_at.isoformat(),
                "limited_by": self.limited_by}


def summarise(agent: Agent, organization: Any, now: datetime | None = None) -> AssuranceSummary:
    oal = int(operator_assurance(agent, organization))
    kal = key_assurance(agent, now)
    key = agent.active_key()
    attestation = key.attestation if key is not None else None
    expires = attestation.expires_at if attestation is not None and attestation.is_valid(now) else None
    return AssuranceSummary(agal=min(oal, kal), oal=oal, kal=kal, attestation_expires_at=expires,
                            limited_by=None if oal == kal else ("oal" if oal < kal else "kal"))
