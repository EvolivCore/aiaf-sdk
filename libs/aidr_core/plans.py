"""What each plan allows. The registry enforces it; the console only displays it.

Decided 2026-10-04 (docs/10-tenant-console-dashboard.md, step 5): every agent that is not revoked
counts — active, suspended and awaiting proof alike, since each holds an identity — so only
revocation frees a place. At the limit a new agent is refused, whether it comes from the console or
from an enrollment token.

Decided 2026-10-12 and 2026-10-13 (docs/14, billing step 4): members, the audit log's window and
export, and credentials per agent per hour follow the plan too. The numbers are copied onto the
organisation (``Organization.limits``) when it signs up and whenever its plan changes, and that
copy is what is enforced — so an organisation that existed before these limits keeps what it had
until its plan changes, and an Enterprise contract can carry its own numbers. Roles are not a
limit: every plan has all four (security visibility is not sold).

Revised 2026-10-18 (docs/14): Developer holds 1 agent, a new Team plan 3, Pro 20. Organisations
that exist already keep the numbers stored on them; only a change of plan brings the new ones.

Nothing here removes anything. A lower limit refuses the next agent, member or export; it never
touches the agents and members an organisation already has, and the ledger is never trimmed.
"""

from __future__ import annotations

from dataclasses import dataclass

from aidr_core.models import OrgLimits, OrgTier


@dataclass(frozen=True)
class PlanLimits:
    #: Agents held (every one not revoked); None is unlimited.
    agents: int | None
    #: Members, counting invitations still pending; None is unlimited.
    members: int | None
    #: Credentials one agent may be issued in an hour. A leaked-key signal, not a product.
    issuance_per_agent_per_hour: int
    #: How far back the console's audit log and its export reach, in days; None is everything.
    audit_window_days: int | None
    #: Entries in one audit export: 0 is no export, None is no cap.
    audit_export_entries: int | None


PLAN_LIMITS: dict[OrgTier, PlanLimits] = {
    OrgTier.FREE: PlanLimits(agents=1, members=3, issuance_per_agent_per_hour=20,
                             audit_window_days=30, audit_export_entries=0),
    OrgTier.TEAM: PlanLimits(agents=3, members=5, issuance_per_agent_per_hour=100,
                             audit_window_days=90, audit_export_entries=1000),
    OrgTier.PRO: PlanLimits(agents=20, members=25, issuance_per_agent_per_hour=100,
                            audit_window_days=365, audit_export_entries=5000),
    OrgTier.ENTERPRISE: PlanLimits(agents=None, members=None, issuance_per_agent_per_hour=100,
                                   audit_window_days=None, audit_export_entries=None),
}

#: Agents an organisation may hold on each plan; None is unlimited.
AGENT_LIMITS: dict[OrgTier, int | None] = {tier: plan.agents for tier, plan in PLAN_LIMITS.items()}


def agent_limit(tier: OrgTier) -> int | None:
    return AGENT_LIMITS[tier]


def limits_for(tier: OrgTier) -> OrgLimits:
    """The plan's numbers as an organisation stores them."""
    plan = PLAN_LIMITS[tier]
    return OrgLimits(max_agents=plan.agents, max_issuance_per_hour=plan.issuance_per_agent_per_hour,
                     max_members=plan.members, audit_window_days=plan.audit_window_days,
                     audit_export_entries=plan.audit_export_entries)
