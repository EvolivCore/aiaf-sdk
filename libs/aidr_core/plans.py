"""What each plan allows. The registry enforces it; the console only displays it.

Decided 2026-10-04 (docs/10-tenant-console-dashboard.md, step 5): every agent that is not revoked
counts — active, suspended and awaiting proof alike, since each holds an identity — so only
revocation frees a place. At the limit a new agent is refused, whether it comes from the console or
from an enrollment token.
"""

from __future__ import annotations

from aidr_core.models import OrgTier

#: Agents an organisation may hold on each plan; None is unlimited.
AGENT_LIMITS: dict[OrgTier, int | None] = {
    OrgTier.FREE: 3,
    OrgTier.PRO: 25,
    OrgTier.ENTERPRISE: None,
}


def agent_limit(tier: OrgTier) -> int | None:
    return AGENT_LIMITS[tier]
