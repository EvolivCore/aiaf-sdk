"""FastAPI helpers over :class:`~aidr_verifier.asgi.AidrMiddleware`.

The middleware lets anonymous traffic through; these dependencies are how a route says it is for
agents only, or for stronger agents than the site-wide floor::

    from aidr_verifier.fastapi import get_identity, require_agent

    @app.get("/api/orders")
    async def orders(agent: AidrIdentity = Depends(require_agent(min_oal=2))):
        return {"hello": agent.organization}

A bypassed path carries no identity, so ``require_agent`` refuses every request on it — do not
bypass a path that needs agents.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from fastapi import HTTPException, Request

from .asgi import AidrIdentity

AGENT_REQUIRED = "aidr.verify.agent_required"


def get_identity(request: Request) -> AidrIdentity:
    identity = getattr(request.state, "aidr", None)
    if not isinstance(identity, AidrIdentity):
        # Failing loudly beats treating every caller as anonymous because of a wiring mistake.
        raise RuntimeError("AidrMiddleware is not installed in front of this route")
    return identity


def require_agent(*, min_agal: int = 0, min_oal: int = 0, min_kal: int = 0,
                  capabilities: Sequence[str] = ()) -> Callable[[Request], AidrIdentity]:
    def dependency(request: Request) -> AidrIdentity:
        identity = get_identity(request)
        if not identity.is_agent:
            raise HTTPException(401, detail={"error": AGENT_REQUIRED,
                                             "reason": "this endpoint serves verified agents only"})
        for axis, have, need in (("AgAL", identity.agal, min_agal), ("OAL", identity.oal, min_oal),
                                 ("KAL", identity.kal, min_kal)):
            if have < need:
                raise HTTPException(403, detail={
                    "error": "aidr.verify.assurance_too_low",
                    "reason": f"agent {axis} {have} is below this endpoint's required {need}"})
        missing = [c for c in capabilities if c not in identity.capabilities]
        if missing:
            raise HTTPException(403, detail={
                "error": "aidr.verify.capability_denied",
                "reason": f"agent lacks required capabilities: {', '.join(missing)}"})
        return identity
    return dependency


__all__ = ["get_identity", "require_agent", "AGENT_REQUIRED"]
