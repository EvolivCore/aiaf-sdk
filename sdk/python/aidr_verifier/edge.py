"""The origin side of the AIDR edge (edge/cloudflare-worker): accept only what the edge vouched for.

When agents are verified at the edge, the origin must not be reachable around it, and must not
believe identity it did not get from it. The edge signs a context onto every request it forwards —
``X-AIDR-Context`` (base64url JSON) and ``X-AIDR-Context-Signature`` (base64url HMAC-SHA256 over
``"aidr-edge-context-v1\\n" + context``) — with a secret only the edge and the origin hold::

    app.add_middleware(EdgeContextMiddleware, secret=os.environ["AIDR_EDGE_CONTEXT_SECRET"])

Every HTTP request without a valid context is refused (401), so a request sent straight to the
origin, or one whose context was forged, altered, re-used for another request or kept for later,
never reaches the application. What the edge decided is in ``request.state.aidr``, exactly as
:class:`~aidr_verifier.asgi.AidrMiddleware` would have put it.

Pair this with network-level isolation too (Cloudflare Tunnel, or Authenticated Origin Pulls with
a certificate of your own — the shared Cloudflare certificate proves only "some Cloudflare
customer"). The context is what proves "this worker, for this request".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from typing import Any

from aidr_core.errors import AidrError
from aidr_crypto.keys import b64url_decode

from .asgi import ANONYMOUS, BYPASSED, AidrIdentity
from .verifier import VerificationResult

CONTEXT_HEADER = "x-aidr-context"
CONTEXT_SIGNATURE_HEADER = "x-aidr-context-signature"
CONTEXT_VERSION = 1
MIN_SECRET_LENGTH = 32
DEFAULT_MAX_AGE_SECONDS = 60
_DOMAIN = b"aidr-edge-context-v1\n"


class EdgeContextInvalid(AidrError):
    code = "aidr.edge.context_invalid"


def verify_edge_context(method: str, target: str, headers: Mapping[str, str], secret: str, *,
                        now: float | None = None,
                        max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS) -> dict[str, Any]:
    """Verify the edge's context for a request. ``target`` is path plus query, as received."""
    if len(secret) < MIN_SECRET_LENGTH:
        raise EdgeContextInvalid(f"edge context secret must be at least {MIN_SECRET_LENGTH} characters")
    lowered = {k.lower(): v for k, v in headers.items()}
    encoded = lowered.get(CONTEXT_HEADER)
    signature = lowered.get(CONTEXT_SIGNATURE_HEADER)
    if not encoded or not signature:
        raise EdgeContextInvalid("request did not come through the AIDR edge")

    expected = hmac.new(secret.encode(), _DOMAIN + encoded.encode(), hashlib.sha256).digest()
    try:
        presented = b64url_decode(signature)
    except AidrError as exc:
        raise EdgeContextInvalid("edge context signature is not base64url") from exc
    if not hmac.compare_digest(expected, presented):
        raise EdgeContextInvalid("edge context signature does not verify")

    try:
        context = json.loads(b64url_decode(encoded))
    except (AidrError, ValueError) as exc:
        raise EdgeContextInvalid("edge context is not valid JSON") from exc
    if not isinstance(context, dict) or context.get("v") != CONTEXT_VERSION:
        raise EdgeContextInvalid("unsupported edge context version")
    try:
        age = (time.time() if now is None else now) - float(context["iat"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EdgeContextInvalid("edge context has no issue time") from exc
    if not -max_age_seconds <= age <= max_age_seconds:
        raise EdgeContextInvalid("edge context is outside its validity window")
    if context.get("method") != method.upper() or context.get("target") != target:
        raise EdgeContextInvalid("edge context was issued for a different request")
    return context


def identity_from_context(context: Mapping[str, Any]) -> AidrIdentity:
    status = context.get("status")
    if status == "anonymous":
        return ANONYMOUS
    if status == "bypassed":
        return BYPASSED
    if status != "verified":
        raise EdgeContextInvalid(f"unknown edge decision {status!r}")
    agal = int(context.get("agal", 0))
    result = VerificationResult(
        aid=str(context["aid"]), organization=str(context.get("organization", "")),
        assurance=agal, agal=agal, oal=int(context.get("oal", 0)), kal=int(context.get("kal", 0)),
        org_domains=list(context.get("org_domains", [])),
        capabilities=list(context.get("capabilities", [])),
        declared=dict(context.get("declared", {})),
    )
    return AidrIdentity("verified", result)


class EdgeContextMiddleware:
    """Refuse every HTTP request the edge did not vouch for; expose its decision to the app."""

    def __init__(self, app: Any, *, secret: str,
                 max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS) -> None:
        if len(secret) < MIN_SECRET_LENGTH:
            raise ValueError(f"edge context secret must be at least {MIN_SECRET_LENGTH} characters")
        self.app = app
        self.secret = secret
        self.max_age_seconds = max_age_seconds

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}
        raw = scope.get("raw_path")
        path = raw.decode("latin-1") if isinstance(raw, bytes) and raw else scope.get("path", "/")
        query = scope.get("query_string", b"").decode("latin-1")
        target = path + (f"?{query}" if query else "")
        try:
            context = verify_edge_context(scope.get("method", "GET"), target, headers, self.secret,
                                          max_age_seconds=self.max_age_seconds)
            identity = identity_from_context(context)
        except (EdgeContextInvalid, KeyError, TypeError, ValueError) as exc:
            reason = exc.message if isinstance(exc, EdgeContextInvalid) else "malformed edge context"
            body = json.dumps({"error": EdgeContextInvalid.code, "reason": reason}).encode()
            await send({"type": "http.response.start", "status": 401, "headers": [
                (b"content-type", b"application/json"), (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        scope.setdefault("state", {})["aidr"] = identity
        await self.app(scope, receive, send)


__all__ = ["EdgeContextMiddleware", "EdgeContextInvalid", "verify_edge_context",
           "identity_from_context", "CONTEXT_HEADER", "CONTEXT_SIGNATURE_HEADER"]
