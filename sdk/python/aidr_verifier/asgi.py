"""ASGI middleware: verify AI agents in front of any ASGI application.

Works with FastAPI, Starlette, and Django under ASGI::

    from aidr_verifier.asgi import AidrMiddleware, RelyingPartyConfig

    app.add_middleware(AidrMiddleware, config=RelyingPartyConfig(
        issuer="https://registry.aidr.example",
        public_origin="https://shop.example",
        min_agal=1,
        bypass=[r"/health", r"/static/.*"],
    ))

    @app.get("/api/products")
    async def products(request: Request):
        identity = request.state.aidr            # always present on HTTP requests
        if identity.is_agent:
            ...identity.organization, identity.agal, identity.org_domains...

Every HTTP request ends in exactly one of these outcomes:

* **anonymous** — none of ``Agent-Credential``, ``Signature``, ``Signature-Input`` is present. Passed
  through: this is a person, or a bot that did not identify itself, and the site's other rules
  apply to it as before — unless the path is verified-only (``mode="verified-only"``), where it is
  refused with 401 ``aidr.edge.agent_required``, as the Cloudflare Worker and the Node middleware do.
* **verified** — the agent's identity was proven and meets the site's policy. Passed through with
  ``request.state.aidr`` populated.
* **refused** — the request claims to be an agent and is not a valid one (401), is a revoked or
  out-of-policy one (403, with a reason code), or cannot be checked right now (503).

A request carrying *some* of the headers is a claim to be an agent, and is judged as one. Treating
it as anonymous would let an agent whose credential fails simply fall back to being a stranger —
which is the site's call to make for strangers, not ours to make for a failed identity.

The identity is placed in the ASGI scope, never in request headers, so there is nothing a client
could forge on the way in.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import math
import posixpath
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from aidr_core.errors import (
    AgentRevoked,
    AidrError,
    AssuranceTooLow,
    CapabilityDenied,
    CredentialRevoked,
    MalformedToken,
    PolicyViolation,
    RegistryUnavailable,
    ReplayDetected,
    UnknownIssuer,
)
from aidr_crypto.signatures import (
    CREDENTIAL_HEADER,
    DEFAULT_MAX_AGE_SECONDS,
    SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER,
    effective_request_uri,
)

from .nonce import MemoryNonceStore, NonceStore
from .origin import PublicOriginRequired, configured_origins, origin_resolver
from .sync import TrustSync
from .trust import KeySet, TrustStore
from .verifier import (
    MAX_REVOCATION_AGE_SECONDS,
    AgentVerifier,
    VerificationPolicy,
    VerificationResult,
)

logger = logging.getLogger("aidr.middleware")

AGENT_HEADERS = tuple(h.lower() for h in (CREDENTIAL_HEADER, SIGNATURE_HEADER,
                                          SIGNATURE_INPUT_HEADER))

#: The refusal for an anonymous request to a verified-only path (shared with the Worker and Node).
AGENT_REQUIRED = "aidr.edge.agent_required"

#: Refusals that mean "you are an agent, and not one this site will serve" rather than "you did
#: not prove who you are".
_FORBIDDEN = (AgentRevoked, CredentialRevoked, AssuranceTooLow, CapabilityDenied, PolicyViolation)


# ==============================================================================================
# Configuration
# ==============================================================================================

@dataclass
class RelyingPartyConfig:
    #: The registry, exactly as it appears in credentials' ``iss``. Trust material is discovered
    #: from ``<issuer>/.well-known/aiaf-registry`` and must live on this origin.
    issuer: str

    #: This site's public origin, e.g. ``https://shop.example`` — or several, for a site served on
    #: more than one host name — else ``AIDR_PUBLIC_ORIGIN``. Signatures are judged against it,
    #: never against the client's Host header (except on localhost): see ``origin.py``. Required
    #: from 0.2.0. The first is also the default expected audience.
    public_origin: str | Sequence[str] | None = None

    #: Assurance floors. AgAL is min(OAL, KAL); the separate floors let a site say which axis it
    #: actually cares about — "a verified company" (OAL) or "a hardware-held key" (KAL).
    min_agal: int = 0
    min_oal: int = 0
    min_kal: int = 0

    required_capabilities: Sequence[str] = ()
    max_upheld_abuse_reports: int | None = None

    #: Audience this site accepts for audience-bound credentials. Defaults to ``public_origin``.
    expected_audience: str | None = None

    #: Regular expressions for paths where agent verification does not run at all. Each is
    #: matched with ``fullmatch`` against the *normalised* path (decoded, dot segments resolved,
    #: slashes collapsed), so ``/health`` never matches ``/health/../admin`` or ``/x/health``.
    #: A path that does not normalise unambiguously is never bypassed.
    bypass: Iterable[str] = ()

    #: "open" (the default): anonymous traffic passes. "verified-only": anonymous requests are
    #: refused with 401 aidr.edge.agent_required — people included, so scope it with
    #: ``verified_only_paths`` (regexes, matched whole against the normalised path; a path that
    #: does not normalise counts as protected) unless that is the intent.
    mode: Literal["open", "verified-only"] = "open"
    verified_only_paths: Iterable[str] | None = None

    #: Replay protection. The default is correct only for a single worker process; any site with
    #: more than one must pass a shared store (:class:`~aidr_verifier.nonce.RedisNonceStore`).
    nonce_store: NonceStore | None = None

    max_signature_age_seconds: int = DEFAULT_MAX_AGE_SECONDS

    #: Agents are refused (503 aidr.registry.unavailable) once the newest revocation data held
    #: was signed this long ago — the registry unreachable for ~10 minutes. ``None`` disables it,
    #: which leaves revoked agents admitted for as long as the registry stays out of reach.
    max_revocation_age_seconds: int | None = MAX_REVOCATION_AGE_SECONDS

    #: Pre-built trust. When given with ``sync=False``, nothing is fetched — for tests and for
    #: sites that manage trust material themselves.
    trust: TrustStore | None = None
    sync: bool = True
    #: An ``httpx.AsyncClient`` for the registry, e.g. one configured with a private CA.
    http_client: Any = None
    initial_sync_timeout: float = 10.0

    #: Injected clock, for replaying time-bound test vectors. Leave unset in production.
    clock: Callable[[], datetime] | None = None


# ==============================================================================================
# The identity handed to the application
# ==============================================================================================

@dataclass(frozen=True)
class AidrIdentity:
    """What the application sees in ``request.state.aidr``."""

    status: Literal["anonymous", "verified", "bypassed"]
    result: VerificationResult | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_agent(self) -> bool:
        return self.status == "verified"

    @property
    def aid(self) -> str | None:
        return self.result.aid if self.result else None

    @property
    def organization(self) -> str | None:
        return self.result.organization if self.result else None

    @property
    def org_domains(self) -> list[str]:
        """Proven domains. Key trust decisions on these, not on the ``organization`` string."""
        return list(self.result.org_domains) if self.result else []

    @property
    def agal(self) -> int:
        return self.result.agal if self.result else 0

    @property
    def oal(self) -> int:
        return self.result.oal if self.result else 0

    @property
    def kal(self) -> int:
        return self.result.kal if self.result else 0

    @property
    def capabilities(self) -> list[str]:
        return list(self.result.capabilities) if self.result else []

    @property
    def declared(self) -> dict[str, Any]:
        """Self-asserted by the operator. Not checked by the registry."""
        return dict(self.result.declared) if self.result else {}


ANONYMOUS = AidrIdentity("anonymous")
BYPASSED = AidrIdentity("bypassed")


# ==============================================================================================
# Paths
# ==============================================================================================

def normalise_path(raw_path: str) -> str | None:
    """The path a bypass rule is judged against, or ``None`` if it is ambiguous.

    Decoded once; a ``%`` still present after that (double encoding such as ``%252e``, a literal
    ``%25``, or a malformed escape) is ambiguous, as are invalid UTF-8, control characters and
    backslashes, which servers disagree about. Dot segments are resolved and repeated slashes
    collapsed, so the result is the path the application's router will most plausibly act on.
    The contract is shared with the edge worker: sdk/testdata/path-normalisation.json.
    """
    try:
        decoded = unquote(raw_path, errors="strict")
    except UnicodeDecodeError:
        return None
    if "%" in decoded or "\\" in decoded:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in decoded):
        return None
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    trailing = decoded.endswith("/") and decoded != "/"
    resolved = posixpath.normpath(re.sub(r"/{2,}", "/", decoded))
    if resolved.startswith("//"):
        resolved = "/" + resolved.lstrip("/")
    return resolved + "/" if trailing and resolved != "/" else resolved


# ==============================================================================================
# The middleware
# ==============================================================================================

_collected_nonce: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar(
    "aidr_collected_nonce", default=None)


def _collect_nonce(nonce: str) -> bool:
    """Handed to the verifier as its replay check: remember the nonce, decide nothing yet.

    The core verifier consults its replay check only after the signature verifies, but before the
    site's own floors, and it can only call a synchronous check. Deferring the claim to the end
    means a request refused for any reason never occupies a nonce, and lets the claim be async
    (a shared store).
    """
    sink = _collected_nonce.get()
    if sink is not None:
        sink.append(nonce)
    return False


class AidrMiddleware:
    def __init__(self, app: Any, config: RelyingPartyConfig) -> None:
        self.app = app
        self.config = config
        self.issuer = config.issuer.rstrip("/")
        self.trust = config.trust or TrustStore(KeySet(keys={}), expected_issuer=self.issuer)
        if self.trust.expected_issuer is None:
            self.trust.expected_issuer = self.issuer
        self.sync = (TrustSync(self.issuer, self.trust, http_client=config.http_client)
                     if config.sync else None)
        self.nonce_store = config.nonce_store or MemoryNonceStore()
        self.bypass = [re.compile(pattern) for pattern in config.bypass]
        if config.mode not in ("open", "verified-only"):
            raise ValueError(f'mode must be "open" or "verified-only", not {config.mode!r}')
        if config.verified_only_paths is not None and config.mode != "verified-only":
            raise ValueError('verified_only_paths needs mode="verified-only"')
        self.verified_only = (None if config.verified_only_paths is None
                              else [re.compile(p) for p in config.verified_only_paths])

        self.origin_for = origin_resolver(config.public_origin)
        origins = configured_origins(config.public_origin)
        audience = config.expected_audience or (origins[0] if origins else None)
        self.policy = VerificationPolicy(
            required_capabilities=list(config.required_capabilities),
            max_signature_age_seconds=config.max_signature_age_seconds,
            require_nonce=True,
            expected_issuer=self.issuer,
            expected_audience=audience,
            max_upheld_abuse_reports=config.max_upheld_abuse_reports,
            max_revocation_age_seconds=config.max_revocation_age_seconds,
            # Fail closed on unknown revocation. Not configurable here on purpose.
            allow_unknown_revocation=False,
        )
        self.verifier = AgentVerifier(self.trust, policy=self.policy, nonce_seen=_collect_nonce)
        self._started = False
        self._start_lock = asyncio.Lock()

    # -- lifecycle -------------------------------------------------------------------------------

    async def startup(self) -> None:
        async with self._start_lock:
            if self._started:
                return
            self._started = True
            synced = await self.sync.start(initial_timeout=self.config.initial_sync_timeout) \
                if self.sync else bool(self.trust.key_set.keys)
            health = self.trust.health()
            logger.info(
                "AIDR relying party: issuer=%s trust=%s keys=%d revocation_serial=%d exact=%s | "
                "policy AgAL>=%d OAL>=%d KAL>=%d | bypass=%d rule(s) | nonce store=%s",
                self.issuer, "ready" if synced else "NOT READY (agent requests get 503)",
                health["keys"], health["revocation_serial"], health["revocation_exact"],
                self.config.min_agal, self.config.min_oal, self.config.min_kal,
                len(self.bypass), type(self.nonce_store).__name__)
            if isinstance(self.nonce_store, MemoryNonceStore):
                logger.info("AIDR: in-memory nonce store — correct for ONE worker process only; "
                            "use RedisNonceStore when running more")

    async def shutdown(self) -> None:
        if self.sync:
            await self.sync.stop()

    def health(self) -> dict[str, Any]:
        return self.sync.health() if self.sync else self.trust.health()

    # -- ASGI --------------------------------------------------------------------------------------

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, self._lifespan_receive(receive), send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if not self._started:
            await self.startup()

        identity, refusal = await self._authenticate(scope)
        if refusal is not None:
            await self._refuse(send, *refusal)
            return
        scope.setdefault("state", {})["aidr"] = identity
        await self.app(scope, receive, send)

    def _lifespan_receive(self, receive: Any) -> Any:
        async def wrapped() -> dict[str, Any]:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await self.startup()
            elif message["type"] == "lifespan.shutdown":
                await self.shutdown()
            return message
        return wrapped

    # -- the decision ------------------------------------------------------------------------------

    def _headers(self, scope: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
            # Repeated fields combine per RFC 9110 §5.3; a doubled credential then fails to parse
            # instead of one copy being silently chosen.
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
        return headers

    def _raw_path(self, scope: dict[str, Any]) -> str:
        raw = scope.get("raw_path")
        return raw.decode("latin-1") if isinstance(raw, bytes) and raw else scope.get("path", "/")

    def _is_bypassed(self, raw_path: str) -> bool:
        if not self.bypass:
            return False
        path = normalise_path(raw_path)
        return path is not None and any(rule.fullmatch(path) for rule in self.bypass)

    def _is_verified_only(self, raw_path: str) -> bool:
        if self.config.mode != "verified-only":
            return False
        if self.verified_only is None:
            return True
        path = normalise_path(raw_path)
        # Fail closed: a path that cannot be normalised counts as protected.
        return path is None or any(rule.fullmatch(path) for rule in self.verified_only)

    def _effective_url(self, scope: dict[str, Any], headers: dict[str, str], raw_path: str) -> str:
        query = scope.get("query_string", b"")
        target = raw_path + (f"?{query.decode('latin-1')}" if query else "")
        # This site's origin; the client's Host only on localhost (origin.py).
        origin = urlsplit(self.origin_for(headers.get("host")))
        return effective_request_uri(origin.scheme, origin.netloc, target)

    async def _authenticate(
        self, scope: dict[str, Any]
    ) -> tuple[AidrIdentity, tuple[int, str, str] | None]:
        headers = self._headers(scope)
        raw_path = self._raw_path(scope)

        if self._is_bypassed(raw_path):
            return BYPASSED, None
        if not any(name in headers for name in AGENT_HEADERS):
            if self._is_verified_only(raw_path):
                return ANONYMOUS, (401, AGENT_REQUIRED,
                                   "this resource is for verified AI agents: present an AIDR "
                                   "credential and a signed request")
            return ANONYMOUS, None
        if self.sync is not None and not self.sync.ready:
            return ANONYMOUS, (503, RegistryUnavailable.code,
                               "agent verification is not ready: registry trust not yet loaded")

        now = self.config.clock() if self.config.clock else datetime.now(timezone.utc)
        sink: list[str] = []
        token = _collected_nonce.set(sink)
        try:
            result = self.verifier.verify(
                method=scope.get("method", "GET"),
                url=self._effective_url(scope, headers, raw_path),
                headers=headers, now=now)
            self._check_floors(result)
            if not sink:
                raise MalformedToken("the signature carries no nonce")
            ttl = self._nonce_ttl(result, now)
            if not await self.nonce_store.claim(result.aid, sink[0], ttl):
                raise ReplayDetected("signature nonce has already been used")
        except AidrError as exc:
            if isinstance(exc, UnknownIssuer) and exc.context.get("kid") and self.sync:
                self.sync.request_key_refresh()
            return ANONYMOUS, self._classify(exc, scope)
        except Exception:  # noqa: BLE001 - never let an unexpected input become a pass or a 500
            logger.exception("AIDR: unexpected error verifying a request; refusing it")
            return ANONYMOUS, (401, MalformedToken.code, "request could not be verified")
        finally:
            _collected_nonce.reset(token)

        if result.warnings:
            logger.warning("AIDR: verified %s with warnings: %s", result.aid,
                           "; ".join(result.warnings))
        return AidrIdentity("verified", result, tuple(result.warnings)), None

    def _check_floors(self, result: VerificationResult) -> None:
        for axis, have, need in (("AgAL", result.agal, self.config.min_agal),
                                 ("OAL", result.oal, self.config.min_oal),
                                 ("KAL", result.kal, self.config.min_kal)):
            if have < need:
                raise AssuranceTooLow(f"agent {axis} {have} is below this site's required {need}",
                                      aid=result.aid, axis=axis, have=have, required=need)

    def _nonce_ttl(self, result: VerificationResult, now: datetime) -> int:
        """Remember the nonce exactly as long as its signature could still be accepted."""
        created = result.signature_created_at or now
        remaining = (created - now).total_seconds() + self.config.max_signature_age_seconds
        return max(1, math.ceil(remaining) + 1)

    def _classify(self, exc: AidrError, scope: dict[str, Any]) -> tuple[int, str, str]:
        if isinstance(exc, (RegistryUnavailable, PublicOriginRequired)):
            status = 503
        elif isinstance(exc, _FORBIDDEN):
            status = 403
        else:
            status = 401
        # Never log the Signature header or the credential: within the signature's lifetime a
        # logged pair is a replayable request on any instance without a shared nonce store.
        logger.info("AIDR: refused %s %s: %d %s", scope.get("method"), scope.get("path"),
                    status, exc.code)
        return status, exc.code, exc.message

    def refusal_headers(self, status: int, code: str) -> list[tuple[str, str]]:
        headers = [("content-type", "application/json"), ("cache-control", "no-store")]
        if status == 503:
            headers.append(("retry-after", "30"))
        if code == AGENT_REQUIRED:
            # Where an agent finds out who to get an identity from.
            headers.append(("link", f'<{self.issuer}/.well-known/aiaf-registry>; rel="aiaf-registry"'))
        return headers

    async def _refuse(self, send: Any, status: int, code: str, reason: str) -> None:
        body = json.dumps({"error": code, "reason": reason}).encode()
        headers = [(name.encode(), value.encode()) for name, value in self.refusal_headers(status, code)]
        headers.append((b"content-length", str(len(body)).encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


__all__ = ["AGENT_REQUIRED", "AidrMiddleware", "RelyingPartyConfig", "AidrIdentity", "ANONYMOUS",
           "BYPASSED", "normalise_path"]
