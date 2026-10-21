"""AIDR relying-party SDK — verify agent identity offline.

Minimal integration::

    from aidr_verifier import AgentVerifier, VerificationPolicy, build_trust_store, NonceCache

    trust = build_trust_store(jwks, delta_token=delta, expected_issuer="https://registry.aidr.example")
    verifier = AgentVerifier(trust, policy=VerificationPolicy(min_assurance=1),
                             nonce_seen=NonceCache())

    result = verifier.verify(method="GET", url="https://shop.example/api", headers=request.headers)

Refresh ``jwks`` hourly and the revocation delta every 60 seconds, in the background. Nothing in
the request path contacts the registry. For ASGI applications, :class:`AidrMiddleware` does all of
this — background sync, shared replay protection, and the anonymous / verified / refused decision —
and puts the result in ``request.state.aidr`` (see ``aidr_verifier.asgi``).
"""

from .agent import AgentClient, AgentCredentialHolder
from .asgi import AidrIdentity, AidrMiddleware, RelyingPartyConfig
from .edge import EdgeContextMiddleware, verify_edge_context
from .nonce import MemoryNonceStore, NonceStore, NonceStoreUnavailable, RedisNonceStore
from .origin import ENFORCE_PUBLIC_ORIGIN, PUBLIC_ORIGIN_ENV, PublicOriginRequired, origin_resolver
from .sync import TrustSync
from .trust import (
    JWKS_REFRESH_SECONDS,
    REVOCATION_REFRESH_SECONDS,
    KeySet,
    NonceCache,
    RevocationState,
    TrustStore,
    build_trust_store,
)
from .verifier import (
    MAX_REVOCATION_AGE_SECONDS,
    AgentVerifier,
    VerificationPolicy,
    VerificationResult,
)

__version__ = "0.2.1"

__all__ = [
    "ENFORCE_PUBLIC_ORIGIN",
    "PUBLIC_ORIGIN_ENV",
    "PublicOriginRequired",
    "origin_resolver",
    "AgentClient",
    "AgentCredentialHolder",
    "AgentVerifier",
    "MAX_REVOCATION_AGE_SECONDS",
    "VerificationPolicy",
    "VerificationResult",
    "TrustStore",
    "KeySet",
    "RevocationState",
    "NonceCache",
    "build_trust_store",
    "AidrMiddleware",
    "RelyingPartyConfig",
    "AidrIdentity",
    "EdgeContextMiddleware",
    "verify_edge_context",
    "TrustSync",
    "NonceStore",
    "NonceStoreUnavailable",
    "MemoryNonceStore",
    "RedisNonceStore",
    "JWKS_REFRESH_SECONDS",
    "REVOCATION_REFRESH_SECONDS",
]
