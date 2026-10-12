"""Agent-side helpers: hold a key, hold a credential, sign outgoing requests.

This runs on the **agent operator's** infrastructure, never on the registry's. The private key is
generated here, stays here, and is never transmitted. The registry only ever sees the public half,
which is why a total compromise of the registry gives an attacker no ability to impersonate any
agent.

Usage::

    private_key, public_key = generate_keypair()
    holder = AgentCredentialHolder(aid, private_key, credential_token, expires_at)
    headers = holder.sign_headers("GET", "https://shop.example/api/products")
    response = httpx.get("https://shop.example/api/products", headers=headers)
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from aidr_core.errors import CredentialExpired
from aidr_crypto.keys import algorithm_for_key, generate_keypair, public_key_to_jwk
from aidr_crypto.signatures import CREDENTIAL_HEADER, DEFAULT_COMPONENTS, sign_request

logger = logging.getLogger(__name__)

#: Renew this long before expiry. A credential that expires mid-flight produces a failure the
#: agent cannot retry its way out of, so renewal is always early rather than just-in-time.
RENEWAL_MARGIN = timedelta(minutes=3)


@dataclass
class AgentCredentialHolder:
    """An agent identity in use: an identifier, a private key, and a current credential."""

    aid: str
    private_key: Any
    credential: str
    expires_at: datetime

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at

    def needs_renewal(self, *, now: datetime | None = None,
                      margin: timedelta = RENEWAL_MARGIN) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at - margin

    def sign_headers(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        components: tuple[str, ...] = DEFAULT_COMPONENTS,
        now: datetime | None = None,
        algorithm: Any = None,
    ) -> dict[str, str]:
        """Return the headers to attach to one outgoing request.

        A fresh nonce and timestamp are generated per request, so the headers are single-use.
        Reusing them across requests would defeat the replay protection the verifier relies on.
        """
        if self.is_expired(now=now):
            raise CredentialExpired(
                "credential has expired — obtain a new one before signing", aid=self.aid
            )

        signed = sign_request(
            method=method,
            url=url,
            headers=headers or {},
            private_key=self.private_key,
            keyid=self.aid,
            components=components,
            created=now,
            # Derived from the key itself rather than configured. An agent holding a P-256 key
            # cannot accidentally advertise ed25519 and have every verifier reject it.
            algorithm=algorithm or algorithm_for_key(self.private_key),
        )
        signed[CREDENTIAL_HEADER] = self.credential
        return signed

    def public_jwk(self) -> dict[str, Any]:
        return public_key_to_jwk(self.private_key.public_key())


class AgentClient:
    """An agent identity with automatic credential renewal.

    ``renew`` is supplied by the operator: it calls the registry's issuance endpoint with whatever
    authentication that deployment uses, and returns ``(credential_token, expires_at)``. Keeping
    it injectable means this SDK carries no HTTP client and no opinion about authentication.
    """

    def __init__(
        self,
        aid: str,
        private_key: Any,
        renew: Callable[[], Awaitable[tuple[str, datetime]]],
        *,
        renewal_margin: timedelta = RENEWAL_MARGIN,
    ) -> None:
        self.aid = aid
        self.private_key = private_key
        self._renew = renew
        self._margin = renewal_margin
        self._holder: AgentCredentialHolder | None = None

    @classmethod
    def with_new_keypair(cls, aid: str,
                         renew: Callable[[], Awaitable[tuple[str, datetime]]]) -> AgentClient:
        private_key, _ = generate_keypair()
        return cls(aid, private_key, renew)

    async def ensure_credential(self, *, now: datetime | None = None) -> AgentCredentialHolder:
        moment = now or datetime.now(timezone.utc)
        if self._holder is None or self._holder.needs_renewal(now=moment, margin=self._margin):
            token, expires_at = await self._renew()
            self._holder = AgentCredentialHolder(
                aid=self.aid, private_key=self.private_key,
                credential=token, expires_at=expires_at,
            )
            logger.debug("renewed credential for %s, expires %s", self.aid, expires_at.isoformat())
        return self._holder

    async def sign_headers(self, method: str, url: str, **kwargs: Any) -> dict[str, str]:
        holder = await self.ensure_credential()
        return holder.sign_headers(method, url, **kwargs)

    @property
    def credential_expires_at(self) -> datetime | None:
        return self._holder.expires_at if self._holder else None

    def public_jwk(self) -> dict[str, Any]:
        return public_key_to_jwk(self.private_key.public_key())

    def forget_credential(self) -> None:
        """Drop the cached credential, forcing renewal on next use.

        Call after a 401 from a relying party: the credential may have been revoked, and the agent
        should not keep presenting one that has already been refused.
        """
        self._holder = None
