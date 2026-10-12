"""The agent: load its identity or enroll once, then sign the requests it is allowed to sign."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Mapping
from typing import Any, Literal

import httpx

from aidr_crypto.signatures import CREDENTIAL_HEADER, sign_request

from .identity import DEFAULT_REGISTRY, AgentIdentity, normalize_origin
from .keystore import EnvKeyStore, FileKeyStore, KeyStore
from .registry import CredentialCache, enroll, token_id

logger = logging.getLogger("aidr_agent")

TOKEN_ENV = "AIDR_ENROLLMENT_TOKEN"  # noqa: S105 - a variable name, not a secret
REGISTRY_ENV = "AIDR_REGISTRY_URL"

OnUnlisted = Literal["unsigned", "refuse"]


class NotAllowed(Exception):
    """The agent was asked to identify itself to a site it is not allowed to (on_unlisted="refuse")."""


class Agent:
    """An enrolled agent. Build one with :meth:`load_or_enroll`.

    ``sign_for`` — the origins this process presents the identity to — defaults to the
    audiences the registry allows. An agent without audiences is unrestricted at the registry;
    this SDK then signs for any https origin. Requests elsewhere go out unsigned (anonymous), or
    are refused with ``on_unlisted="refuse"``. Plain http is never signed except to localhost: a
    credential sent in clear text is a credential given away.
    """

    def __init__(self, identity: AgentIdentity, *, sign_for: Iterable[str] | None = None,
                 on_unlisted: OnUnlisted = "unsigned", registry_http: httpx.Client | None = None,
                 registry_async_http: httpx.AsyncClient | None = None) -> None:
        self.identity = identity
        allowed = identity.audiences if sign_for is None else [normalize_origin(o) for o in sign_for]
        if identity.audiences and not set(allowed) <= set(identity.audiences):
            raise NotAllowed(f"the registry issues credentials only for {identity.audiences}")
        self.sign_for: frozenset[str] = frozenset(allowed)
        self.on_unlisted = on_unlisted
        #: ``registry_http`` / ``registry_async_http``: clients for the registry only (a proxy,
        #: a private CA). Never the clients the agent's own requests go through.
        self.credentials = CredentialCache(identity, http=registry_http,
                                           async_http=registry_async_http)

    # -- construction ----------------------------------------------------------------------------

    @classmethod
    def load_or_enroll(cls, name: str, *, audiences: list[str] | None = None,
                       token: str | None = None, registry: str | None = None,
                       key_store: KeyStore | None = None, description: str = "",
                       on_unlisted: OnUnlisted = "unsigned",
                       registry_http: httpx.Client | None = None,
                       registry_async_http: httpx.AsyncClient | None = None) -> Agent:
        """The identity saved for ``name``, or — first run only — enroll with the token.

        The token comes from ``token`` or AIDR_ENROLLMENT_TOKEN and is used once; after that the
        saved identity is enough, and the token can be removed from the environment.
        """
        stores: list[KeyStore] = [key_store] if key_store else [EnvKeyStore(), FileKeyStore()]
        for store in stores:
            identity = store.load(name)
            if identity is not None:
                if token or os.environ.get(TOKEN_ENV):
                    logger.info("agent %s is already enrolled (%s); %s is no longer needed",
                                name, identity.aid, TOKEN_ENV)
                return cls(identity, on_unlisted=on_unlisted, registry_http=registry_http,
                           registry_async_http=registry_async_http)

        presented = token or os.environ.get(TOKEN_ENV)
        if not presented:
            raise LookupError(f"agent {name!r} is not enrolled here and no enrollment token was given "
                              f"(set {TOKEN_ENV}, or pass token=)")
        target = registry or os.environ.get(REGISTRY_ENV) or DEFAULT_REGISTRY
        writable = next((s for s in stores if not isinstance(s, EnvKeyStore)), None)
        if writable is None:
            raise LookupError("no writable key store to keep the new identity in")
        logger.info("enrolling agent %s at %s with token %s", name, target, token_id(presented))
        identity = enroll(presented, name=name, registry=target,
                          audiences=[normalize_origin(a) for a in audiences] if audiences else None,
                          description=description, http=registry_http)
        writable.save(identity)
        logger.info("enrolled %s", identity.aid)
        return cls(identity, on_unlisted=on_unlisted, registry_http=registry_http,
                   registry_async_http=registry_async_http)

    @property
    def aid(self) -> str:
        return self.identity.aid

    # -- the signing decision ------------------------------------------------------------------

    def should_sign(self, url: str) -> bool:
        origin = normalize_origin(url)
        scheme = origin.split("://", 1)[0]
        host = origin.split("://", 1)[1].split(":")[0]
        if scheme != "https" and not (scheme == "http" and host in ("localhost", "127.0.0.1")):
            return False
        return origin in self.sign_for if self.sign_for else True

    def _unlisted(self, url: str) -> None:
        if self.on_unlisted == "refuse":
            raise NotAllowed(f"{normalize_origin(url)} is not an origin this agent identifies to")

    def sign_headers(self, method: str, url: str, headers: Mapping[str, str] | None = None,
                     *, http: httpx.Client | None = None) -> dict[str, str]:
        """The headers that identify this agent on one request, or ``{}`` when it should not."""
        if not self.should_sign(url):
            self._unlisted(url)
            return {}
        credential = self.credentials.get(normalize_origin(url), http)
        signed = sign_request(method=method, url=url, headers=dict(headers or {}),
                              private_key=self.identity.private_key, keyid=self.identity.aid)
        signed[CREDENTIAL_HEADER] = credential
        return signed

    async def asign_headers(self, method: str, url: str, headers: Mapping[str, str] | None = None,
                            *, http: httpx.AsyncClient | None = None) -> dict[str, str]:
        if not self.should_sign(url):
            self._unlisted(url)
            return {}
        credential = await self.credentials.aget(normalize_origin(url), http)
        signed = sign_request(method=method, url=url, headers=dict(headers or {}),
                              private_key=self.identity.private_key, keyid=self.identity.aid)
        signed[CREDENTIAL_HEADER] = credential
        return signed

    # -- adapters -----------------------------------------------------------------------------

    def auth(self) -> Any:
        """A ``requests`` auth object: ``requests.get(url, auth=agent.auth())``."""
        from .http import RequestsAuth

        return RequestsAuth(self)

    def session(self) -> Any:
        """A ``requests.Session`` that identifies the agent where it may."""
        import requests

        session = requests.Session()
        session.auth = self.auth()
        return session

    def httpx_auth(self) -> httpx.Auth:
        """An ``httpx.Auth`` for ``httpx.Client`` and ``httpx.AsyncClient``."""
        from .http import HttpxAuth

        return HttpxAuth(self)
