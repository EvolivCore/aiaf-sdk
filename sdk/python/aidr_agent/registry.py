"""The two conversations an agent has with the registry: enrolling once, and asking for credentials.

Enrolling is authenticated by the enrollment token; asking for a credential by an RFC 9421
signature with the agent's own key. The token is never needed again after enrollment.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from aidr_crypto.keys import b64url_encode, generate_keypair, public_key_to_jwk, sign_raw
from aidr_crypto.signatures import sign_request

from .identity import AgentIdentity

POP_CONTEXT = "aiaf-pop-v1"
TOKEN_PREFIX = "aidr_et_"  # noqa: S105 - a format prefix, not a secret


class RegistryError(Exception):
    """The registry refused, with its own error code (``aidr.…``) where it gave one."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{message} ({code})")
        self.status = status
        self.code = code


def _refusal(response: httpx.Response) -> RegistryError:
    try:
        error = response.json().get("error") or {}
    except ValueError:
        error = {}
    return RegistryError(response.status_code, error.get("code", "aidr.unknown"),
                         error.get("message", f"the registry answered HTTP {response.status_code}"))


def token_id(token: str) -> str:
    """The non-secret part of a token, for messages and logs: ``etk_…``."""
    parts = token[len(TOKEN_PREFIX):].split("_", 2) if token.startswith(TOKEN_PREFIX) else []
    return f"{parts[0]}_{parts[1]}" if len(parts) == 3 else "(not an enrollment token)"


def enroll(token: str, *, name: str, registry: str, audiences: list[str] | None = None,
           description: str = "", http: httpx.Client | None = None,
           private_key: Any = None) -> AgentIdentity:
    """Generate a key here, register the agent with the token, and prove the key. Two requests."""
    if not token.startswith(TOKEN_PREFIX):
        raise ValueError("that is not an enrollment token (they start with aidr_et_)")
    if private_key is None:
        private_key, _ = generate_keypair()
    base = registry.rstrip("/")
    headers = {"Authorization": f"AIDR-Enrollment {token}", "AIDR-PoP-Context": POP_CONTEXT}
    body: dict[str, Any] = {"name": name, "description": description,
                            "public_key_jwk": public_key_to_jwk(private_key.public_key())}
    if audiences is not None:
        body["audiences"] = audiences
    client = http or httpx.Client(timeout=15)
    try:
        started = client.post(f"{base}/v1/enroll", json=body, headers=headers)
        if started.status_code != 201:
            raise _refusal(started)
        registration = started.json()
        challenge = registration["challenge"]
        if not challenge["sign_this"].startswith(POP_CONTEXT + ":"):
            raise RegistryError(0, "aidr.client.bad_challenge",
                                "the registry asked for a signature this SDK does not make")
        signature = b64url_encode(sign_raw(private_key, challenge["sign_this"].encode()))
        aid = registration["agent"]["aid"]
        proven = client.post(f"{base}/v1/enroll/{aid}/proof", headers=headers,
                             json={"challenge_id": challenge["challenge_id"], "signature": signature})
        if proven.status_code != 200:
            raise _refusal(proven)
    finally:
        if http is None:
            client.close()
    return AgentIdentity(aid=aid, name=name, registry=base, private_key=private_key,
                         audiences=list(registration.get("allowed_audiences") or []))


@dataclass
class Credential:
    token: str
    renew_at: float        # monotonic clock
    expires_at: float      # monotonic clock

    def fresh(self, now: float) -> bool:
        return now < self.renew_at


def _credential_request(identity: AgentIdentity, audience: str | None) -> tuple[str, dict, dict]:
    url = f"{identity.registry}/v1/credentials"
    headers = sign_request(method="POST", url=url, private_key=identity.private_key, keyid=identity.aid)
    body = {"aid": identity.aid, **({"audience": audience} if audience else {})}
    return url, headers, body


def _credential_from(response: httpx.Response, now: float) -> Credential:
    if response.status_code != 200:
        raise _refusal(response)
    body = response.json()
    return Credential(token=body["credential"], renew_at=now + body["renew_after"],
                      expires_at=now + body["expires_in"])


class CredentialCache:
    """Short-lived credentials (15 minutes or less), one per audience, renewed early.

    Agents with allowed audiences get a credential bound to each site, because the registry
    issues only those. An unrestricted agent gets one unbound credential (key ``None``): one
    issuance instead of one per site (credentials issued are what is billed), and accepted by
    relying parties still on verifiers older than the ones that check a bound credential against
    the site being visited.
    """

    def __init__(self, identity: AgentIdentity, *, http: httpx.Client | None = None,
                 async_http: httpx.AsyncClient | None = None) -> None:
        self.identity = identity
        self._http = http
        self._async_http = async_http
        self._cache: dict[str | None, Credential] = {}
        self._lock = threading.Lock()

    def key_for(self, origin: str) -> str | None:
        return origin if self.identity.audiences else None

    def get(self, origin: str, http: httpx.Client | None = None) -> str:
        key = self.key_for(origin)
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached.fresh(time.monotonic()):
                return cached.token
            url, headers, body = _credential_request(self.identity, key)
            given = http or self._http
            client = given or httpx.Client(timeout=15)
            try:
                credential = _credential_from(client.post(url, json=body, headers=headers),
                                              time.monotonic())
            finally:
                if given is None:
                    client.close()
            self._cache[key] = credential
            return credential.token

    async def aget(self, origin: str, http: httpx.AsyncClient | None = None) -> str:
        key = self.key_for(origin)
        cached = self._cache.get(key)
        if cached and cached.fresh(time.monotonic()):
            return cached.token
        url, headers, body = _credential_request(self.identity, key)
        given = http or self._async_http
        if given is None:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(url, json=body, headers=headers)
        else:
            response = await given.post(url, json=body, headers=headers)
        credential = _credential_from(response, time.monotonic())
        self._cache[key] = credential
        return credential.token

    def forget(self, origin: str | None = None) -> None:
        """Drop cached credentials (after a relying party refuses one: it may be revoked)."""
        with self._lock:
            if origin is None:
                self._cache.clear()
            else:
                self._cache.pop(self.key_for(origin), None)
