"""Keep a :class:`TrustStore` current in the background.

Fetching trust material once at boot is not enough: a long-running server that never refreshes
keeps accepting agents revoked after it started, and rejects every credential signed after the
registry rotates its key. :class:`TrustSync` runs two loops beside the application:

* the registry's **JWKS**, hourly, and on demand (rate-limited) when a credential names a ``kid``
  we have not seen — which is what a key rotation looks like from the outside;
* the **revocation delta**, every 60 s, from the serial we hold. A delta that would leave a gap
  triggers a full rebuild from serial 0 rather than being skipped.

Nothing here is on the request path. Where things are fetched from comes from the registry's
discovery document, and every endpoint it names must be on the issuer's own origin: the JWKS is
not itself signed, so its authenticity rests entirely on TLS to the issuer, and a discovery
document that pointed elsewhere would hand that trust to someone else.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from aidr_core.errors import MalformedToken, RegistryUnavailable

from .trust import (
    JWKS_REFRESH_SECONDS,
    REVOCATION_REFRESH_SECONDS,
    KeySet,
    RevocationState,
    TrustStore,
)

logger = logging.getLogger("aidr.sync")

DISCOVERY_PATH = "/.well-known/aiaf-registry"

#: How soon to retry after a failed fetch. Short, because a failed revocation fetch is time the
#: site spends not learning about revoked agents.
RETRY_SECONDS = 15

#: At most one out-of-schedule JWKS fetch per this interval, however many unknown ``kid`` values
#: arrive. Otherwise a stream of credentials with invented ``kid``s becomes a stream of requests
#: to the registry.
UNKNOWN_KID_REFRESH_SECONDS = 60


def _origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme.lower(), (parts.netloc or "").lower()


@dataclass
class Endpoints:
    jwks: str
    revocation_delta: str


class TrustSync:
    """Background refresh of one :class:`TrustStore` from one registry."""

    def __init__(
        self,
        issuer: str,
        trust: TrustStore,
        *,
        http_client: Any = None,
        jwks_interval: float = JWKS_REFRESH_SECONDS,
        revocation_interval: float = REVOCATION_REFRESH_SECONDS,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.trust = trust
        self.jwks_interval = jwks_interval
        self.revocation_interval = revocation_interval
        self._client = http_client
        self._owns_client = http_client is None
        self._endpoints: Endpoints | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._kid_refresh: asyncio.Task[None] | None = None
        self._last_kid_refresh = float("-inf")
        self.last_error: str | None = None

    # -- lifecycle -------------------------------------------------------------------------------

    @property
    def ready(self) -> bool:
        """True once keys are loaded. Revocation readiness is the verifier's call (fail closed)."""
        return bool(self.trust.key_set.keys)

    async def start(self, *, initial_timeout: float = 10.0) -> bool:
        """Sync once (bounded by ``initial_timeout``), then keep syncing in the background.

        Returns whether the initial sync succeeded. The application starts either way: anonymous
        traffic needs no registry, and agent requests fail closed with a 503 until trust loads.
        """
        succeeded = False
        try:
            await asyncio.wait_for(self.refresh_all(), timeout=initial_timeout)
            succeeded = True
        except Exception as exc:  # noqa: BLE001 - reported, and retried by the loops
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("AIDR: initial trust sync from %s failed (%s); agent requests will be "
                           "refused with 503 until it succeeds", self.issuer, self.last_error)
        self._tasks = [
            asyncio.create_task(self._loop(self.refresh_jwks, self.jwks_interval), name="aidr-jwks"),
            asyncio.create_task(self._loop(self.refresh_revocations, self.revocation_interval),
                                name="aidr-revocation"),
        ]
        return succeeded

    async def stop(self) -> None:
        tasks = [*self._tasks, *([self._kid_refresh] if self._kid_refresh else [])]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks = []
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _loop(self, refresh: Any, interval: float) -> None:
        delay = interval
        while True:
            # Jitter, so a fleet restarted together does not refresh in lockstep.
            await asyncio.sleep(delay * random.uniform(0.9, 1.1))  # noqa: S311 - not security
            try:
                await refresh()
                delay = interval
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a background loop must survive anything
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("AIDR: %s failed: %s", getattr(refresh, "__name__", "refresh"),
                               self.last_error)
                delay = min(interval, RETRY_SECONDS)

    # -- fetching --------------------------------------------------------------------------------

    def _http(self) -> Any:
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
        return self._client

    async def _get_json(self, url: str, **params: Any) -> dict[str, Any]:
        response = await self._http().get(url, params=params or None)
        if response.status_code != 200:
            raise RegistryUnavailable(f"GET {url} returned HTTP {response.status_code}", url=url)
        body = response.json()
        if not isinstance(body, dict):
            raise MalformedToken(f"GET {url} did not return a JSON object", url=url)
        return body

    async def endpoints(self) -> Endpoints:
        if self._endpoints is None:
            document = await self._get_json(self.issuer + DISCOVERY_PATH)
            if str(document.get("issuer", "")).rstrip("/") != self.issuer:
                raise RegistryUnavailable("discovery document names a different issuer",
                                          expected=self.issuer, got=document.get("issuer"))
            found = Endpoints(jwks=str(document.get("jwks_uri", "")),
                              revocation_delta=str(document.get("revocation_delta_endpoint", "")))
            for url in (found.jwks, found.revocation_delta):
                if _origin(url) != _origin(self.issuer):
                    raise RegistryUnavailable(
                        "discovery points trust material off the issuer's origin; refusing it",
                        url=url, issuer=self.issuer)
            self._endpoints = found
        return self._endpoints

    async def refresh_all(self) -> None:
        await self.refresh_jwks()
        await self.refresh_revocations()

    async def refresh_jwks(self) -> None:
        document = await self._get_json((await self.endpoints()).jwks)
        # from_jwks raises on an empty or unusable document, leaving the keys we already hold in
        # place: a bad fetch must never wipe working trust.
        key_set = KeySet.from_jwks(document)
        added = set(key_set.keys) - set(self.trust.key_set.keys)
        self.trust.key_set = key_set
        if added:
            logger.info("AIDR: registry keys now %s", ", ".join(sorted(key_set.keys)))

    async def refresh_revocations(self) -> None:
        url = (await self.endpoints()).revocation_delta
        state = self.trust.revocation
        if not state.exact:
            await self._rebuild_revocations(url)
            return
        body = await self._get_json(url, since=state.serial)
        try:
            self.trust.ingest_delta(str(body.get("delta", "")))
        except RegistryUnavailable:
            # A gap between our serial and the delta. Start again from zero rather than guess.
            logger.warning("AIDR: revocation feed gap at serial %d; rebuilding", state.serial)
            await self._rebuild_revocations(url)

    async def _rebuild_revocations(self, url: str) -> None:
        body = await self._get_json(url, since=0)
        fresh = TrustStore(self.trust.key_set, RevocationState(),
                           expected_issuer=self.trust.expected_issuer)
        fresh.ingest_delta(str(body.get("delta", "")))
        # Swap only a complete, verified state in. Readers never see a half-built one.
        self.trust.revocation = fresh.revocation

    def request_key_refresh(self) -> None:
        """Called when a credential names an unknown ``kid``. Rate-limited, never awaited."""
        now = time.monotonic()
        if now - self._last_kid_refresh < UNKNOWN_KID_REFRESH_SECONDS:
            return
        if self._kid_refresh is not None and not self._kid_refresh.done():
            return
        self._last_kid_refresh = now
        self._kid_refresh = asyncio.create_task(self._safe_jwks_refresh(), name="aidr-kid")

    async def _safe_jwks_refresh(self) -> None:
        try:
            await self.refresh_jwks()
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("AIDR: on-demand key refresh failed: %s", self.last_error)

    def health(self) -> dict[str, Any]:
        return {**self.trust.health(), "ready": self.ready, "last_error": self.last_error}


__all__ = ["TrustSync", "Endpoints", "DISCOVERY_PATH"]
