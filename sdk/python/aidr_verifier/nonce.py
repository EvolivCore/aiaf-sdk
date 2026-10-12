"""Replay protection for request signatures: nonce stores a relying party can share.

A signature is acceptable for a bounded window (300 s either side of its ``created`` time), so a
captured request can be replayed until that window closes. Remembering every nonce seen inside the
window closes it — but only if every instance serving the site consults the same memory:

* :class:`MemoryNonceStore` — one process. Correct for a single worker, and only then.
* :class:`RedisNonceStore` — any number of processes and hosts, via ``SET NX`` with a TTL.

A nonce is **claimed only after the request has fully verified** (see ``asgi.py``). Claiming before
the signature check would let anyone fill the store with nonces from requests that were never
valid, and a store that evicts under pressure would then forget the genuine ones.

Both stores fail closed. A store that cannot answer raises :class:`NonceStoreUnavailable`, which the
middleware turns into a 503: an unanswerable replay check is not a passed one.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Protocol

from aidr_core.errors import RegistryUnavailable


class NonceStoreUnavailable(RegistryUnavailable):
    """The replay check could not be performed. The request must not be treated as verified."""


class NonceStore(Protocol):
    async def claim(self, aid: str, nonce: str, ttl_seconds: int) -> bool:
        """Record ``nonce`` for ``aid``. Return ``True`` if this is its first use in the window."""
        ...


def nonce_key(aid: str, nonce: str) -> str:
    """A fixed-length key: identifiers and nonces are attacker-chosen strings."""
    return hashlib.sha256(f"{aid}\x1f{nonce}".encode()).hexdigest()


class MemoryNonceStore:
    """In-process store for a single worker.

    Entries expire when their signature could no longer be accepted anyway. When the store is full
    of *unexpired* entries it refuses rather than evicting them: dropping a live nonce re-opens
    replay for that request, and only verified agents can add entries, so a full store means an
    undersized limit, not an attack to absorb.
    """

    def __init__(self, max_entries: int = 1_000_000) -> None:
        self.max_entries = max_entries
        self._expiry: dict[str, float] = {}

    async def claim(self, aid: str, nonce: str, ttl_seconds: int) -> bool:
        now = time.monotonic()
        key = nonce_key(aid, nonce)
        expires = self._expiry.get(key)
        if expires is not None and expires > now:
            return False
        if len(self._expiry) >= self.max_entries:
            self._expiry = {k: t for k, t in self._expiry.items() if t > now}
            if len(self._expiry) >= self.max_entries:
                raise NonceStoreUnavailable(
                    "nonce store is full of live entries; refusing rather than forgetting one",
                    max_entries=self.max_entries)
        self._expiry[key] = now + ttl_seconds
        return True

    def __len__(self) -> int:
        return len(self._expiry)


class RedisNonceStore:
    """Shared store over Redis or Valkey: ``SET key 1 NX EX ttl`` is the whole algorithm.

    Takes a ``redis.asyncio.Redis`` (or any client with the same ``set`` signature) so the SDK
    carries no Redis dependency of its own.
    """

    def __init__(self, client: Any, *, prefix: str = "aidr:nonce:") -> None:
        self.client = client
        self.prefix = prefix

    async def claim(self, aid: str, nonce: str, ttl_seconds: int) -> bool:
        try:
            created = await self.client.set(self.prefix + nonce_key(aid, nonce), b"1",
                                            nx=True, ex=max(1, ttl_seconds))
        except Exception as exc:  # noqa: BLE001 - any client failure means "cannot answer"
            raise NonceStoreUnavailable(f"nonce store unreachable: {exc}") from exc
        return bool(created)


__all__ = ["NonceStore", "NonceStoreUnavailable", "MemoryNonceStore", "RedisNonceStore",
           "nonce_key"]
