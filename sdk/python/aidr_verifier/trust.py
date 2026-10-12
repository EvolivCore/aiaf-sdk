"""Trust material a relying party holds locally: the key set and the revocation state.

A website keeps two things in memory and refreshes them in the background:

* the registry's **JWKS** (hourly) — public keys, to check that a credential really was issued by
  the registry;
* the **revocation state** (every 60 s) — either an exact set built from signed deltas, or a
  signed bloom filter.

That is two background HTTP requests per minute, no matter how much agent traffic the site sees.
Nothing in the request path ever contacts the registry, which is what makes verification cost
~200 µs and keeps working while the registry is entirely offline.

**Everything fetched is signed and verified before it is trusted.** An unsigned revocation feed
would let anyone who can interpose on the fetch silently strip their own agent's revocation. The
worst an interceptor can do against a signed feed is serve a stale one, which
:meth:`RevocationState.is_stale` makes visible.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aidr_core.bloom import BloomFilter
from aidr_core.errors import MalformedToken, RegistryUnavailable, UnknownIssuer
from aidr_crypto.jws import validate_time_claims, verify_compact

logger = logging.getLogger(__name__)

DELTA_TYP = "aidr-crl+jwt"
FILTER_TYP = "aidr-crl-filter+jwt"

#: Refresh cadences the registry's cache headers also advertise.
JWKS_REFRESH_SECONDS = 3600
REVOCATION_REFRESH_SECONDS = 60

#: How far past its refresh interval revocation state may drift before it is considered stale.
#: Generous, because a stale feed is a degraded signal rather than a broken one — but a site that
#: has not refreshed in an hour should know.
STALENESS_GRACE_SECONDS = 600


@dataclass
class KeySet:
    """The registry's public keys, indexed by ``kid``."""

    keys: dict[str, dict[str, Any]] = field(default_factory=dict)
    fetched_at: float = field(default_factory=time.monotonic)

    @classmethod
    def from_jwks(cls, document: dict[str, Any]) -> KeySet:
        entries = document.get("keys")
        if not isinstance(entries, list) or not entries:
            raise MalformedToken("JWKS document contains no keys")

        keys: dict[str, dict[str, Any]] = {}
        for jwk in entries:
            kid = jwk.get("kid")
            if not isinstance(kid, str):
                # A key without a kid cannot be selected deterministically. Skipping it is safer
                # than guessing, and the registry always publishes one.
                logger.warning("ignoring JWKS entry without a 'kid'")
                continue
            if "d" in jwk:
                # The registry must never publish private material. If it ever appears here,
                # something is badly wrong upstream and the key must not be used.
                raise MalformedToken("JWKS contains private key material — refusing to trust it")
            keys[kid] = jwk

        if not keys:
            raise MalformedToken("JWKS document contains no usable keys")
        return cls(keys=keys)

    def resolve(self, kid: str) -> dict[str, Any] | None:
        return self.keys.get(kid)

    def is_stale(self, *, now: float | None = None) -> bool:
        elapsed = (now or time.monotonic()) - self.fetched_at
        return elapsed > JWKS_REFRESH_SECONDS + STALENESS_GRACE_SECONDS


@dataclass
class RevocationState:
    """Locally held revocation knowledge.

    Two modes, and the difference matters when a lookup hits:

    * **exact** — built from signed deltas. A membership test is definitive.
    * **filter** — a bloom filter. A miss is definitive; a hit is only "possibly revoked" and
      needs either an exact set or an online check to resolve.
    """

    revoked: set[str] = field(default_factory=set)
    filter: BloomFilter | None = None
    serial: int = 0
    #: False until a full snapshot has been ingested. A fresh store knows nothing, and must not
    #: claim that an unknown identifier is definitively healthy.
    exact: bool = False
    fetched_at: float = field(default_factory=time.monotonic)
    issued_at: datetime | None = None

    def contains(self, subject_id: str) -> tuple[bool, bool]:
        """Return ``(revoked, definitive)``.

        ``(True, True)``  — revoked, no doubt.
        ``(False, True)`` — not revoked, no doubt.
        ``(True, False)`` — possibly revoked; the caller's policy decides whether to deny or to
        resolve it with an online check.
        """
        if subject_id in self.revoked:
            return True, True
        if self.filter is not None and subject_id in self.filter:
            # A bloom hit with an exact set present means the exact set already said no, so this
            # is a false positive and the exact answer wins.
            return (True, False) if not self.exact else (False, True)
        return False, self.exact

    def is_stale(self, *, now: float | None = None) -> bool:
        elapsed = (now or time.monotonic()) - self.fetched_at
        return elapsed > REVOCATION_REFRESH_SECONDS + STALENESS_GRACE_SECONDS

    def apply_delta(self, payload: dict[str, Any]) -> None:
        """Merge a verified delta payload into the current state."""
        for entry in payload.get("revocations", []):
            subject_id = entry.get("subject_id")
            if isinstance(subject_id, str):
                self.revoked.add(subject_id)
        self.serial = max(self.serial, int(payload.get("serial", self.serial)))
        self.fetched_at = time.monotonic()
        iat = payload.get("iat")
        if iat is not None:
            self.issued_at = datetime.fromtimestamp(float(iat), tz=timezone.utc)


class TrustStore:
    """Everything a relying party needs to verify offline."""

    def __init__(
        self,
        key_set: KeySet,
        revocation: RevocationState | None = None,
        *,
        expected_issuer: str | None = None,
    ) -> None:
        self.key_set = key_set
        self.revocation = revocation or RevocationState()
        self.expected_issuer = expected_issuer

    # -- construction --------------------------------------------------------------------------

    @classmethod
    def from_jwks(cls, jwks: dict[str, Any], *, expected_issuer: str | None = None) -> TrustStore:
        return cls(KeySet.from_jwks(jwks), expected_issuer=expected_issuer)

    def resolve_key(self, kid: str) -> dict[str, Any] | None:
        return self.key_set.resolve(kid)

    # -- ingesting signed revocation artefacts ---------------------------------------------------

    def ingest_delta(self, delta_token: str) -> int:
        """Verify and apply a signed revocation delta. Returns the new serial."""
        _, payload = verify_compact(delta_token, self.resolve_key, expected_typ=DELTA_TYP)
        self._check_issuer(payload)
        validate_time_claims(payload, require_exp=False)

        if int(payload.get("since", 0)) > self.revocation.serial:
            # A delta that starts after where we are would leave an unnoticed gap: revocations
            # between our serial and the delta's start would never be learned. Refuse and let the
            # caller re-request from its own serial.
            raise RegistryUnavailable(
                "revocation delta starts beyond the local serial — a gap would go unnoticed",
                local_serial=self.revocation.serial, delta_since=payload.get("since"),
            )

        self.revocation.apply_delta(payload)
        if int(payload.get("since", 0)) == 0 and payload.get("complete", True):
            # Only a delta from serial 0 delivers the complete set. Marking the state exact after
            # an incremental delta would be wrong in a specific and dangerous way: a site that
            # bootstrapped from a bloom filter and then applied an empty incremental delta would
            # hold an empty "exact" set and report every revoked agent as healthy.
            self.revocation.exact = True
        logger.debug("applied revocation delta: serial=%d total=%d",
                     self.revocation.serial, len(self.revocation.revoked))
        return self.revocation.serial

    def ingest_filter(self, filter_token: str) -> int:
        """Verify and install a signed revocation bloom filter."""
        _, payload = verify_compact(filter_token, self.resolve_key, expected_typ=FILTER_TYP)
        self._check_issuer(payload)
        validate_time_claims(payload, require_exp=False)

        self.revocation.filter = BloomFilter.from_dict(payload["filter"])
        self.revocation.serial = max(self.revocation.serial, int(payload.get("serial", 0)))
        self.revocation.fetched_at = time.monotonic()
        # A filter is supplementary and never makes the state exact — only a delta from serial 0
        # delivers a complete set. The existing ``exact`` flag is left untouched.
        return self.revocation.serial

    def _check_issuer(self, payload: dict[str, Any]) -> None:
        if self.expected_issuer and payload.get("iss") != self.expected_issuer:
            raise UnknownIssuer(
                f"artefact issued by {payload.get('iss')!r}, expected {self.expected_issuer!r}",
                issuer=payload.get("iss"),
            )

    # -- diagnostics ---------------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Export for the site's own monitoring.

        Worth alerting on: a site whose revocation state has gone stale is still verifying
        signatures correctly, but is no longer learning about revoked agents.
        """
        return {
            "keys": len(self.key_set.keys),
            "keys_stale": self.key_set.is_stale(),
            "revocation_serial": self.revocation.serial,
            "revocation_entries": len(self.revocation.revoked),
            "revocation_exact": self.revocation.exact,
            "revocation_stale": self.revocation.is_stale(),
            "has_filter": self.revocation.filter is not None,
            # When the registry signed the newest revocation data held (Unix seconds). Verifiers
            # refuse agents once it is MAX_REVOCATION_AGE_SECONDS (660) old: alert well before.
            "revocation_issued_at": (int(self.revocation.issued_at.timestamp())
                                     if self.revocation.issued_at else None),
        }


class NonceCache:
    """In-process replay cache for signature nonces.

    Sufficient for a single-process site. A multi-instance deployment must back this with a shared
    store (Valkey ``SET NX`` with a TTL matching the maximum signature age) — otherwise a captured
    request simply replays against a different instance, and the nonce check becomes decorative.

    The default TTL is twice the maximum signature age: a signature may be dated up to 300 s in
    the future (clock skew) and stays acceptable until 300 s after that, so a nonce must be
    remembered for 600 s to cover every moment its request could still be accepted.

    When the cache is full of live entries it **refuses** (``RegistryUnavailable``) rather than
    evicting: forgetting a live nonce re-opens replay for exactly that request.
    """

    def __init__(self, ttl_seconds: int = 600, max_entries: int = 100_000) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}

    def __call__(self, nonce: str) -> bool:
        """Return ``True`` if this nonce has been seen. Records it either way."""
        now = time.monotonic()
        previous = self._seen.get(nonce)
        if previous is not None and now - previous < self.ttl:
            return True
        if len(self._seen) >= self.max_entries:
            cutoff = now - self.ttl
            self._seen = {n: t for n, t in self._seen.items() if t > cutoff}
            if len(self._seen) >= self.max_entries:
                raise RegistryUnavailable(
                    "replay cache is full of live nonces; refusing rather than forgetting one",
                    max_entries=self.max_entries)
        self._seen[nonce] = now
        return False

    def __len__(self) -> int:
        return len(self._seen)


def build_trust_store(
    jwks: dict[str, Any],
    *,
    delta_token: str | None = None,
    filter_token: str | None = None,
    expected_issuer: str | None = None,
) -> TrustStore:
    """Convenience constructor for the usual bootstrap: JWKS plus initial revocation state."""
    store = TrustStore.from_jwks(jwks, expected_issuer=expected_issuer)
    if filter_token:
        store.ingest_filter(filter_token)
    if delta_token:
        store.ingest_delta(delta_token)
    return store
