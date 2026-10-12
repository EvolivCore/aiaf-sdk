"""Revocation bloom filter.

Every relying party and every verification gateway holds the full set of revoked identifiers in
memory. A bloom filter is what makes that affordable: ~1.2 MB covers a million revocations at a
1 % false-positive rate, against roughly 60 MB for the raw identifier strings.

**The error direction is the whole point.** A bloom filter can say "possibly present" about
something absent, but never "absent" about something present. Applied to revocation:

* revoked identifier  -> always reported as possibly-revoked  -> always caught
* healthy identifier  -> occasionally reported as possibly-revoked -> falls through to an
  authoritative online check, which clears it

So the failure mode is a slow verification, never a wrong one. If the polarity were reversed —
a filter of *valid* identifiers — a false positive would admit a revoked agent, and the structure
would be unusable here. Anyone modifying this module must preserve that direction.

The construction is specified exactly, because the Python, Node and Go SDKs must all agree on it:

* digest = SHA-256(identifier encoded as UTF-8)
* h1 = int.from_bytes(digest[0:8], "big"), h2 = int.from_bytes(digest[8:16], "big")
* bit index i (for i in 0..k-1) = ((h1 + i * h2 + i * i) mod 2**64) mod m
* bit b lives in byte b // 8, at bit position b % 8 counting from the least significant bit

The ``+ i*i`` term is Kirsch-Mitzenmacher enhanced double hashing; it removes the degenerate cycles
that plain double hashing exhibits when h2 shares a factor with m.

**The ``mod 2**64`` is load-bearing and must not be dropped.** Python integers are arbitrary
precision, so the intermediate sum does not wrap; a uint64 in Go or Rust does. Without an explicit
mask the two languages select different bits for the same identifier once the sum exceeds 2**64 —
and a revoked agent then verifies as healthy in one SDK and is refused in another. This was a real
bug, caught by the cross-language conformance vectors rather than in production.
"""

from __future__ import annotations

import base64
import hashlib
import math
from collections.abc import Iterable
from dataclasses import dataclass

FORMAT_VERSION = 1

#: The index arithmetic is defined modulo 2**64 so that every language agrees.
_UINT64_MASK = (1 << 64) - 1

# Ceiling from docs/02-data-model.md §3: the filter must stay small enough that every relying
# party can hold it in memory without thinking about it. Exceeding this is an architectural
# event, not a tuning detail, so it raises rather than silently degrading.
MAX_FILTER_BYTES = 10 * 1024 * 1024


def _optimal_parameters(expected_items: int, false_positive_rate: float) -> tuple[int, int]:
    """Return (m bits, k hash functions) for the target capacity and error rate."""
    if expected_items <= 0:
        raise ValueError("expected_items must be positive")
    if not 0.0 < false_positive_rate < 1.0:
        raise ValueError("false_positive_rate must be between 0 and 1 exclusive")

    m = math.ceil(-expected_items * math.log(false_positive_rate) / (math.log(2) ** 2))
    m = max(8, (m + 7) // 8 * 8)  # round up to a whole byte
    k = max(1, round(m / expected_items * math.log(2)))
    return m, k


@dataclass
class BloomFilter:
    """A fixed-capacity bloom filter over identifier strings."""

    m: int                      # size in bits
    k: int                      # number of hash functions
    bits: bytearray             # m // 8 bytes
    count: int = 0              # items added (informational; bloom filters cannot count)

    # -- construction ---------------------------------------------------------------------

    @classmethod
    def create(cls, expected_items: int, false_positive_rate: float = 0.01) -> BloomFilter:
        m, k = _optimal_parameters(expected_items, false_positive_rate)
        if m // 8 > MAX_FILTER_BYTES:
            raise ValueError(
                f"filter would be {m // 8 // 1024 // 1024} MB, over the {MAX_FILTER_BYTES // 1024 // 1024} MB "
                "budget — revocation volume needs an architectural response (sharded filters or "
                "shorter credential TTLs), not a larger filter"
            )
        return cls(m=m, k=k, bits=bytearray(m // 8))

    @classmethod
    def build(
        cls,
        items: Iterable[str],
        *,
        expected_items: int | None = None,
        false_positive_rate: float = 0.01,
        headroom: float = 2.0,
    ) -> BloomFilter:
        """Build a filter from an iterable, sized with headroom for growth.

        A bloom filter degrades gracefully but not gently: past its design capacity the
        false-positive rate climbs fast. Sizing for twice the current population means a
        rebuild is a scheduled event rather than an incident.
        """
        materialised = list(items)
        capacity = max(1, expected_items or int(len(materialised) * headroom) or 1)
        filter_ = cls.create(capacity, false_positive_rate)
        for item in materialised:
            filter_.add(item)
        return filter_

    # -- membership -----------------------------------------------------------------------

    def _indices(self, item: str) -> list[int]:
        digest = hashlib.sha256(item.encode("utf-8")).digest()
        h1 = int.from_bytes(digest[0:8], "big")
        h2 = int.from_bytes(digest[8:16], "big")
        # Mask to 64 bits before the modulus: see the module docstring. Python would otherwise
        # carry unbounded precision where every other SDK wraps.
        return [((h1 + i * h2 + i * i) & _UINT64_MASK) % self.m for i in range(self.k)]

    def add(self, item: str) -> None:
        for index in self._indices(item):
            self.bits[index // 8] |= 1 << (index % 8)
        self.count += 1

    def __contains__(self, item: str) -> bool:
        """``True`` means *possibly* present. ``False`` means *definitely* absent."""
        return all(self.bits[i // 8] & (1 << (i % 8)) for i in self._indices(item))

    def might_contain(self, item: str) -> bool:
        """Explicit alias. Prefer it at call sites where the uncertainty must be obvious."""
        return item in self

    # -- diagnostics ----------------------------------------------------------------------

    @property
    def size_bytes(self) -> int:
        return self.m // 8

    @property
    def saturation(self) -> float:
        """Fraction of bits set. Past ~0.5 the filter needs resizing."""
        return sum(bin(byte).count("1") for byte in self.bits) / self.m

    def estimated_false_positive_rate(self) -> float:
        """Estimate the *current* false-positive rate from actual bit saturation.

        Derived from observed saturation rather than the design parameters, so it stays honest
        after the filter has been overfilled. Worth exporting as a metric: a filter quietly past
        capacity shows up here long before it shows up as user-visible latency.
        """
        return self.saturation ** self.k

    # -- serialisation --------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "format": FORMAT_VERSION,
            "m": self.m,
            "k": self.k,
            "count": self.count,
            "bits": base64.b64encode(bytes(self.bits)).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict) -> BloomFilter:
        if data.get("format") != FORMAT_VERSION:
            raise ValueError(f"unsupported bloom filter format {data.get('format')!r}")
        m, k = int(data["m"]), int(data["k"])
        bits = bytearray(base64.b64decode(data["bits"]))
        if len(bits) * 8 != m:
            raise ValueError("bloom filter bit length does not match declared size")
        return cls(m=m, k=k, bits=bits, count=int(data.get("count", 0)))
