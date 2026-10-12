"""The ``aid:`` agent identifier.

    aid:v1:acme-corp:01J8Z3QX7KFM2N5T9VB0WXYZ:k3f9
    └┬┘ └┬┘ └───┬───┘ └──────────┬───────────┘ └─┬┘
     │   │      │                │               └── 4-char checksum over everything to its left
     │   │      │                └────────────────── ULID: 48-bit ms timestamp + 80 bits entropy
     │   │      └─────────────────────────────────── owner namespace (DNS-label safe, immutable)
     │   └────────────────────────────────────────── format version
     └────────────────────────────────────────────── URN scheme

Design rationale is in ``docs/02-data-model.md`` §1. The three properties that matter in code:

1. **The identifier is not a secret.** It is a licence plate. Nothing in this module tries to make
   it unguessable, and no security property may depend on it being unguessable.
2. **It is self-describing.** Namespace and creation time are readable without a database lookup,
   which is what lets a relying party attribute an agent to an organisation entirely offline.
3. **It is checksummed.** A mistyped identifier fails as a checksum error, not as a lookup miss.
   The difference matters at 3am: one points at a typo, the other at a missing record.
"""

from __future__ import annotations

import os
import re
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from .errors import ChecksumMismatch, InvalidAgentID, InvalidNamespace, UnsupportedVersion

# Crockford base32: no I, L, O or U. Excluding them removes the 1/l/I and 0/O confusions that
# generate support tickets, and drops U so the alphabet cannot spell unfortunate words.
_ALPHABET: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE: Final = {c: i for i, c in enumerate(_ALPHABET)}
# Crockford's documented ambiguity folding, applied on input only.
_DECODE.update({"I": 1, "L": 1, "O": 0})
_DECODE.update({c.lower(): v for c, v in list(_DECODE.items())})

SCHEME: Final = "aid"
CURRENT_VERSION: Final = "v1"
SUPPORTED_VERSIONS: Final = frozenset({"v1"})

ULID_LENGTH: Final = 26
CHECKSUM_LENGTH: Final = 4

_NAMESPACE_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$")
NAMESPACE_MIN_LENGTH: Final = 3
NAMESPACE_MAX_LENGTH: Final = 63

# Namespaces nobody may register. Squatting on these would let an attacker mint identifiers that
# *look* like infrastructure. Cheap to reserve now, impossible to reclaim later.
RESERVED_NAMESPACES: Final = frozenset({
    "aidr", "admin", "administrator", "api", "root", "system", "internal", "official",
    "registry", "authority", "ca", "security", "abuse", "support", "help", "www",
    "test", "example", "invalid", "localhost", "null", "none", "undefined",
})


# ----------------------------------------------------------------------------------------------
# Base32 / ULID primitives
# ----------------------------------------------------------------------------------------------

def _encode_base32(value: int, length: int) -> str:
    """Encode ``value`` as ``length`` Crockford base32 characters, most significant first."""
    if value < 0:
        raise ValueError("value must be non-negative")
    if value >= 1 << (5 * length):
        raise ValueError(f"value does not fit in {length} base32 characters")
    chars = [""] * length
    for i in range(length - 1, -1, -1):
        chars[i] = _ALPHABET[value & 0x1F]
        value >>= 5
    return "".join(chars)


def _decode_base32(text: str) -> int:
    value = 0
    for char in text:
        digit = _DECODE.get(char)
        if digit is None:
            raise InvalidAgentID(f"invalid base32 character {char!r}", character=char)
        value = (value << 5) | digit
    return value


def new_ulid(when: datetime | None = None, entropy: bytes | None = None) -> str:
    """Generate a ULID: 48 bits of millisecond timestamp followed by 80 bits of entropy.

    Chosen over UUIDv4 because the time prefix makes identifiers sort chronologically, which gives
    us free creation-time ordering in every index and a natural component for the shard key.

    ``entropy`` is injectable for deterministic tests only. Production always uses ``os.urandom``.
    """
    moment = when or datetime.now(timezone.utc)
    timestamp_ms = int(moment.timestamp() * 1000)
    if not 0 <= timestamp_ms < (1 << 48):
        raise ValueError("timestamp out of ULID range")
    random_bits = entropy if entropy is not None else os.urandom(10)
    if len(random_bits) != 10:
        raise ValueError("ULID entropy must be exactly 10 bytes")
    return _encode_base32((timestamp_ms << 80) | int.from_bytes(random_bits, "big"), ULID_LENGTH)


def ulid_timestamp(ulid: str) -> datetime:
    """Extract the creation time encoded in a ULID's first 48 bits."""
    if len(ulid) != ULID_LENGTH:
        raise InvalidAgentID("ULID must be 26 characters", ulid=ulid)
    return datetime.fromtimestamp((_decode_base32(ulid) >> 80) / 1000, tz=timezone.utc)


def _checksum(payload: str) -> str:
    """Four Crockford base32 characters over the 20 low bits of CRC32.

    CRC32 is not a security control and is not used as one — an attacker who alters an identifier
    simply recomputes it. It catches transcription and truncation, which is its entire job.
    """
    return _encode_base32(zlib.crc32(payload.encode("ascii")) & 0xFFFFF, CHECKSUM_LENGTH).lower()


# ----------------------------------------------------------------------------------------------
# Namespace validation
# ----------------------------------------------------------------------------------------------

def validate_namespace(namespace: str, *, allow_reserved: bool = False) -> str:
    """Validate and canonicalise an organisation namespace.

    Constrained to DNS-label syntax so a namespace can appear in a hostname, a certificate SAN or
    a ``did:aidr:`` identifier without re-encoding.
    """
    if not isinstance(namespace, str):
        raise InvalidNamespace("namespace must be a string")
    candidate = namespace.strip().lower()
    if not NAMESPACE_MIN_LENGTH <= len(candidate) <= NAMESPACE_MAX_LENGTH:
        raise InvalidNamespace(
            f"namespace must be {NAMESPACE_MIN_LENGTH}-{NAMESPACE_MAX_LENGTH} characters",
            namespace=namespace,
        )
    if not _NAMESPACE_RE.match(candidate):
        raise InvalidNamespace(
            "namespace must be lowercase alphanumeric with internal hyphens only",
            namespace=namespace,
        )
    if not allow_reserved and candidate in RESERVED_NAMESPACES:
        raise InvalidNamespace("namespace is reserved", namespace=candidate)
    return candidate


# ----------------------------------------------------------------------------------------------
# AgentID
# ----------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AgentID:
    """A parsed, validated agent identifier.

    Immutable and hashable so it can be used as a dict key and passed around without defensive
    copying. ``str(agent_id)`` always yields the canonical form.
    """

    namespace: str
    ulid: str
    version: str = CURRENT_VERSION

    # -- construction ---------------------------------------------------------------------

    @classmethod
    def generate(
        cls,
        namespace: str,
        *,
        when: datetime | None = None,
        entropy: bytes | None = None,
        allow_reserved: bool = False,
    ) -> AgentID:
        return cls(
            namespace=validate_namespace(namespace, allow_reserved=allow_reserved),
            ulid=new_ulid(when=when, entropy=entropy),
        )

    @classmethod
    def parse(cls, value: str, *, allow_reserved: bool = True) -> AgentID:
        """Parse a canonical ``aid:`` string, validating structure and checksum.

        Parsing accepts mixed case and folds Crockford's ambiguous characters, then re-canonicalises.
        Reserved namespaces are *accepted* when parsing by default: refusing to parse an identifier
        we ourselves issued under a reserved namespace would make the registry unable to read its
        own records. Reservation is enforced at registration, which is where it belongs.
        """
        if not isinstance(value, str):
            raise InvalidAgentID("identifier must be a string")

        parts = value.strip().split(":")
        if len(parts) != 5:
            raise InvalidAgentID(
                "identifier must have the form aid:<version>:<namespace>:<ulid>:<checksum>",
                value=value,
            )

        scheme, version, namespace, ulid, checksum = parts
        if scheme.lower() != SCHEME:
            raise InvalidAgentID(f"unknown scheme {scheme!r}", value=value)

        version = version.lower()
        if version not in SUPPORTED_VERSIONS:
            # Deliberately distinct from a generic parse failure: a v2 identifier arriving at a v1
            # verifier is a "you need to upgrade" condition, not a malformed input.
            raise UnsupportedVersion(f"unsupported identifier version {version!r}", value=value)

        namespace = validate_namespace(namespace, allow_reserved=allow_reserved)

        if len(ulid) != ULID_LENGTH:
            raise InvalidAgentID(f"ULID must be {ULID_LENGTH} characters", value=value)
        canonical_ulid = _encode_base32(_decode_base32(ulid), ULID_LENGTH)

        if len(checksum) != CHECKSUM_LENGTH:
            raise InvalidAgentID(f"checksum must be {CHECKSUM_LENGTH} characters", value=value)

        expected = _checksum(f"{SCHEME}:{version}:{namespace}:{canonical_ulid}")
        if checksum.lower() != expected:
            raise ChecksumMismatch(
                "identifier checksum does not match — likely a transcription error",
                value=value,
                expected=expected,
                received=checksum.lower(),
            )

        return cls(namespace=namespace, ulid=canonical_ulid, version=version)

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Non-raising validity check, for hot paths that only need a boolean."""
        try:
            cls.parse(value)
        except AidrErrorTuple:
            return False
        return True

    # -- representation -------------------------------------------------------------------

    @property
    def prefix(self) -> str:
        """Everything the checksum is computed over."""
        return f"{SCHEME}:{self.version}:{self.namespace}:{self.ulid}"

    @property
    def checksum(self) -> str:
        return _checksum(self.prefix)

    @property
    def did(self) -> str:
        """W3C DID spelling of the same identity, for decentralised-identity interop."""
        return f"did:aidr:{self.namespace}:{self.ulid}"

    @property
    def created_at(self) -> datetime:
        """Creation time, read straight out of the identifier — no database lookup."""
        return ulid_timestamp(self.ulid)

    def __str__(self) -> str:
        return f"{self.prefix}:{self.checksum}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"AgentID({str(self)!r})"


# Tuple used by :meth:`AgentID.is_valid`. Defined after the class to keep the import list at the
# top of the module honest about what it actually uses.
AidrErrorTuple = (InvalidAgentID,)


def new_record_id(prefix: str) -> str:
    """Generate a prefixed ULID for non-agent records (``org_``, ``usr_``, ``cred_``, ...).

    The prefix is purely for human legibility in logs and support tickets. It is never parsed for
    authorization: a record's type comes from the collection it lives in, not from its name.
    """
    return f"{prefix}_{new_ulid()}"


def monotonic_ms() -> int:
    """Millisecond wall-clock, isolated here so tests can freeze it in one place."""
    return int(time.time() * 1000)
