"""HTTP Message Signatures (RFC 9421) — the subset AIDR uses.

An agent signs each request it makes; the website verifies that signature locally. This is what
makes offline verification possible, and it is why AIDR aligns with RFC 9421 and the Web Bot Auth
profile rather than inventing a header format: a site that already verifies signed agent requests
should accept an AIDR identity by adding one trust anchor, not by adopting our SDK.

**The security property that matters is binding.** A signature over *nothing in particular*
verifies perfectly well anywhere. By covering ``@method``, ``@authority`` and ``@path``, plus a
``created`` timestamp and a ``nonce``, a captured signature becomes useless against a different
host, a different path, a different verb, or the same request twice::

    "@method": GET
    "@authority": shop.example
    "@path": /api/products
    "@signature-params": ("@method" "@authority" "@path");created=1758700000;keyid="aid:v1:...";alg="ed25519";nonce="..."

This is a deliberately narrow implementation. It handles the component set above plus ordinary
header components, and **rejects** the exotic corners of the specification (structured-field
parameters, binary-wrapped values, request-response binding) rather than half-implementing them.
A verifier that mis-parses an unusual construction is more dangerous than one that refuses it.
"""

from __future__ import annotations

import base64
import os
import secrets
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from aidr_core.errors import (
    CoveredComponentMismatch,
    MalformedToken,
    ReplayDetected,
    SignatureInvalid,
    SignatureTooOld,
    UnsupportedAlgorithm,
)
from aidr_core.serde import utcnow

from .algorithms import Algorithm, by_http_alg
from .keys import algorithm_for_key, resolve_algorithm, sign_raw

#: RFC 9421 algorithm registry name for Ed25519.
ALG_ED25519_HTTP = "ed25519"

#: Components every AIDR signature must cover. Dropping any one of them re-enables a real attack:
#: without @method a GET signature replays as a DELETE; without @authority it replays against
#: another site; without @path it replays against another endpoint on the same site.
REQUIRED_COMPONENTS: tuple[str, ...] = ("@method", "@authority", "@path")

DEFAULT_COMPONENTS: tuple[str, ...] = REQUIRED_COMPONENTS

#: Maximum age of a signature. 300s is the Web Bot Auth convention: long enough to survive clock
#: drift and a slow proxy, short enough that a captured signature is stale before it is useful.
DEFAULT_MAX_AGE_SECONDS = 300

DEFAULT_LABEL = "sig1"

SIGNATURE_INPUT_HEADER = "Signature-Input"
SIGNATURE_HEADER = "Signature"
CREDENTIAL_HEADER = "Agent-Credential"


# ==============================================================================================
# Structured-field parsing (the narrow subset we emit and accept)
# ==============================================================================================

def _split_top_level(text: str, separator: str) -> list[str]:
    """Split on ``separator``, ignoring separators inside quotes or parentheses."""
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    depth = 0

    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and in_quotes:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if not in_quotes:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth < 0:
                    raise MalformedToken("unbalanced ')' in structured field")
            elif char == separator and depth == 0:
                parts.append("".join(current).strip())
                current = []
                continue
        current.append(char)

    if in_quotes:
        raise MalformedToken("unterminated quoted string in structured field")
    if depth != 0:
        raise MalformedToken("unbalanced parentheses in structured field")

    parts.append("".join(current).strip())
    return [p for p in parts if p]


def _unquote(token: str) -> str:
    if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
        return token[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return token


def _parse_params(text: str) -> dict[str, object]:
    params: dict[str, object] = {}
    for item in _split_top_level(text, ";"):
        if "=" not in item:
            params[item.strip()] = True
            continue
        key, _, raw_value = item.partition("=")
        key = key.strip()
        raw_value = raw_value.strip()
        if raw_value.startswith('"'):
            params[key] = _unquote(raw_value)
        elif raw_value.lstrip("-").isdigit():
            params[key] = int(raw_value)
        else:
            params[key] = raw_value
    return params


@dataclass(frozen=True)
class SignatureInputEntry:
    """One parsed ``Signature-Input`` member."""

    label: str
    components: tuple[str, ...]
    params: dict[str, object]
    raw_value: str
    """The exact bytes of the member's value.

    Kept verbatim and reused as the ``@signature-params`` line when rebuilding the signature base.
    Re-serialising from the parsed form instead would risk a canonicalisation mismatch — a
    different space or quoting style produces a different base and therefore a bogus verification
    failure against a perfectly valid signature.
    """

    @property
    def keyid(self) -> str | None:
        value = self.params.get("keyid")
        return value if isinstance(value, str) else None

    @property
    def algorithm(self) -> str | None:
        value = self.params.get("alg")
        return value if isinstance(value, str) else None

    @property
    def nonce(self) -> str | None:
        value = self.params.get("nonce")
        return value if isinstance(value, str) else None

    @property
    def created(self) -> datetime | None:
        value = self.params.get("created")
        return datetime.fromtimestamp(value, tz=timezone.utc) if isinstance(value, int) else None

    @property
    def expires(self) -> datetime | None:
        value = self.params.get("expires")
        return datetime.fromtimestamp(value, tz=timezone.utc) if isinstance(value, int) else None


def parse_signature_input(header_value: str) -> dict[str, SignatureInputEntry]:
    """Parse a ``Signature-Input`` header into label → entry."""
    entries: dict[str, SignatureInputEntry] = {}

    for member in _split_top_level(header_value, ","):
        label, _, value = member.partition("=")
        label = label.strip()
        value = value.strip()
        if not label or not value.startswith("("):
            raise MalformedToken(f"malformed Signature-Input member: {member[:64]!r}")

        close = value.index(")")
        inner = value[1:close].strip()
        params_text = value[close + 1:].lstrip(";")

        components = tuple(_unquote(tok) for tok in _split_top_level(inner, " ")) if inner else ()
        entries[label] = SignatureInputEntry(
            label=label,
            components=components,
            params=_parse_params(params_text) if params_text else {},
            raw_value=value,
        )

    if not entries:
        raise MalformedToken("Signature-Input header contains no signatures")
    return entries


def parse_signature_header(header_value: str) -> dict[str, bytes]:
    """Parse a ``Signature`` header into label → raw signature bytes."""
    signatures: dict[str, bytes] = {}
    for member in _split_top_level(header_value, ","):
        label, _, value = member.partition("=")
        label, value = label.strip(), value.strip()
        if not (value.startswith(":") and value.endswith(":") and len(value) >= 2):
            raise MalformedToken(f"malformed Signature member for label {label!r}")
        try:
            signatures[label] = base64.b64decode(value[1:-1], validate=True)
        except Exception as exc:  # noqa: BLE001
            raise MalformedToken(f"signature for {label!r} is not valid base64") from exc
    if not signatures:
        raise MalformedToken("Signature header contains no signatures")
    return signatures


# ==============================================================================================
# Signature base construction
# ==============================================================================================

@dataclass
class RequestContext:
    """Everything needed to derive component values from an HTTP request.

    On the server side, ``url`` must be the effective request URI **as the server actually
    received it** — built from the real Host header and path, never from anything supplied inside
    the signature. Use :func:`effective_request_uri`. Taking the URI from attacker-controlled
    input would let a signature certify a request that was never made.
    """

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)

    def normalised_headers(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}


def _accepted_keyids(expected: str | Collection[str] | None) -> tuple[str, ...] | None:
    if expected is None:
        return None
    return (expected,) if isinstance(expected, str) else tuple(expected)


def _choose_label(entries: Mapping[str, SignatureInputEntry],
                  accepted: tuple[str, ...] | None) -> str:
    """Which signature to verify when a request carries several (RFC 9421 allows any number):
    the first, in header order, whose keyid is one the credential names; otherwise the first,
    which then fails on its keyid as it should. A signature for someone else beside it (another
    intermediary's, say) is ignored rather than mistaken for the agent's."""
    if accepted:
        for name, entry in entries.items():
            if entry.keyid in accepted:
                return name
    return next(iter(entries))


def effective_request_uri(scheme: str, host_header: str, path_with_query: str) -> str:
    """Reconstruct the request URI a server actually received."""
    if not host_header:
        raise MalformedToken("cannot derive request URI without a Host header")
    if not path_with_query.startswith("/"):
        path_with_query = "/" + path_with_query
    return f"{scheme}://{host_header}{path_with_query}"


def _derive_component(name: str, context: RequestContext) -> str:
    parts = urlsplit(context.url)

    if name == "@method":
        return context.method.upper()
    if name == "@target-uri":
        return context.url
    if name == "@authority":
        # Lowercase, with the default port omitted: https://HOST:443/ and https://host/ are the
        # same origin, and an agent must not have to guess which spelling the server will use.
        authority = (parts.netloc or "").lower()
        for scheme, default_port in (("https", ":443"), ("http", ":80")):
            if parts.scheme == scheme and authority.endswith(default_port):
                authority = authority[: -len(default_port)]
        return authority
    if name == "@scheme":
        return (parts.scheme or "").lower()
    if name == "@path":
        return parts.path or "/"
    if name == "@query":
        return f"?{parts.query}" if parts.query else "?"

    if name.startswith("@"):
        raise UnsupportedAlgorithm(
            f"derived component {name!r} is not supported by this implementation", component=name
        )

    value = context.normalised_headers().get(name.lower())
    if value is None:
        raise CoveredComponentMismatch(
            f"signature covers header {name!r}, which is absent from the request",
            component=name,
        )
    return " ".join(value.split())


def build_signature_base(components: Sequence[str], signature_params: str,
                         context: RequestContext) -> bytes:
    """Build the RFC 9421 signature base.

    ``signature_params`` is the serialised parameter string, passed in verbatim so signing and
    verification agree byte for byte.
    """
    lines = [f'"{name.lower()}": {_derive_component(name, context)}' for name in components]
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines).encode("utf-8")


def serialize_signature_params(components: Sequence[str], params: Mapping[str, object]) -> str:
    """Serialise the inner list and parameters, in the order given."""
    inner = " ".join(f'"{name.lower()}"' for name in components)
    rendered = [f"({inner})"]
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            rendered.append(f";{key}" if value else "")
        elif isinstance(value, int):
            rendered.append(f";{key}={value}")
        else:
            rendered.append(f';{key}="{value}"')
    return "".join(rendered)


def generate_nonce(length: int = 16) -> str:
    """A random, URL-safe nonce for replay prevention."""
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).rstrip(b"=").decode("ascii")


# ==============================================================================================
# Signing
# ==============================================================================================

def sign_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str] | None = None,
    sign: Callable[[bytes], bytes] | None = None,
    private_key: Any = None,
    keyid: str,
    components: Sequence[str] = DEFAULT_COMPONENTS,
    label: str = DEFAULT_LABEL,
    created: datetime | None = None,
    expires_in_seconds: int | None = None,
    nonce: str | None = None,
    tag: str | None = "aidr",
    algorithm: Algorithm | str | None = None,
) -> dict[str, str]:
    """Sign a request, returning the headers to add.

    ``sign`` is a plain callable rather than a Signer object because the agent's private key lives
    with the agent — ``private_key.sign`` is passed directly. The registry never participates in
    signing an agent's request, and this signature reflects that.
    """
    if (sign is None) == (private_key is None):
        raise ValueError("pass exactly one of 'private_key' or 'sign'")

    if private_key is not None:
        # Preferred form: the algorithm is derived from the key, so an agent holding a P-256 key
        # cannot advertise ed25519 and have every verifier reject it. The 'sign' callable form
        # remains for HSM-held keys, where no key object exists in process.
        resolved = resolve_algorithm(algorithm) if algorithm else algorithm_for_key(private_key)
        sign = lambda data: sign_raw(private_key, data)  # noqa: E731
    else:
        resolved = resolve_algorithm(algorithm)

    context = RequestContext(method=method, url=url, headers=dict(headers or {}))
    created_at = created or utcnow()

    params: dict[str, object] = {
        "created": int(created_at.timestamp()),
        "keyid": keyid,
        "alg": resolved.http_alg,
        "nonce": nonce or generate_nonce(),
    }
    if expires_in_seconds:
        params["expires"] = int(created_at.timestamp()) + expires_in_seconds
    if tag:
        params["tag"] = tag

    signature_params = serialize_signature_params(components, params)
    signature = sign(build_signature_base(components, signature_params, context))

    return {
        SIGNATURE_INPUT_HEADER: f"{label}={signature_params}",
        SIGNATURE_HEADER: f"{label}=:{base64.b64encode(signature).decode('ascii')}:",
    }


# ==============================================================================================
# Verification
# ==============================================================================================

@dataclass(frozen=True)
class VerifiedSignature:
    label: str
    keyid: str
    created: datetime
    nonce: str | None
    components: tuple[str, ...]
    tag: str | None


def verify_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    public_key_resolver: Callable[[str], object | None],
    required_components: Iterable[str] = REQUIRED_COMPONENTS,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    now: datetime | None = None,
    nonce_seen: Callable[[str], bool] | None = None,
    label: str | None = None,
    expected_keyid: str | Collection[str] | None = None,
) -> VerifiedSignature:
    """Verify an RFC 9421 signature on a received request.

    Checks run cheapest-first, so a malformed or stale request is rejected before any
    cryptography happens. That ordering is a small DoS mitigation: signature verification is the
    expensive step, and an attacker should not be able to force it by sending garbage.

    ``nonce_seen`` is supplied by the relying party — typically a Valkey ``SET NX`` with a TTL
    matching ``max_age_seconds``. It must return ``True`` if the nonce has been used before. If it
    is omitted, replay protection is **off**, and the caller has accepted that. It is consulted
    only for a request whose signature has verified — the one exception to cheapest-first.
    """
    moment = now or utcnow()
    normalised = {k.lower(): v for k, v in headers.items()}

    raw_input = normalised.get(SIGNATURE_INPUT_HEADER.lower())
    raw_signature = normalised.get(SIGNATURE_HEADER.lower())
    if not raw_input or not raw_signature:
        raise MalformedToken("request is missing Signature-Input or Signature headers")

    entries = parse_signature_input(raw_input)
    signatures = parse_signature_header(raw_signature)

    accepted = _accepted_keyids(expected_keyid)
    chosen = label or _choose_label(entries, accepted)
    entry = entries.get(chosen)
    if entry is None:
        raise MalformedToken(f"no Signature-Input member labelled {chosen!r}")
    signature = signatures.get(chosen)
    if signature is None:
        raise MalformedToken(f"no Signature member labelled {chosen!r}")

    declared_algorithm = by_http_alg(entry.algorithm) if entry.algorithm else None

    keyid = entry.keyid
    if not keyid:
        raise MalformedToken("signature parameters are missing 'keyid'")
    if accepted is not None and keyid not in accepted:
        # The credential says one identity, the signature another. Almost always an attempt to
        # pair a stolen credential with a key the attacker actually controls.
        raise CoveredComponentMismatch(
            "signature keyid does not match the presented credential",
            signature_keyid=keyid, credential_keyid=next(iter(accepted)),
        )

    created = entry.created
    if created is None:
        raise MalformedToken("signature parameters are missing 'created'")
    age = (moment - created).total_seconds()
    if age > max_age_seconds:
        raise SignatureTooOld(
            f"signature is {int(age)}s old, older than the {max_age_seconds}s limit",
            age_seconds=int(age),
        )
    if age < -max_age_seconds:
        raise SignatureTooOld(
            "signature was created in the future beyond clock-skew tolerance",
            age_seconds=int(age),
        )
    expires = entry.expires
    if expires is not None and moment > expires:
        raise SignatureTooOld("signature has passed its stated expiry")

    covered = {name.lower() for name in entry.components}
    missing = [name for name in required_components if name.lower() not in covered]
    if missing:
        raise CoveredComponentMismatch(
            f"signature does not cover required components: {', '.join(missing)}",
            missing=missing, covered=sorted(covered),
        )

    nonce = entry.nonce
    if nonce_seen is not None and not nonce:
        raise MalformedToken("replay protection is enabled but the signature carries no nonce")

    public_key = public_key_resolver(keyid)
    if public_key is None:
        raise SignatureInvalid(f"no public key available for keyid {keyid!r}", keyid=keyid)

    # Select the algorithm from the key we hold, then require the signature's declared algorithm
    # to agree. Trusting the declared value alone would let an attacker pick the algorithm; using
    # the key alone would silently accept a signature that claims to be something else.
    key_algorithm = algorithm_for_key(public_key)
    if declared_algorithm is not None and declared_algorithm.name != key_algorithm.name:
        raise UnsupportedAlgorithm(
            f"signature declares {declared_algorithm.http_alg} but the key for {keyid!r} is "
            f"{key_algorithm.name}",
            alg=declared_algorithm.http_alg, key_alg=key_algorithm.name,
        )

    context = RequestContext(method=method, url=url, headers=dict(headers))
    base = build_signature_base(entry.components, entry.raw_value, context)
    key_algorithm.verify(public_key, signature, base)   # raises SignatureInvalid on mismatch

    # The replay check comes last, after the signature has verified. ``nonce_seen`` records the
    # nonce it is asked about, so consulting it earlier would let a forged request occupy a nonce:
    # anyone who saw a genuine request in flight could have it refused as a replay, and a stream
    # of forgeries could fill the store until it forgot real entries.
    if nonce_seen is not None and nonce_seen(nonce):
        raise ReplayDetected("signature nonce has already been used", nonce=nonce)

    return VerifiedSignature(
        label=chosen,
        keyid=keyid,
        created=created,
        nonce=entry.nonce,
        components=entry.components,
        tag=entry.params.get("tag") if isinstance(entry.params.get("tag"), str) else None,
    )


def constant_time_env_flag(name: str) -> bool:  # pragma: no cover - configuration helper
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}
