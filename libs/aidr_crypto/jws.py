"""Compact JWS (RFC 7515) with EdDSA, plus claim validation.

This is the envelope for the ``Agent-Credential`` header. It is a deliberately small, strict
implementation rather than a general-purpose JOSE library, because the well-known JWT
vulnerabilities all come from generality:

* **alg=none** — a token that declares no algorithm and is accepted anyway. Here the header's
  ``alg`` must equal ``EdDSA``; anything else, including ``none``, is rejected before any
  signature work happens.
* **Algorithm confusion** (RS256 token verified as HS256 against the public key) — impossible
  here, because exactly one algorithm is implemented and the key type is fixed.
* **Unverified claim reads** — the parse and verify steps are one function. There is no code path
  that returns claims without having checked the signature, so no caller can accidentally trust
  an unverified payload. The one function that does read without verifying is named
  :func:`decode_unverified_header` and returns *only* the header, which is all that is needed to
  look up a key.
* **Trusting the token's own key** — the verifier takes a resolver that maps ``kid`` to a
  *trusted* JWK. An embedded key in the header is never used.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from aidr_core.errors import (
    CredentialExpired,
    CredentialNotYetValid,
    MalformedToken,
    UnknownIssuer,
    UnsupportedAlgorithm,
)
from aidr_core.serde import utcnow

from .algorithms import by_jose_alg, for_jwk
from .keys import ALG_ED25519, b64url_decode, b64url_encode, jwk_to_public_key

#: Media type for an AIDR agent credential. Set as ``typ`` so a credential cannot be replayed into
#: a different JWT-consuming system that happens to trust the same key.
CREDENTIAL_TYP = "aidr-cred+jwt"
CERTIFICATE_TYP = "aidr-cert+jwt"

#: Clock skew tolerance. Larger than feels necessary because unsynchronised clocks are the single
#: most common cause of spurious verification failures in the field; 60s is enough to absorb a
#: drifting VM without meaningfully extending a stolen credential's life.
DEFAULT_LEEWAY = timedelta(seconds=60)


def _b64url_json(data: dict) -> str:
    return b64url_encode(json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8"))


async def sign_compact(payload: dict[str, Any], signer: Any, *, typ: str = CREDENTIAL_TYP,
                       extra_header: dict[str, Any] | None = None) -> str:
    """Produce a compact JWS: ``base64url(header).base64url(payload).base64url(signature)``."""
    # The algorithm comes from the signer, not from a constant: a FIPS-strict deployment signs
    # with ES256, and the header must say so or every verifier will reject it.
    # The kid is read once and the signature made with exactly that key version (sign_as), so the
    # header never names a version other than the one that signed, even mid-rotation.
    from .signer import sign_as

    kid = signer.key_id
    header: dict[str, Any] = {
        "alg": getattr(signer, "algorithm", ALG_ED25519), "typ": typ, "kid": kid,
    }
    if extra_header:
        header.update(extra_header)

    signing_input = f"{_b64url_json(header)}.{_b64url_json(payload)}"
    signature, _ = await sign_as(signer, signing_input.encode("ascii"), kid)
    return f"{signing_input}.{b64url_encode(signature)}"


def decode_unverified_header(token: str) -> dict[str, Any]:
    """Read the header without verifying anything.

    The **only** legitimate use is looking up which key to verify with. Never read claims this
    way: nothing in the payload means anything until the signature has been checked.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedToken("compact JWS must have exactly three dot-separated parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
    except (ValueError, TypeError) as exc:
        raise MalformedToken(f"JWS header is not valid JSON: {exc}") from exc
    if not isinstance(header, dict):
        raise MalformedToken("JWS header must be a JSON object")
    return header


def verify_compact(
    token: str,
    key_resolver: Callable[[str], dict[str, Any] | None],
    *,
    expected_typ: str | None = CREDENTIAL_TYP,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a compact JWS and return ``(header, payload)``.

    ``key_resolver`` maps a ``kid`` to a JWK the caller already trusts — typically a cached JWKS
    entry. Returning ``None`` means "I do not trust this key", which surfaces as
    :class:`UnknownIssuer`.

    This function verifies the *signature* only. Time-based claims are checked separately by
    :func:`validate_time_claims`, because a caller sometimes needs to inspect an expired token
    (to render "your credential expired 4 minutes ago" rather than a blank denial).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedToken("compact JWS must have exactly three dot-separated parts")
    header_b64, payload_b64, signature_b64 = parts

    header = decode_unverified_header(token)

    # Resolve the algorithm from the registry. Covers alg=none, HS256 confusion, RS256 and
    # anything else, and does so before any key lookup or signature work.
    algorithm = by_jose_alg(header.get("alg"))

    if expected_typ is not None and header.get("typ") != expected_typ:
        raise MalformedToken(
            f"unexpected token type {header.get('typ')!r}; expected {expected_typ!r}"
        )

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise MalformedToken("JWS header is missing 'kid'")

    jwk = key_resolver(kid)
    if jwk is None:
        raise UnknownIssuer(f"no trusted key for kid {kid!r}", kid=kid)

    # The header's algorithm must match the key we actually trust for this kid. Without this
    # check, a header claiming ES256 against an Ed25519 trusted key (or the reverse) would be
    # resolved by whichever side the implementation happened to consult — the classic
    # algorithm-confusion bug, reintroduced by supporting two algorithms.
    key_algorithm = for_jwk(jwk)
    if key_algorithm.jose_alg != algorithm.jose_alg:
        raise UnsupportedAlgorithm(
            f"header declares {algorithm.jose_alg} but the trusted key for kid {kid!r} is "
            f"{key_algorithm.jose_alg}",
            alg=algorithm.jose_alg, key_alg=key_algorithm.jose_alg,
        )

    public_key = jwk_to_public_key(jwk)
    algorithm.verify(
        public_key,
        b64url_decode(signature_b64),
        f"{header_b64}.{payload_b64}".encode("ascii"),
    )

    try:
        payload = json.loads(b64url_decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise MalformedToken(f"JWS payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MalformedToken("JWS payload must be a JSON object")

    return header, payload


def validate_time_claims(
    payload: dict[str, Any],
    *,
    now: datetime | None = None,
    leeway: timedelta = DEFAULT_LEEWAY,
    require_exp: bool = True,
) -> None:
    """Validate ``exp`` and ``nbf`` with clock-skew tolerance.

    ``exp`` is mandatory by default. A credential without an expiry is a permanent credential, and
    this architecture's safety argument rests on credentials being short-lived: with a 15-minute
    TTL, a stolen credential has a bounded blast radius even if revocation fails completely.
    """
    moment = now or utcnow()

    exp = payload.get("exp")
    if exp is None:
        if require_exp:
            raise MalformedToken("credential has no 'exp' claim — non-expiring credentials are refused")
    else:
        expires_at = datetime.fromtimestamp(float(exp), tz=timezone.utc)
        if moment > expires_at + leeway:
            raise CredentialExpired(
                "credential has expired",
                expired_at=expires_at.isoformat(),
                seconds_ago=int((moment - expires_at).total_seconds()),
            )

    nbf = payload.get("nbf")
    if nbf is not None:
        not_before = datetime.fromtimestamp(float(nbf), tz=timezone.utc)
        if moment < not_before - leeway:
            raise CredentialNotYetValid(
                "credential is not yet valid", not_before=not_before.isoformat()
            )


def to_epoch(moment: datetime) -> int:
    """Convert an aware datetime to a JWT NumericDate."""
    if moment.tzinfo is None:
        raise ValueError("naive datetime rejected — attach an explicit timezone")
    return int(moment.timestamp())


def from_epoch(value: float) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)
