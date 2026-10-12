"""Key handling: generation, JWK encoding, thumbprints, raw sign/verify.

Algorithm-specific behaviour lives in :mod:`aidr_crypto.algorithms`; this module is the ergonomic
surface over it. Two algorithms are supported — Ed25519 (default, fastest to verify) and ECDSA
P-256 (for FIPS-constrained deployments). See :mod:`aidr_crypto.fips` for why both exist.

**Private keys in this module belong to owner-side tooling and tests.** In production, agent
private keys live with the agent's owner and never reach us, and CA private keys live in an HSM
behind Vault. :func:`private_key_to_jwk` is named to be conspicuous in a diff precisely so that a
grep for it finds every place private key material is handled.
"""

from __future__ import annotations

import hmac
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aidr_core.errors import InvalidKey, UnsupportedAlgorithm

from .algorithms import (
    ED25519,
    ES256,
    Algorithm,
    _b64url_decode,
    _b64url_encode,
    by_jose_alg,
    by_name,
    for_jwk,
)
from .algorithms import jwk_thumbprint as _jwk_thumbprint

#: Retained for backwards compatibility: the JOSE algorithm name of the default algorithm.
ALG_ED25519 = ED25519.jose_alg          # "EdDSA"
CURVE_ED25519 = ED25519.name            # "Ed25519"
ALG_ES256 = ES256.jose_alg              # "ES256"

SUPPORTED_ALGORITHMS = frozenset({ED25519.jose_alg, ED25519.name, ES256.jose_alg, ES256.name})

DEFAULT_ALGORITHM = ED25519


# ----------------------------------------------------------------------------------------------
# base64url (RFC 7515 §2)
# ----------------------------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return _b64url_encode(data)


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url, rejecting anything outside the alphabet.

    Validation is not optional here: ``urlsafe_b64decode`` silently discards stray characters, so
    a token with injected junk would decode to something plausible instead of being rejected.
    """
    return _b64url_decode(text)


# ----------------------------------------------------------------------------------------------
# Algorithm resolution
# ----------------------------------------------------------------------------------------------

def resolve_algorithm(algorithm: Algorithm | str | None) -> Algorithm:
    if algorithm is None:
        return DEFAULT_ALGORITHM
    if isinstance(algorithm, Algorithm):
        return algorithm
    if algorithm in ("EdDSA", "ES256"):
        return by_jose_alg(algorithm)
    return by_name(algorithm)


def algorithm_for_key(key: Any) -> Algorithm:
    """Select the algorithm from the key object's own type.

    Derived from the key rather than from any accompanying metadata. Metadata is attacker-supplied
    on an inbound path; the key object is not.
    """
    if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey)):
        return ED25519
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve = key.curve
        if not isinstance(curve, ec.SECP256R1):
            raise UnsupportedAlgorithm(f"unsupported EC curve {curve.name!r}; expected secp256r1")
        return ES256
    raise UnsupportedAlgorithm(f"unsupported key type {type(key).__name__}")


# ----------------------------------------------------------------------------------------------
# Generation and encoding
# ----------------------------------------------------------------------------------------------

def generate_keypair(algorithm: Algorithm | str | None = None) -> tuple[Any, Any]:
    """Generate a keypair. Defaults to Ed25519.

    In production this runs **on the agent owner's machine**, not on ours. It lives in this
    library so owner tooling, the SDK and the tests share one implementation.
    """
    resolved = resolve_algorithm(algorithm)
    private_key = resolved.generate()
    return private_key, private_key.public_key()


def public_key_to_jwk(public_key: Any, *, kid: str | None = None, use: str = "sig") -> dict[str, Any]:
    return algorithm_for_key(public_key).public_to_jwk(public_key, kid=kid, use=use)


def jwk_to_public_key(jwk: dict[str, Any]) -> Any:
    """Decode a public JWK, validating every structural field.

    Each check corresponds to a real attack: a mismatched ``kty``/``crv`` is algorithm confusion, a
    present ``d`` means a private key arrived where a public one belongs, a wrong-length coordinate
    is malformed input some libraries will happily pad, and an off-curve EC point is an
    invalid-curve attack.
    """
    if not isinstance(jwk, dict):
        raise InvalidKey("JWK must be an object")
    return for_jwk(jwk).jwk_to_public(jwk)


def private_key_to_jwk(private_key: Any) -> dict[str, Any]:
    """Encode a private key as a JWK. **Owner-side tooling and tests only.**

    Nothing in the registry services may call this.
    """
    return algorithm_for_key(private_key).private_to_jwk(private_key)


def jwk_to_private_key(jwk: dict[str, Any]) -> Any:
    """Decode a private JWK. **Owner-side tooling and tests only.**"""
    if not isinstance(jwk, dict):
        raise InvalidKey("JWK must be an object")
    return for_jwk(jwk).jwk_to_private(jwk)


# ----------------------------------------------------------------------------------------------
# Thumbprints and key identifiers
# ----------------------------------------------------------------------------------------------

def jwk_thumbprint(jwk: dict[str, Any]) -> bytes:
    """RFC 7638 thumbprint: SHA-256 over the canonical required members for the key type.

    Extra members such as ``kid``, ``alg`` and ``use`` are excluded by the specification, which is
    what keeps the thumbprint stable while metadata changes around it.
    """
    return _jwk_thumbprint(jwk)


def derive_kid(jwk: dict[str, Any]) -> str:
    """Derive a key identifier from the key material itself.

    Deriving rather than assigning gives one useful property: a ``kid`` cannot be pointed at a
    different key without changing the ``kid``. An attacker who swaps the key under an existing
    identifier produces a mismatch any verifier can detect locally, with no registry lookup.
    """
    return "key_" + b64url_encode(jwk_thumbprint(jwk))[:22]


def verify_kid(jwk: dict[str, Any], kid: str) -> bool:
    """Check that a ``kid`` really is the thumbprint of the key it is attached to."""
    return hmac.compare_digest(derive_kid(jwk), kid)


# ----------------------------------------------------------------------------------------------
# Raw sign / verify
# ----------------------------------------------------------------------------------------------

def sign_raw(private_key: Any, data: bytes) -> bytes:
    """Sign, returning the JOSE-form signature (fixed width, never DER)."""
    return algorithm_for_key(private_key).sign(private_key, data)


def verify_raw(public_key: Any, signature: bytes, data: bytes) -> None:
    """Verify a signature, raising :class:`SignatureInvalid` on failure.

    Raises rather than returning a boolean on purpose: a boolean invites ``if verify(...)`` to be
    written as ``verify(...)`` with the result dropped — a bug that looks correct in review and
    fails open in production.
    """
    algorithm_for_key(public_key).verify(public_key, signature, data)
