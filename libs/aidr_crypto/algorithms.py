"""Signature algorithm registry — Ed25519 and ECDSA P-256 behind one interface.

AIDR supports exactly two algorithms, and the reason there are two is compliance rather than
preference:

* **Ed25519** is the default. Keys and signatures are compact, there is no per-signature nonce to
  get wrong, and no curve-parameter ambiguity to exploit. Note that the *speed* advantage often
  claimed for Ed25519 does not necessarily survive contact with a real runtime: measured through
  these bindings the two algorithms are within noise of each other, because per-call overhead
  dominates the curve arithmetic. Run ``scripts/benchmark_algorithms.py`` on the target stack
  rather than assuming. The durable reasons to prefer Ed25519 are the misuse-resistance ones, not
  the throughput one.

* **ECDSA P-256 (ES256)** exists for FIPS-constrained deployments. FIPS 186-5 approved EdDSA in
  2023, but the CMVP-validated module inventory has not followed: most FIPS 140-2/3 validated
  HSMs, and HashiCorp Vault's FIPS-Inside builds, do not carry Ed25519 inside their validated
  cryptographic boundary. An operator who must present a validation certificate therefore needs
  P-256 today. See ``docs/04-compliance.md``.

Everything algorithm-specific lives here. The rest of the codebase asks this registry for an
:class:`Algorithm` and never branches on a curve name — which is what makes adding ML-DSA for
``aid:v2`` an addition to this file rather than a change everywhere.

**JOSE signature encoding.** Ed25519 signatures are the raw 64 bytes. ECDSA signatures are ``R‖S``
fixed-width (RFC 7515 §3.4), *not* the DER encoding that ``cryptography`` produces and consumes.
Converting between them is the single most common ES256 interop bug, so it is done once, here, and
the fixed-width form is what every caller sees.
"""

from __future__ import annotations

# --------------------------------------------------------------------------------------------
# base64url (duplicated from keys.py deliberately: this module must not import from it, because
# keys.py imports from here)
# --------------------------------------------------------------------------------------------
import base64
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from aidr_core.errors import InvalidKey, SignatureInvalid, UnsupportedAlgorithm


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise InvalidKey("base64url input must be a string")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:  # noqa: BLE001
        raise InvalidKey(f"invalid base64url encoding: {exc}") from exc


# --------------------------------------------------------------------------------------------
# Algorithm descriptor
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Algorithm:
    """One signature algorithm, with everything the rest of the system needs to use it."""

    name: str                   # AgentKey.alg, e.g. "Ed25519"
    jose_alg: str               # JWS "alg" header, e.g. "EdDSA"
    http_alg: str               # RFC 9421 "alg" parameter, e.g. "ed25519"
    vault_key_type: str         # Vault Transit key type
    signature_length: int       # fixed length of the JOSE-form signature, in bytes

    #: Approved by a current FIPS standard (FIPS 186-5 for both EdDSA and ECDSA).
    fips_approved: bool
    #: Widely present inside the validated boundary of shipping CMVP-certified modules. This is the
    #: field that actually decides whether an auditor accepts the deployment, and it is the one
    #: where Ed25519 and ECDSA differ today.
    fips_module_available: bool

    #: NIST SP 800-57 comparable security strength, in bits.
    security_strength: int

    _generate: Callable[[], Any]
    _public_to_jwk: Callable[[Any], dict]
    _jwk_to_public: Callable[[dict], Any]
    _sign: Callable[[Any, bytes], bytes]
    _verify: Callable[[Any, bytes, bytes], None]
    _private_to_jwk: Callable[[Any], dict]
    _jwk_to_private: Callable[[dict], Any]

    # -- operations ------------------------------------------------------------------------

    def generate(self) -> Any:
        return self._generate()

    def public_to_jwk(self, public_key: Any, *, kid: str | None = None,
                      use: str = "sig") -> dict[str, Any]:
        jwk = self._public_to_jwk(public_key)
        jwk["alg"] = self.jose_alg
        jwk["use"] = use
        if kid:
            jwk["kid"] = kid
        return jwk

    def jwk_to_public(self, jwk: dict[str, Any]) -> Any:
        if "d" in jwk:
            raise InvalidKey("a private key was supplied where a public key is required")
        return self._jwk_to_public(jwk)

    def private_to_jwk(self, private_key: Any) -> dict[str, Any]:
        return self._private_to_jwk(private_key)

    def jwk_to_private(self, jwk: dict[str, Any]) -> Any:
        return self._jwk_to_private(jwk)

    def sign(self, private_key: Any, data: bytes) -> bytes:
        """Sign, returning the JOSE-form signature (fixed width, never DER)."""
        return self._sign(private_key, data)

    def verify(self, public_key: Any, signature: bytes, data: bytes) -> None:
        """Verify, raising :class:`SignatureInvalid` on failure.

        Raises rather than returning a boolean so that ``verify(...)`` with the result dropped
        cannot silently become a pass — a bug that reads as correct in review and fails open in
        production.
        """
        if len(signature) != self.signature_length:
            raise SignatureInvalid(
                f"{self.name} signature must be {self.signature_length} bytes, "
                f"got {len(signature)}",
                algorithm=self.name,
            )
        self._verify(public_key, signature, data)

    #: RFC 7638 required JWK members for this key type, in the order the thumbprint uses.
    @property
    def thumbprint_members(self) -> tuple[str, ...]:
        return ("crv", "kty", "x") if self.name == "Ed25519" else ("crv", "kty", "x", "y")


# --------------------------------------------------------------------------------------------
# Ed25519
# --------------------------------------------------------------------------------------------

def _ed25519_generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _ed25519_public_to_jwk(public_key: Ed25519PublicKey) -> dict[str, Any]:
    raw = public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                  format=serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_encode(raw)}


def _ed25519_jwk_to_public(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP":
        raise UnsupportedAlgorithm(f"expected kty=OKP for Ed25519, got {jwk.get('kty')!r}")
    if jwk.get("crv") != "Ed25519":
        raise UnsupportedAlgorithm(f"expected crv=Ed25519, got {jwk.get('crv')!r}")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise InvalidKey("JWK is missing its 'x' coordinate")
    raw = _b64url_decode(x)
    if len(raw) != 32:
        raise InvalidKey(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise InvalidKey(f"invalid Ed25519 public key: {exc}") from exc


def _ed25519_private_to_jwk(private_key: Ed25519PrivateKey) -> dict[str, Any]:
    raw = private_key.private_bytes(encoding=serialization.Encoding.Raw,
                                    format=serialization.PrivateFormat.Raw,
                                    encryption_algorithm=serialization.NoEncryption())
    jwk = _ed25519_public_to_jwk(private_key.public_key())
    jwk.update({"alg": "EdDSA", "use": "sig", "d": _b64url_encode(raw)})
    return jwk


def _ed25519_jwk_to_private(jwk: dict[str, Any]) -> Ed25519PrivateKey:
    d = jwk.get("d")
    if not isinstance(d, str):
        raise InvalidKey("JWK is missing its 'd' parameter")
    raw = _b64url_decode(d)
    if len(raw) != 32:
        raise InvalidKey(f"Ed25519 private key must be 32 bytes, got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _ed25519_sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def _ed25519_verify(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> None:
    try:
        public_key.verify(signature, data)
    except InvalidSignature as exc:
        raise SignatureInvalid("signature verification failed") from exc


# --------------------------------------------------------------------------------------------
# ECDSA P-256 (ES256)
# --------------------------------------------------------------------------------------------

P256_COORDINATE_BYTES = 32


def _p256_generate() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _p256_public_to_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(numbers.x.to_bytes(P256_COORDINATE_BYTES, "big")),
        "y": _b64url_encode(numbers.y.to_bytes(P256_COORDINATE_BYTES, "big")),
    }


def _p256_jwk_to_public(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC":
        raise UnsupportedAlgorithm(f"expected kty=EC for ES256, got {jwk.get('kty')!r}")
    if jwk.get("crv") != "P-256":
        raise UnsupportedAlgorithm(f"expected crv=P-256, got {jwk.get('crv')!r}")

    x, y = jwk.get("x"), jwk.get("y")
    if not isinstance(x, str) or not isinstance(y, str):
        raise InvalidKey("EC JWK requires both 'x' and 'y' coordinates")

    x_bytes, y_bytes = _b64url_decode(x), _b64url_decode(y)
    # RFC 7518 §6.2.1.2 requires fixed-width coordinates. Accepting short ones would let the same
    # key be encoded several ways, which would give it several different thumbprints.
    if len(x_bytes) != P256_COORDINATE_BYTES or len(y_bytes) != P256_COORDINATE_BYTES:
        raise InvalidKey(
            f"P-256 coordinates must be exactly {P256_COORDINATE_BYTES} bytes each"
        )

    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError as exc:
        # Raised when the point is not on the curve — an invalid-curve attack attempt, or a
        # corrupted key. Either way it must never reach a verification call.
        raise InvalidKey(f"point is not on the P-256 curve: {exc}") from exc


def _p256_private_to_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    jwk = _p256_public_to_jwk(private_key.public_key())
    jwk.update({
        "alg": "ES256", "use": "sig",
        "d": _b64url_encode(
            private_key.private_numbers().private_value.to_bytes(P256_COORDINATE_BYTES, "big")),
    })
    return jwk


def _p256_jwk_to_private(jwk: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    d = jwk.get("d")
    if not isinstance(d, str):
        raise InvalidKey("JWK is missing its 'd' parameter")
    raw = _b64url_decode(d)
    if len(raw) != P256_COORDINATE_BYTES:
        raise InvalidKey(f"P-256 private key must be {P256_COORDINATE_BYTES} bytes")
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def _p256_sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign and convert DER to the fixed-width ``R‖S`` form JOSE requires."""
    der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(P256_COORDINATE_BYTES, "big")
            + s.to_bytes(P256_COORDINATE_BYTES, "big"))


def _p256_verify(public_key: ec.EllipticCurvePublicKey, signature: bytes, data: bytes) -> None:
    r = int.from_bytes(signature[:P256_COORDINATE_BYTES], "big")
    s = int.from_bytes(signature[P256_COORDINATE_BYTES:], "big")
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise SignatureInvalid("signature verification failed") from exc


# --------------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------------

ED25519 = Algorithm(
    name="Ed25519",
    jose_alg="EdDSA",
    http_alg="ed25519",
    vault_key_type="ed25519",
    signature_length=64,
    fips_approved=True,          # FIPS 186-5 (2023)
    fips_module_available=False,  # rarely inside a CMVP-validated boundary today
    security_strength=128,
    _generate=_ed25519_generate,
    _public_to_jwk=_ed25519_public_to_jwk,
    _jwk_to_public=_ed25519_jwk_to_public,
    _sign=_ed25519_sign,
    _verify=_ed25519_verify,
    _private_to_jwk=_ed25519_private_to_jwk,
    _jwk_to_private=_ed25519_jwk_to_private,
)

ES256 = Algorithm(
    name="ES256",
    jose_alg="ES256",
    http_alg="ecdsa-p256-sha256",
    vault_key_type="ecdsa-p256",
    signature_length=64,
    fips_approved=True,          # FIPS 186-4 and 186-5
    fips_module_available=True,   # universally validated
    security_strength=128,
    _generate=_p256_generate,
    _public_to_jwk=_p256_public_to_jwk,
    _jwk_to_public=_p256_jwk_to_public,
    _sign=_p256_sign,
    _verify=_p256_verify,
    _private_to_jwk=_p256_private_to_jwk,
    _jwk_to_private=_p256_jwk_to_private,
)

ALGORITHMS: dict[str, Algorithm] = {ED25519.name: ED25519, ES256.name: ES256}

_BY_JOSE = {a.jose_alg: a for a in ALGORITHMS.values()}
_BY_HTTP = {a.http_alg: a for a in ALGORITHMS.values()}
_BY_VAULT = {a.vault_key_type: a for a in ALGORITHMS.values()}


def by_name(name: str) -> Algorithm:
    algorithm = ALGORITHMS.get(name)
    if algorithm is None:
        raise UnsupportedAlgorithm(f"unknown algorithm {name!r}", algorithm=name)
    return algorithm


def by_jose_alg(alg: str) -> Algorithm:
    algorithm = _BY_JOSE.get(alg)
    if algorithm is None:
        # Covers "none", HS256 confusion, RS256 and everything else, before any key lookup.
        raise UnsupportedAlgorithm(f"unsupported or unsafe JWS algorithm {alg!r}", alg=alg)
    return algorithm


def by_http_alg(alg: str) -> Algorithm:
    algorithm = _BY_HTTP.get(alg)
    if algorithm is None:
        raise UnsupportedAlgorithm(f"unsupported signature algorithm {alg!r}", alg=alg)
    return algorithm


def by_vault_key_type(key_type: str) -> Algorithm:
    algorithm = _BY_VAULT.get(key_type)
    if algorithm is None:
        raise UnsupportedAlgorithm(f"unsupported Vault transit key type {key_type!r}")
    return algorithm


def for_jwk(jwk: dict[str, Any]) -> Algorithm:
    """Select the algorithm from a JWK's key type and curve.

    Derived from ``kty``/``crv`` rather than trusted from ``alg``: the ``alg`` member is a hint
    that an attacker controls, and honouring it over the actual key material is precisely the
    algorithm-confusion bug.
    """
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        return ED25519
    if kty == "EC" and crv == "P-256":
        return ES256
    raise UnsupportedAlgorithm(f"unsupported key type kty={kty!r} crv={crv!r}", kty=kty, crv=crv)


def jwk_thumbprint(jwk: dict[str, Any]) -> bytes:
    """RFC 7638 thumbprint, using the required members for the key's own type."""
    import json

    algorithm = for_jwk(jwk)
    try:
        required = {member: jwk[member] for member in algorithm.thumbprint_members}
    except KeyError as exc:
        raise InvalidKey(f"JWK is missing required member {exc.args[0]!r}") from exc
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).digest()
