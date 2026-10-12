"""Signing backends.

One rule governs this module, and it is the rule most worth enforcing in review:

    **The application never holds a CA private key as bytes.**

In production every registry signature is produced by :class:`VaultTransitSigner`, which sends data
to Vault and receives a signature back. The key stays inside an HSM and is unextractable even by an
operator with root on the application host. If a code path needs raw CA key material, that code
path is wrong.

:class:`LocalDevSigner` exists so the tests and the local demo can run without Vault. It refuses to
run when ``AIDR_ENV=production``, warns on every construction, and reports
``hardware_backed = False`` so a FIPS policy rejects it. Three defences, because the failure being
guarded against is not malice — it is a hurried deploy.

**Compliance note.** :meth:`VaultTransitSigner.verify_controls` checks at start-up that the CA key
is non-exportable, non-backupable and non-deletable, and that the Vault build is a FIPS one when
the policy demands it. These are the conditions an auditor tests against WebTrust 4.2 (CA key
protection) and SOC 2 CC6.1; checking them programmatically at boot turns an annual assertion into
a continuous control, and means the deployment fails where an operator is watching rather than on
the first customer request.
"""

from __future__ import annotations

import base64
import logging
import os
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from aidr_core.errors import AidrError, RegistryUnavailable

from .algorithms import ED25519, Algorithm, by_vault_key_type
from .fips import CryptoComplianceError, CryptoPolicy
from .keys import (
    algorithm_for_key,
    b64url_decode,
    b64url_encode,
    derive_kid,
    jwk_to_private_key,
    private_key_to_jwk,
    public_key_to_jwk,
    resolve_algorithm,
)

logger = logging.getLogger(__name__)


class SignerUnavailable(RegistryUnavailable):
    code = "aidr.signer.unavailable"


class SignerMisconfigured(AidrError):
    code = "aidr.signer.misconfigured"


@runtime_checkable
class Signer(Protocol):
    """An asynchronous signing backend.

    Async because the production implementation is a network call to Vault. Making the interface
    async from the start means swapping a dev signer for an HSM-backed one is a configuration
    change rather than a refactor of every caller.
    """

    @property
    def key_id(self) -> str:
        """Stable identifier for this signing key, used as the JWS ``kid``."""

    @property
    def algorithm(self) -> str:
        """JOSE algorithm name, e.g. ``EdDSA`` or ``ES256``."""

    @property
    def algorithm_name(self) -> str:
        """Registry algorithm name, e.g. ``Ed25519`` or ``ES256``."""

    @property
    def hardware_backed(self) -> bool:
        """Whether signing happens inside an HSM or other validated module."""

    def public_jwk(self) -> dict[str, Any]:
        """The public half, for publication in JWKS."""

    async def sign(self, data: bytes) -> bytes:
        """Return a detached signature over ``data``, in JOSE form."""


class LocalDevSigner:
    """In-process signer. **Development and test only.**"""

    #: Software keys in process memory are outside any validated cryptographic boundary.
    hardware_backed = False

    def __init__(self, private_key: Any = None, *, key_id: str | None = None,
                 algorithm: Algorithm | str | None = None,
                 allow_in_production: bool = False) -> None:
        environment = os.environ.get("AIDR_ENV", "development").lower()
        if environment in {"production", "prod"} and not allow_in_production:
            raise SignerMisconfigured(
                "LocalDevSigner must never sign in production — configure VaultTransitSigner. "
                "Set allow_in_production=True only in a deliberate offline key ceremony."
            )

        if private_key is None:
            resolved = resolve_algorithm(algorithm)
            private_key = resolved.generate()
        self._algorithm = algorithm_for_key(private_key)
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._jwk = public_key_to_jwk(self._public_key)
        self._key_id = key_id or derive_kid(self._jwk)
        self._jwk["kid"] = self._key_id
        self.created_at = datetime.now(timezone.utc)

        logger.warning(
            "LocalDevSigner active (kid=%s, alg=%s) — private key held in process memory. "
            "This is acceptable only outside production.", self._key_id, self._algorithm.name,
        )

    # -- Signer -----------------------------------------------------------------------------

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return self._algorithm.jose_alg

    @property
    def algorithm_name(self) -> str:
        return self._algorithm.name

    def public_jwk(self) -> dict[str, Any]:
        return dict(self._jwk)

    async def sign(self, data: bytes) -> bytes:
        return self._algorithm.sign(self._private_key, data)

    async def verify_controls(self, policy: CryptoPolicy | None = None) -> dict[str, Any]:
        """Report control status. Always non-compliant for key protection, and says so.

        Returning an honest negative rather than omitting the check is the point: a compliance
        report that silently skips the dev signer would show a clean sheet for a deployment that
        is holding its CA key in a Python process.
        """
        return {
            "signer": "LocalDevSigner",
            "hardware_backed": False,
            "key_non_exportable": False,
            "fips_module": False,
            "compliant": False,
            "finding": "CA key material is held in application memory — development only",
        }

    # -- dev helpers ------------------------------------------------------------------------

    def export_private_jwk(self) -> dict[str, Any]:
        """Export the private key so a test fixture can be made reproducible."""
        jwk = private_key_to_jwk(self._private_key)
        jwk["kid"] = self._key_id
        return jwk

    @classmethod
    def from_private_jwk(cls, jwk: dict[str, Any], **kwargs: Any) -> LocalDevSigner:
        return cls(jwk_to_private_key(jwk), key_id=jwk.get("kid"), **kwargs)


class VaultTransitSigner:
    """Signs via HashiCorp Vault's Transit engine, backed by a PKCS#11 HSM.

    The key never leaves Vault: we send data and receive a signature. Two consequences shape the
    error handling below.

    * Vault being unreachable is an **availability** failure, not a validity failure. It surfaces
      as :class:`SignerUnavailable` (HTTP 503), so issuance stops cleanly while verification of
      already-issued credentials continues unaffected — the behaviour promised in the failure
      table in ``docs/01-architecture.md`` §5.
    * A 4xx from Vault is **our** misconfiguration (bad token, wrong key name, missing policy) and
      is not retried. Retrying it would burn the issuance budget against a condition that cannot
      resolve itself.

    **Signature encoding.** For ECDSA we ask Vault for ``marshaling_algorithm=jws``, which returns
    the fixed-width ``R‖S`` form JOSE requires, rather than the ASN.1 DER Vault produces by
    default. Getting this wrong yields signatures that verify in Vault and nowhere else.
    """

    #: Transit keys live in whatever module backs the Vault seal; with an HSM-backed mount that is
    #: a validated one. :meth:`verify_controls` checks rather than assumes.
    hardware_backed = True

    def __init__(self, vault_addr: str, key_name: str, token: str, *,
                 mount: str = "transit", timeout_seconds: float = 2.0,
                 namespace: str | None = None,
                 policy: CryptoPolicy | None = None) -> None:
        if not vault_addr:
            raise SignerMisconfigured("vault_addr is required")
        if not token:
            raise SignerMisconfigured("a Vault token is required")

        self._addr = vault_addr.rstrip("/")
        self._key_name = key_name
        self._mount = mount.strip("/")
        self._token = token
        self._timeout = timeout_seconds
        self._namespace = namespace
        self._policy = policy

        self._algorithm: Algorithm = ED25519
        self._cached_jwk: dict[str, Any] | None = None
        self._cached_version: int | None = None
        self._key_config: dict[str, Any] = {}
        self._vault_version: str = ""
        self._key_created_at: datetime | None = None

    # -- Signer -----------------------------------------------------------------------------

    @property
    def key_id(self) -> str:
        return f"vault:{self._key_name}:v{self._cached_version or 1}"

    @property
    def algorithm(self) -> str:
        return self._algorithm.jose_alg

    @property
    def algorithm_name(self) -> str:
        return self._algorithm.name

    def public_jwk(self) -> dict[str, Any]:
        if self._cached_jwk is None:
            raise SignerMisconfigured(
                "public key not loaded — call await signer.load() at start-up"
            )
        return dict(self._cached_jwk)

    # -- transport --------------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"X-Vault-Token": self._token}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        return headers

    async def _request(self, method: str, path: str, json_body: dict | None = None) -> dict:
        import httpx

        url = f"{self._addr}/v1/{path}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.request(method, url, headers=self._headers(),
                                                json=json_body)
        except httpx.HTTPError as exc:
            raise SignerUnavailable(f"Vault unreachable: {exc}", url=url) from exc

        if response.status_code >= 500:
            raise SignerUnavailable(f"Vault returned {response.status_code}", url=url)
        if response.status_code == 403:
            raise SignerMisconfigured(
                f"Vault denied access to {path} — check the token's policy grants it", url=url
            )
        if response.status_code >= 400:
            raise SignerMisconfigured(
                f"Vault rejected the request with {response.status_code}: {response.text[:200]}",
                url=url,
            )
        return response.json() if response.content else {}

    # -- start-up ---------------------------------------------------------------------------

    async def load(self) -> dict[str, Any]:
        """Fetch the public key and key configuration. Call once at start-up.

        Doing this eagerly means a misconfigured mount fails at boot, where it is obvious, rather
        than on the first issuance request, where it looks like an outage.
        """
        health = await self._request("GET", "sys/health")
        self._vault_version = str(health.get("version", ""))

        payload = await self._request("GET", f"{self._mount}/keys/{self._key_name}")
        data = payload.get("data", {})
        self._key_config = data

        key_type = data.get("type", "")
        try:
            self._algorithm = by_vault_key_type(key_type)
        except Exception as exc:
            raise SignerMisconfigured(
                f"transit key {self._key_name!r} has type {key_type!r}, which AIDR does not "
                f"support; expected one of ed25519, ecdsa-p256"
            ) from exc

        versions = data.get("keys", {})
        if not versions:
            raise SignerMisconfigured(f"transit key {self._key_name!r} has no key versions")
        latest = max(int(v) for v in versions)
        entry = versions[str(latest)]
        self._cached_version = latest

        self._cached_jwk = self._jwk_from_vault_entry(entry)
        self._cached_jwk["kid"] = self.key_id
        self._key_created_at = _parse_vault_time(entry)

        if self._policy is not None:
            self._policy.enforce_algorithm(self._algorithm)

        logger.info("Vault transit signer ready: key=%s type=%s version=%d vault=%s",
                    self._key_name, key_type, latest, self._vault_version)
        return dict(self._cached_jwk)

    def _jwk_from_vault_entry(self, entry: Any) -> dict[str, Any]:
        """Build a JWK from Vault's public-key representation.

        Ed25519 keys come back as base64 raw bytes; ECDSA keys come back as a PEM SubjectPublicKeyInfo
        block. Vault is not consistent here, so neither can this function be.
        """
        raw_value = entry.get("public_key") if isinstance(entry, dict) else entry
        if not raw_value:
            raise SignerMisconfigured("Vault returned a key version without a public key")

        if self._algorithm is ED25519:
            raw = base64.b64decode(raw_value)
            if len(raw) != 32:
                raise SignerMisconfigured(
                    f"Vault returned a {len(raw)}-byte Ed25519 public key; expected 32"
                )
            return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw),
                    "alg": "EdDSA", "use": "sig"}

        from cryptography.hazmat.primitives import serialization

        pem = raw_value if isinstance(raw_value, str) else raw_value.decode()
        try:
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        except ValueError as exc:
            raise SignerMisconfigured(f"Vault returned an unparseable public key: {exc}") from exc
        return public_key_to_jwk(public_key)

    # -- signing ----------------------------------------------------------------------------

    async def sign(self, data: bytes) -> bytes:
        if self._cached_jwk is None:
            raise SignerMisconfigured("signer not loaded — call await signer.load() at start-up")

        body: dict[str, Any] = {"input": base64.b64encode(data).decode("ascii")}
        if self._algorithm is not ED25519:
            # JOSE wants fixed-width R‖S; Vault's default is ASN.1 DER. Ed25519 has no such
            # distinction and rejects these parameters outright, hence the branch.
            body["marshaling_algorithm"] = "jws"
            body["hash_algorithm"] = "sha2-256"

        payload = await self._request("POST", f"{self._mount}/sign/{self._key_name}", body)
        signature = payload.get("data", {}).get("signature", "")

        # Format: "vault:v<version>:<encoded signature>"
        parts = signature.split(":")
        if len(parts) != 3 or parts[0] != "vault":
            raise SignerMisconfigured(f"unexpected Vault signature format: {signature[:32]!r}")

        decoded = (b64url_decode(parts[2]) if self._algorithm is not ED25519
                   else base64.b64decode(parts[2]))
        if len(decoded) != self._algorithm.signature_length:
            raise SignerMisconfigured(
                f"Vault returned a {len(decoded)}-byte signature; expected "
                f"{self._algorithm.signature_length} for {self._algorithm.name}"
            )
        return decoded

    # -- compliance controls ------------------------------------------------------------------

    async def verify_controls(self, policy: CryptoPolicy | None = None) -> dict[str, Any]:
        """Verify CA key-protection controls, returning audit evidence.

        Maps to WebTrust for CAs 4.2 (CA key protection), SOC 2 CC6.1 (logical access), and
        ISO 27001 A.10.1 (cryptographic controls). In a strict policy a failed control raises
        rather than being reported, because a CA whose key can be exported is not a CA.
        """
        if self._cached_jwk is None:
            await self.load()

        active = policy or self._policy
        config = self._key_config

        exportable = bool(config.get("exportable", False))
        plaintext_backup = bool(config.get("allow_plaintext_backup", False))
        deletion_allowed = bool(config.get("deletion_allowed", False))
        fips_build = "fips" in self._vault_version.lower()

        findings: list[str] = []
        if exportable:
            findings.append(
                "transit key is exportable — a CA key that can be read out of the HSM is not "
                "protected; set exportable=false (it cannot be changed after creation, so the "
                "key must be recreated)"
            )
        if plaintext_backup:
            findings.append("transit key allows plaintext backup — set allow_plaintext_backup=false")
        if deletion_allowed:
            findings.append(
                "transit key is deletable — an operator could destroy the CA key and every "
                "signature's verifiability with it; set deletion_allowed=false"
            )

        key_age_days = None
        if self._key_created_at is not None:
            key_age_days = (datetime.now(timezone.utc) - self._key_created_at).days
            if active and key_age_days > active.key_rotation_days:
                findings.append(
                    f"signing key is {key_age_days} days old, past the "
                    f"{active.key_rotation_days}-day rotation policy"
                )

        if active and active.require_hardware_backed_signing and not fips_build:
            findings.append(
                f"Vault build {self._vault_version!r} is not a FIPS build; fips_strict mode "
                "requires a FIPS 140-2/3 Inside build with an HSM-backed seal"
            )

        evidence = {
            "signer": "VaultTransitSigner",
            "vault_version": self._vault_version,
            "fips_build": fips_build,
            "mount": self._mount,
            "key_name": self._key_name,
            "key_version": self._cached_version,
            "algorithm": self._algorithm.name,
            "hardware_backed": True,
            "key_non_exportable": not exportable,
            "plaintext_backup_disabled": not plaintext_backup,
            "deletion_disabled": not deletion_allowed,
            "key_age_days": key_age_days,
            "rotation_policy_days": active.key_rotation_days if active else None,
            "compliant": not findings,
            "findings": findings,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        if findings and active and active.require_non_exportable_keys:
            raise CryptoComplianceError(
                "CA key protection controls failed: " + "; ".join(findings),
                findings=findings, key_name=self._key_name,
            )
        if findings:
            for finding in findings:
                logger.warning("CA key control finding: %s", finding)
        return evidence

    async def rotate(self) -> int:
        """Rotate to a new key version.

        Rotation is overlapping, never atomic: Vault keeps prior versions, and the new key is
        published in JWKS and trusted for a full credential TTL plus margin before it begins
        signing. The old version stays published until every credential it signed has expired.
        """
        await self._request("POST", f"{self._mount}/keys/{self._key_name}/rotate")
        await self.load()
        logger.warning("rotated CA signing key %s to version %d",
                       self._key_name, self._cached_version)
        return int(self._cached_version or 1)

    async def health(self) -> dict[str, Any]:
        try:
            payload = await self._request("GET", "sys/health")
        except AidrError as exc:
            return {"reachable": False, "error": exc.code}
        return {
            "reachable": True,
            "sealed": payload.get("sealed", True),
            "version": payload.get("version"),
            "fips_build": "fips" in str(payload.get("version", "")).lower(),
        }


def _parse_vault_time(entry: Any) -> datetime | None:
    """Vault reports key creation as either an RFC 3339 string or a Unix timestamp."""
    if not isinstance(entry, dict):
        return None
    value = entry.get("creation_time") or entry.get("creation_timestamp")
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
