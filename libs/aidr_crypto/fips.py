"""Cryptographic policy enforcement, including FIPS-strict mode.

A word on what this module can and cannot deliver, because the distinction is the whole reason it
exists as code rather than as a paragraph in a policy document:

**FIPS 140-2/3 validates modules, not applications.** No amount of Python makes a deployment
FIPS-validated. Validation attaches to the cryptographic module performing the operations — the
HSM, or the certified library inside Vault. What this module does is narrower and still valuable:
it *enforces the conditions under which a validated module is actually being used*, and refuses to
start when they are not met. That is the control an auditor tests, and it is the control that
stops a hurried deploy from quietly signing with an in-process key.

The three modes:

* ``permissive`` — the default. Ed25519 preferred; anything in the registry is allowed.
* ``fips_transition`` — FIPS-approved algorithms only (FIPS 186-5, so Ed25519 still qualifies).
  For operators who need the approved-algorithm property but not a validation certificate.
* ``fips_strict`` — approved algorithms that are also commonly present inside shipping CMVP
  validated boundaries. In practice this means **ECDSA P-256 only**, and it additionally requires
  an HSM-backed signer. This is the mode to run when an auditor will ask for a certificate number.

The cost of ``fips_strict`` is usually assumed to be verification throughput, since Ed25519 is the
faster curve in principle. Measure before believing it: through high-level bindings the per-call
overhead dominates the curve arithmetic and the two can land within noise of each other.
``scripts/benchmark_algorithms.py`` measures the actual ratio on the target runtime. The costs of
strict mode that are *not* in doubt are operational: an HSM-backed Vault mount, a FIPS build, and
key ceremonies.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aidr_core.errors import AidrError

from .algorithms import ALGORITHMS, Algorithm, by_name

logger = logging.getLogger(__name__)


class CryptoComplianceError(AidrError):
    """Raised when a cryptographic operation would violate the configured policy."""

    code = "aidr.crypto.policy_violation"
    http_status = 500


class CryptoMode(str, Enum):
    PERMISSIVE = "permissive"
    FIPS_TRANSITION = "fips_transition"
    FIPS_STRICT = "fips_strict"


@dataclass(frozen=True)
class CryptoPolicy:
    """The cryptographic rules a deployment operates under."""

    mode: CryptoMode = CryptoMode.PERMISSIVE

    #: Minimum comparable security strength in bits (NIST SP 800-57 Part 1 Rev. 5). 112 is the
    #: floor for use beyond 2030; 128 is what both supported algorithms provide.
    min_security_strength: int = 112

    #: Require signing to happen inside an HSM or a remote validated module. In FIPS-strict mode
    #: an in-process software key is not merely discouraged — it takes the operation outside the
    #: validated boundary, which is the thing being certified.
    require_hardware_backed_signing: bool = False

    #: Require that the CA key be non-exportable at the key-management layer. WebTrust
    #: 4.2 (CA key protection) and SOC 2 CC6.1: the key must be usable and unextractable, and the
    #: system must be able to demonstrate it rather than assert it.
    require_non_exportable_keys: bool = False

    #: Maximum age of a CA signing key before rotation is required.
    key_rotation_days: int = 90

    #: Algorithms explicitly permitted. Empty means "derive from the mode".
    allowed_algorithms: frozenset[str] = field(default_factory=frozenset)

    # -- derived rules ---------------------------------------------------------------------

    def permitted_algorithms(self) -> frozenset[str]:
        if self.allowed_algorithms:
            return self.allowed_algorithms
        if self.mode is CryptoMode.FIPS_STRICT:
            return frozenset(
                name for name, alg in ALGORITHMS.items()
                if alg.fips_approved and alg.fips_module_available
                and alg.security_strength >= self.min_security_strength
            )
        if self.mode is CryptoMode.FIPS_TRANSITION:
            return frozenset(
                name for name, alg in ALGORITHMS.items()
                if alg.fips_approved and alg.security_strength >= self.min_security_strength
            )
        return frozenset(
            name for name, alg in ALGORITHMS.items()
            if alg.security_strength >= self.min_security_strength
        )

    def preferred_algorithm(self) -> Algorithm:
        """The algorithm to use when the caller expresses no preference."""
        permitted = self.permitted_algorithms()
        for candidate in ("Ed25519", "ES256"):      # fastest first, subject to policy
            if candidate in permitted:
                return by_name(candidate)
        raise CryptoComplianceError(
            "no algorithm satisfies the configured crypto policy", mode=self.mode.value,
            min_security_strength=self.min_security_strength,
        )

    # -- enforcement -----------------------------------------------------------------------

    def enforce_algorithm(self, algorithm: Algorithm | str) -> Algorithm:
        """Check an algorithm against the policy, returning it or raising."""
        resolved = algorithm if isinstance(algorithm, Algorithm) else by_name(algorithm)
        permitted = self.permitted_algorithms()

        if resolved.name not in permitted:
            detail = (
                "not approved under a current FIPS standard"
                if not resolved.fips_approved else
                "approved by FIPS 186-5 but rarely inside a CMVP-validated module boundary, "
                "which fips_strict requires"
            )
            raise CryptoComplianceError(
                f"algorithm {resolved.name} is not permitted in {self.mode.value} mode: {detail}",
                algorithm=resolved.name, mode=self.mode.value,
                permitted=sorted(permitted),
            )

        if resolved.security_strength < self.min_security_strength:
            raise CryptoComplianceError(
                f"{resolved.name} provides {resolved.security_strength}-bit security, "
                f"below the required {self.min_security_strength}",
                algorithm=resolved.name,
            )
        return resolved

    def enforce_signer(self, signer: Any) -> None:
        """Check that a signing backend satisfies the policy.

        Called at start-up, not at first signature. A deployment that cannot sign compliantly must
        fail where an operator is watching, not on the first customer request.
        """
        hardware_backed = bool(getattr(signer, "hardware_backed", False))

        if self.require_hardware_backed_signing and not hardware_backed:
            raise CryptoComplianceError(
                f"{type(signer).__name__} is not hardware-backed, which {self.mode.value} mode "
                "requires — configure VaultTransitSigner against an HSM-backed Transit mount",
                signer=type(signer).__name__, mode=self.mode.value,
            )

        declared = getattr(signer, "algorithm_name", None)
        if declared:
            self.enforce_algorithm(declared)

    # -- evidence --------------------------------------------------------------------------

    def compliance_report(self) -> dict[str, Any]:
        """Machine-readable statement of the active policy.

        Exported by every service's ``/health/compliance`` endpoint so that an auditor collecting
        SOC 2 or ISO 27001 evidence can observe the running configuration rather than read an
        assertion about it. Evidence that must be gathered by hand is evidence that goes stale.
        """
        permitted = sorted(self.permitted_algorithms())
        return {
            "mode": self.mode.value,
            "permitted_algorithms": permitted,
            "preferred_algorithm": self.preferred_algorithm().name,
            "min_security_strength_bits": self.min_security_strength,
            "hardware_backed_signing_required": self.require_hardware_backed_signing,
            "non_exportable_keys_required": self.require_non_exportable_keys,
            "key_rotation_days": self.key_rotation_days,
            "algorithm_detail": {
                name: {
                    "fips_approved": ALGORITHMS[name].fips_approved,
                    "commonly_in_validated_modules": ALGORITHMS[name].fips_module_available,
                    "security_strength_bits": ALGORITHMS[name].security_strength,
                }
                for name in ALGORITHMS
            },
            "caveat": (
                "FIPS 140-2/3 validation attaches to the cryptographic module, not to this "
                "application. This report states the policy the application enforces; the "
                "validation certificate belongs to the HSM or Vault build in use."
            ),
        }

    # -- construction ----------------------------------------------------------------------

    @classmethod
    def from_environment(cls) -> CryptoPolicy:
        mode = CryptoMode(os.environ.get("AIDR_CRYPTO_MODE", CryptoMode.PERMISSIVE.value).lower())
        strict = mode is CryptoMode.FIPS_STRICT
        policy = cls(
            mode=mode,
            min_security_strength=int(os.environ.get("AIDR_MIN_SECURITY_STRENGTH", "112")),
            require_hardware_backed_signing=_flag("AIDR_REQUIRE_HSM", default=strict),
            require_non_exportable_keys=_flag("AIDR_REQUIRE_NON_EXPORTABLE_KEYS", default=strict),
            key_rotation_days=int(os.environ.get("AIDR_KEY_ROTATION_DAYS", "90")),
        )
        if strict:
            logger.info("crypto policy: FIPS-STRICT — permitted algorithms: %s",
                        ", ".join(sorted(policy.permitted_algorithms())))
        return policy

    @classmethod
    def fips_strict(cls) -> CryptoPolicy:
        return cls(
            mode=CryptoMode.FIPS_STRICT,
            min_security_strength=128,
            require_hardware_backed_signing=True,
            require_non_exportable_keys=True,
        )


def _flag(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


#: The policy used when a caller supplies none. Permissive, because most deployments are not
#: FIPS-constrained and should not pay P-256 verification cost for a certificate they will never
#: be asked to produce.
DEFAULT_POLICY = CryptoPolicy()


def describe_fips_position() -> str:
    """Plain-language summary for a compliance questionnaire.

    Kept in code, next to the enforcement it describes, so the two cannot drift apart — which is
    the usual fate of a compliance claim maintained in a separate document.
    """
    return (
        "AIDR performs no cryptography in application code beyond encoding: all CA signing is "
        "delegated to HashiCorp Vault's Transit engine, backed by a PKCS#11 HSM, and the "
        "validated module is that HSM. In fips_strict mode the application enforces ECDSA P-256 "
        "(FIPS 186-4/5), refuses any signer that is not hardware-backed, and verifies at start-up "
        "that CA keys are non-exportable and non-deletable. Ed25519 is FIPS 186-5 approved but is "
        "not yet commonly inside CMVP-validated module boundaries, so fips_strict excludes it; "
        "deployments that need the approved-algorithm property without a validation certificate "
        "should use fips_transition, which permits it."
    )
