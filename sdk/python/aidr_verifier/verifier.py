"""The relying-party verifier: check an agent's identity without calling the registry.

This is the piece adoption actually depends on. If integrating AIDR is not close to trivial, no
amount of architecture elsewhere matters. The whole integration is::

    verifier = AgentVerifier(trust_store, policy=VerificationPolicy(min_assurance=1))
    result = verifier.verify(method=request.method, url=request.url, headers=request.headers)
    # result.aid, result.organization, result.assurance, result.capabilities

Verification order is cheapest-first, so a malformed or stale request is rejected before any
cryptography runs. That ordering is a deliberate DoS mitigation: signature verification is the
expensive step, and an attacker should not be able to force it by sending garbage.

The checks, in order:

1. the ``Agent-Credential`` header is present and is a well-formed JWS;
2. the credential was signed by a key in the locally cached JWKS (this is the registry's word);
3. the credential is inside its validity window, with clock-skew tolerance;
4. the issuer — and audience, when bound — are the expected ones;
5. the agent identifier is not revoked;
6. the request signature (RFC 9421) verifies against the key **inside the credential**, and covers
   the method, authority and path actually received;
7. the site's own policy — minimum assurance, required capabilities, standing.

Step 6 is what makes the credential non-transferable. The credential says "this identifier holds
this public key"; the signature proves the sender holds the matching private key, for this
request. Without step 6, a credential captured from any request would be reusable by anyone.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from aidr_core.errors import (
    AgentRevoked,
    AidrError,
    AssuranceTooLow,
    CapabilityDenied,
    CoveredComponentMismatch,
    MalformedToken,
    PolicyViolation,
    RegistryUnavailable,
    UnknownIssuer,
)
from aidr_crypto.jws import DEFAULT_LEEWAY, validate_time_claims, verify_compact
from aidr_crypto.keys import jwk_to_public_key
from aidr_crypto.signatures import (
    CREDENTIAL_HEADER,
    DEFAULT_MAX_AGE_SECONDS,
    REQUIRED_COMPONENTS,
    effective_request_uri,
    verify_request,
)
from aidr_crypto.web_bot_auth import jwk_thumbprint

from .trust import TrustStore

logger = logging.getLogger(__name__)

#: The oldest revocation data agents may be verified against: one 60 s refresh plus 600 s of grace
#: (11 minutes). The same limit in every AIDR verifier (sdk/testdata/vectors.json pins it).
MAX_REVOCATION_AGE_SECONDS = 660


@dataclass
class VerificationPolicy:
    """What this site requires of an agent. Every field is the site's decision, not ours."""

    #: Minimum composite assurance (AgAL): 0 none, 1 identified, 2 verified publisher,
    #: 3 accountable enterprise. AgAL is min(OAL, KAL), so this is a floor on the weaker axis.
    #: Checked against the ``agal`` claim only — never the legacy ``assurance`` claim, which
    #: carries OAL alone and would admit a strong operator running a weakly held key.
    min_assurance: int = 0

    #: Minimum **key** assurance (KAL), independent of AgAL.
    #:
    #: A site that cares specifically about key protection — "the key must be in hardware" —
    #: cannot express that through AgAL, because a high AgAL can be reached with a strong operator
    #: and a merely adequate key. KAL2 means attested non-exportability; KAL3 adds an attested
    #: runtime. Requiring KAL directly is how a payments endpoint says what it actually needs.
    min_kal: int = 0

    #: Refuse an attestation backed only by a third party's word rather than a verifiable chain
    #: (AIAF §3.3 evidence classes). Off by default: most sites care about the level, not the
    #: provenance of the evidence behind it.
    require_cryptographic_attestation: bool = False

    #: Capabilities the agent must carry for this endpoint.
    required_capabilities: Sequence[str] = ()

    #: Maximum age of the request signature.
    max_signature_age_seconds: int = DEFAULT_MAX_AGE_SECONDS

    #: Require a nonce and check it. Disabling this removes replay protection entirely.
    require_nonce: bool = True

    #: Expected credential issuer. Leave ``None`` only in testing.
    expected_issuer: str | None = None

    #: This site's origin. When a credential is audience-bound, it must match. ``None``: the
    #: origin of the URL being verified — the site being visited, as the Cloudflare Worker and the
    #: WordPress plugin do. (The request signature covers @authority, so that origin is the one
    #: the agent signed for.) Set it behind a proxy that changes the host.
    expected_audience: str | None = None

    #: Refuse agents with more than this many upheld abuse reports. ``None`` disables the check.
    max_upheld_abuse_reports: int | None = None

    #: What to do when revocation state cannot give a definitive answer — either the local state
    #: was never bootstrapped, or the bloom filter reported a possible hit with no exact set to
    #: resolve it.
    #:
    #: Defaults to **deny**. Soft-failing on unknown revocation is the mistake the web PKI spent
    #: two decades regretting: it makes revocation optional for anyone who can block a fetch. A
    #: site that would rather stay available supplies ``online_revocation_check``, or sets this to
    #: ``True`` deliberately and knowingly.
    allow_unknown_revocation: bool = False

    #: Authoritative online check, called only when local state is inconclusive — roughly 1 % of
    #: requests when running in bloom-filter mode, and never when running from exact deltas.
    online_revocation_check: Callable[[str], bool] | None = None

    #: Refuse agents (503, ``aidr.registry.unavailable``) when the newest revocation data held was
    #: signed by the registry longer ago than this: 60 s refresh + 600 s grace, as the Cloudflare
    #: Worker and the WordPress plugin enforce. Judged from the delta's signed ``iat`` (AIAF §6.3),
    #: so a feed replayed by an interceptor cannot pass for a fresh one. ``None`` disables it —
    #: a site then keeps admitting agents on revocation data of any age.
    max_revocation_age_seconds: int | None = MAX_REVOCATION_AGE_SECONDS

    #: Clock skew tolerance for credential validity.
    leeway: timedelta = DEFAULT_LEEWAY

    #: Components the request signature must cover.
    required_components: Sequence[str] = REQUIRED_COMPONENTS


@dataclass
class VerificationResult:
    """A verified agent identity, plus what the site needs to make its decision."""

    aid: str
    organization: str
    #: The composite level a site should act on: equal to ``agal``. (The credential's own legacy
    #: ``assurance`` claim is OAL only and is not surfaced here.)
    assurance: int

    #: AIAF assurance axes. ``agal`` is min(oal, kal); a credential without an ``agal`` claim
    #: predates the axes and is treated as AgAL 0 rather than guessed at from its OAL.
    agal: int = 0
    oal: int = 0
    kal: int = 0
    dal: int = 0

    #: Domains the operator has proven control of (AIAF §4.2). Trust decisions should key on
    #: (issuer, verified domain), never on the namespace string, which any registry can issue.
    org_domains: list[str] = field(default_factory=list)

    capabilities: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    key_id: str = ""
    credential_jti: str = ""
    credential_expires_at: datetime | None = None
    signature_created_at: datetime | None = None

    #: Self-asserted by the owner and **not verified by the registry**. Kept in its own attribute
    #: so no site can mistake it for a checked fact: the registry can prove who owns the agent, not
    #: what model it runs.
    declared: dict[str, Any] = field(default_factory=dict)

    #: Registry-internal standing: counts only, never who reported or what was said.
    standing: dict[str, Any] = field(default_factory=dict)

    #: Non-fatal observations — stale trust material, soft-failed revocation, and similar. Worth
    #: logging and alerting on; a site running permanently with warnings is not verifying as well
    #: as it thinks.
    warnings: list[str] = field(default_factory=list)

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def summary(self) -> str:
        return (f"{self.aid} (org={self.organization}, assurance={self.assurance}, "
                f"capabilities={','.join(self.capabilities) or 'none'})")


class AgentVerifier:
    """Verifies agent identity from HTTP request headers, entirely locally."""

    def __init__(
        self,
        trust_store: TrustStore,
        *,
        policy: VerificationPolicy | None = None,
        nonce_seen: Callable[[str], bool] | None = None,
    ) -> None:
        self.trust = trust_store
        self.policy = policy or VerificationPolicy()
        self.nonce_seen = nonce_seen
        if self.policy.expected_issuer is None and trust_store.expected_issuer:
            self.policy.expected_issuer = trust_store.expected_issuer

    # -- entry points ----------------------------------------------------------------------------

    def verify(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        now: datetime | None = None,
    ) -> VerificationResult:
        """Verify a request. Raises a :class:`VerificationError` subclass on any failure.

        Raises rather than returning a verdict object so a dropped result cannot be mistaken for a
        pass. Sites wanting a boolean use :meth:`try_verify`.
        """
        moment = now or datetime.now(timezone.utc)
        warnings: list[str] = []
        normalised = {k.lower(): v for k, v in headers.items()}

        # 1. credential present
        raw_credential = normalised.get(CREDENTIAL_HEADER.lower())
        if not raw_credential:
            raise MalformedToken(
                f"request carries no {CREDENTIAL_HEADER} header — the agent is unidentified"
            )
        if raw_credential.lower().startswith("bearer "):
            raw_credential = raw_credential[7:].strip()

        # 2. the registry's signature over the credential
        _, claims = verify_compact(raw_credential, self.trust.resolve_key)

        # 3. validity window
        validate_time_claims(claims, now=moment, leeway=self.policy.leeway)

        # 4. issuer and audience
        self._check_issuer_and_audience(claims, url)

        aid = claims.get("sub")
        if not isinstance(aid, str) or not aid:
            raise MalformedToken("credential has no subject")

        # 5. revocation: fresh enough to rely on, then the identifier itself
        self._check_revocation_age(moment)
        warnings.extend(self._check_revocation(aid))

        # 6. proof that the sender holds the credential's key, for THIS request
        confirmation = claims.get("cnf") or {}
        agent_jwk = confirmation.get("jwk")
        if not isinstance(agent_jwk, dict):
            raise MalformedToken("credential carries no key confirmation ('cnf.jwk')")
        agent_public_key = jwk_to_public_key(agent_jwk)

        verified = verify_request(
            method=method,
            url=url,
            headers=headers,
            public_key_resolver=lambda kid: agent_public_key,
            required_components=self.policy.required_components,
            max_age_seconds=self.policy.max_signature_age_seconds,
            now=moment,
            nonce_seen=self.nonce_seen if self.policy.require_nonce else None,
            # The signature's keyid must name the credential's own key: the identifier it was
            # issued for, or (a Web Bot Auth signature) the thumbprint of its cnf.jwk. Without
            # this, a valid credential for agent A could be paired with a signature made by agent
            # B's key, letting B act under A's identity. The key that verifies is cnf.jwk either way.
            expected_keyid=(aid, jwk_thumbprint(agent_jwk)),
        )

        # 7. the site's own policy
        # AgAL never falls back to the legacy `assurance` claim: that claim is OAL only, and
        # reading it as AgAL overstates any agent whose key assurance is below its operator's.
        # OAL may fall back to it, because OAL is exactly what it carries.
        agal = int(claims.get("agal", 0))
        result = VerificationResult(
            aid=aid,
            organization=str(claims.get("org", "")),
            assurance=agal,
            agal=agal,
            oal=int(claims.get("oal", claims.get("assurance", 0))),
            kal=int(claims.get("kal", 0)),
            dal=int(claims.get("dal", 0)),
            org_domains=list(claims.get("org_domains", [])),
            capabilities=list(claims.get("capabilities", [])),
            scopes=list(claims.get("scopes", [])),
            key_id=str(confirmation.get("kid", "")),
            credential_jti=str(claims.get("jti", "")),
            credential_expires_at=(
                datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc)
                if claims.get("exp") else None
            ),
            signature_created_at=verified.created,
            declared=dict(claims.get("declared", {})),
            standing=dict(claims.get("standing", {})),
            warnings=warnings,
        )
        self._apply_policy(result)

        if self.trust.key_set.is_stale():
            result.warnings.append("registry key set is stale — refresh JWKS")
        if self.trust.revocation.is_stale():
            result.warnings.append("revocation state is stale — refresh the delta feed")

        logger.debug("verified %s", result.summary())
        return result

    def try_verify(self, **kwargs: Any) -> tuple[VerificationResult | None, AidrError | None]:
        """Non-raising form: returns ``(result, None)`` or ``(None, error)``.

        Catches the whole :class:`AidrError` taxonomy, not just :class:`VerificationError`. A
        malformed credential and a revoked agent are different diagnoses but the same outcome for
        the caller — the request is not verifiable — and a "non-raising" helper that still raises
        on some inputs is worse than no helper at all.

        Inspect ``error.code`` to distinguish a denial (``aidr.verify.*``) from an inability to
        decide (``aidr.registry.unavailable``); the correct response to those differs, and only
        the site can choose it.
        """
        try:
            return self.verify(**kwargs), None
        except AidrError as exc:
            return None, exc

    def verify_from_asgi(self, scope: Mapping[str, Any], headers: Mapping[str, str], *,
                         public_origin: str | Sequence[str] | None = None,
                         **kwargs: Any) -> VerificationResult:
        """Convenience wrapper that reconstructs the effective request URI from an ASGI scope.

        The URI is built from this site's origin (``public_origin``, or ``AIDR_PUBLIC_ORIGIN``) —
        never from anything inside the signature, and not from the client's Host header except on
        localhost (``origin.py``).
        """
        path = scope.get("path", "/")
        query = scope.get("query_string", b"")
        if isinstance(query, bytes):
            query = query.decode("latin-1")
        if query:
            path = f"{path}?{query}"

        from .origin import origin_resolver

        host = headers.get("host") or headers.get("Host") or ""
        origin = urlsplit(origin_resolver(public_origin, scheme=scope.get("scheme", "https"))(host))
        return self.verify(
            method=scope.get("method", "GET"),
            url=effective_request_uri(origin.scheme, origin.netloc, path),
            headers=headers,
            **kwargs,
        )

    # -- internals -------------------------------------------------------------------------------

    def _check_issuer_and_audience(self, claims: Mapping[str, Any], url: str) -> None:
        expected_issuer = self.policy.expected_issuer
        if expected_issuer and claims.get("iss") != expected_issuer:
            raise UnknownIssuer(
                f"credential issued by {claims.get('iss')!r}, expected {expected_issuer!r}",
                issuer=claims.get("iss"),
            )

        audience = claims.get("aud")
        if audience is not None:
            # An audience-bound credential is valid only at the named site. Ignoring the claim
            # would silently undo the binding the issuer deliberately applied.
            expected = self.policy.expected_audience or request_origin(url)
            allowed = audience if isinstance(audience, list) else [audience]
            if expected not in allowed:
                raise PolicyViolation(
                    f"credential is bound to {audience!r}, not to {expected!r}",
                    audience=audience, expected=expected,
                )

    def _check_revocation_age(self, now: datetime) -> None:
        limit = self.policy.max_revocation_age_seconds
        issued = self.trust.revocation.issued_at
        if limit is None or issued is None:
            return
        age = (now - issued).total_seconds()
        if age > limit:
            raise RegistryUnavailable(
                f"revocation data is {int(age)} s old (limit {limit} s): agents are refused until "
                "it is refreshed", age_seconds=int(age), limit_seconds=limit)

    def _check_revocation(self, aid: str) -> list[str]:
        warnings: list[str] = []
        revoked, definitive = self.trust.revocation.contains(aid)

        if revoked and definitive:
            raise AgentRevoked("agent identity has been revoked", aid=aid)

        if definitive:
            return warnings

        # Inconclusive: either a bloom hit with no exact set, or state never bootstrapped.
        check = self.policy.online_revocation_check
        if check is not None:
            try:
                if check(aid):
                    raise AgentRevoked("agent identity has been revoked", aid=aid)
                return warnings
            except AgentRevoked:
                raise
            except Exception as exc:  # noqa: BLE001 - the callback is site-supplied
                if not self.policy.allow_unknown_revocation:
                    raise RegistryUnavailable(
                        f"online revocation check failed and the policy is fail-closed: {exc}",
                        aid=aid,
                    ) from exc
                warnings.append(f"online revocation check failed: {exc}")
                return warnings

        if not self.policy.allow_unknown_revocation:
            raise RegistryUnavailable(
                "revocation state is inconclusive for this identifier and no online check is "
                "configured; policy is fail-closed",
                aid=aid, revocation_exact=self.trust.revocation.exact,
            )

        warnings.append("revocation status unverified — local state is not authoritative")
        return warnings

    def _apply_policy(self, result: VerificationResult) -> None:
        if result.agal < self.policy.min_assurance:
            raise AssuranceTooLow(
                f"agent assurance AgAL{result.agal} is below the required "
                f"AgAL{self.policy.min_assurance}",
                aid=result.aid, agal=result.agal, oal=result.oal, kal=result.kal,
                required=self.policy.min_assurance,
            )

        if result.kal < self.policy.min_kal:
            raise AssuranceTooLow(
                f"agent key assurance KAL{result.kal} is below the required "
                f"KAL{self.policy.min_kal} — this endpoint requires a hardware-protected key",
                aid=result.aid, kal=result.kal, required_kal=self.policy.min_kal,
            )

        missing = [c for c in self.policy.required_capabilities
                   if c not in result.capabilities]
        if missing:
            raise CapabilityDenied(
                f"agent lacks required capabilities: {', '.join(missing)}",
                aid=result.aid, missing=missing, granted=result.capabilities,
            )

        limit = self.policy.max_upheld_abuse_reports
        if limit is not None:
            upheld = int(result.standing.get("abuse_reports_upheld", 0))
            if upheld > limit:
                raise PolicyViolation(
                    f"agent has {upheld} upheld abuse reports, above this site's limit of {limit}",
                    aid=result.aid, upheld=upheld, limit=limit,
                )


__all__ = [
    "AgentVerifier",
    "VerificationPolicy",
    "VerificationResult",
    "CoveredComponentMismatch",
]


def request_origin(url: str) -> str:
    """``https://Shop.Example:443/a?b`` → ``https://shop.example``: scheme, lower-cased host, and a
    port only when it is not the scheme's default — the form credentials are bound to."""
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    default = {"https": 443, "http": 80}.get(parts.scheme)
    port = f":{parts.port}" if parts.port and parts.port != default else ""
    return f"{parts.scheme}://{host}{port}"
