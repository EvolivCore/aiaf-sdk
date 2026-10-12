"""Proof-of-possession and domain-control challenges.

Before an identifier is minted, the owner must prove they actually hold the private key matching
the public key they submitted. Without this step, anyone could register a key they do not control
and then *deny* that requests signed with it were theirs — or, worse, register someone else's
published public key and claim their traffic.

The signed message is domain-separated::

    aiaf-pop-v1:<challenge_id>:<nonce>:<subject>

(AIAF §5.3.) Until 2026 the prefix was ``aidr-pop-v1``, and desktop 0.1.0 signs nothing else. A
challenge therefore records the prefix it was issued with, and is verified against that one only:
the registry issues the legacy prefix during a transition window, and only to clients that do not
ask for the current one (services/registry_api/app.py).

The prefix matters more than it looks. The same Ed25519 key may be used by its owner for other
protocols, and a signature is just a signature — without a distinguishing prefix, a signature
produced for some unrelated purpose could be replayed here as proof of possession. Binding the
protocol name, the challenge, and the subject into the signed bytes means a signature made for
this purpose is usable only for this purpose, once.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any

from aidr_core.errors import ChallengeAlreadyUsed, ChallengeExpired, SignatureInvalid
from aidr_core.identifier import new_record_id
from aidr_core.models import Challenge, ChallengeType
from aidr_core.serde import utcnow

from .keys import b64url_decode, b64url_encode, jwk_to_public_key, sign_raw, verify_raw

POP_CONTEXT = "aiaf-pop-v1"
#: Issued only during the transition window; never the default.
LEGACY_POP_CONTEXT = "aidr-pop-v1"
POP_CONTEXTS = (POP_CONTEXT, LEGACY_POP_CONTEXT)
DOMAIN_CONTEXT = "aiaf-domain-v1"

#: Challenges are short-lived and single-use. Fifteen minutes is enough for a human to complete a
#: registration flow and short enough that an intercepted challenge is worthless by the time it
#: could be used.
DEFAULT_CHALLENGE_TTL = timedelta(minutes=15)

#: DNS propagation is slow and unpredictable, so domain-control challenges get far longer.
DOMAIN_CHALLENGE_TTL = timedelta(hours=24)

NONCE_BYTES = 32


def build_pop_message(challenge_id: str, nonce: str, subject: str, *,
                      context: str = POP_CONTEXT) -> bytes:
    """The exact bytes an owner signs to prove key possession."""
    if context not in POP_CONTEXTS:
        raise ValueError(f"not a proof-of-possession prefix: {context!r}")
    return f"{context}:{challenge_id}:{nonce}:{subject}".encode()


def pop_context_of(challenge: Challenge) -> str:
    """The prefix a challenge was issued with. Challenges stored before the rename carry none,
    and were issued with the legacy prefix."""
    return challenge.context.get("pop_context", LEGACY_POP_CONTEXT)


def pop_message_for(challenge: Challenge) -> str:
    """What the owner must sign for this challenge — the registry's ``sign_this``."""
    return build_pop_message(challenge.id, challenge.nonce, challenge.subject,
                             context=pop_context_of(challenge)).decode()


def build_domain_message(challenge_id: str, nonce: str, fqdn: str) -> str:
    """The DNS TXT record value that proves control of ``fqdn``."""
    return f"{DOMAIN_CONTEXT}:{challenge_id}:{nonce}:{fqdn.lower()}"


def create_challenge(
    subject: str,
    *,
    challenge_type: ChallengeType = ChallengeType.PROOF_OF_POSSESSION,
    ttl: timedelta | None = None,
    context: dict[str, Any] | None = None,
    pop_context: str = POP_CONTEXT,
) -> Challenge:
    """Mint a single-use challenge.

    A proof-of-possession challenge records ``pop_context``, the prefix its response must carry.

    ``secrets.token_bytes`` rather than ``random``: this nonce is a security parameter, and a
    predictable one would let an attacker precompute a response before ever being challenged.
    """
    lifetime = ttl or (
        DOMAIN_CHALLENGE_TTL if challenge_type == ChallengeType.DOMAIN_CONTROL
        else DEFAULT_CHALLENGE_TTL
    )
    context = dict(context or {})
    if challenge_type == ChallengeType.PROOF_OF_POSSESSION:
        if pop_context not in POP_CONTEXTS:
            raise ValueError(f"not a proof-of-possession prefix: {pop_context!r}")
        context["pop_context"] = pop_context
    now = utcnow()
    return Challenge(
        id=new_record_id("chl"),
        type=challenge_type,
        nonce=b64url_encode(secrets.token_bytes(NONCE_BYTES)),
        subject=subject,
        created_at=now,
        expires_at=now + lifetime,
        context=context,
    )


def verify_proof_of_possession(challenge: Challenge, signature: str,
                               public_key_jwk: dict[str, Any], *,
                               check_state: bool = True) -> None:
    """Verify a proof-of-possession response.

    Raises on failure and returns ``None`` on success — never a boolean, so a caller cannot
    accidentally treat a dropped result as a pass.

    State is checked before cryptography: an expired or already-consumed challenge is rejected
    without spending a verification, and the caller learns *why* it failed rather than just that
    it did.

    ``check_state=False`` is for the one caller that has already claimed the challenge atomically
    at the storage layer (:meth:`ChallengeRepository.claim`). That claim marks the challenge
    consumed, so re-checking here would reject the very redemption it just authorised.
    """
    if check_state:
        if challenge.is_consumed():
            raise ChallengeAlreadyUsed(
                "challenge has already been used", challenge_id=challenge.id
            )
        if challenge.is_expired():
            raise ChallengeExpired(
                "challenge has expired; request a new one", challenge_id=challenge.id
            )

    # Only the prefix this challenge was issued with: a signature over the other one is refused.
    message = pop_message_for(challenge).encode()
    public_key = jwk_to_public_key(public_key_jwk)

    try:
        verify_raw(public_key, b64url_decode(signature), message)
    except SignatureInvalid as exc:
        raise SignatureInvalid(
            "proof of possession failed — the signature does not match the submitted public key",
            challenge_id=challenge.id,
        ) from exc


def sign_challenge(challenge: Challenge, private_key: Any) -> str:
    """Owner-side helper: sign a challenge and return the base64url response.

    Lives here so the owner tooling, the SDK and the tests share one implementation of the exact
    message format. In production this runs on the owner's machine, never on ours.
    """
    message = pop_message_for(challenge).encode()
    # Routed through the registry rather than calling private_key.sign(): an EC key's own
    # sign() requires a hash argument and returns DER, and neither is what JOSE accepts.
    return b64url_encode(sign_raw(private_key, message))
