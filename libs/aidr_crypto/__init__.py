"""AIDR cryptography: Ed25519 keys, JWS credentials, RFC 9421 signatures, Merkle ledger proofs.

Depends only on ``cryptography`` and ``aidr_core``. ``httpx`` is imported lazily inside
:class:`~aidr_crypto.signer.VaultTransitSigner`, so a relying party that only verifies never pays
for a dependency it does not use.
"""

from .algorithms import (
    ALGORITHMS,
    ED25519,
    ES256,
    Algorithm,
    by_http_alg,
    by_jose_alg,
    by_name,
    for_jwk,
)
from .challenge import (
    LEGACY_POP_CONTEXT,
    POP_CONTEXT,
    POP_CONTEXTS,
    build_domain_message,
    build_pop_message,
    create_challenge,
    pop_context_of,
    pop_message_for,
    sign_challenge,
    verify_proof_of_possession,
)
from .fips import (
    DEFAULT_POLICY,
    CryptoComplianceError,
    CryptoMode,
    CryptoPolicy,
    describe_fips_position,
)
from .jws import (
    CERTIFICATE_TYP,
    CREDENTIAL_TYP,
    DEFAULT_LEEWAY,
    decode_unverified_header,
    from_epoch,
    sign_compact,
    to_epoch,
    validate_time_claims,
    verify_compact,
)
from .keys import (
    ALG_ED25519,
    ALG_ES256,
    CURVE_ED25519,
    algorithm_for_key,
    b64url_decode,
    b64url_encode,
    derive_kid,
    generate_keypair,
    jwk_thumbprint,
    jwk_to_private_key,
    jwk_to_public_key,
    private_key_to_jwk,
    public_key_to_jwk,
    resolve_algorithm,
    sign_raw,
    verify_kid,
    verify_raw,
)
from .merkle import (
    GENESIS_HASH,
    HashChain,
    assert_consistency,
    canonical_json,
    compute_entry_hash,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from .signatures import (
    CREDENTIAL_HEADER,
    DEFAULT_MAX_AGE_SECONDS,
    REQUIRED_COMPONENTS,
    SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER,
    RequestContext,
    VerifiedSignature,
    build_signature_base,
    effective_request_uri,
    generate_nonce,
    parse_signature_header,
    parse_signature_input,
    sign_request,
    verify_request,
)
from .signer import (
    LocalDevSigner,
    Signer,
    SignerMisconfigured,
    SignerUnavailable,
    VaultTransitSigner,
)

__all__ = [name for name in dir() if not name.startswith("_")]
