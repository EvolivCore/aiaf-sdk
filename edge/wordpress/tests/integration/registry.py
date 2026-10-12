"""A local AIDR registry for the WordPress integration test, built from the real services.

The same CertificateAuthority and RevocationService the registry runs, in memory, served over TLS
with a certificate generated at startup. Writes, for the other containers:

    /shared/registry-ca.pem   the TLS certificate (WordPress trusts it via AIDR_REGISTRY_CA_FILE)
    /shared/agent-key.json    the agent's private key, in the format scripts/staging_agent.py uses
    /shared/aid.txt           the agent's identifier

Test-only endpoints: POST /test/credential issues a fresh credential for the agent, POST
/test/revoke revokes it. Everything else is the registry's public surface.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import sys
from pathlib import Path

REPO = Path("/repo")
for path in (REPO, REPO / "libs", REPO / "sdk/python"):
    sys.path.insert(0, str(path))

import uvicorn  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from services.audit_ledger.ledger import AuditLedger, system_actor  # noqa: E402
from services.issuance.ca import CertificateAuthority  # noqa: E402
from services.registry_api.service import RegistryService  # noqa: E402
from services.revocation.service import RevocationService  # noqa: E402

from aidr_core.models import AgentProfile, OrgTier, OwnerRole, VerificationLevel  # noqa: E402
from aidr_crypto import LocalDevSigner, generate_keypair, public_key_to_jwk  # noqa: E402
from aidr_crypto.challenge import sign_challenge  # noqa: E402
from aidr_crypto.keys import private_key_to_jwk  # noqa: E402
from aidr_db import InMemoryStore, Repositories  # noqa: E402

ISSUER = "https://registry:8443"
SHARED = Path("/shared")


def tls_certificate() -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "registry")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("registry")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = SHARED / "registry-ca.pem", Path("/tmp/registry.key")
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


async def build():
    repos = Repositories(InMemoryStore())
    signer = LocalDevSigner()
    ledger = AuditLedger(repos.audit, repos.tree_heads, signer=signer)
    ca = CertificateAuthority(signer, repos.credentials, repos.agents, issuer=ISSUER)
    revocation = RevocationService(repos.revocations, repos.credentials, repos.agents, signer, ledger,
                                   issuer=ISSUER)
    registry = RegistryService(repos, ledger, revocation)

    org = await registry.create_organization(namespace="wp-test", legal_name="WP Test Ltd",
                                             tier=OrgTier.FREE)
    org.verification.level = VerificationLevel.VERIFIED_LEGAL_ENTITY
    await repos.organizations.update(org)
    owner = await registry.create_owner(org_id=org.id, email="ops@wp-test.example",
                                        role=OwnerRole.ORG_ADMIN)
    private_key, public_key = generate_keypair()
    agent, challenge = await registry.register_agent(
        org_id=org.id, owner_id=owner.id, profile=AgentProfile(name="wp-integration-bot"),
        public_key_jwk=public_key_to_jwk(public_key), capabilities=["http.read"])
    agent = await registry.submit_proof_of_possession(
        aid=agent.id, challenge_id=challenge.id, signature=sign_challenge(challenge, private_key))

    (SHARED / "agent-key.json").write_text(json.dumps(private_key_to_jwk(private_key)), encoding="utf-8")
    (SHARED / "aid.txt").write_text(agent.id, encoding="utf-8")

    app = FastAPI()

    @app.get("/.well-known/aiaf-registry")
    async def discovery():
        return {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                "revocation_delta_endpoint": f"{ISSUER}/v1/revocations/delta"}

    @app.get("/.well-known/jwks.json")
    async def jwks():
        return ca.jwks()

    @app.get("/v1/revocations/delta")
    async def delta(since: int = 0):
        return await revocation.delta(since=since)

    @app.post("/test/credential")
    async def credential():
        current = await repos.agents.require(agent.id)
        organization = await repos.organizations.require(org.id)
        token, _ = await ca.issue_credential(current, organization)
        return {"credential": token}

    @app.post("/test/revoke")
    async def revoke():
        await revocation.revoke(agent.id, actor=system_actor("wp-integration"))
        return {"revoked": agent.id}

    return app


def main() -> None:
    SHARED.mkdir(parents=True, exist_ok=True)
    cert, key = tls_certificate()
    app = asyncio.run(build())
    uvicorn.run(app, host="0.0.0.0", port=8443, ssl_certfile=str(cert), ssl_keyfile=str(key),
                log_level="warning")


if __name__ == "__main__":
    main()
