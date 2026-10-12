"""A minimal site behind AidrMiddleware, for trying the middleware against a real registry.

    AIDR_ISSUER=https://api.evolivcore.com AIDR_PUBLIC_ORIGIN=http://localhost:8000 \
    AIDR_CA_FILE=deploy/terraform/staging/staging-edge.pem AIDR_MIN_AGAL=1 \
    PYTHONPATH=libs:sdk/python uvicorn --app-dir sdk/python/examples protected_site:app

Then sign a request with the CLI mock agent and send it with the agent's credential:

    python scripts/staging_agent.py sign agent-key.json "$AID" GET http://localhost:8000/whoami sig.txt
    curl -H @sig.txt -H "Agent-Credential: $CREDENTIAL" http://localhost:8000/whoami
"""

from __future__ import annotations

import logging
import os

import httpx
from fastapi import Depends, FastAPI, Request

from aidr_verifier import AidrIdentity, AidrMiddleware, RedisNonceStore, RelyingPartyConfig
from aidr_verifier.fastapi import require_agent

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

ca_file = os.environ.get("AIDR_CA_FILE")
nonce_store = None
if os.environ.get("AIDR_REDIS_URL"):
    import redis.asyncio as redis

    nonce_store = RedisNonceStore(redis.from_url(os.environ["AIDR_REDIS_URL"]))

app = FastAPI(title="AIDR protected example")
app.add_middleware(AidrMiddleware, config=RelyingPartyConfig(
    issuer=os.environ["AIDR_ISSUER"],
    public_origin=os.environ.get("AIDR_PUBLIC_ORIGIN"),
    min_agal=int(os.environ.get("AIDR_MIN_AGAL", "0")),
    min_oal=int(os.environ.get("AIDR_MIN_OAL", "0")),
    min_kal=int(os.environ.get("AIDR_MIN_KAL", "0")),
    bypass=[r"/health"],
    nonce_store=nonce_store,
    http_client=httpx.AsyncClient(verify=ca_file, timeout=10.0) if ca_file else None,
))


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/whoami")
async def whoami(request: Request):
    identity: AidrIdentity = request.state.aidr
    if not identity.is_agent:
        return {"status": identity.status}
    return {"status": identity.status, "aid": identity.aid, "organization": identity.organization,
            "org_domains": identity.org_domains, "agal": identity.agal, "oal": identity.oal,
            "kal": identity.kal, "declared": identity.declared}


VERIFIED_AGENT = Depends(require_agent(min_agal=1))


@app.get("/agents-only")
async def agents_only(agent: AidrIdentity = VERIFIED_AGENT):
    return {"hello": agent.organization}
