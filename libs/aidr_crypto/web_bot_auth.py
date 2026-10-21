"""Web Bot Auth: the IETF webbotauth profile of RFC 9421, as Cloudflare verifies it.

With Web Bot Auth on, an AIDR agent signs each request once, in this profile, and the one signature
serves both kinds of verifier: AIDR verifiers (0.2.1 and later) accept a keyid that is the JWK
thumbprint of the key in the agent's credential, and Web Bot Auth verifiers (Cloudflare's edge, for
one) find the key through Signature-Agent:

    Agent-Credential: <the AIDR credential>
    Signature-Agent: "https://agent.example.com"
    Signature-Input: wba=("@authority" "@method" "@path" "signature-agent");created=…;expires=…;
        keyid="<JWK thumbprint>";alg="ed25519";nonce="…";tag="web-bot-auth"
    Signature: wba=:…:

One signature rather than two: Cloudflare's own verifier library refuses a request carrying more
than one unless told which to check, which an edge cannot know.

Choices, each where the drafts and Cloudflare's implementation differ:

* ``Signature-Agent`` is a bare quoted string. draft-meunier-webbotauth-httpsig-protocol asks
  signers for the dictionary form, but Cloudflare rejects it and the draft lets verifiers accept the
  string form; the string is what works everywhere today.
* ``signature-agent`` is covered without a ``key`` parameter: Cloudflare does not support ``key``.
* ``keyid`` is the base64url JWK SHA-256 thumbprint (RFC 7638; RFC 8037 appendix A.3 for Ed25519).
* Ed25519 only: the one algorithm Cloudflare verifies.
* ``expires`` five minutes after ``created`` by default: the age AIDR verifiers accept. Cloudflare
  sets no maximum and suggests short lifetimes; pass ``lifetime`` for a shorter one.

Keys are found through the key directory at ``<Signature-Agent>/.well-known/
http-message-signatures-directory``, which must carry one signature per key made by that key
(:func:`signed_directory`). The agent's operator hosts it and registers it with Cloudflare.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from aidr_core.errors import InvalidKey
from aidr_core.serde import utcnow

from .keys import public_key_to_jwk
from .signatures import (
    RequestContext,
    build_signature_base,
    serialize_signature_params,
)

TAG = "web-bot-auth"
DIRECTORY_TAG = "http-message-signatures-directory"
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
LABEL = "wba"
COMPONENTS = ("@authority", "@method", "@path", "signature-agent")
DEFAULT_LIFETIME = timedelta(minutes=5)   # AIDR verifiers' window; Cloudflare sets no maximum

_THUMBPRINT_MEMBERS = {"OKP": ("crv", "kty", "x"), "EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n")}


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """The base64url SHA-256 JWK thumbprint (RFC 7638): the required members, sorted, no spaces."""
    members = _THUMBPRINT_MEMBERS.get(jwk.get("kty", ""))
    if members is None or any(name not in jwk for name in members):
        raise InvalidKey(f"cannot take the thumbprint of a {jwk.get('kty')!r} key")
    canonical = json.dumps({name: jwk[name] for name in members}, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _ed25519_jwk(private_key: Any) -> dict[str, Any]:
    jwk = public_key_to_jwk(private_key.public_key())
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise InvalidKey("Web Bot Auth signatures need an Ed25519 key (the one algorithm Cloudflare verifies)")
    return jwk


def _signature_agent(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError(f"Signature-Agent must be an https:// URL, not {url!r}")
    return url.rstrip("/")


def _nonce() -> str:
    return base64.b64encode(secrets.token_bytes(64)).decode("ascii")   # 64 bytes, as recommended


def sign_request(*, method: str, url: str, private_key: Any, signature_agent: str,
                 created: datetime | None = None, lifetime: timedelta = DEFAULT_LIFETIME,
                 label: str = LABEL, nonce: str | None = None) -> dict[str, str]:
    """The headers of a Web Bot Auth signature for one request: Signature-Agent, Signature-Input
    and Signature, each holding only this signature (:func:`combine` merges them with others)."""
    agent_header = f'"{_signature_agent(signature_agent)}"'
    moment = created or utcnow()
    created_at = int(moment.timestamp())
    params = {
        "created": created_at,
        "expires": created_at + int(lifetime.total_seconds()),
        "keyid": jwk_thumbprint(_ed25519_jwk(private_key)),
        "alg": "ed25519",
        "nonce": nonce or _nonce(),
        "tag": TAG,
    }
    signature_params = serialize_signature_params(COMPONENTS, params)
    context = RequestContext(method=method, url=url, headers={"Signature-Agent": agent_header})
    signature = private_key.sign(build_signature_base(COMPONENTS, signature_params, context))
    return {
        "Signature-Agent": agent_header,
        "Signature-Input": f"{label}={signature_params}",
        "Signature": f"{label}=:{base64.b64encode(signature).decode('ascii')}:",
    }


def signed_directory(private_key: Any, authority: str, *, created: datetime | None = None,
                     lifetime: timedelta = timedelta(days=1)) -> tuple[dict[str, str], bytes]:
    """The key directory response an agent's operator serves at DIRECTORY_PATH on ``authority``:
    the body (a JWKS whose ``kid`` is the thumbprint) and its headers, including the signature by
    the key itself that Cloudflare requires (tag http-message-signatures-directory, covering the
    request's ``@authority``). Re-make it before it expires."""
    jwk = _ed25519_jwk(private_key)
    keyid = jwk_thumbprint(jwk)
    entry = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "kid": keyid, "use": "sig"}
    body = json.dumps({"keys": [entry]}, separators=(",", ":")).encode("utf-8")
    moment = created or utcnow()
    created_at = int(moment.timestamp())
    signature_params = (f'("@authority";req);created={created_at};'
                        f'expires={created_at + int(lifetime.total_seconds())};'
                        f'keyid="{keyid}";alg="ed25519";tag="{DIRECTORY_TAG}"')
    base = f'"@authority";req: {authority.lower()}\n"@signature-params": {signature_params}'
    signature = private_key.sign(base.encode("utf-8"))
    headers = {
        "Content-Type": DIRECTORY_MEDIA_TYPE,
        "Cache-Control": "max-age=300",
        "Signature-Input": f"sig1={signature_params}",
        "Signature": f"sig1=:{base64.b64encode(signature).decode('ascii')}:",
    }
    return headers, body
