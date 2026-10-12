"""An agent's identity: its identifier, where it is registered, what it may sign for, and its key.

The private key is generated on the machine the agent runs on and never leaves it except where the
operator puts it (a key file, or the one environment variable a container reads). The registry
only ever received the public half.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from aidr_crypto.keys import jwk_to_private_key, private_key_to_jwk, public_key_to_jwk

#: The registry an identity belongs to when nothing else says (AIDR_REGISTRY_URL overrides it).
DEFAULT_REGISTRY = "https://api.evolivcore.com"

FORMAT = "aidr-agent-identity/1"


class IdentityError(Exception):
    """A stored identity is missing, unreadable, or not safe to use."""


@dataclass
class AgentIdentity:
    aid: str
    name: str
    registry: str
    private_key: Any = field(repr=False)
    #: Origins the registry issues credentials for; empty = unrestricted.
    audiences: list[str] = field(default_factory=list)

    def public_jwk(self) -> dict[str, Any]:
        return public_key_to_jwk(self.private_key.public_key())

    # -- serialisation ---------------------------------------------------------------------------

    def to_document(self) -> dict[str, Any]:
        """Everything, private key included. Treat the result as a secret."""
        return {"format": FORMAT, "aid": self.aid, "name": self.name, "registry": self.registry,
                "audiences": list(self.audiences), "private_jwk": private_key_to_jwk(self.private_key)}

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> AgentIdentity:
        if document.get("format") != FORMAT:
            raise IdentityError(f"not an {FORMAT} document")
        try:
            return cls(aid=document["aid"], name=document["name"], registry=document["registry"],
                       audiences=list(document.get("audiences") or []),
                       private_key=jwk_to_private_key(document["private_jwk"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise IdentityError(f"malformed identity: {exc}") from exc

    def to_portable(self) -> str:
        """One line for a secret store: base64url(JSON). A secret — it holds the private key."""
        raw = json.dumps(self.to_document(), separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def from_portable(cls, value: str) -> AgentIdentity:
        value = value.strip()
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            return cls.from_document(json.loads(raw))
        except (ValueError, json.JSONDecodeError) as exc:
            raise IdentityError("AIDR_AGENT_IDENTITY is not a valid identity") from exc


def normalize_origin(url: str) -> str:
    """``https://Shop.Example:443/path`` → ``https://shop.example`` (the registry's normalisation)."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"not a URL: {url!r}")
    host = parts.hostname.lower().rstrip(".")
    default = {"https": 443, "http": 80}.get(parts.scheme)
    port = f":{parts.port}" if parts.port and parts.port != default else ""
    return f"{parts.scheme}://{host}{port}"
