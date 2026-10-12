"""Where an agent's identity (and so its private key) is kept between runs.

FileKeyStore   a laptop, a VM, a persistent volume: ``<home>/<name>/identity.json``, mode 0600.
EnvKeyStore    a container or a serverless function: the whole identity in AIDR_AGENT_IDENTITY,
               held by the platform's secret store (``python -m aidr_agent enroll --print-identity``).

An ephemeral container with a FileKeyStore on a throwaway disk enrolls a NEW agent every time it
starts, and spends a use of the token each time. Use EnvKeyStore there.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Protocol

from .identity import AgentIdentity, IdentityError

IDENTITY_ENV = "AIDR_AGENT_IDENTITY"
HOME_ENV = "AIDR_AGENT_HOME"


class KeyStore(Protocol):
    def load(self, name: str) -> AgentIdentity | None: ...
    def save(self, identity: AgentIdentity) -> None: ...


def default_home() -> Path:
    return Path(os.environ.get(HOME_ENV) or Path.home() / ".aidr" / "agents")


class FileKeyStore:
    def __init__(self, home: str | os.PathLike[str] | None = None) -> None:
        self.home = Path(home) if home is not None else default_home()

    def path(self, name: str) -> Path:
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise IdentityError(f"not a usable agent name for a directory: {name!r}")
        return self.home / name / "identity.json"

    def load(self, name: str) -> AgentIdentity | None:
        path = self.path(name)
        if not path.exists():
            return None
        _refuse_if_shared(path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise IdentityError(f"{path} is unreadable: {exc}") from exc
        return AgentIdentity.from_document(document)

    def save(self, identity: AgentIdentity) -> None:
        path = self.path(identity.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if sys.platform != "win32":
            os.chmod(path.parent, 0o700)
        # Created 0600 from the start, never widened then narrowed: there is no moment at which
        # another user could read the key.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        tmp = path.with_suffix(".tmp")
        if tmp.exists():
            tmp.unlink()
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(identity.to_document(), handle, indent=2)
        os.replace(tmp, path)


class EnvKeyStore:
    """Read-only: the identity is put in the environment by whoever deploys the agent."""

    def __init__(self, variable: str = IDENTITY_ENV) -> None:
        self.variable = variable

    def load(self, name: str) -> AgentIdentity | None:
        value = os.environ.get(self.variable)
        if not value:
            return None
        identity = AgentIdentity.from_portable(value)
        if identity.name != name:
            raise IdentityError(f"{self.variable} holds agent {identity.name!r}, not {name!r}")
        return identity

    def save(self, identity: AgentIdentity) -> None:
        raise IdentityError(f"{self.variable} is read-only; enroll with "
                            "`python -m aidr_agent enroll --print-identity` and store the output")


def _refuse_if_shared(path: Path) -> None:
    """A key file that other users can read is a key other users may have copied."""
    if sys.platform == "win32":
        return          # NTFS ACLs, not mode bits; the profile directory is private by default
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise IdentityError(f"{path} is readable by other users (mode {oct(mode & 0o777)}); "
                            f"run: chmod 600 {path}")
