"""What the framework tools share: which sites they may reach, and the signed requests themselves.

The LangChain and LlamaIndex tools wrap these same functions, so both refuse the same URLs and
sign the same way.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import httpx

from .identity import normalize_origin

if TYPE_CHECKING:
    from .agent import Agent

DEFAULT_MAX_CHARS = 20_000


class OriginNotAllowed(ValueError):
    pass


def allowed_origins(agent: Agent, origins: Iterable[str] | None) -> frozenset[str]:
    chosen = frozenset(normalize_origin(o) for o in origins) if origins is not None else agent.sign_for
    if not chosen:
        raise ValueError("name the origins these tools may reach (origins=[...]): this agent has no "
                         "allowed audiences to default to")
    return chosen


def check_origin(url: str, allowed: frozenset[str]) -> None:
    try:
        origin = normalize_origin(url)
    except ValueError as exc:
        raise OriginNotAllowed(f"not a URL: {url!r}") from exc
    if origin not in allowed:
        raise OriginNotAllowed(f"{origin} is not one of the sites this tool may reach: "
                               f"{', '.join(sorted(allowed))}")


def render(response: httpx.Response, max_chars: int) -> str:
    text = response.text
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n…[truncated, {len(response.text)} characters in all]"
    return f"HTTP {response.status_code}\n{text}"


class SignedCalls:
    """GET and POST, sync and async, signed as the agent and limited to ``allowed``."""

    def __init__(self, agent: Agent, allowed: frozenset[str], *, max_chars: int, timeout: float) -> None:
        self.allowed = allowed
        self.sites = ", ".join(sorted(allowed))
        self._auth = agent.httpx_auth()
        self._max_chars = max_chars
        self._timeout = timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(auth=self._auth, timeout=self._timeout, follow_redirects=False)

    def _aclient(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(auth=self._auth, timeout=self._timeout, follow_redirects=False)

    def get(self, url: str) -> str:
        check_origin(url, self.allowed)
        with self._client() as client:
            return render(client.get(url), self._max_chars)

    async def aget(self, url: str) -> str:
        check_origin(url, self.allowed)
        async with self._aclient() as client:
            return render(await client.get(url), self._max_chars)

    def post(self, url: str, body: dict[str, Any] | None = None) -> str:
        check_origin(url, self.allowed)
        with self._client() as client:
            return render(client.post(url, json=body or {}), self._max_chars)

    async def apost(self, url: str, body: dict[str, Any] | None = None) -> str:
        check_origin(url, self.allowed)
        async with self._aclient() as client:
            return render(await client.post(url, json=body or {}), self._max_chars)
