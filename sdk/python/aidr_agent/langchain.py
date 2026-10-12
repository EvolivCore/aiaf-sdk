"""LangChain: give an agent's HTTP tools an AIDR identity.

Built on ``langchain-core`` (``pip install langchain-core``)::

    from aidr_agent import Agent
    from aidr_agent.langchain import aidr_http_tools

    agent = Agent.load_or_enroll("research-01", audiences=["https://shop.example"])
    tools = aidr_http_tools(agent)          # http_get and http_post, signed, limited to the audiences

The tools reach only the origins they are given — by default the agent's allowed audiences —
because an LLM choosing URLs is exactly the prompt-injection path by which an agent would present
its identity (or fetch internal addresses) somewhere it should not.

``langchain-community`` is being sunset; for code that still uses its ``RequestsToolkit``,
:func:`signed_requests_wrapper` returns a drop-in ``TextRequestsWrapper`` that signs, sync and async.
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


def _origins(agent: Agent, origins: Iterable[str] | None) -> frozenset[str]:
    chosen = frozenset(normalize_origin(o) for o in origins) if origins is not None else agent.sign_for
    if not chosen:
        raise ValueError("name the origins these tools may reach (origins=[...]): this agent has no "
                         "allowed audiences to default to")
    return chosen


def _check(url: str, allowed: frozenset[str]) -> None:
    try:
        origin = normalize_origin(url)
    except ValueError as exc:
        raise OriginNotAllowed(f"not a URL: {url!r}") from exc
    if origin not in allowed:
        raise OriginNotAllowed(f"{origin} is not one of the sites this tool may reach: "
                               f"{', '.join(sorted(allowed))}")


def _render(response: httpx.Response, max_chars: int) -> str:
    text = response.text
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n…[truncated, {len(response.text)} characters in all]"
    return f"HTTP {response.status_code}\n{text}"


def aidr_http_tools(agent: Agent, *, origins: Iterable[str] | None = None,
                    max_chars: int = DEFAULT_MAX_CHARS, timeout: float = 30.0,
                    methods: Iterable[str] = ("GET", "POST")) -> list[Any]:
    """``http_get`` / ``http_post`` tools that identify the agent to the sites they reach."""
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, Field

    allowed = _origins(agent, origins)
    auth = agent.httpx_auth()
    sites = ", ".join(sorted(allowed))
    tools: list[Any] = []

    class GetArgs(BaseModel):
        url: str = Field(description=f"Absolute URL on one of: {sites}")

    class PostArgs(BaseModel):
        url: str = Field(description=f"Absolute URL on one of: {sites}")
        body: dict[str, Any] = Field(default_factory=dict, description="JSON body to send")

    def get(url: str) -> str:
        _check(url, allowed)
        with httpx.Client(auth=auth, timeout=timeout, follow_redirects=False) as client:
            return _render(client.get(url), max_chars)

    async def aget(url: str) -> str:
        _check(url, allowed)
        async with httpx.AsyncClient(auth=auth, timeout=timeout, follow_redirects=False) as client:
            return _render(await client.get(url), max_chars)

    def post(url: str, body: dict[str, Any] | None = None) -> str:
        _check(url, allowed)
        with httpx.Client(auth=auth, timeout=timeout, follow_redirects=False) as client:
            return _render(client.post(url, json=body or {}), max_chars)

    async def apost(url: str, body: dict[str, Any] | None = None) -> str:
        _check(url, allowed)
        async with httpx.AsyncClient(auth=auth, timeout=timeout, follow_redirects=False) as client:
            return _render(await client.post(url, json=body or {}), max_chars)

    wanted = {m.upper() for m in methods}
    if "GET" in wanted:
        tools.append(StructuredTool.from_function(
            func=get, coroutine=aget, name="http_get", args_schema=GetArgs,
            description=f"Fetch a URL as the verified agent {agent.aid}. Sites: {sites}."))
    if "POST" in wanted:
        tools.append(StructuredTool.from_function(
            func=post, coroutine=apost, name="http_post", args_schema=PostArgs,
            description=f"POST JSON to a URL as the verified agent {agent.aid}. Sites: {sites}."))
    return tools


def signed_requests_wrapper(agent: Agent, *, json_responses: bool = False) -> Any:
    """A ``langchain_community`` ``TextRequestsWrapper`` (or ``JsonRequestsWrapper``) that signs.

    Its sync methods go through ``requests`` with the agent's auth; its async ones through aiohttp,
    which accepts only BasicAuth as ``auth=``, so there the signature is added as headers instead.
    """
    from contextlib import asynccontextmanager

    from langchain_community.utilities.requests import (
        JsonRequestsWrapper,
        Requests,
        TextRequestsWrapper,
    )

    class SignedRequests(Requests):
        agent: Any = None

        @asynccontextmanager
        async def _arequest(self, method: str, url: str, **kwargs: Any):  # noqa: ANN202
            import aiohttp

            headers = {**(self.headers or {}), **await self.agent.asign_headers(method, url)}
            if self.aiosession is not None:
                async with self.aiosession.request(method, url, headers=headers, **kwargs) as response:
                    yield response
            else:
                async with aiohttp.ClientSession() as session, \
                        session.request(method, url, headers=headers, **kwargs) as response:
                    yield response

    base = JsonRequestsWrapper if json_responses else TextRequestsWrapper

    class SignedRequestsWrapper(base):  # type: ignore[valid-type,misc]
        agent: Any = None

        @property
        def requests(self) -> Requests:
            return SignedRequests(headers=self.headers, aiosession=self.aiosession,
                                  auth=self.auth, verify=self.verify, agent=self.agent)

    return SignedRequestsWrapper(auth=agent.auth(), agent=agent)


__all__ = ["OriginNotAllowed", "aidr_http_tools", "signed_requests_wrapper"]
