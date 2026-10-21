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

from ._tools import DEFAULT_MAX_CHARS, OriginNotAllowed, SignedCalls, allowed_origins

if TYPE_CHECKING:
    from .agent import Agent


def aidr_http_tools(agent: Agent, *, origins: Iterable[str] | None = None,
                    max_chars: int = DEFAULT_MAX_CHARS, timeout: float = 30.0,
                    methods: Iterable[str] = ("GET", "POST")) -> list[Any]:
    """``http_get`` / ``http_post`` tools that identify the agent to the sites they reach."""
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, Field

    calls = SignedCalls(agent, allowed_origins(agent, origins), max_chars=max_chars, timeout=timeout)
    sites = calls.sites
    tools: list[Any] = []

    class GetArgs(BaseModel):
        url: str = Field(description=f"Absolute URL on one of: {sites}")

    class PostArgs(BaseModel):
        url: str = Field(description=f"Absolute URL on one of: {sites}")
        body: dict[str, Any] = Field(default_factory=dict, description="JSON body to send")

    wanted = {m.upper() for m in methods}
    if "GET" in wanted:
        tools.append(StructuredTool.from_function(
            func=calls.get, coroutine=calls.aget, name="http_get", args_schema=GetArgs,
            description=f"Fetch a URL as the verified agent {agent.aid}. Sites: {sites}."))
    if "POST" in wanted:
        tools.append(StructuredTool.from_function(
            func=calls.post, coroutine=calls.apost, name="http_post", args_schema=PostArgs,
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
