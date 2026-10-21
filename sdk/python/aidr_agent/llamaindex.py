"""LlamaIndex: give an agent's HTTP tools an AIDR identity.

Built on ``llama-index-core`` (``pip install "aidr-agent[llamaindex]"``)::

    from aidr_agent import Agent
    from aidr_agent.llamaindex import aidr_http_tools
    from llama_index.core.agent.workflow import FunctionAgent

    agent = Agent.load_or_enroll("research-01", audiences=["https://shop.example"])
    workflow = FunctionAgent(tools=aidr_http_tools(agent), llm=llm)

The same tools as :mod:`aidr_agent.langchain` (``http_get`` and ``http_post``, sync and async),
under the same rule: they reach only the origins they are given, by default the agent's allowed
audiences, so a prompt-injected model cannot present the agent's identity, or fetch internal
addresses, anywhere else. A refused URL raises :class:`OriginNotAllowed`; LlamaIndex's agents hand
the error back to the model as the tool's result.
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
    """``http_get`` / ``http_post`` ``FunctionTool``\\ s that identify the agent to the sites they reach."""
    from llama_index.core.tools import FunctionTool
    from pydantic import BaseModel, Field

    calls = SignedCalls(agent, allowed_origins(agent, origins), max_chars=max_chars, timeout=timeout)
    sites = calls.sites

    class GetArgs(BaseModel):
        url: str = Field(description=f"Absolute URL on one of: {sites}")

    class PostArgs(BaseModel):
        url: str = Field(description=f"Absolute URL on one of: {sites}")
        body: dict[str, Any] = Field(default_factory=dict, description="JSON body to send")

    wanted = {m.upper() for m in methods}
    tools: list[Any] = []
    if "GET" in wanted:
        tools.append(FunctionTool.from_defaults(
            fn=calls.get, async_fn=calls.aget, name="http_get", fn_schema=GetArgs,
            description=f"Fetch a URL as the verified agent {agent.aid}. Sites: {sites}."))
    if "POST" in wanted:
        tools.append(FunctionTool.from_defaults(
            fn=calls.post, async_fn=calls.apost, name="http_post", fn_schema=PostArgs,
            description=f"POST JSON to a URL as the verified agent {agent.aid}. Sites: {sites}."))
    return tools


__all__ = ["OriginNotAllowed", "aidr_http_tools"]
