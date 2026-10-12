"""A LangChain agent with an AIDR identity, calling a site that verifies it.

    pip install cryptography httpx langchain-core langchain-openai   # or any chat model package
    export AIDR_ENROLLMENT_TOKEN=aidr_et_…        # first run only; from the AIDR console
    export OPENAI_API_KEY=…
    python examples/langchain_agent.py https://shop.example "What is on sale today?"

First run: the agent enrolls and keeps its identity in ~/.aidr/agents/shop-assistant/. Every run:
its HTTP tools sign requests to the one site given, and refuse any other.
"""

from __future__ import annotations

import sys

from aidr_agent import Agent
from aidr_agent.langchain import aidr_http_tools


def main(site: str, question: str) -> None:
    agent = Agent.load_or_enroll("shop-assistant", audiences=[site])
    print(f"acting as {agent.aid}", file=sys.stderr)
    tools = aidr_http_tools(agent, origins=[site])

    from langchain_openai import ChatOpenAI

    model = ChatOpenAI(model="gpt-4o-mini").bind_tools(tools)
    by_name = {tool.name: tool for tool in tools}
    messages: list = [("system", f"Answer using the site {site}. Fetch pages with http_get."),
                      ("human", question)]
    for _ in range(5):
        reply = model.invoke(messages)
        messages.append(reply)
        if not reply.tool_calls:
            print(reply.content)
            return
        for call in reply.tool_calls:
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": by_name[call["name"]].invoke(call["args"])})
    print("stopped after five tool rounds", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
