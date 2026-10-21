"""A LlamaIndex agent with an AIDR identity, calling a site that verifies it.

    pip install "aidr-agent[llamaindex]" llama-index-llms-openai   # or any LLM integration
    export AIDR_ENROLLMENT_TOKEN=aidr_et_…        # first run only; from the AIDR console
    export OPENAI_API_KEY=…
    python examples/llamaindex_agent.py https://shop.example "What is on sale today?"

First run: the agent enrolls and keeps its identity in ~/.aidr/agents/shop-assistant/. Every run:
its HTTP tools sign requests to the one site given, and refuse any other.
"""

from __future__ import annotations

import asyncio
import sys

from aidr_agent import Agent
from aidr_agent.llamaindex import aidr_http_tools


async def main(site: str, question: str) -> None:
    agent = Agent.load_or_enroll("shop-assistant", audiences=[site])
    print(f"acting as {agent.aid}", file=sys.stderr)

    from llama_index.core.agent.workflow import FunctionAgent
    from llama_index.llms.openai import OpenAI

    workflow = FunctionAgent(
        tools=aidr_http_tools(agent, origins=[site]),
        llm=OpenAI(model="gpt-4o-mini"),
        system_prompt=f"Answer using the site {site}. Fetch pages with http_get.",
    )
    print(await workflow.run(user_msg=question))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
