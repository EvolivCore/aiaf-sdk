"""The Phase 1 demo: a LangChain agent through a Cloudflare Worker in "verified agents only" mode.

    pip install "aidr-agent[langchain]"               # + langchain-openai for --ask
    export AIDR_ENROLLMENT_TOKEN=aidr_et_…              # first run only (AIDR console)
    python worker_demo.py https://aidr-edge-demo.<you>.workers.dev
    python worker_demo.py https://aidr-edge-demo.<you>.workers.dev --ask "What is in the catalogue?"

It shows, in order, and exits non-zero if any step does not behave:
  1. a person or an unidentified bot is refused (401 aidr.edge.agent_required);
  2. the agent enrolls on its first run (or loads its saved identity) and gets in: the origin
     greets it by its verified identifier, organisation and assurance levels;
  3. the same signed request sent again is refused as a replay;
  4. a LangChain tool built on the agent fetches the page — and, with --ask and OPENAI_API_KEY,
     a model answers a question through it.

edge/cloudflare-worker/demo/README.md is the runbook (deploying the Worker, issuing the token).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

from aidr_agent import Agent
from aidr_agent.identity import normalize_origin
from aidr_agent.langchain import aidr_http_tools

PATH = "/agents/catalogue"
failures: list[str] = []


def step(title: str) -> None:
    print(f"\n== {title}")


def expect(ok: bool, what: str) -> None:
    print(f"   {'PASS' if ok else 'FAIL'}  {what}")
    if not ok:
        failures.append(what)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("site", help="the Worker's URL, e.g. https://aidr-edge-demo.<you>.workers.dev")
    parser.add_argument("--name", default="worker-demo", help="the agent's name (default worker-demo)")
    parser.add_argument("--ask", help="a question for an LLM that uses the signed tools")
    args = parser.parse_args()
    site = normalize_origin(args.site)
    url = f"{site}{PATH}"

    step("1. A person, or a bot that does not identify itself")
    anonymous = httpx.get(url, timeout=20)
    body = anonymous.json() if anonymous.headers.get("content-type", "").startswith("application/json") else {}
    print(f"   GET {PATH} -> {anonymous.status_code} {body.get('error', '')}")
    expect(anonymous.status_code == 401 and body.get("error") == "aidr.edge.agent_required",
           "refused: this path is for verified agents only")

    step("2. The agent: its identity, then the same request")
    # An https site is named as the agent's audience (the registry binds its credentials to it);
    # a local rehearsal on http://127.0.0.1 cannot be one, so the agent is unrestricted there.
    audiences = [site] if site.startswith("https://") else None
    agent = Agent.load_or_enroll(args.name, audiences=audiences)
    print(f"   agent {agent.aid}")
    with httpx.Client(auth=agent.httpx_auth(), timeout=20) as client:
        verified = client.get(url)
    greeting = verified.json() if verified.status_code == 200 else {}
    print(f"   GET {PATH} -> {verified.status_code}")
    print("   origin says: " + greeting.get("message", verified.text[:200]))
    if greeting:
        print("   the edge proved: " + json.dumps(greeting["you"]))
    expect(verified.status_code == 200 and greeting.get("you", {}).get("aid") == agent.aid,
           "admitted, and the origin knows exactly which agent it is")

    step("3. Someone replays the agent's signed request")
    headers = agent.sign_headers("GET", url)
    first = httpx.get(url, headers=headers, timeout=20)
    replay = httpx.get(url, headers=headers, timeout=20)
    replay_error = replay.json().get("error") if replay.status_code != 200 else None
    print(f"   original -> {first.status_code}; replay -> {replay.status_code} {replay_error or ''}")
    expect(first.status_code == 200 and replay.status_code == 401 and replay_error == "aidr.verify.replay_detected",
           "a captured request cannot be used twice")

    step("4. LangChain")
    get_tool, _ = aidr_http_tools(agent, origins=[site])
    result = get_tool.invoke({"url": url})
    print("   http_get tool -> " + result.splitlines()[0])
    expect(result.startswith("HTTP 200"), "the agent's LangChain tool is signed and admitted")
    if args.ask:
        if not os.environ.get("OPENAI_API_KEY"):
            print("   (skipped --ask: set OPENAI_API_KEY)")
        else:
            from langchain_openai import ChatOpenAI

            model = ChatOpenAI(model="gpt-4o-mini").bind_tools([get_tool])
            messages: list = [("system", f"Use http_get on {url} to answer."), ("human", args.ask)]
            for _ in range(4):
                reply = model.invoke(messages)
                messages.append(reply)
                if not reply.tool_calls:
                    print(f"   model: {reply.content}")
                    break
                for call in reply.tool_calls:
                    messages.append({"role": "tool", "tool_call_id": call["id"],
                                     "content": get_tool.invoke(call["args"])})

    print("\n" + ("All steps behaved." if not failures else f"{len(failures)} step(s) did not behave."))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
