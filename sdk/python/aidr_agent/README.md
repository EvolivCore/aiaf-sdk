# aidr-agent (Python)

Give an AI agent a verifiable AIDR identity from its first run. Apache-2.0.

```
pip install "aidr-agent[requests]"          # add ,langchain for the LangChain tools
```

```python
from aidr_agent import Agent

agent = Agent.load_or_enroll("research-01", audiences=["https://shop.example"])
agent.session().get("https://shop.example/products")   # signed; other sites get anonymous requests
```

1. An organisation admin issues an **enrollment token** in the console (Organisations → Enrollment tokens).
2. Put it in `AIDR_ENROLLMENT_TOKEN` where the agent runs. The first run generates the key **on that
   machine**, enrolls, proves the key and saves the identity; later runs load it. The token is then
   no longer needed.
3. Requests to the agent's allowed sites carry an RFC 9421 signature and a short-lived credential.
   Anything else goes out unsigned, or is refused with `on_unlisted="refuse"`. Plain http is never
   signed, except to localhost.

Python 3.10+. Extras: `requests` (for `agent.session()` / `agent.auth()`), `langchain` (the tools, on
`langchain-core`), `langchain-community` (the `RequestsToolkit` wrapper). It installs `aidr-crypto`
and `aidr-core`, the same signing code the registry runs.

## Where the identity is kept

| Store | Use it for | How |
| --- | --- | --- |
| `FileKeyStore` (default) | laptops, VMs, persistent volumes | `~/.aidr/agents/<name>/identity.json`, mode 0600 (`AIDR_AGENT_HOME` moves it) |
| `EnvKeyStore` | containers, serverless | `python -m aidr_agent enroll --name <name> --print-identity`, then store the line as the secret `AIDR_AGENT_IDENTITY` |

A container that starts with an empty disk would enroll a new agent on every start and spend a use of
the token each time: use `AIDR_AGENT_IDENTITY` there.

## HTTP clients

- `agent.session()`: a `requests.Session`. `agent.auth()`: for `requests.get(url, auth=…)`.
- `agent.httpx_auth()`: for `httpx.Client` and `httpx.AsyncClient`.
- `agent.sign_headers(method, url)`: the headers themselves, for any other client.

## LangChain

```python
from aidr_agent.langchain import aidr_http_tools

tools = aidr_http_tools(agent)      # http_get, http_post: signed, and limited to the agent's sites
```

The tools reach only the origins they are given (by default the agent's allowed audiences). An LLM
choosing URLs is how a prompt-injected agent would present its identity somewhere it should not, or
reach internal addresses. For code still on `langchain-community`'s `RequestsToolkit`,
`signed_requests_wrapper(agent)` is a drop-in `TextRequestsWrapper` that signs, sync and async.
`langchain-community` is being sunset, so new code should use the tools.

## Command line

```
aidr-agent enroll --name research-01 --audience https://shop.example
aidr-agent whoami --name research-01
```

(`python -m aidr_agent …` is the same command.)

The token is read only from `AIDR_ENROLLMENT_TOKEN`, never from the command line.
