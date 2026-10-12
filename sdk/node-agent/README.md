# @evoliv/aidr-agent

A verifiable identity for an AI agent, in one line. The agent enrolls once with a token from the
AIDR console, keeps its key on its own machine, and signs every request to the sites it may reach,
so those sites can check who it is — offline, with no call to the registry. Part of Project AIDR,
implementing the AIAF draft standard. Apache-2.0.

```sh
npm install @evoliv/aidr-agent        # Node 20 or later, no dependencies
```

## One line

```js
import { Agent, createSignedFetch } from '@evoliv/aidr-agent';

const agent = await Agent.loadOrEnroll('research-01');   // first run: enrolls with AIDR_ENROLLMENT_TOKEN
const fetch = createSignedFetch(agent);                  // identifies the agent where it may

const response = await fetch('https://shop.example/api/products');
```

1. An organisation admin issues an **enrollment token** in the console (passkey sign-in). Put it in
   `AIDR_ENROLLMENT_TOKEN` for the first run only.
2. `loadOrEnroll` generates the key here, registers the agent, proves the key, and saves the
   identity to `~/.aidr/agents/research-01/identity.json` (mode 0600). After that the token is not
   needed; remove it.
3. `createSignedFetch` adds an `Agent-Credential` and an RFC 9421 signature to each request to a
   site the agent may identify to, renewing the short-lived credential before it expires.

The identity file is the same one the Python SDK (`aidr-agent` on PyPI) writes: one agent can run
from either language.

This snippet is run as written, against a live verified-only site, on every change to this package
and every week (the one-minute check: `scripts/one_minute/node_agent.py`).

## Containers and serverless

A throwaway disk would enroll a new agent on every start. Enroll once instead and keep the identity
in the platform's secret store:

```sh
AIDR_ENROLLMENT_TOKEN=… npx @evoliv/aidr-agent enroll --name research-01 --print-identity
# store the printed line as the secret AIDR_AGENT_IDENTITY; loadOrEnroll reads it from there
npx @evoliv/aidr-agent whoami --name research-01   # with AIDR_AGENT_IDENTITY set: which agent it is
```

The token is read only from the environment, never from the command line.

## Which requests are signed

- Only **https** requests (and plain http to `localhost` / `127.0.0.1`): a credential sent in clear
  text is a credential given away.
- Only to the **origins the registry allows** for this agent (the token's audiences), or — for an
  agent with none — any https origin. Other requests go out unsigned; with
  `new Agent(identity, { onUnlisted: 'refuse' })` they are refused instead (`NotAllowed`).
- Redirects are not followed for signed requests unless you pass `redirect`: a redirect to another
  origin would carry a request signed for this one.

## Vercel AI SDK

```js
import { Agent } from '@evoliv/aidr-agent';
import { aidrHttpTools } from '@evoliv/aidr-agent/ai';
import { generateText } from 'ai';

const agent = await Agent.loadOrEnroll('research-01', { audiences: ['https://shop.example'] });
const tools = await aidrHttpTools(agent);   // httpGet and httpPost, signed

await generateText({ model, tools, prompt: 'Find the cheapest product on shop.example' });
```

The tools reach **only** the origins they are given — by default the agent's allowed audiences —
because a model choosing URLs is how an agent would be steered into presenting its identity, or
fetching internal addresses, somewhere it should not. Responses are cut to 20,000 characters
(`maxChars`). `ai` is an optional peer dependency.

## API

| | |
|---|---|
| `Agent.loadOrEnroll(name, { audiences, token, registry, keyStore, onUnlisted })` | the saved identity, or enroll once |
| `new Agent(identity, { signFor, onUnlisted })` | an agent from an identity you hold |
| `agent.signHeaders(method, url)` | the headers for one request (`{}` where it does not sign) |
| `createSignedFetch(agent, { fetch })` | a `fetch` that signs |
| `FileKeyStore(home)`, `EnvKeyStore(variable)` | where identities live (`AIDR_AGENT_HOME`, `AIDR_AGENT_IDENTITY`) |
| `enroll(token, { name, registry, audiences })` | the two-request enrollment, on its own |
| `RegistryError` | a refusal, with the registry's `code` (`aidr.…`) |

`AIDR_REGISTRY_URL` points at another registry (default `https://api.evolivcore.com`).

## Conformance

Every release is gated on the shared AIAF conformance vectors: requests signed through this package
must be accepted — and their tampered copies refused — by the Python, Node, Go and Cloudflare Worker
verifiers.
