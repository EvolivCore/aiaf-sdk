# AIAF SDKs

Open-source code for the Agent Identity Assurance Framework (AIAF, draft 0.1): verify an AI agent's
identity on your own server, or give your agent an identity it can prove. Apache-2.0.

Verification is offline. A site checks the agent's credential and its RFC 9421 request signature
against keys and revocation data it fetches from the registry; the registry never learns which
sites an agent visited. No package here reports installs, usage or destinations.

| Path | What | Install |
|---|---|---|
| `go/` | Verifier for Go, standard library only | `go get github.com/evolivcore/aiaf-sdk/go` |
| `sdk/node/` | Verifier for Node.js, with Express middleware | `npm install @evoliv/aidr-verifier` |
| `sdk/node-agent/` | Agent SDK for Node.js, with Vercel AI SDK tools | `npm install @evoliv/aidr-agent` |
| `sdk/python/aidr_verifier/` | Verifier for Python: ASGI, FastAPI, WSGI, Django | `pip install aidr-verifier` |
| `sdk/python/aidr_agent/` | Agent SDK for Python, with LangChain tools | `pip install aidr-agent` |
| `libs/` | `aidr-core` and `aidr-crypto`, which the Python packages use | installed with them |
| `edge/cloudflare-worker/` | Verification at the edge, as a Cloudflare Worker | see its README |
| `edge/wordpress/` | WordPress plugin | see its README |
| `sdk/testdata/` | The shared test vectors every implementation must agree on | |
| `spec/` | The AIAF draft | |

The Go module is at `go/`, not under `sdk/`, because a Go module's path must match where it sits in
its repository.

## Conformance

Every verifier here replays the same vectors in `sdk/testdata/` and must reach the same verdicts;
the workflow in `.github/workflows/` runs them all on every change. An implementation of your own
can use the same files.

```sh
(cd go && go test ./...)
(cd sdk/node && npm test)
(cd sdk/node-agent && npm test)
(cd edge/cloudflare-worker && npm test)
pip install cryptography pytest
PYTHONPATH=libs:sdk/python python -m pytest tests
```

## Contributing

This repository is written by a release script from Evoliv Core's source repository, one commit per
release. Issues are welcome here. A pull request is reviewed here and applied at the source, so it
arrives in the next sync rather than being merged directly.

Report a security problem privately, not in an issue: the Security tab, "Report a vulnerability".
