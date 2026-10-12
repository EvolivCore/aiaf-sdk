# Phase 1 demo: a LangChain agent through "verified agents only"

Two Workers on your Cloudflare account, and an agent built on `aidr-agent`:

```
LangChain agent ──signed──▶ aidr-edge-demo (workers.dev) ──service binding──▶ aidr-demo-origin (no public URL)
  aidr-agent SDK            verified-only below /agents/                    trusts only the edge's signed context
```

A person or an unidentified bot gets `401 aidr.edge.agent_required` below `/agents/`; the agent
gets in, and the origin greets it by the identity the edge proved (agent ID, organisation, AgAL,
OAL, KAL). A replayed request is refused. `/` stays open to people.

## 0. Rehearse locally (no Cloudflare account needed)

The same two Workers on workerd, trust synced from the real registry, the agent from the built wheels:

```sh
python scripts/build_python_packages.py                  # once: dist/pypi/*.whl
AIDR_ENROLLMENT_TOKEN=aidr_et_… scripts/rehearse_worker_demo.sh
```

The token is needed on the first run only (the agent's identity is kept in the Docker volume
`aidr-demo-agent`). The script exits non-zero if any step misbehaves.

## 1. Deploy (once, about five minutes)

```sh
cd edge/cloudflare-worker
npx wrangler login                                        # opens the browser: your Cloudflare account
openssl rand -base64 48 > edge-secret                     # never commit it
(cd demo && npx wrangler secret put AIDR_EDGE_CONTEXT_SECRET < ../edge-secret && npx wrangler deploy)
npx wrangler deploy --env demo
npx wrangler secret put AIDR_EDGE_CONTEXT_SECRET --env demo < edge-secret
```

The origin is deployed first, because the edge's service binding names it. `wrangler deploy --env demo`
prints the edge's URL: `https://aidr-edge-demo.<your-subdomain>.workers.dev`. Open it in a browser:
`/` shows the demo page, `/agents/catalogue` shows the 401.

## 2. Issue the token

In the AIDR console (console.evolivcore.com → your organisation → **Enrollment tokens**): one use,
1 hour, and under *Sites its agents may identify to* the edge's URL. Copy it.

## 3. Run the demo

```sh
pip install "aidr-agent[langchain]" langchain-openai      # from PyPI
export AIDR_ENROLLMENT_TOKEN=aidr_et_…                    # first run only
export OPENAI_API_KEY=…                                   # only for --ask
python sdk/python/examples/worker_demo.py https://aidr-edge-demo.<you>.workers.dev \
  --ask "What is in the catalogue, and what did the site verify about you?"
```

What the audience sees, step by step:

1. `GET /agents/catalogue` without an identity: **401 aidr.edge.agent_required**.
2. The agent enrolls (first run) and asks again: **200**, and the origin answers
   `Hello, aid:v1:<namespace>:…` with the organisation and assurance levels the edge proved.
3. The same signed request sent twice: **200**, then **401 aidr.verify.replay_detected**.
4. The LangChain `http_get` tool gets in; with `--ask`, the model answers from the page.

To show the live side: `npx wrangler tail --env demo` streams one line per decision (verified,
refused, with the reason). Raise `AIDR_MIN_AGAL` to `"1"` in `[env.demo.vars]` to show a floor:
agents of an organisation without a proven domain are then refused with 403.

## Afterwards

`npx wrangler delete --env demo` and `(cd demo && npx wrangler delete)` remove both Workers;
revoke the token in the console if it was not used.
