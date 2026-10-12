# AIDR edge verifier — Cloudflare Workers

Verifies AI agents at the edge, before a request reaches your origin. No runtime dependencies:
WebCrypto for the cryptography, Durable Objects for state.

| Outcome | When | Result |
|---|---|---|
| bypassed | normalised path fully matches an `AIDR_BYPASS` rule | forwarded, not verified |
| anonymous | none of `Agent-Credential`, `Signature`, `Signature-Input` | forwarded; in `verified-only` mode, 401 `aidr.edge.agent_required` |
| verified | identity proven, policy met | forwarded, identity in the context |
| refused | claims to be an agent and is not a valid one / revoked or out of policy / cannot be checked | 401 / 403 / 503, JSON `{error, reason}` |

## Modes

`AIDR_MODE = "open"` (the default) forwards anonymous traffic: people and unidentified bots reach
the site, identified agents are verified. `AIDR_MODE = "verified-only"` refuses anonymous requests
with 401 `aidr.edge.agent_required` and a `Link` to the registry's discovery document. That refuses
people too, so scope it with `AIDR_VERIFIED_ONLY_PATHS` (JSON array of path regexes, matched like
bypass rules; a path that cannot be normalised counts as protected). A mistyped mode is a
configuration error (503 for every request), never an open site.

An origin that is itself a Worker can be bound as the `ORIGIN` service binding instead of
`AIDR_ORIGIN`: it then needs no public URL at all (`demo/` does this).

## How it is sealed

- **Verification** is a WebCrypto port of the SDK verifiers (`src/crypto.mjs`, `src/verifier.mjs`).
  It passes the shared vectors in `sdk/testdata/vectors.json`, including the multi-step sequences.
  Floors on AgAL, OAL and KAL are separate; AgAL is read from `agal` only.
- **Replay** — `NonceStore` Durable Objects, 256 shards by `sha256(aid, nonce)`. A claim is one
  synchronous SQLite upsert, so two claims for one nonce can never both succeed, from any isolate or
  location. A nonce is claimed only after the request fully verifies and meets policy, and is kept
  for exactly as long as its signature could still be accepted. KV is not used: it is eventually
  consistent.
- **Trust sync** — one `TrustState` Durable Object fetches the registry's JWKS (hourly) and a
  complete signed revocation snapshot (every 60 s, on its own alarm). Discovered endpoints must be
  on the issuer's origin. Isolates reload the snapshot at most once a minute and re-verify it. Agent
  requests get 503 `aidr.registry.unavailable` once the snapshot was signed (its `iat`) more than
  11 minutes (660 s) earlier, the limit every AIDR verifier applies. An unknown `kid`
  triggers a key refresh, at most once a minute.
- **Origin** — every forwarded request carries `X-AIDR-Context` + `X-AIDR-Context-Signature`, an
  HMAC over the edge's decision bound to the method, path+query and a 60-second window. Client-sent
  `x-aidr-*` headers are removed first, and the agent's own headers are not forwarded. **The origin
  must verify the context on every request** and refuse anything without it:
  - Python: `app.add_middleware(EdgeContextMiddleware, secret=...)` from `aidr_verifier.edge`
  - Node: `verifyEdgeContext()` from `@aidr/cloudflare-edge/edge-context`
- **Bypass rules** are anchored (`^(?:rule)$`) and matched against the decoded, dot-segment-resolved
  path; an ambiguous path (double encoding, `%`, `\`, control characters) is never bypassed. Same
  contract as the Python middleware: `sdk/testdata/path-normalisation.json`.
- **Fails closed** on misconfiguration (503 `aidr.edge.misconfigured` for every request), on an
  unreachable replay store, and on missing or stale revocation data. Logs are one JSON line per
  decision and never contain the credential or the signature.

## Deploy

```sh
openssl rand -base64 48 > edge-secret        # share with the origin; never commit
wrangler secret put AIDR_EDGE_CONTEXT_SECRET < edge-secret
wrangler deploy
```

Set `AIDR_ISSUER`, the floors and `AIDR_BYPASS` in `wrangler.toml`. Then make the origin
unreachable except through the worker: **Cloudflare Tunnel**, or **Authenticated Origin Pulls with a
certificate of your own** (the shared Cloudflare certificate proves only "some Cloudflare customer").
The context HMAC is what proves "this worker, for this request"; network isolation keeps everyone
else from even trying.

## Your responsibilities

- Responses that depend on the caller's identity must be marked `Cache-Control: private` (or
  `no-store`) by the origin, or a cache in front of it can serve one caller's page to another.
- Durable Objects live in one location each. Nonce claims from far-away regions pay the round trip
  to that location; that is the price of a replay check that is actually global.

## Test

```sh
npm test                      # Node 22+: vectors, paths, edge context, Durable Objects, the worker
```

`test/integration/live-staging.mjs` runs the worker on workerd (miniflare) with real Durable
Objects against a real registry, with requests signed by `scripts/staging_agent.py`.
