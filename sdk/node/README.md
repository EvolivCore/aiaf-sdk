# @evoliv/aidr-verifier

Verify AI agents' [AIDR](https://aidr.evolivcore.com) identities on your own site, offline: the
agent's credential (signed by the registry) and its RFC 9421 request signature. Zero dependencies:
Node's built-in crypto only. Node 18.17+. Apache-2.0.

```
npm install @evoliv/aidr-verifier
```

## Express in one line

```js
import express from 'express';
import { aidr } from '@evoliv/aidr-verifier';

const app = express();
app.use(aidr({ issuer: 'https://api.evolivcore.com', publicOrigin: 'https://shop.example' }));

app.get('/products', (req, res) => {
  if (req.aidr.status === 'verified') {
    // req.agent: { aid, organization, orgDomains, agal, oal, kal, capabilities, declared, … }
  }
  res.json({ ok: true });
});
```

Every request ends one of three ways, the same as with the Cloudflare Worker and the Python
middleware:

| `req.aidr.status` | When | What happens |
|---|---|---|
| `anonymous` | no `Agent-Credential`, `Signature` or `Signature-Input` header | passed on: a person, or a bot that did not identify itself |
| `verified` | the agent's identity was proven and meets your floors | passed on, with the identity in `req.aidr` and `req.agent` |
| refused | it claims to be an agent and is not a valid one / revoked or below your floors / cannot be checked right now | `401` / `403` / `503`, JSON `{ error, reason }` |

`publicOrigin` is your site's own origin (or set `AIDR_PUBLIC_ORIGIN`; a list for several host
names). Signatures are checked against it, never against the Host header a client sends, which
would let a request signed for another site be replayed here. On localhost it can be left out. In
0.1.3 a missing `publicOrigin` logs a warning; from 0.2.0 agents are refused without it.

The registry's keys (hourly) and signed revocation list (every 60 s) are kept current in the
background; nothing on the request path calls the registry. Works with Connect and Node's own
`http` server too: it is a `(req, res, next)` function.

## Options

```js
aidr({
  issuer: 'https://api.evolivcore.com',     // required
  minAgal: 1,                              // floors, 0–3: AgAL, and separately OAL and KAL
  minOal: 0, minKal: 0,
  requiredCapabilities: [],
  mode: 'verified-only',                   // refuse anonymous traffic (401 aidr.edge.agent_required)…
  verifiedOnlyPaths: ['/api/.*'],          // …only here, so people keep the rest of the site
  bypass: ['/health'],                     // never verified
  publicOrigin: 'https://shop.example',    // your origin(s); or AIDR_PUBLIC_ORIGIN (required from 0.2.0)
  maxRevocationAgeSeconds: 660,            // the default; null disables it (not recommended)
});
```

`verified-only` with no `verifiedOnlyPaths` refuses people too. Paths are matched whole, after
decoding and resolving dot segments; a path that cannot be read unambiguously counts as protected.

An audience-bound credential is checked against the site being visited (or `publicOrigin`).
Replay protection is in memory, which is right for one process; several processes behind a
balancer pass a shared `nonceStore` (any object with `check(nonce)` returning `false` for a repeat).

If the registry stays out of reach, agents are refused (`503 aidr.registry.unavailable`) once the
newest revocation list held was signed 11 minutes (660 s) earlier, judged from the list's signed
`iat`; anonymous visitors are unaffected. Every AIDR verifier applies the same limit, so an agent
is never refused by one and admitted by another. `health().revocationIssuedAt` tells you how close
you are: alert well before 660 s.

`await middleware.ready` resolves once the first trust load finished; `middleware.health()`
reports staleness for your monitoring; `middleware.close()` stops the background refresh.

## Lower level

`AgentVerifier`, `TrustStore` / `buildTrustStore`, `TrustSync` and `NonceCache` are exported for
sites that want to own the request flow. They pass the same cross-language test vectors as the
Python, Go and PHP verifiers.
