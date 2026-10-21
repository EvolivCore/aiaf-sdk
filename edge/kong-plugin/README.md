# AIDR for Kong Gateway

The `aidr` plugin verifies AI agents' [AIDR](https://aidr.evolivcore.com) identities in Kong's access
phase, before a request reaches your service: the registry's signature on the agent's credential,
the agent's RFC 9421 signature on this exact request, revocation, replay and your floors. It runs
on Kong's JavaScript plugin server and uses the published verifier, `@evoliv/aidr-verifier`,
unchanged: the code that passes the shared AIAF conformance vectors. Apache-2.0.

| Outcome | When | Kong |
|---|---|---|
| anonymous | no `Agent-Credential`, `Signature` or `Signature-Input` | proxied, `X-AIDR-Status: anonymous`; 401 on verified-only paths |
| verified | identity proven, floors met | proxied with `X-AIDR-Status: verified`, `X-AIDR-Agent`, `X-AIDR-Organization`, `X-AIDR-Org-Domains`, `X-AIDR-AgAL`, `X-AIDR-OAL`, `X-AIDR-KAL`, `X-AIDR-Capabilities` |
| refused | not a valid agent / revoked or below the floors / cannot be checked | 401 / 403 / 503, JSON `{error, reason}` |

`X-AIDR-*` headers sent by a client are removed first, so your service can trust the ones it gets.

## Install (Kong 3.x)

```sh
npm install -g kong-pdk                                   # Kong's JavaScript plugin server
mkdir -p /usr/local/kong/js-plugins && cd /usr/local/kong/js-plugins
npm install @evoliv/kong-plugin-aidr && cp node_modules/@evoliv/kong-plugin-aidr/aidr.js .
```

`kong.conf` (or the same as `KONG_*` environment variables):

```
plugins = bundled,aidr
pluginserver_names = js
pluginserver_js_socket = /usr/local/kong/js_pluginserver.sock
pluginserver_js_start_cmd = /usr/local/bin/kong-js-pluginserver --plugins-directory /usr/local/kong/js-plugins
pluginserver_js_query_cmd = /usr/local/bin/kong-js-pluginserver --plugins-directory /usr/local/kong/js-plugins --dump-all-plugins
```

Enable it on a service or route:

```sh
curl -X POST http://localhost:8001/services/data-api/plugins \
  --data name=aidr \
  --data config.public_origin=https://api.example.com \
  --data config.min_agal=1
```

## Configuration

| Field | |
|---|---|
| `public_origin` | required: your API's origin(s) as agents call it, comma-separated. Signatures are judged against it, never against the Host header a client sends |
| `mode` | `open` (default) or `verified-only` |
| `verified_only_paths` | whole-path regexes verified-only applies to (empty: every path) |
| `bypass` | paths never verified |
| `min_agal`, `min_oal`, `min_kal` | floors, 0–3 |
| `required_capabilities` | e.g. `["http.read"]` |
| `issuer` | default `https://api.evolivcore.com` |

## Performance and clusters

- Nothing on the request path calls the registry: keys (hourly) and the signed revocation list
  (every minute) are refreshed in the background. Verification is two signature checks, well
  under a millisecond of CPU. People's requests skip it entirely.
- Kong talks to the JavaScript plugin server over a local socket, a few calls per request: an
  overhead native Lua plugins do not have. We have not measured it yet; measure it on your own
  traffic before relying on a number.
- Replay protection is in the plugin server's memory, shared by all workers of one Kong node.
  With several Kong nodes, a signed request replayed to another node within its five-minute window
  is not detected. Route agent traffic consistently (for example, hash on the client), or run
  the verification at one tier.

## Test

```sh
npm test      # every shared vector case through a fake Kong PDK; replays, spoofed headers, verified-only
```
