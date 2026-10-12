# AIDR Agent Verification — WordPress plugin

`aidr-agent-verification/` is the plugin. Copy it to `wp-content/plugins/` and activate it.
Requires WordPress 6.4+, PHP 8.1+ with the `sodium` and `openssl` extensions (both standard).

| Outcome | When | Result |
|---|---|---|
| bypassed | the decoded path fully matches a bypass rule | served, not verified |
| anonymous | none of `Agent-Credential`, `Signature`, `Signature-Input` | served normally |
| verified | identity proven, policy met | served; `aidr_agent()` returns the identity |
| refused | claims to be an agent and is not a valid one / revoked, blocked or below a floor / cannot be checked | 401 / 403 / 503, JSON `{error, reason}` |

The decision runs on `plugins_loaded` at priority −1000: before themes and before other plugins'
`init` handlers, for pages, REST, admin-ajax and feeds alike.

## Setup

1. **Settings → AIDR Agents**: set the registry issuer (https), the AgAL / OAL / KAL floors, and
   bypass rules (one regex per line, matched against the whole decoded path).
2. **Sync every minute from the system crontab** — WP-Cron only runs when someone visits:

   ```
   * * * * * wp --path=/var/www/html aidr sync --quiet
   ```

   Without it the plugin still syncs (see below), but real cron is what keeps revocations at most a
   minute old on a quiet site.
3. A private registry CA goes in `wp-config.php`, never in the database:
   `define('AIDR_REGISTRY_CA_FILE', '/path/to/ca.pem');`

## How it is sealed

- **Verification** is a PHP port of the SDK verifiers (libsodium for Ed25519, OpenSSL for ES256).
  It passes every case and sequence in `sdk/testdata/vectors.json`. AgAL is read from `agal` only.
- **Replay**: `{prefix}aidr_nonces`, keyed by `sha256(aid, nonce)`. A claim deletes the row only if
  expired, then `INSERT IGNORE`s it: the primary key lets exactly one concurrent request win, on any
  number of PHP workers or web servers sharing the database. A nonce is claimed only after the
  request verifies and meets policy; a forged or refused request never occupies one.
- **Trust sync**: the JWKS (hourly) and a complete signed revocation snapshot (every 60 s), pinned
  to the issuer's origin, stored only after they verify and re-verified on every agent request.
  Refreshes hold an atomic lock (`INSERT IGNORE` in the plugin's own state table —
  `add_option()` upserts and is not a lock). Order of preference: `wp aidr sync` from cron; else,
  when a request finds the snapshot due, a refresh *after* its response is sent
  (`fastcgi_finish_request`); else a non-blocking WP-Cron spawn. Agent requests get 503
  `aidr.registry.unavailable` once the snapshot was signed (its `iat`) more than 11 minutes (660 s)
  earlier — the limit every AIDR verifier applies; anonymous traffic is unaffected.
- **Caching**: every response carries `Vary: Agent-Credential, Signature, Signature-Input`, so HTTP
  caches never answer an agent with someone else's copy. Responses to agent requests are
  `Cache-Control: private, no-store` and set `DONOTCACHEPAGE` (WP Super Cache, W3TC, WP Rocket)
  and LiteSpeed's no-cache flag. A PHP page cache (`advanced-cache.php`) answers before any plugin
  runs; the admin page warns when one is active, with what to exclude.
- **Audit log**: one row per request that claimed to be an agent — outcome, reason code, agent,
  organisation, AgAL, method and path. Never the credential, the signature, the query string or the
  client address. Retention is configurable; rows can be turned into blocklist entries in one click.
- **Blocklist** by agent identifier or by the organisation's proven domain (403
  `aidr.verify.blocked_by_site`).

## For theme and plugin code

```php
$agent = aidr_agent();                 // AIDR\Identity: status, aid, organization, orgDomains, agal, oal, kal
if ($agent->isAgent() && in_array('example.com', $agent->orgDomains, true)) { ... }

register_rest_route('shop/v1', '/orders', [
    'methods' => 'GET',
    'permission_callback' => fn () => aidr_require_agent(['min_agal' => 2]),
    'callback' => ...,
]);
```

`GET /wp-json/aidr/v1/whoami` tells a caller what the site verified about it (filter
`aidr_enable_whoami` to turn it off). `do_action('aidr_request_decided', $decision)` fires for every
request.

## Tests

```sh
docker run --rm -v "$PWD:/repo" -w /repo/edge/wordpress/aidr-agent-verification php:8.3-cli php tests/run.php
edge/wordpress/tests/integration/run.sh
```

The first is the WordPress-independent core: the shared vectors, the shared path table, crypto edge
cases, the outcome logic and trust sync. The second runs real WordPress + MariaDB with the plugin, a
registry built from the real AIDR services, and requests signed by `scripts/staging_agent.py`.

Not yet built from the PRD: traffic charts and drag-and-drop rules in the admin UI.
