#!/usr/bin/env bash
# WordPress integration test: real WordPress (Apache, PHP 8.3) and MariaDB with the plugin active, a
# local registry built from the real AIDR services, and requests signed by the CLI mock agent.
#
#   edge/wordpress/tests/integration/run.sh          # KEEP=1 leaves the containers running
set -euo pipefail
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && (pwd -W 2>/dev/null || pwd))"
P=aidr-wpit
NET=$P-net
DB_ENV=(-e WORDPRESS_DB_HOST=db -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp
        -e "WORDPRESS_CONFIG_EXTRA=define('AIDR_REGISTRY_CA_FILE', '/shared/registry-ca.pem');")

cleanup() {
  docker rm -f $P-db $P-registry $P-wp >/dev/null 2>&1 || true
  docker volume rm $P-shared $P-html >/dev/null 2>&1 || true
  docker network rm $NET >/dev/null 2>&1 || true
}
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup

say() { printf '\n== %s\n' "$*"; }
wp() { docker run --rm --network $NET --volumes-from $P-wp --user 33:33 "${DB_ENV[@]}" wordpress:cli-php8.3 wp "$@"; }
checks() { docker exec $P-registry python /repo/edge/wordpress/tests/integration/checks.py "$@"; }
settings() { wp option update aidr_settings "$1" --format=json >/dev/null; }
wait_for() {  # name, command...
  local name=$1; shift
  for _ in $(seq 1 120); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done
  echo "timed out waiting for $name" >&2; return 1
}

say "starting MariaDB, the registry and WordPress"
docker network create $NET >/dev/null
docker volume create $P-shared >/dev/null
docker volume create $P-html >/dev/null
docker run -d --name $P-db --network $NET --network-alias db -e MARIADB_ROOT_PASSWORD=root \
  -e MARIADB_DATABASE=wp -e MARIADB_USER=wp -e MARIADB_PASSWORD=wp mariadb:11 >/dev/null
docker run -d --name $P-registry --network $NET --network-alias registry -v "$REPO:/repo:ro" \
  -v $P-shared:/shared python:3.12-slim sh -c \
  'pip install -q --root-user-action=ignore --disable-pip-version-check -r /repo/requirements.txt && exec python /repo/edge/wordpress/tests/integration/registry.py' >/dev/null
docker run -d --name $P-wp --network $NET --network-alias wordpress -v $P-html:/var/www/html \
  -v "$REPO/edge/wordpress/aidr-agent-verification:/var/www/html/wp-content/plugins/aidr-agent-verification:ro" \
  -v $P-shared:/shared:ro "${DB_ENV[@]}" wordpress:6-php8.3-apache >/dev/null
wait_for registry docker exec $P-registry python -c "import ssl,socket; socket.create_connection(('localhost', 8443), 2)"
wait_for wordpress docker exec $P-wp sh -c 'test -f /var/www/html/wp-config.php && curl -fs -o /dev/null localhost/wp-admin/install.php'

say "installing WordPress and activating the plugin"
wp core install --url=http://wordpress --title="AIDR integration" --admin_user=admin \
  --admin_password="$(head -c 24 /dev/urandom | base64)" --admin_email=admin@example.com --skip-email >/dev/null
wp rewrite structure '/%postname%/' >/dev/null
wp plugin activate aidr-agent-verification
wp db query "SHOW TABLES LIKE 'wp_aidr_%'" --skip-column-names
BASE='"issuer":"https://registry:8443","bypass":["/robots\\.txt"]'
settings "{$BASE}"
wp aidr sync

say "three outcomes, cache headers, replay, bypass"
checks outcomes

say "policy: floors (this agent is AgAL1: OAL1, KAL1)"
settings "{$BASE,\"min_agal\":2}"
checks expect aidr.verify.assurance_too_low
settings "{$BASE,\"min_kal\":2}"
checks expect aidr.verify.assurance_too_low
settings "{$BASE,\"min_agal\":1,\"min_oal\":1,\"min_kal\":1}"
checks verified

say "manual blocklist"
settings "{$BASE,\"blocked_aids\":[\"$(docker exec $P-registry cat /shared/aid.txt)\"]}"
checks expect aidr.verify.blocked_by_site
settings "{$BASE}"

say "revocation: revoked at the registry, picked up by the next sync"
checks revoke
wp aidr sync --quiet
checks revoked

say "audit log: outcomes recorded, nothing replayable stored"
wp db query "SELECT outcome, status, code, method, path FROM wp_aidr_log ORDER BY id" --skip-column-names
LEAKS=$(wp db query "SELECT COUNT(*) FROM wp_aidr_log WHERE CONCAT(path, code, aid) REGEXP 'eyJ|sig1=|nonce='" --skip-column-names)
NONHASH=$(wp db query "SELECT COUNT(*) FROM wp_aidr_nonces WHERE nonce_key NOT REGEXP '^[0-9a-f]{64}$'" --skip-column-names)
[ "$LEAKS" = 0 ] && [ "$NONHASH" = 0 ] && echo "PASS  no credential, signature or raw nonce stored" \
  || { echo "FAIL  leaks=$LEAKS non-hash nonce keys=$NONHASH"; exit 1; }

say "admin page"
wp eval 'require_once ABSPATH . "wp-admin/includes/admin.php"; wp_set_current_user(1);
  ob_start(); AIDR\WP\Admin::render(); $h = ob_get_clean();
  $want = ["AgAL floor", "OAL floor", "KAL floor", "Registry sync", "aidr.verify.replay_detected", ">Block<", "Sync now"];
  $missing = array_filter($want, fn ($w) => !str_contains($h, $w));
  echo $missing ? "FAIL  admin page is missing: " . implode(", ", $missing) . "\n" : "PASS  admin page renders policy, sync status and the decision log\n";'

say "done"
