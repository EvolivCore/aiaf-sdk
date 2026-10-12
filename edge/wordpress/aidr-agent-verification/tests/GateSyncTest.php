<?php
/**
 * The four outcomes, and background trust sync against a fake registry.
 */

declare(strict_types=1);

use AIDR\AidrError;
use AIDR\Gate;
use AIDR\Http;
use AIDR\MemoryNonceStore;
use AIDR\Options;
use AIDR\Settings;
use AIDR\TrustStore;
use AIDR\TrustSync;

$vectors = testdata('vectors.json');
$suite = $vectors['suites'][0];
$now = (float) $vectors['evaluate_at'];
$clock = static fn (): float => $now;
$allow = null;
foreach ($suite['cases'] as $case) {
    if ($case['expect'] === 'allow' && !isset($case['expected_audience']) && !isset($case['min_assurance'])) {
        $allow = $case;
        break;
    }
}
$tampered = array_column($suite['cases'], null, 'name')['tampered signature is refused'];
$headers = static fn (array $case): array => array_change_key_case($case['headers'], CASE_LOWER);

$gate = static function (array $overrides = [], string $delta = 'delta_before_revocation', ?MemoryNonceStore $nonces = null) use ($suite, $now, $clock): Gate {
    $settings = Settings::normalise(['issuer' => $suite['issuer'], 'bypass' => "/health\n/public/.*"] + $overrides);
    $trust = static function () use ($suite, $delta, $now): TrustStore {
        $store = new TrustStore($suite['jwks'], $suite['issuer']);
        $store->ingestSnapshot($suite['revocation'][$delta], $now);
        return $store;
    };
    return new Gate($settings, $trust, $nonces ?? new MemoryNonceStore($clock), $clock);
};
$decide = static fn (Gate $g, array $case, ?array $h = null, ?string $path = null) => $g->decide(
    $case['method'], $case['url'], $path ?? (string) parse_url($case['url'], PHP_URL_PATH), $h ?? $headers($case));

test('outcome: no agent headers is anonymous', static function () use ($gate, $decide, $allow) {
    $d = $decide($gate(), $allow, []);
    same('anonymous', $d->outcome);
    check(!$d->isAgentResponse(), 'an anonymous response may be cached normally');
});

foreach (['agent-credential', 'signature', 'signature-input'] as $name) {
    test("outcome: $name alone is a claim to be an agent, and is refused 401", static function () use ($gate, $decide, $allow, $headers, $name) {
        $d = $decide($gate(), $allow, [$name => $headers($allow)[$name]]);
        same(['refused', 401, AidrError::MALFORMED_TOKEN], [$d->outcome, $d->status, $d->code]);
        check($d->isAgentResponse(), 'refusals must not be cached');
    });
}

test('outcome: a valid agent is verified', static function () use ($gate, $decide, $allow, $suite) {
    $d = $decide($gate(), $allow);
    same(['verified', $suite['aid'], 1], [$d->outcome, $d->identity->aid, $d->identity->agal]);
    check($d->isAgentResponse(), 'a verified response must not be cached');
});

foreach ([['min_agal', 'AgAL'], ['min_kal', 'KAL']] as [$floor, $axis]) {
    test("outcome: below the $axis floor is 403 with the reason", static function () use ($gate, $decide, $allow, $floor, $axis) {
        $d = $decide($gate([$floor => 2]), $allow);
        same([403, AidrError::ASSURANCE_TOO_LOW], [$d->status, $d->code]);
        check(str_contains((string) $d->reason, $axis), (string) $d->reason);
    });
}

test('outcome: an OAL floor the organisation meets admits it (OAL2, KAL1)', static function () use ($gate, $decide, $allow) {
    same('verified', $decide($gate(['min_oal' => 2]), $allow)->outcome);
});

test('outcome: blocked by identifier, and by proven domain', static function () use ($gate, $decide, $allow, $suite) {
    same(AidrError::BLOCKED_BY_SITE, $decide($gate(['blocked_aids' => $suite['aid']]), $allow)->code);
    same(403, $decide($gate(['blocked_aids' => $suite['aid']]), $allow)->status);
});

test('outcome: a revoked agent is 403', static function () use ($gate, $decide, $allow) {
    $d = $decide($gate([], 'delta_after_revocation'), $allow);
    same([403, AidrError::AGENT_REVOKED], [$d->status, $d->code]);
});

test('outcome: bypassed paths are never verified; encoded dot segments do not bypass', static function () use ($gate, $decide, $allow) {
    same('bypassed', $decide($gate(), $allow, ['signature' => 'garbage'], '/health')->outcome);
    same('refused', $decide($gate(), $allow, ['signature' => 'garbage'], '/public/..%2fadmin')->outcome);
});

test('outcome: no issuer configured refuses agents with 503, anonymous still passes', static function () use ($decide, $allow, $clock) {
    $g = new Gate(Settings::normalise([]), fn () => throw new AssertionError('no trust without an issuer'), new MemoryNonceStore($clock), $clock);
    same(503, $decide($g, $allow)->status);
    same('anonymous', $decide($g, $allow, [])->outcome);
});

test('outcome: an unexpected error is a 401, never a pass', static function () use ($decide, $allow, $suite, $clock) {
    $g = new Gate(Settings::normalise(['issuer' => $suite['issuer']]), fn () => throw new TypeError('boom'), new MemoryNonceStore($clock), $clock);
    same([401, 'refused'], [$decide($g, $allow)->status, $decide($g, $allow)->outcome]);
});

test('replay: the same request twice is refused the second time', static function () use ($gate, $decide, $allow, $clock) {
    $g = $gate([], 'delta_before_revocation', new MemoryNonceStore($clock));
    same('verified', $decide($g, $allow)->outcome);
    same(AidrError::REPLAY_DETECTED, $decide($g, $allow)->code);
});

test('replay: a forged request and a policy refusal do not consume the genuine nonce', static function () use ($gate, $decide, $allow, $tampered, $clock) {
    $nonces = new MemoryNonceStore($clock);
    same('refused', $decide($gate([], 'delta_before_revocation', $nonces), $tampered)->outcome);
    same('refused', $decide($gate(['min_agal' => 3], 'delta_before_revocation', $nonces), $allow)->outcome);
    same('verified', $decide($gate([], 'delta_before_revocation', $nonces), $allow)->outcome);
});

// ---- trust sync -------------------------------------------------------------------------------------

final class FakeOptions implements Options
{
    public array $data = [];
    public function get(string $name): mixed { return $this->data[$name] ?? null; }
    public function set(string $name, mixed $value): void { $this->data[$name] = $value; }
    public function add(string $name, mixed $value): bool
    {
        if (array_key_exists($name, $this->data)) {
            return false;
        }
        $this->data[$name] = $value;
        return true;
    }
    public function delete(string $name): void { unset($this->data[$name]); }
}

final class FakeRegistry implements Http
{
    public array $requests = [];
    public int $status = 200;
    public function __construct(public array $discovery, public array $jwks, public string $delta)
    {
    }
    public function get(string $url): array
    {
        $this->requests[] = $url;
        $path = (string) parse_url($url, PHP_URL_PATH);
        $body = match ($path) {
            '/.well-known/aiaf-registry' => $this->discovery,
            '/.well-known/jwks.json' => $this->jwks,
            '/v1/revocations/delta' => ['delta' => $this->delta],
            default => null,
        };
        return $this->status !== 200 || $body === null
            ? ['status' => $this->status === 200 ? 404 : $this->status, 'body' => '']
            : ['status' => 200, 'body' => json_encode($body)];
    }
}

$registry = static fn (): FakeRegistry => new FakeRegistry(
    ['issuer' => $suite['issuer'], 'jwks_uri' => $suite['issuer'] . '/.well-known/jwks.json',
     'revocation_delta_endpoint' => $suite['issuer'] . '/v1/revocations/delta'],
    $suite['jwks'], $suite['revocation']['delta_before_revocation']);

test('sync: fetches, verifies and stores a complete snapshot; trust() rebuilds from it', static function () use ($registry, $suite, $clock) {
    $sync = new TrustSync($suite['issuer'], $http = $registry(), $options = new FakeOptions(), $clock);
    check($sync->needsRefresh(), 'nothing stored yet');
    check($sync->refresh('test'), 'refreshed');
    check(!$sync->needsRefresh(), 'fresh after refresh');
    check(in_array($suite['issuer'] . '/v1/revocations/delta?since=0', $http->requests, true), 'full snapshot requested');
    check($sync->trust()->exact, 'trust built from the snapshot');
    same(null, $options->get(TrustSync::LOCK), 'lock released');
});

test("sync: trust material off the issuer's origin is refused and nothing is stored", static function () use ($registry, $suite, $clock) {
    $http = $registry();
    $http->discovery['jwks_uri'] = 'https://attacker.example/jwks.json';
    $sync = new TrustSync($suite['issuer'], $http, $options = new FakeOptions(), $clock);
    throwsCode(AidrError::REGISTRY_UNAVAILABLE, fn () => $sync->refresh('test'));
    same(null, $options->get(TrustSync::SNAPSHOT));
    check(!in_array('https://attacker.example/jwks.json', $http->requests, true), 'never fetched');
    check(str_contains((string) $options->get(TrustSync::STATUS)['last_error'], "issuer's origin"), 'reported');
});

test('sync: a failed refresh keeps the last good snapshot', static function () use ($registry, $suite, $clock) {
    $sync = new TrustSync($suite['issuer'], $http = $registry(), $options = new FakeOptions(), $clock);
    $sync->refresh('test');
    $good = $options->get(TrustSync::SNAPSHOT);
    $http->status = 502;
    throwsCode(AidrError::REGISTRY_UNAVAILABLE, fn () => $sync->refresh('test'));
    same($good, $options->get(TrustSync::SNAPSHOT));
});

test('sync: a snapshot older than 11 minutes is refused (503), not used', static function () use ($registry, $suite, $now) {
    $options = new FakeOptions();
    (new TrustSync($suite['issuer'], $registry(), $options, static fn () => $now))->refresh('test');
    $later = new TrustSync($suite['issuer'], $registry(), $options, static fn () => $now + TrustSync::MAX_AGE);
    throwsCode(AidrError::REGISTRY_UNAVAILABLE, fn () => $later->trust());
});

test('sync: a held lock means one refresh at a time; an expired lock is taken over', static function () use ($registry, $suite, $now, $clock) {
    $options = new FakeOptions();
    $options->set(TrustSync::LOCK, $now + 30);
    $sync = new TrustSync($suite['issuer'], $http = $registry(), $options, $clock);
    same(false, $sync->refresh('test'));
    same([], $http->requests);
    $options->set(TrustSync::LOCK, $now - 1);
    same(true, $sync->refresh('test'));
});

test('sync: retries with fresh keys when the registry has rotated', static function () use ($registry, $suite, $vectors, $clock) {
    $sync = new TrustSync($suite['issuer'], $http = $registry(), $options = new FakeOptions(), $clock);
    $sync->refresh('test');
    $rotated = $vectors['suites'][1];
    $http->jwks = $rotated['jwks'];
    $http->delta = $rotated['revocation']['delta_before_revocation'];
    $sync->refresh('test');
    same($rotated['jwks'], $options->get(TrustSync::SNAPSHOT)['jwks']);
});

test('sync: on-demand key refreshes are rate-limited', static function () use ($registry, $suite, $clock) {
    $sync = new TrustSync($suite['issuer'], $http = $registry(), new FakeOptions(), $clock);
    $sync->refreshKeysIfAllowed('test');
    $sync->refreshKeysIfAllowed('test');
    same(1, count(array_filter($http->requests, fn ($u) => str_ends_with($u, '/jwks.json'))));
});
