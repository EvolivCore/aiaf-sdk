<?php
/**
 * sdk/testdata/vectors.json, replayed against the PHP port: every case and sequence must reach the
 * same verdict, with the same error code, as the Python, Node, Go and edge implementations.
 */

declare(strict_types=1);

use AIDR\AidrError;
use AIDR\Gate;
use AIDR\MemoryNonceStore;
use AIDR\Settings;
use AIDR\TrustStore;
use AIDR\Verifier;

$vectors = testdata('vectors.json');
$now = (float) $vectors['evaluate_at'];
$clock = static fn (): float => $now;

$trustFor = static function (array $suite, string $delta = 'delta_before_revocation') use ($now): TrustStore {
    $trust = new TrustStore($suite['jwks'], $suite['issuer']);
    $trust->ingestSnapshot($suite['revocation'][$delta], $now);
    return $trust;
};
$lower = static fn (array $headers): array => array_change_key_case($headers, CASE_LOWER);

$verify = static function (TrustStore $trust, array $suite, array $case, MemoryNonceStore $nonces) use ($now, $lower) {
    return Verifier::verifyAgent($trust, [
        'expected_issuer' => $suite['issuer'],
        'expected_audience' => $case['expected_audience'] ?? null,
        'min_agal' => $case['min_assurance'] ?? 0,
    ], $case['method'], $case['url'], $lower($case['headers']), (float) ($case['evaluate_at'] ?? $now),
        static fn (string $aid, string $nonce): bool => $nonces->claim(hash('sha256', "$aid\x1f$nonce"), 600));
};

$expectVerdict = static function (callable $run, array $suite, string $expect, ?string $code): void {
    try {
        $identity = $run();
    } catch (AidrError $error) {
        same('deny', $expect, "denied with {$error->errorCode}: {$error->getMessage()};");
        if ($code !== null) {
            same($code, $error->errorCode);
        }
        return;
    }
    same('allow', $expect, 'accepted;');
    same($suite['aid'], $identity->aid);
    same($suite['organization'], $identity->organization);
    same([$suite['expected_agal'], $suite['expected_oal'], $suite['expected_kal']], [$identity->agal, $identity->oal, $identity->kal]);
};

foreach ($vectors['suites'] as $suite) {
    $alg = $suite['algorithm'];
    $byName = array_column($suite['cases'], null, 'name');

    // freshness_cases: trust loaded at evaluate_at, each verified at its own, later instant.
    foreach (array_merge($suite['cases'], $suite['freshness_cases']) as $case) {
        test("conformance $alg: {$case['name']}", static function () use ($suite, $case, $trustFor, $verify, $expectVerdict, $clock) {
            $expectVerdict(fn () => $verify($trustFor($suite), $suite, $case, new MemoryNonceStore($clock)),
                $suite, $case['expect'], $case['expect_code'] ?? null);
        });
    }

    foreach ($suite['sequences'] as $sequence) {
        test("conformance $alg: sequence: {$sequence['name']}", static function () use ($suite, $sequence, $byName, $trustFor, $verify, $expectVerdict, $clock) {
            $trust = $trustFor($suite);
            $nonces = new MemoryNonceStore($clock);
            foreach ($sequence['steps'] as $step) {
                $case = $byName[$step['case']];
                $expectVerdict(fn () => $verify($trust, $suite, $case, $nonces), $suite, $step['expect'], $step['expect_code'] ?? null);
            }
        });
    }

    test("conformance $alg: a stored snapshot is rebuilt after its delta exp; its age is judged from iat", static function () use ($suite, $now) {
        $later = $now + 600;
        throwsCode(AidrError::CREDENTIAL_EXPIRED, fn () => (new TrustStore($suite['jwks'], $suite['issuer']))
            ->ingestSnapshot($suite['revocation']['delta_before_revocation'], $later));
        $trust = new TrustStore($suite['jwks'], $suite['issuer']);
        $trust->ingestSnapshot($suite['revocation']['delta_before_revocation'], $later, true);
        same($now, $trust->issuedAt);
        same(Verifier::MAX_REVOCATION_AGE_SECONDS, $suite['max_revocation_age_seconds']);
    });

    test("conformance $alg: a revoked agent is refused", static function () use ($suite, $trustFor, $verify, $clock) {
        $first = $suite['cases'][0];
        throwsCode(AidrError::AGENT_REVOKED, fn () => $verify($trustFor($suite, 'delta_after_revocation'), $suite, $first, new MemoryNonceStore($clock)));
    });

    test("conformance $alg: a feed with a gap is not a snapshot", static function () use ($suite, $now) {
        $trust = new TrustStore($suite['jwks'], $suite['issuer']);
        throwsCode(AidrError::REGISTRY_UNAVAILABLE, fn () => $trust->ingestSnapshot($suite['revocation']['delta_with_gap'], $now));
    });

    test("conformance $alg: no revocation state fails closed", static function () use ($suite, $verify, $clock) {
        $trust = new TrustStore($suite['jwks'], $suite['issuer']);
        throwsCode(AidrError::REGISTRY_UNAVAILABLE, fn () => $verify($trust, $suite, $suite['cases'][0], new MemoryNonceStore($clock)));
    });

    // The same cases through the Gate: the outcome and HTTP status a WordPress site would produce.
    foreach ($suite['cases'] as $case) {
        test("gate $alg: {$case['name']}", static function () use ($suite, $case, $trustFor, $clock, $lower) {
            $settings = Settings::normalise([
                'issuer' => $suite['issuer'],
                'public_origin' => $case['expected_audience'] ?? '',
                'min_agal' => $case['min_assurance'] ?? 0,
            ]);
            $gate = new Gate($settings, fn () => $trustFor($suite), new MemoryNonceStore($clock), $clock);
            $decision = $gate->decide($case['method'], $case['url'], (string) parse_url($case['url'], PHP_URL_PATH), $lower($case['headers']));
            if ($case['expect'] === 'allow') {
                same('verified', $decision->outcome, (string) $decision->code);
                same($suite['aid'], $decision->identity->aid);
            } else {
                same('refused', $decision->outcome);
                check(in_array($decision->status, [401, 403], true), "status {$decision->status}");
                if (isset($case['expect_code'])) {
                    same($case['expect_code'], $decision->code);
                }
            }
        });
    }
}
