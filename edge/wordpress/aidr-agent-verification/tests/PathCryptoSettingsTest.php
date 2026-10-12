<?php
declare(strict_types=1);

use AIDR\AidrError;
use AIDR\Crypto;
use AIDR\Encoding;
use AIDR\Path;
use AIDR\Settings;

// ---- path normalisation: the table shared with the Python middleware and the edge worker ----------
foreach (testdata('path-normalisation.json')['cases'] as $case) {
    test('path ' . json_encode($case['raw']) . ' → ' . json_encode($case['normalised']), static function () use ($case) {
        same($case['normalised'], Path::normalise($case['raw']));
    });
}

test('bypass rules are anchored at both ends, alternations included', static function () {
    $rules = array_map([Path::class, 'compile'], ['/health', '/public/.*', 'a|/b']);
    foreach ([['/health', true], ['/healthz', false], ['/x/health', false], ['/public/page', true],
              ['/public/..%2fadmin', false], ['/public/%252e%252e/admin', false], ['/b', true], ['/b/x', false],
              ['/xa', false]] as [$path, $expected]) {
        same($expected, Path::isBypassed($rules, $path), $path);
    }
});

test('an invalid bypass pattern does not compile', static function () {
    same(null, Path::compile('(unclosed'));
    same(null, Path::compile(''));
    check(Path::compile('/a#b') !== null, 'a # in a rule must be escaped, not break the delimiter');
});

// ---- crypto edge cases ------------------------------------------------------------------------------
test('R‖S → DER: leading zeros stripped, high bit padded', static function () {
    $r = "\x00\x00" . str_repeat("\x01", 30);
    $s = "\x80" . str_repeat("\x02", 31);
    $der = Crypto::rawToDer($r . $s);
    same("\x30" . chr(4 + 30 + 33) . "\x02\x1e" . str_repeat("\x01", 30) . "\x02\x21\x00\x80" . str_repeat("\x02", 31), $der);
});

test('an off-curve P-256 point is refused on import', static function () {
    throwsCode(AidrError::INVALID_KEY, fn () => Crypto::importPublicKey([
        'kty' => 'EC', 'crv' => 'P-256',
        'x' => Encoding::b64urlEncode(str_repeat("\x01", 32)), 'y' => Encoding::b64urlEncode(str_repeat("\x02", 32)),
    ]));
});

test('a private key is refused where a public key is required', static function () {
    throwsCode(AidrError::INVALID_KEY, fn () => Crypto::importPublicKey(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'AA', 'd' => 'AA']));
});

test('alg=none and HS256 are refused before any key lookup', static function () {
    foreach (['none', 'HS256', 'RS256'] as $alg) {
        $header = Encoding::b64urlEncode(json_encode(['alg' => $alg, 'typ' => 'aidr-cred+jwt', 'kid' => 'k']));
        throwsCode(AidrError::UNSUPPORTED_ALGORITHM, fn () => Crypto::verifyCompact("$header.e30.", static function () {
            throw new AssertionError('the key must not be looked up');
        }));
    }
});

test('base64url with injected characters is refused, not decoded leniently', static function () {
    throwsCode(AidrError::INVALID_KEY, fn () => Encoding::b64urlDecode('abc$def'));
    throwsCode(AidrError::INVALID_KEY, fn () => Encoding::b64urlDecode('ab+c'));
});

test('a JSON array is not a JSON object', static function () {
    throwsCode(AidrError::MALFORMED_TOKEN, fn () => Encoding::jsonObject('["a"]', 'x'));
});

// ---- settings ----------------------------------------------------------------------------------------
test('settings: an http issuer, a bad origin and a broken bypass rule are refused with reasons', static function () {
    $errors = [];
    $settings = Settings::normalise(['issuer' => 'http://registry.example', 'public_origin' => 'shop.example/x',
        'bypass' => "/health\n(broken"], $errors);
    same('', $settings['issuer']);
    same('', $settings['public_origin']);
    same(['/health'], $settings['bypass']);
    same(3, count($errors));
});

test('settings: floors are clamped to 0-3, lists parsed from text', static function () {
    $settings = Settings::normalise(['issuer' => 'https://registry.example/', 'min_agal' => '9', 'min_oal' => '-1',
        'blocked_domains' => "Bad.Example\nnot a domain", 'blocked_aids' => 'aid:v1:acme:01M3KKNXHERTAF8ZSMZWVDVSF8:rkws, junk']);
    same('https://registry.example', $settings['issuer']);
    same([3, 0], [$settings['min_agal'], $settings['min_oal']]);
    same(['bad.example'], $settings['blocked_domains']);
    same(['aid:v1:acme:01M3KKNXHERTAF8ZSMZWVDVSF8:rkws'], $settings['blocked_aids']);
});
