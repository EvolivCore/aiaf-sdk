<?php
/**
 * A dependency-free test runner: `php tests/run.php`. Loads the plugin's WordPress-independent core
 * and every tests/*Test.php, runs each registered test, and exits non-zero on any failure.
 */

declare(strict_types=1);

$root = dirname(__DIR__);
foreach (['Errors', 'Encoding', 'Crypto', 'Verifier', 'Path', 'NonceStore', 'TrustSync', 'Settings', 'Gate'] as $file) {
    require_once "$root/src/$file.php";
}

const TESTDATA = __DIR__ . '/../../../../sdk/testdata';

/** @var array<string, callable> */
$GLOBALS['aidr_tests'] = [];

function test(string $name, callable $body): void
{
    $GLOBALS['aidr_tests'][$name] = $body;
}

function check(bool $condition, string $message = 'assertion failed'): void
{
    if (!$condition) {
        throw new AssertionError($message);
    }
}

function same(mixed $expected, mixed $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        throw new AssertionError(trim("$message expected " . var_export($expected, true) . ', got ' . var_export($actual, true)));
    }
}

function throwsCode(string $code, callable $body): void
{
    try {
        $body();
    } catch (AIDR\AidrError $error) {
        same($code, $error->errorCode, $error->getMessage());
        return;
    }
    throw new AssertionError("expected AidrError $code, nothing was thrown");
}

function testdata(string $name): array
{
    return json_decode((string) file_get_contents(TESTDATA . "/$name"), true, 512, JSON_THROW_ON_ERROR);
}

foreach (glob(__DIR__ . '/*Test.php') as $file) {
    require $file;
}

$failed = 0;
foreach ($GLOBALS['aidr_tests'] as $name => $body) {
    try {
        $body();
        echo "  ok    $name\n";
    } catch (Throwable $error) {
        $failed++;
        echo "  FAIL  $name\n        " . get_class($error) . ': ' . $error->getMessage() . "\n";
    }
}
$total = count($GLOBALS['aidr_tests']);
echo "\n" . ($total - $failed) . "/$total passed\n";
exit($failed === 0 ? 0 : 1);
