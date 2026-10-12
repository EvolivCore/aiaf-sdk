<?php
/**
 * The decision for one request, independent of WordPress.
 *
 *   bypassed  — the normalised path fully matches a bypass rule. Not verified.
 *   anonymous — none of Agent-Credential / Signature / Signature-Input is present. Passed through.
 *   verified  — identity proven, policy met.
 *   refused   — claims to be an agent and is not a valid one (401), is revoked, blocked or outside
 *               policy (403), or cannot be checked right now (503).
 *
 * A request carrying SOME of the agent headers is a claim to be an agent and is judged as one;
 * letting a failed agent fall back to "anonymous" would make every refusal optional.
 */

declare(strict_types=1);

namespace AIDR;

final class Decision
{
    public function __construct(
        public readonly string $outcome,
        public readonly Identity $identity,
        public readonly int $status = 200,
        public readonly ?string $code = null,
        public readonly ?string $reason = null,
        /** @var array<string, mixed> */
        public readonly array $context = [],
    ) {
    }

    /** Did the caller present itself as an agent? Such responses must never be shared by a cache. */
    public function isAgentResponse(): bool
    {
        return $this->outcome === 'verified' || $this->outcome === 'refused';
    }
}

final class Gate
{
    public const AGENT_HEADERS = ['agent-credential', 'signature', 'signature-input'];
    private const MAX_SIGNATURE_AGE = 300;

    /**
     * @param array<string, mixed> $settings normalised (Settings::normalise)
     * @param \Closure(): TrustStore $trust throws AidrError when trust is unavailable
     */
    public function __construct(
        private readonly array $settings,
        private readonly \Closure $trust,
        private readonly NonceStore $nonces,
        private readonly \Closure $clock,
    ) {
    }

    /** @param array<string, string> $headers lower-cased names */
    public function decide(string $method, string $url, string $rawPath, array $headers): Decision
    {
        $bypass = array_values(array_filter(array_map([Path::class, 'compile'], $this->settings['bypass'])));
        if (Path::isBypassed($bypass, $rawPath)) {
            return new Decision('bypassed', new Identity('bypassed'));
        }
        $claimsToBeAgent = false;
        foreach (self::AGENT_HEADERS as $name) {
            $claimsToBeAgent = $claimsToBeAgent || array_key_exists($name, $headers);
        }
        if (!$claimsToBeAgent) {
            return new Decision('anonymous', new Identity('anonymous'));
        }

        try {
            if ($this->settings['issuer'] === '') {
                throw new AidrError(AidrError::MISCONFIGURED, 'no registry issuer is configured');
            }
            $now = ($this->clock)();
            $origin = parse_url($url, PHP_URL_SCHEME) . '://' . parse_url($url, PHP_URL_HOST)
                . (parse_url($url, PHP_URL_PORT) ? ':' . parse_url($url, PHP_URL_PORT) : '');
            $identity = Verifier::verifyAgent(($this->trust)(), [
                'expected_issuer' => $this->settings['issuer'],
                'expected_audience' => $this->settings['public_origin'] !== '' ? $this->settings['public_origin'] : $origin,
                'min_agal' => $this->settings['min_agal'],
                'min_oal' => $this->settings['min_oal'],
                'min_kal' => $this->settings['min_kal'],
                'required_capabilities' => $this->settings['required_capabilities'],
                'max_upheld_abuse_reports' => $this->settings['max_upheld_abuse_reports'],
                'blocked_aids' => $this->settings['blocked_aids'],
                'blocked_domains' => $this->settings['blocked_domains'],
            ], $method, $url, $headers, $now, function (string $aid, string $nonce, int $created) use ($now): bool {
                // Remember the nonce exactly as long as its signature could still be accepted.
                $ttl = max(1, (int) ceil($created + self::MAX_SIGNATURE_AGE - $now) + 1);
                return $this->nonces->claim(hash('sha256', $aid . "\x1f" . $nonce), $ttl);
            });
            return new Decision('verified', $identity);
        } catch (AidrError $error) {
            return new Decision('refused', new Identity('anonymous'), $error->httpStatus(), $error->errorCode,
                $error->getMessage(), $error->context);
        } catch (\Throwable) {
            // Never a pass and never a 500: an input we did not anticipate is an unverified request.
            return new Decision('refused', new Identity('anonymous'), 401, AidrError::MALFORMED_TOKEN, 'request could not be verified');
        }
    }
}
