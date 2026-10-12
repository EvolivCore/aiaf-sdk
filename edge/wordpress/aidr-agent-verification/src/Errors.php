<?php
/**
 * The error taxonomy: the same codes as the Python, Node, Go and edge implementations.
 * Codes are the contract; messages are for humans.
 */

declare(strict_types=1);

namespace AIDR;

final class AidrError extends \RuntimeException
{
    public const REGISTRY_UNAVAILABLE = 'aidr.registry.unavailable';
    public const MALFORMED_TOKEN = 'aidr.crypto.malformed_token';
    public const SIGNATURE_INVALID = 'aidr.crypto.signature_invalid';
    public const UNSUPPORTED_ALGORITHM = 'aidr.crypto.unsupported_algorithm';
    public const INVALID_KEY = 'aidr.crypto.invalid_key';
    public const CREDENTIAL_EXPIRED = 'aidr.verify.credential_expired';
    public const CREDENTIAL_NOT_YET_VALID = 'aidr.verify.credential_not_yet_valid';
    public const AGENT_REVOKED = 'aidr.verify.agent_revoked';
    public const UNKNOWN_ISSUER = 'aidr.verify.unknown_issuer';
    public const REPLAY_DETECTED = 'aidr.verify.replay_detected';
    public const SIGNATURE_TOO_OLD = 'aidr.verify.signature_too_old';
    public const COMPONENT_MISMATCH = 'aidr.verify.covered_component_mismatch';
    public const ASSURANCE_TOO_LOW = 'aidr.verify.assurance_too_low';
    public const CAPABILITY_DENIED = 'aidr.verify.capability_denied';
    public const POLICY_VIOLATION = 'aidr.registry.policy_violation';
    /** This site has blocked the agent or its organisation. */
    public const BLOCKED_BY_SITE = 'aidr.verify.blocked_by_site';
    public const MISCONFIGURED = 'aidr.edge.misconfigured';

    /** Refusals meaning "you are an agent, and not one this site will serve". */
    private const FORBIDDEN = [
        self::AGENT_REVOKED, self::ASSURANCE_TOO_LOW, self::CAPABILITY_DENIED,
        self::POLICY_VIOLATION, self::BLOCKED_BY_SITE,
    ];

    /** @param array<string, mixed> $context */
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly array $context = [],
    ) {
        parent::__construct($message);
    }

    /** 401 for a failed identity, 403 for a refused one, 503 when it cannot be decided. */
    public function httpStatus(): int
    {
        if ($this->errorCode === self::REGISTRY_UNAVAILABLE || $this->errorCode === self::MISCONFIGURED) {
            return 503;
        }
        return in_array($this->errorCode, self::FORBIDDEN, true) ? 403 : 401;
    }
}
