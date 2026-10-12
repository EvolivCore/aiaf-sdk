import { timingSafeEqual } from 'node:crypto';

/**
 * Shared utilities: the error taxonomy and base64url.
 *
 * The error codes are identical to the Python SDK's, because a relying party running both (a Node
 * edge and a Python origin, say) must be able to branch on one set of codes. Messages are for
 * humans and may be reworded; codes are the contract.
 */

/** Base class. Every AIDR error carries a stable machine-readable `code`. */
export class AidrError extends Error {
  constructor(code, message, context = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.context = context;
  }
}

/** The identity is not valid. A denial. */
export class VerificationError extends AidrError {}

/** We could not determine whether the identity is valid. NOT a denial — see the SDK README. */
export class RegistryUnavailable extends AidrError {
  constructor(message, context = {}) {
    super('aidr.registry.unavailable', message, context);
  }
}

export class MalformedToken extends AidrError {
  constructor(message, context = {}) {
    super('aidr.crypto.malformed_token', message, context);
  }
}

export class SignatureInvalid extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.crypto.signature_invalid', message, context);
  }
}

export class UnsupportedAlgorithm extends AidrError {
  constructor(message, context = {}) {
    super('aidr.crypto.unsupported_algorithm', message, context);
  }
}

export class InvalidKey extends AidrError {
  constructor(message, context = {}) {
    super('aidr.crypto.invalid_key', message, context);
  }
}

export class CredentialExpired extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.credential_expired', message, context);
  }
}

export class CredentialNotYetValid extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.credential_not_yet_valid', message, context);
  }
}

export class AgentRevoked extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.agent_revoked', message, context);
  }
}

export class UnknownIssuer extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.unknown_issuer', message, context);
  }
}

export class ReplayDetected extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.replay_detected', message, context);
  }
}

export class SignatureTooOld extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.signature_too_old', message, context);
  }
}

/**
 * The signature is valid but does not cover the request that was actually received.
 *
 * The attack naive implementations miss: a signature over a *different* method, host or path
 * verifies perfectly well against the right key.
 */
export class CoveredComponentMismatch extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.covered_component_mismatch', message, context);
  }
}

export class AssuranceTooLow extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.assurance_too_low', message, context);
  }
}

export class CapabilityDenied extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.verify.capability_denied', message, context);
  }
}

export class PolicyViolation extends VerificationError {
  constructor(message, context = {}) {
    super('aidr.registry.policy_violation', message, context);
  }
}

/** Decode unpadded base64url, rejecting anything outside the alphabet. */
export function b64urlDecode(text) {
  if (typeof text !== 'string') {
    throw new InvalidKey('base64url input must be a string');
  }
  // Node's Buffer decoder is lenient: it silently drops characters outside the alphabet, so a
  // token with injected junk would decode to something plausible rather than being rejected.
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new InvalidKey('invalid base64url encoding');
  }
  return Buffer.from(text, 'base64url');
}

export function b64urlEncode(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

/** Constant-time comparison, for anything an attacker can submit repeatedly. */
export function timingSafeEqualStrings(left, right) {
  const a = Buffer.from(String(left), 'utf8');
  const b = Buffer.from(String(right), 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
