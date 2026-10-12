/**
 * The error taxonomy, with the same codes as the Python, Node and Go SDKs. Codes are the contract;
 * messages are for humans.
 */

export class AidrError extends Error {
  constructor(code, message, context = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.context = context;
  }
}

const define = (name, code) => ({
  [name]: class extends AidrError {
    constructor(message, context = {}) {
      super(code, message, context);
      this.name = name;
    }
  },
})[name];

export const RegistryUnavailable = define('RegistryUnavailable', 'aidr.registry.unavailable');
export const MalformedToken = define('MalformedToken', 'aidr.crypto.malformed_token');
export const SignatureInvalid = define('SignatureInvalid', 'aidr.crypto.signature_invalid');
export const UnsupportedAlgorithm = define('UnsupportedAlgorithm', 'aidr.crypto.unsupported_algorithm');
export const InvalidKey = define('InvalidKey', 'aidr.crypto.invalid_key');
export const CredentialExpired = define('CredentialExpired', 'aidr.verify.credential_expired');
export const CredentialNotYetValid = define('CredentialNotYetValid', 'aidr.verify.credential_not_yet_valid');
export const AgentRevoked = define('AgentRevoked', 'aidr.verify.agent_revoked');
export const UnknownIssuer = define('UnknownIssuer', 'aidr.verify.unknown_issuer');
export const ReplayDetected = define('ReplayDetected', 'aidr.verify.replay_detected');
export const SignatureTooOld = define('SignatureTooOld', 'aidr.verify.signature_too_old');
export const CoveredComponentMismatch = define('CoveredComponentMismatch',
  'aidr.verify.covered_component_mismatch');
export const AssuranceTooLow = define('AssuranceTooLow', 'aidr.verify.assurance_too_low');
export const CapabilityDenied = define('CapabilityDenied', 'aidr.verify.capability_denied');
export const PolicyViolation = define('PolicyViolation', 'aidr.registry.policy_violation');
/** The request did not come through the edge, or its context was altered on the way. */
export const EdgeContextInvalid = define('EdgeContextInvalid', 'aidr.edge.context_invalid');
