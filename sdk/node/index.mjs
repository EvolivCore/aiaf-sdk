/**
 * AIDR relying-party SDK for Node.js — verify agent identity offline.
 *
 * Zero dependencies: Node's built-in crypto only. A verification library with a dependency tree
 * is a verification library that can be compromised without touching its own code.
 *
 * One line for Express, Connect or node:http — keys and revocations kept current in the background:
 *
 *   app.use(aidr({ issuer: 'https://api.evolivcore.com' }));   // req.aidr.status: anonymous | verified
 *
 * Or build an AgentVerifier yourself and refresh `jwks` hourly and the revocation delta every 60
 * seconds (TrustSync does both). Nothing in the request path contacts the registry.
 */

export { aidr } from './src/middleware.mjs';
export { TrustSync } from './src/sync.mjs';
export { compileBypass, isBypassed, normalisePath } from './src/path.mjs';
export {
  ENFORCE_PUBLIC_ORIGIN, PUBLIC_ORIGIN_ENV, PublicOriginRequired, isLoopbackHost, originResolver,
} from './src/origin.mjs';

export {
  AgentVerifier,
  DEFAULT_POLICY,
  MAX_REVOCATION_AGE_SECONDS,
  expressMiddleware,
} from './src/verifier.mjs';

export {
  BloomFilter,
  JWKS_REFRESH_SECONDS,
  KeySet,
  NonceCache,
  REVOCATION_REFRESH_SECONDS,
  RevocationState,
  TrustStore,
  buildTrustStore,
} from './src/trust.mjs';

export {
  CREDENTIAL_HEADER,
  REQUIRED_COMPONENTS,
  SIGNATURE_HEADER,
  SIGNATURE_INPUT_HEADER,
  effectiveRequestUri,
  jwkThumbprint,
  parseSignatureInput,
  verifyCompact,
  verifyRequestSignature,
} from './src/crypto.mjs';

export {
  AgentRevoked,
  AidrError,
  AssuranceTooLow,
  CapabilityDenied,
  CoveredComponentMismatch,
  CredentialExpired,
  CredentialNotYetValid,
  InvalidKey,
  MalformedToken,
  PolicyViolation,
  RegistryUnavailable,
  ReplayDetected,
  SignatureInvalid,
  SignatureTooOld,
  UnknownIssuer,
  UnsupportedAlgorithm,
  VerificationError,
} from './src/util.mjs';
