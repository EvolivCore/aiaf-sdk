/**
 * @evoliv/aidr-agent — a verifiable identity for an AI agent, in one line (AIAF; Apache-2.0).
 *
 *   import { Agent, createSignedFetch } from '@evoliv/aidr-agent';
 *
 *   const agent = await Agent.loadOrEnroll('research-01');   // enrolls once with AIDR_ENROLLMENT_TOKEN
 *   const fetch = createSignedFetch(agent);                  // identifies the agent where it may
 *   await fetch('https://shop.example/api/products');
 *
 * The key is generated here and never leaves this machine; the registry only ever receives the
 * public half. The same identity file and format as the Python SDK (`aidr-agent`).
 */

export { Agent, NotAllowed, REGISTRY_ENV, TOKEN_ENV } from './src/agent.mjs';
export { createSignedFetch } from './src/fetch.mjs';
export { AgentIdentity, DEFAULT_REGISTRY, FORMAT, IdentityError, normalizeOrigin } from './src/identity.mjs';
export { EnvKeyStore, FileKeyStore, HOME_ENV, IDENTITY_ENV, defaultHome } from './src/keystore.mjs';
export { generateKey, publicJwk } from './src/keys.mjs';
export { CredentialCache, POP_CONTEXT, RegistryError, enroll, tokenId } from './src/registry.mjs';
export { CREDENTIAL_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, signRequest } from './src/signatures.mjs';
