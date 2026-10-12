/**
 * One conformance-vector request, signed the way an agent built on @evoliv/aidr-agent sends it:
 * through `Agent` and `createSignedFetch`, captured as the request would leave the process.
 * Used by `scripts/generate_test_vectors.py --signer node-agent` (docs/13, step 1).
 *
 *   stdin:  {"method", "url", "private_jwk", "keyid", "credential", "created"?: epoch seconds}
 *   stdout: the request's headers, as JSON
 */

import { readFileSync } from 'node:fs';

import { Agent, AgentIdentity, createSignedFetch } from '../index.mjs';
import { privateKeyFromJwk } from '../src/keys.mjs';

const input = JSON.parse(readFileSync(0, 'utf8'));
const identity = new AgentIdentity({ aid: input.keyid, name: 'conformance', registry: 'https://registry.aidr.example',
  privateKey: privateKeyFromJwk(input.private_jwk) });
const agent = new Agent(identity, { clock: () => (input.created ? new Date(input.created * 1000) : new Date()) });
// The credential the fixture issued, in place of a registry round trip.
agent.credentials = { get: async () => input.credential };

let sent = null;
const signedFetch = createSignedFetch(agent, { fetch: async (request) => { sent = request; return new Response(null, { status: 200 }); } });
await signedFetch(input.url, { method: input.method });
if (!sent?.headers.get('agent-credential')) throw new Error('the agent sent no credential: it did not sign the request');
process.stdout.write(JSON.stringify(Object.fromEntries(sent.headers.entries())));
