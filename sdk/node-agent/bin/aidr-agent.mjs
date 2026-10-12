#!/usr/bin/env node
/**
 * `npx @evoliv/aidr-agent` — enroll an agent, or show who it is.
 *
 *   aidr-agent enroll --name research-01 [--audience https://shop.example] [--description …] [--registry …] [--print-identity]
 *   aidr-agent whoami --name research-01
 *
 * `enroll` reads the token from AIDR_ENROLLMENT_TOKEN — never from the command line, where it would
 * land in shell history and process listings. `--print-identity` prints the whole identity, private
 * key included, as one line for AIDR_AGENT_IDENTITY in a container's secret store, and saves nothing.
 */

import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { REGISTRY_ENV, TOKEN_ENV } from '../src/agent.mjs';
import { DEFAULT_REGISTRY, normalizeOrigin } from '../src/identity.mjs';
import { EnvKeyStore, FileKeyStore, IDENTITY_ENV } from '../src/keystore.mjs';
import { enroll, tokenId } from '../src/registry.mjs';

const USAGE = `usage:
  aidr-agent enroll --name <name> [--audience <origin>]... [--description <text>] [--registry <url>] [--print-identity]
  aidr-agent whoami --name <name>

The enrollment token is read from ${TOKEN_ENV}.`;

export async function main(argv = process.argv.slice(2), { env = process.env, out = console.log, err = console.error,
  fetch: fetchImpl = fetch, store = new FileKeyStore() } = {}) {
  const [command, ...rest] = argv;
  let values;
  try {
    ({ values } = parseArgs({ args: rest, options: {
      name: { type: 'string' }, audience: { type: 'string', multiple: true }, description: { type: 'string', default: '' },
      registry: { type: 'string' }, 'print-identity': { type: 'boolean', default: false },
    } }));
  } catch (error) {
    err(`${error.message}\n${USAGE}`);
    return 2;
  }
  if (!['enroll', 'whoami'].includes(command) || !values.name) {
    err(USAGE);
    return 2;
  }
  try {
    if (command === 'whoami') {
      // Where Agent.loadOrEnroll looks, in its order: the one-line secret first, then the file.
      const fromEnv = new EnvKeyStore(IDENTITY_ENV, env).load(values.name);
      const identity = fromEnv ?? store.load(values.name);
      if (!identity) {
        err(`agent ${JSON.stringify(values.name)} is not enrolled here`);
        return 1;
      }
      out(`aid:       ${identity.aid}\nregistry:  ${identity.registry}\n`
        + `audiences: ${identity.audiences.join(', ') || '(any https site)'}\n`
        + (fromEnv ? `from:      ${IDENTITY_ENV}` : `file:      ${store.path(values.name)}`));
      return 0;
    }
    const token = env[TOKEN_ENV];
    if (!token) {
      err(`set ${TOKEN_ENV} to the token from the AIDR console`);
      return 1;
    }
    if (!values['print-identity'] && store.load(values.name)) {
      err(`agent ${JSON.stringify(values.name)} is already enrolled here (${store.path(values.name)})`);
      return 1;
    }
    const registry = values.registry ?? env[REGISTRY_ENV] ?? DEFAULT_REGISTRY;
    err(`enrolling ${values.name} at ${registry} with token ${tokenId(token)}…`);
    const identity = await enroll(token, { name: values.name, registry, description: values.description, fetch: fetchImpl,
      audiences: values.audience ? values.audience.map(normalizeOrigin) : null });
    if (values['print-identity']) {
      err(`enrolled ${identity.aid}. Store this line as the secret ${IDENTITY_ENV} (it holds the private key):`);
      out(identity.toPortable());
    } else {
      store.save(identity);
      err(`enrolled ${identity.aid}; saved to ${store.path(values.name)}`);
    }
    return 0;
  } catch (error) {
    err(`error: ${error.message}`);
    return 1;
  }
}

// Run only when invoked (npx links bin/ through a symlink), not when a test imports main().
const invoked = (() => {
  try {
    return process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (invoked) process.exitCode = await main();
