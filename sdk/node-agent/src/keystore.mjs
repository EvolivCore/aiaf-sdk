/**
 * Where an agent's identity (and so its private key) is kept between runs.
 *
 *   FileKeyStore  a laptop, a VM, a persistent volume: <home>/<name>/identity.json, mode 0600 —
 *                 the same path and format as the Python SDK (~/.aidr/agents, or AIDR_AGENT_HOME).
 *   EnvKeyStore   a container or a serverless function: the whole identity in AIDR_AGENT_IDENTITY,
 *                 held by the platform's secret store (`npx @evoliv/aidr-agent enroll --print-identity`).
 *
 * An ephemeral container with a FileKeyStore on a throwaway disk enrolls a NEW agent every time it
 * starts, and spends a use of the token each time. Use EnvKeyStore there.
 */

import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync, closeSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import { AgentIdentity, IdentityError } from './identity.mjs';

export const IDENTITY_ENV = 'AIDR_AGENT_IDENTITY';
export const HOME_ENV = 'AIDR_AGENT_HOME';

export function defaultHome(env = process.env) {
  return env[HOME_ENV] || join(homedir(), '.aidr', 'agents');
}

const WINDOWS = process.platform === 'win32';

export class FileKeyStore {
  constructor(home = defaultHome()) { this.home = home; }

  path(name) {
    if (!name || name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
      throw new IdentityError(`not a usable agent name for a directory: ${JSON.stringify(name)}`);
    }
    return join(this.home, name, 'identity.json');
  }

  load(name) {
    const path = this.path(name);
    if (!existsSync(path)) return null;
    // A key file other users can read is a key other users may have copied.
    if (!WINDOWS && (statSync(path).mode & 0o077) !== 0) {
      throw new IdentityError(`${path} is readable by other users; run: chmod 600 ${path}`);
    }
    let document;
    try {
      document = JSON.parse(readFileSync(path, 'utf8'));
    } catch (error) {
      throw new IdentityError(`${path} is unreadable: ${error.message}`);
    }
    return AgentIdentity.fromDocument(document);
  }

  save(identity) {
    const path = this.path(identity.name);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    if (!WINDOWS) chmodSync(dirname(path), 0o700);
    // Created 0600 from the start, never widened then narrowed.
    const tmp = `${path}.tmp`;
    if (existsSync(tmp)) unlinkSync(tmp);
    const fd = openSync(tmp, 'wx', 0o600);
    try {
      writeSync(fd, JSON.stringify(identity.toDocument(), null, 2));
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  }
}

/** Read-only: the identity is put in the environment by whoever deploys the agent. */
export class EnvKeyStore {
  constructor(variable = IDENTITY_ENV, env = process.env) {
    this.variable = variable;
    this.env = env;
  }

  load(name) {
    const value = this.env[this.variable];
    if (!value) return null;
    const identity = AgentIdentity.fromPortable(value);
    if (identity.name !== name) {
      throw new IdentityError(`${this.variable} holds agent ${JSON.stringify(identity.name)}, not ${JSON.stringify(name)}`);
    }
    return identity;
  }

  save() {
    throw new IdentityError(`${this.variable} is read-only; enroll with \`npx @evoliv/aidr-agent enroll --print-identity\` `
      + 'and store the output');
  }
}
