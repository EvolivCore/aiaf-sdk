import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../bin/aidr-agent.mjs';
import { AgentIdentity, FileKeyStore } from '../index.mjs';

const TOKEN = 'aidr_et_etk_01CLI_secret';

function registry() {
  const json = (status, body) => new Response(JSON.stringify(body), { status });
  return async (url) => (new URL(url).pathname === '/v1/enroll'
    ? json(201, { agent: { aid: 'aid:v1:acme:01CLI:x' }, challenge: { challenge_id: 'c', sign_this: 'aiaf-pop-v1:x' }, allowed_audiences: [] })
    : json(200, {}));
}

function run(argv, env = {}) {
  const store = new FileKeyStore(mkdtempSync(join(tmpdir(), 'aidr-cli-')));
  const out = [];
  const err = [];
  return main(argv, { env, out: (l) => out.push(l), err: (l) => err.push(l), fetch: registry(), store })
    .then((code) => ({ code, out, err, store }));
}

describe('aidr-agent CLI', () => {
  it('enroll saves the identity; whoami shows it, never the key', async () => {
    const { code, store, err } = await run(['enroll', '--name', 'bot'], { AIDR_ENROLLMENT_TOKEN: TOKEN, AIDR_REGISTRY_URL: 'https://r.test' });
    assert.equal(code, 0, err.join('\n'));
    assert.equal(store.load('bot').aid, 'aid:v1:acme:01CLI:x');
    const out = [];
    const whoami = await main(['whoami', '--name', 'bot'], { out: (l) => out.push(l), err: () => {}, store });
    assert.equal(whoami, 0);
    assert.match(out[0], /aid:v1:acme:01CLI:x/);
    assert.doesNotMatch(out[0], /"d"|private/);
  });

  it('--print-identity prints one line for a secret store and saves nothing', async () => {
    const { code, out, store } = await run(['enroll', '--name', 'bot', '--print-identity'], { AIDR_ENROLLMENT_TOKEN: TOKEN });
    assert.equal(code, 0);
    assert.equal(AgentIdentity.fromPortable(out[0]).aid, 'aid:v1:acme:01CLI:x');
    assert.equal(store.load('bot'), null);

    // …and whoami finds it where loadOrEnroll will: in AIDR_AGENT_IDENTITY.
    const shown = [];
    const whoami = await main(['whoami', '--name', 'bot'], { env: { AIDR_AGENT_IDENTITY: out[0] },
      out: (l) => shown.push(l), err: () => {}, store });
    assert.equal(whoami, 0);
    assert.match(shown[0], /aid:v1:acme:01CLI:x/);
    assert.match(shown[0], /from:\s+AIDR_AGENT_IDENTITY/);
  });

  it('the token only from the environment; usage otherwise', async () => {
    assert.equal((await run(['enroll', '--name', 'bot'])).code, 1);
    assert.equal((await run(['enroll', '--name', 'bot', '--token', TOKEN])).code, 2);
    assert.equal((await run(['nonsense'])).code, 2);
  });
});

describe('the published package', () => {
  it('declares the CLI in the form npm keeps (a "./" path is dropped on publish)', async () => {
    const { readFileSync } = await import('node:fs');
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    assert.equal(pkg.bin['aidr-agent'], 'bin/aidr-agent.mjs');
  });
});
