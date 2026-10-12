/**
 * Test doubles for the Workers runtime: Durable Object storage and namespaces, and ExecutionContext.
 *
 * The Durable Object classes under test are the real ones; only the platform around them is faked.
 * test/integration/ runs the same worker on workerd (miniflare) with real Durable Objects.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const TESTDATA = resolve(HERE, '../../../sdk/testdata');
// AIDR_VECTORS: replay another signer's vectors (the conformance gate, docs/13).
export const VECTORS = JSON.parse(readFileSync(process.env.AIDR_VECTORS || resolve(TESTDATA, 'vectors.json'), 'utf8'));
export const NOW_MS = VECTORS.evaluate_at * 1000;

/** A header's value whatever the case of its name: a transport may send it in lower case. */
export function header(headers, name) {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : headers[key];
}

/** The headers with one replaced, under the name it already has (never a second copy in another case). */
export function withHeader(headers, name, value) {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase()) ?? name;
  return { ...headers, [key]: value };
}
export const SECRET = 'test-edge-context-secret-0123456789abcdef';

/** SQLite-backed Durable Object storage: the KV methods, plus `sql` on a real in-memory SQLite. */
export class FakeStorage {
  constructor() {
    this.data = new Map();
    this.alarm = null;
    const db = new DatabaseSync(':memory:');
    this.db = db;
    this.sql = {
      // Synchronous, like the real API: this is what makes the nonce claim atomic.
      exec: (query, ...bindings) => {
        const statement = db.prepare(query);
        const rows = /^\s*(SELECT|INSERT[\s\S]*RETURNING)/i.test(query)
          ? statement.all(...bindings) : (statement.run(...bindings), []);
        return { toArray: () => rows };
      },
    };
  }
  async get(key) { return structuredClone(this.data.get(key)); }
  async put(key, value) { this.data.set(key, structuredClone(value)); }
  async delete(keys) {
    for (const key of Array.isArray(keys) ? keys : [keys]) this.data.delete(key);
  }
  async list() { return new Map(this.data); }
  async getAlarm() { return this.alarm; }
  async setAlarm(when) { this.alarm = when; }
}

/** A Durable Object namespace whose stubs call real instances of `DOClass`. */
export class FakeNamespace {
  constructor(DOClass, env = {}) {
    this.DOClass = DOClass;
    this.env = env;
    this.instances = new Map();
    this.calls = [];
  }
  idFromName(name) { return name; }
  instance(id) {
    if (!this.instances.has(id)) {
      this.instances.set(id, new this.DOClass({ storage: new FakeStorage() }, this.env));
    }
    return this.instances.get(id);
  }
  get(id) {
    return {
      fetch: async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        this.calls.push({ id, path: new URL(request.url).pathname });
        return this.instance(id).fetch(request);
      },
    };
  }
}

/** A TRUST namespace that serves a fixed snapshot instead of fetching from a registry. */
export function snapshotNamespace(snapshot) {
  const calls = [];
  return {
    calls,
    idFromName: (name) => name,
    get: () => ({
      fetch: async (input) => {
        const path = new URL(typeof input === 'string' ? input : input.url).pathname;
        calls.push(path);
        if (typeof snapshot === 'function') return snapshot(path);
        if (path === '/snapshot') return Response.json(snapshot);
        return Response.json({ ok: true });
      },
    }),
  };
}

export function executionContext() {
  const pending = [];
  return { pending, waitUntil: (promise) => pending.push(promise), passThroughOnException() {} };
}

export const firstAllow = (suite) => suite.cases.find(
  (c) => c.expect === 'allow' && !c.expected_audience && !c.min_assurance);
export const caseNamed = (suite, name) => suite.cases.find((c) => c.name === name);

export function tamper(signatureHeader) {
  const [label, value] = signatureHeader.split('=:');
  const bytes = Buffer.from(value.replace(/:$/, ''), 'base64');
  bytes[0] ^= 0x01;
  return `${label}=:${bytes.toString('base64')}:`;
}
