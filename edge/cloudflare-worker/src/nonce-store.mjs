/**
 * Replay protection across every isolate and location: a Durable Object per nonce shard.
 *
 * Workers KV cannot do this — it is eventually consistent, so two locations can both see "unused"
 * for the same nonce within the propagation window. A Durable Object has exactly one instance
 * worldwide, and the worker routes each (aid, nonce) to a fixed shard, so every claim for a given
 * nonce is decided by the same object.
 *
 * The claim is ONE SQLite statement, executed synchronously (the SQLite storage API is
 * synchronous): insert the nonce, or take over its row only if that row has expired, and report
 * whether a row was written. Nothing can interleave inside a synchronous call, so two concurrent
 * claims for one nonce cannot both succeed — no reasoning about input gates required.
 *
 * Entries expire when their signature could no longer be accepted anyway; an alarm sweeps them.
 */

export const SHARDS = 256;
const SWEEP_INTERVAL_MS = 10 * 60 * 1000;
const MAX_TTL_SECONDS = 1200;

/** The shard name for a claim key (a SHA-256 hex digest). */
export function shardFor(key) {
  return `nonce-${key.slice(0, 2)}`;
}

export class NonceStore {
  constructor(state) {
    this.storage = state.storage;
    this.sql = state.storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS nonces (key TEXT PRIMARY KEY, expires INTEGER NOT NULL)');
  }

  async fetch(request) {
    let body;
    try {
      body = await request.json();
    } catch {
      return Response.json({ error: 'bad request' }, { status: 400 });
    }
    const { key, ttl } = body ?? {};
    if (typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key)
        || !Number.isInteger(ttl) || ttl < 1 || ttl > MAX_TTL_SECONDS) {
      return Response.json({ error: 'bad request' }, { status: 400 });
    }

    const now = Date.now();
    const written = this.sql.exec(
      `INSERT INTO nonces (key, expires) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET expires = excluded.expires WHERE nonces.expires <= ?
       RETURNING key`,
      key, now + ttl * 1000, now,
    ).toArray();

    if (written.length === 1 && (await this.storage.getAlarm()) === null) {
      await this.storage.setAlarm(now + SWEEP_INTERVAL_MS);
    }
    return Response.json({ fresh: written.length === 1 });
  }

  async alarm() {
    const now = Date.now();
    this.sql.exec('DELETE FROM nonces WHERE expires <= ?', now);
    const [{ remaining }] = this.sql.exec('SELECT COUNT(*) AS remaining FROM nonces').toArray();
    if (remaining > 0) await this.storage.setAlarm(now + SWEEP_INTERVAL_MS);
  }
}
