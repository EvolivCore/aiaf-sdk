/**
 * Which site a request was meant for — the authority a signature must cover.
 *
 * A signature covers `@authority`, so the verifier must judge it against THIS site's own origin.
 * The request's Host header is what the client sent: a request signed for another site, replayed
 * here with that site's Host, would verify wherever the server answers any host name (found
 * 2026-10-10). So the site says who it is:
 *
 *   publicOrigin: 'https://shop.example'                     one origin
 *   publicOrigin: ['https://shop.example', 'https://www.shop.example']   several host names
 *   AIDR_PUBLIC_ORIGIN=https://shop.example,https://www.shop.example     the same, from the environment
 *
 * A request whose Host matches a configured origin is judged as that origin; any other Host as the
 * first — so a signature made for a host that is not this site's never matches.
 *
 * Without an origin, localhost (and 127.0.0.0/8, ::1) still works, for development. Any other host:
 * in 0.1.x a warning, once, and the Host header is used as before; from 0.2.0 an agent's request is
 * refused (aidr.config.public_origin_required) — people without agent headers are never affected.
 */

import { AidrError } from './util.mjs';

export const PUBLIC_ORIGIN_ENV = 'AIDR_PUBLIC_ORIGIN';

/** true from 0.2.0 (refuse); 0.1.x warned. */
export const ENFORCE_PUBLIC_ORIGIN = true;

export class PublicOriginRequired extends AidrError {
  constructor() {
    super('aidr.config.public_origin_required',
      'this site has not configured its public origin (publicOrigin or AIDR_PUBLIC_ORIGIN), so agents cannot be verified');
  }
}

function normaliseOrigin(value) {
  const url = new URL(value.trim());
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error(`publicOrigin: not an http(s) origin: ${value}`);
  return url.origin;
}

/** Configured origins: the option, else the environment; [] when neither. */
export function configuredOrigins(publicOrigin, env = process.env) {
  const raw = publicOrigin ?? env?.[PUBLIC_ORIGIN_ENV] ?? null;
  if (raw === null || raw === '') return [];
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  return list.filter((v) => String(v).trim() !== '').map(normaliseOrigin);
}

/** localhost, *.localhost, 127.0.0.0/8 and ::1, with or without a port. */
export function isLoopbackHost(host) {
  const name = String(host ?? '').trim().toLowerCase().replace(/:\d+$/, '').replace(/^\[(.*)\]$/, '$1');
  return name === 'localhost' || name.endsWith('.localhost') || name === '::1' || /^127(\.\d{1,3}){3}$/.test(name);
}

let warned = false;

/** For tests: forget that the warning was given. */
export function resetOriginWarning() { warned = false; }

/**
 * Resolves the origin a request is judged as. `resolve(hostHeader)` returns the origin string, or
 * throws PublicOriginRequired when enforcement is on and nothing says who this site is.
 */
export function originResolver({ publicOrigin = null, scheme = 'https', enforce = ENFORCE_PUBLIC_ORIGIN,
  warn = (message) => console.warn(message), env = process.env } = {}) {
  const origins = configuredOrigins(publicOrigin, env);
  return (hostHeader) => {
    const host = String(hostHeader ?? '').trim().toLowerCase();
    if (origins.length > 0) {
      return origins.find((o) => new URL(o).host === host) ?? origins[0];
    }
    if (isLoopbackHost(host)) return `${scheme}://${host}`;
    if (enforce) throw new PublicOriginRequired();
    if (!warned) {
      warned = true;
      warn('[aidr] publicOrigin is not set: requests are judged by their Host header, which the client '
        + 'chooses. A request signed for another site could be replayed here. Set publicOrigin (or '
        + `${PUBLIC_ORIGIN_ENV}) to this site's origin; from @evoliv/aidr-verifier 0.2.0 it is required.`);
    }
    return `${scheme}://${host}`;
  };
}
