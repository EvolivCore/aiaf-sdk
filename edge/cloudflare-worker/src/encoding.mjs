/** base64, base64url and UTF-8 over Uint8Array — the Workers runtime has no Buffer. */

import { InvalidKey } from './errors.mjs';

export const utf8Encode = (text) => new TextEncoder().encode(text);
export const utf8Decode = (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes);

export function base64Decode(text) {
  let binary;
  try {
    binary = atob(text);
  } catch {
    throw new InvalidKey('invalid base64 encoding');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Decode unpadded base64url, rejecting anything outside the alphabet. */
export function b64urlDecode(text) {
  // A lenient decoder would silently drop injected characters and decode something plausible.
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new InvalidKey('invalid base64url encoding');
  }
  const standard = text.replace(/-/g, '+').replace(/_/g, '/');
  return base64Decode(standard + '='.repeat((4 - (standard.length % 4)) % 4));
}

export function b64urlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}
