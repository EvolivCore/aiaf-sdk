// Copied from edge/cloudflare-worker/src/path.mjs — keep the two identical; both are held to
// sdk/testdata/path-normalisation.json.

/**
 * Bypass rules: anchored regular expressions judged against a normalised path.
 *
 * Same contract as the Python middleware (aidr_verifier.asgi.normalise_path), checked against the
 * shared table in sdk/testdata/path-normalisation.json:
 *
 * - decoded exactly once; a path still containing '%' afterwards (double encoding, or a literal
 *   '%') is ambiguous, as are backslashes and control characters — and an ambiguous path is never
 *   bypassed;
 * - repeated slashes collapsed and dot segments resolved, so `/public/..%2fadmin` is `/admin`;
 * - each rule must match the WHOLE path (`^(?:rule)$`), so `/health` never matches `/x/health`.
 *
 * Not bypassing is always the safe direction: the request is then simply verified.
 */

export function normalisePath(rawPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return null;                       // malformed escape or invalid UTF-8
  }
  if (decoded.includes('%') || decoded.includes('\\')) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(decoded)) return null;
  if (!decoded.startsWith('/')) decoded = `/${decoded}`;

  const trailing = decoded.length > 1 && decoded.endsWith('/');
  const stack = [];
  for (const segment of decoded.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') { stack.pop(); continue; }
    stack.push(segment);
  }
  const resolved = `/${stack.join('/')}`;
  return trailing && resolved !== '/' ? `${resolved}/` : resolved;
}

export function compileBypass(patterns) {
  return patterns.map((pattern) => {
    if (typeof pattern !== 'string' || !pattern) throw new Error('bypass rules must be non-empty strings');
    return new RegExp(`^(?:${pattern})$`);
  });
}

export function isBypassed(rules, rawPath) {
  if (rules.length === 0) return false;
  const path = normalisePath(rawPath);
  return path !== null && rules.some((rule) => rule.test(path));
}
