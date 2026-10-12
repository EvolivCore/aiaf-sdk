/**
 * `createSignedFetch(agent)`: a `fetch` that identifies the agent to the sites it may, and leaves
 * every other request as it was (or refuses it, with `onUnlisted: 'refuse'`). Anything that takes
 * a `fetch` — the AI SDK, LangChain.js, an HTTP client — gets the agent's identity this way.
 *
 * The signature is made when the request is sent, with a fresh nonce, for the request's own method
 * and URL. Redirects are not followed by default: a 3xx to another origin would otherwise carry a
 * request signed for this one. Pass `redirect` explicitly to change that.
 */

export function createSignedFetch(agent, { fetch: baseFetch = globalThis.fetch } = {}) {
  return async function signedFetch(input, init = {}) {
    const request = new Request(input, init);
    const signed = await agent.signHeaders(request.method, request.url);
    if (Object.keys(signed).length === 0) return baseFetch(request);
    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(signed)) headers.set(name, value);
    const redirect = init.redirect ?? 'manual';
    // duplex: a streamed body may be re-wrapped only half-duplex (undici's rule).
    return baseFetch(new Request(request, { headers, redirect, ...(request.body ? { duplex: 'half' } : {}) }));
  };
}
