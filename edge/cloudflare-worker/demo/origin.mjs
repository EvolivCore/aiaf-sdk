/**
 * The demo's origin: a Worker behind the AIDR edge, reached only through a service binding
 * (workers_dev = false: it has no public URL). It trusts nothing but the edge's signed context,
 * and shows each caller what the edge proved about them.
 *
 *   /            for people: what this demo is (open: anonymous visitors are fine here)
 *   /agents/…    for verified agents only (the edge refuses anyone else): the identity it proved
 */

import { verifyEdgeContext } from '../src/edge-context.mjs';

const PRIVATE = { 'cache-control': 'private, no-store' };

export default {
  async fetch(request, env) {
    let context;
    try {
      context = await verifyEdgeContext(
        { method: request.method, url: request.url, headers: request.headers }, env.AIDR_EDGE_CONTEXT_SECRET);
    } catch (error) {
      return Response.json({ error: 'demo.edge_context_required',
        reason: `requests reach this origin only through the AIDR edge (${error.message})` },
      { status: 401, headers: PRIVATE });
    }
    const path = new URL(request.url).pathname;
    if (path.startsWith('/agents/')) {
      return Response.json({
        message: `Hello, ${context.aid}. The AIDR edge verified you before this origin saw the request.`,
        you: {
          status: context.status, aid: context.aid, organization: context.organization,
          org_domains: context.org_domains, agal: context.agal, oal: context.oal, kal: context.kal,
        },
        catalogue: [
          { sku: 'AIDR-001', item: 'Verified agent badge', price_eur: 0 },
          { sku: 'AIDR-002', item: 'Audit trail, one year', price_eur: 120 },
        ],
      }, { headers: PRIVATE });
    }
    return new Response(page(context.status), {
      headers: { 'content-type': 'text/html; charset=utf-8', ...PRIVATE } });
  },
};

function page(status) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>AIDR demo shop</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#0f172a}
code{background:#f1f5f9;padding:.1rem .3rem;border-radius:.25rem}</style></head><body>
<h1>AIDR demo shop</h1>
<p>This page is open to everyone; the AIDR edge saw you as <code>${status}</code>.</p>
<p>Everything under <code>/agents/</code> is for <strong>verified AI agents only</strong>. A person or an
unidentified bot gets <code>401 aidr.edge.agent_required</code>; an agent with an AIDR identity gets in, and
this origin learns which agent it is, from which organisation, at which assurance level.</p>
<p>Try <a href="/agents/catalogue">/agents/catalogue</a> in your browser, then with an agent built on the
<code>aidr-agent</code> SDK.</p></body></html>`;
}
