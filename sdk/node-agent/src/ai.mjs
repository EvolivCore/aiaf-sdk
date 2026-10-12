/**
 * Vercel AI SDK: give an agent's HTTP tools an AIDR identity.
 *
 *   import { Agent } from '@evoliv/aidr-agent';
 *   import { aidrHttpTools } from '@evoliv/aidr-agent/ai';
 *   import { generateText } from 'ai';
 *
 *   const agent = await Agent.loadOrEnroll('research-01', { audiences: ['https://shop.example'] });
 *   const tools = await aidrHttpTools(agent);   // httpGet and httpPost, signed, limited to the audiences
 *   await generateText({ model, tools, prompt });
 *
 * The tools reach only the origins they are given — by default the agent's allowed audiences —
 * because an LLM choosing URLs is exactly the prompt-injection path by which an agent would present
 * its identity (or fetch internal addresses) somewhere it should not. The same rule as the Python
 * LangChain module (aidr_agent.langchain).
 *
 * `ai` is a peer dependency; nothing here is loaded until this function is called.
 */

import { normalizeOrigin } from './identity.mjs';
import { createSignedFetch } from './fetch.mjs';

export const DEFAULT_MAX_CHARS = 20_000;

export class OriginNotAllowed extends Error {}

function originsFor(agent, origins) {
  const chosen = origins ? origins.map(normalizeOrigin) : [...agent.signFor];
  if (chosen.length === 0) {
    throw new Error('name the origins these tools may reach ({ origins: [...] }): this agent has no allowed audiences to default to');
  }
  return new Set(chosen);
}

export function checkOrigin(url, allowed) {
  let origin;
  try {
    origin = normalizeOrigin(url);
  } catch {
    throw new OriginNotAllowed(`not a URL: ${url}`);
  }
  if (!allowed.has(origin)) {
    throw new OriginNotAllowed(`${origin} is not one of the sites this tool may reach: ${[...allowed].sort().join(', ')}`);
  }
}

export async function render(response, maxChars = DEFAULT_MAX_CHARS) {
  const text = await response.text();
  const shown = text.length > maxChars ? `${text.slice(0, maxChars)}\n…[truncated, ${text.length} characters in all]` : text;
  return `HTTP ${response.status}\n${shown}`;
}

/**
 * `{ httpGet, httpPost }` for the AI SDK's `tools`. Options: `origins` (default the agent's
 * audiences), `maxChars` (response text kept, 20,000), `methods` (['GET', 'POST']), `fetch`.
 */
export async function aidrHttpTools(agent, { origins = null, maxChars = DEFAULT_MAX_CHARS, methods = ['GET', 'POST'],
  fetch: baseFetch = globalThis.fetch, ai = null } = {}) {
  const { tool, jsonSchema } = ai ?? await import('ai');
  const allowed = originsFor(agent, origins);
  const signedFetch = createSignedFetch(agent, { fetch: baseFetch });
  const sites = [...allowed].sort().join(', ');
  const urlSchema = { type: 'string', description: `Absolute URL on one of: ${sites}` };
  const wanted = new Set(methods.map((m) => m.toUpperCase()));
  const tools = {};
  // Both `inputSchema` (AI SDK 5) and `parameters` (AI SDK 4) carry the same schema.
  const make = (description, schema, execute) => {
    const input = jsonSchema(schema);
    return tool({ description, inputSchema: input, parameters: input, execute });
  };
  if (wanted.has('GET')) {
    tools.httpGet = make(`Fetch a URL as the verified agent ${agent.aid}. Sites: ${sites}.`,
      { type: 'object', properties: { url: urlSchema }, required: ['url'], additionalProperties: false },
      async ({ url }) => {
        checkOrigin(url, allowed);
        return render(await signedFetch(url), maxChars);
      });
  }
  if (wanted.has('POST')) {
    tools.httpPost = make(`POST JSON to a URL as the verified agent ${agent.aid}. Sites: ${sites}.`,
      { type: 'object', properties: { url: urlSchema, body: { type: 'object', description: 'JSON body to send' } },
        required: ['url'], additionalProperties: false },
      async ({ url, body = {} }) => {
        checkOrigin(url, allowed);
        return render(await signedFetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body) }), maxChars);
      });
  }
  return tools;
}
