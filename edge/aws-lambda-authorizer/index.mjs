/**
 * AIDR verification for Amazon API Gateway: a Lambda REQUEST authorizer.
 *
 * Works with REST APIs (IAM-policy responses) and HTTP APIs (payload format 2.0, simple
 * responses). It runs the published verifier, @evoliv/aidr-verifier, unchanged: the same code that
 * passes the shared AIAF conformance vectors. Nothing here re-implements cryptography.
 *
 * Every request ends one of three ways:
 *   anonymous  no Agent-Credential, Signature or Signature-Input: allowed (a person, or a bot that
 *              did not identify itself), unless AIDR_MODE=verified-only covers the path;
 *   verified   the agent proved who it is and meets the floors: allowed, its identity in the
 *              authorizer context (aidr_aid, aidr_org, aidr_agal, …) for the backend;
 *   refused    it claims to be an agent and is not a valid one, is revoked or below the floors, or
 *              cannot be checked right now: denied, with aidr_error in the context.
 *
 * Configuration (environment):
 *   AIDR_ISSUER              the registry, default https://api.evolivcore.com
 *   AIDR_PUBLIC_ORIGIN       required: this API's origin(s) as agents call it, comma-separated
 *                            (https://api.bank.example). Signatures are judged against it.
 *   AIDR_MODE                open (default) | verified-only
 *   AIDR_VERIFIED_ONLY_PATHS JSON array of path regexes (whole path) verified-only applies to
 *   AIDR_BYPASS              JSON array of path regexes never verified
 *   AIDR_MIN_AGAL, AIDR_MIN_OAL, AIDR_MIN_KAL   floors, 0-3 (default 0)
 *   AIDR_REQUIRED_CAPABILITIES                  comma-separated
 *   AIDR_NONCE_TABLE         optional DynamoDB table (partition key "pk", TTL attribute "ttl"):
 *                            replay protection across every concurrent Lambda instance. Without
 *                            it, a nonce is remembered only inside one warm instance.
 *
 * API Gateway settings this needs (template.yaml sets them): authorizer result caching OFF (each
 * signature is single-use, and a cached Allow would let a replay through), and no identity
 * sources (people's requests carry none of the agent headers and must still reach the function).
 */

const AGENT_HEADERS = ['agent-credential', 'signature', 'signature-input'];
const SIGNATURE_LIFETIME_SECONDS = 300 + 60;   // the verifiers' maximum signature age plus leeway

/** Header values as one string per name, lower-cased names; repeated headers joined with ", ". */
function headersOf(event) {
  const out = {};
  if (event.multiValueHeaders) {
    for (const [name, values] of Object.entries(event.multiValueHeaders)) {
      if (Array.isArray(values)) out[name.toLowerCase()] = values.join(', ');
    }
  }
  for (const [name, value] of Object.entries(event.headers ?? {})) {
    if (!(name.toLowerCase() in out) && value != null) out[name.toLowerCase()] = String(value);
  }
  return out;
}

/** The path and query exactly as the client sent them, which is what its signature covers. */
function targetOf(event) {
  if (event.version === '2.0') {
    const query = event.rawQueryString ? `?${event.rawQueryString}` : '';
    return { method: event.requestContext.http.method, path: event.rawPath, query };
  }
  // REST API. requestContext.path is the path the client used (with the stage on the default
  // execute-api host, with the base path on a custom domain); event.path drops those.
  const params = event.multiValueQueryStringParameters ?? {};
  const query = Object.entries(params)
    .flatMap(([name, values]) => (values ?? []).map((value) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`))
    .join('&');
  return { method: event.httpMethod, path: event.requestContext?.path ?? event.path, query: query ? `?${query}` : '' };
}

function listFrom(name, env) {
  const raw = env[name];
  if (!raw) return [];
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error(`${name} must be a JSON array`);
  return parsed;
}

function floor(name, env) {
  const value = Number(env[name] ?? 0);
  if (!Number.isInteger(value) || value < 0 || value > 3) throw new Error(`${name} must be 0-3`);
  return value;
}

/** Context values must be strings, numbers or booleans. */
function contextOf(identity) {
  if (identity.status !== 'verified') return { aidr_status: identity.status };
  return {
    aidr_status: 'verified',
    aidr_aid: identity.aid,
    aidr_org: identity.organization,
    aidr_org_domains: (identity.orgDomains ?? []).join(','),
    aidr_agal: identity.agal,
    aidr_oal: identity.oal,
    aidr_kal: identity.kal,
    aidr_capabilities: (identity.capabilities ?? []).join(','),
  };
}

function policy(event, effect, principalId, context) {
  if (event.version === '2.0') return { isAuthorized: effect === 'Allow', context };
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{ Action: 'execute-api:Invoke', Effect: effect, Resource: event.methodArn }],
    },
    context,
  };
}

/**
 * A DynamoDB nonce claim: a conditional put, so of two requests with one nonce exactly one wins,
 * whichever instance each lands on. Claimed only after the request has fully verified.
 */
export function dynamoNonceClaimer(table, { client = null, loadSdk = () => import('@aws-sdk/client-dynamodb') } = {}) {
  let sdk = null;
  return async (aid, nonce, nowSeconds) => {
    sdk ??= await loadSdk();                                   // part of the Node.js Lambda runtime
    const ddb = client ?? (client = new sdk.DynamoDBClient({}));
    try {
      await ddb.send(new sdk.PutItemCommand({
        TableName: table,
        Item: { pk: { S: `${aid} ${nonce}` }, ttl: { N: String(nowSeconds + SIGNATURE_LIFETIME_SECONDS) } },
        ConditionExpression: 'attribute_not_exists(pk)',
      }));
      return true;
    } catch (error) {
      if (error?.name === 'ConditionalCheckFailedException') return false;
      throw error;   // the table cannot answer: refuse rather than risk a replay (handler fails closed)
    }
  };
}

/**
 * @param {object} [options]
 * @param {Record<string,string>} [options.env]   default process.env
 * @param {() => Promise<object>} [options.loadSdk]  default: import('@evoliv/aidr-verifier')
 * @param {typeof fetch} [options.fetch]  @param {() => Date} [options.clock]
 * @param {(aid: string, nonce: string, nowSeconds: number) => Promise<boolean>} [options.claimNonce]
 */
export function createHandler({ env = process.env, loadSdk = () => import('@evoliv/aidr-verifier'),
  fetch: fetchImpl = undefined, clock = () => new Date(), claimNonce = undefined } = {}) {
  let ready = null;

  const setUp = async () => {
    const sdk = await loadSdk();
    if (!env.AIDR_PUBLIC_ORIGIN) {
      throw new Error('AIDR_PUBLIC_ORIGIN is required: this API\'s origin as agents call it, e.g. https://api.bank.example');
    }
    const issuer = env.AIDR_ISSUER || 'https://api.evolivcore.com';
    const sync = new sdk.TrustSync(issuer, fetchImpl ? { fetch: fetchImpl } : {});
    const middleware = sdk.aidr({
      issuer,
      sync,
      publicOrigin: env.AIDR_PUBLIC_ORIGIN.split(',').map((o) => o.trim()).filter(Boolean),
      mode: env.AIDR_MODE || 'open',
      verifiedOnlyPaths: env.AIDR_VERIFIED_ONLY_PATHS ? listFrom('AIDR_VERIFIED_ONLY_PATHS', env) : null,
      bypass: listFrom('AIDR_BYPASS', env),
      minAgal: floor('AIDR_MIN_AGAL', env),
      minOal: floor('AIDR_MIN_OAL', env),
      minKal: floor('AIDR_MIN_KAL', env),
      requiredCapabilities: (env.AIDR_REQUIRED_CAPABILITIES ?? '').split(',').map((c) => c.trim()).filter(Boolean),
      clock,
    });
    await middleware.ready;
    const claim = claimNonce ?? (env.AIDR_NONCE_TABLE ? dynamoNonceClaimer(env.AIDR_NONCE_TABLE) : null);
    return { sdk, sync, middleware, claim };
  };

  /** Run the verifier the way a Node server would, and report what it decided. */
  const decide = (middleware, method, path, query, headers) => new Promise((resolve) => {
    const req = { method, originalUrl: path + query, url: path + query, headers };
    const res = {
      statusCode: 200, headers: {},
      setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
      end(body) {
        let parsed = {};
        try { parsed = JSON.parse(body); } catch { /* not JSON */ }
        resolve({ refused: true, status: this.statusCode, code: parsed.error ?? 'aidr.verify.refused' });
      },
    };
    middleware(req, res, () => resolve({ refused: false, identity: req.aidr }));
  });

  async function handler(event) {
    ready ??= setUp().catch((error) => { ready = null; throw error; });
    const { sdk, sync, middleware, claim } = await ready;
    const headers = headersOf(event);
    const { method, path, query } = targetOf(event);
    const isAgent = AGENT_HEADERS.some((name) => name in headers);

    // A Lambda instance is frozen between invocations, and its refresh timers with it: after a
    // long pause the revocation list may be older than verifiers accept (11 minutes). Catch up
    // first, rather than refusing the agent with 503.
    if (isAgent && sync.trust) {
      const issuedAt = sync.trust.revocation.issuedAt;
      if (!issuedAt || clock().getTime() - issuedAt > sdk.REVOCATION_REFRESH_SECONDS * 1000) {
        await sync.refreshRevocations().catch(() => { /* the verifier fails closed on its own */ });
      }
    }

    const outcome = await decide(middleware, method, path, query, headers);
    if (outcome.refused) {
      // REST: "Unauthorized" makes API Gateway answer 401; a Deny policy answers 403.
      if (outcome.status === 401 && event.version !== '2.0') throw new Error('Unauthorized');
      return policy(event, 'Deny', 'aidr-refused', { aidr_status: 'refused', aidr_error: outcome.code });
    }

    const identity = outcome.identity;
    if (identity.status === 'verified' && claim) {
      const nowSeconds = Math.floor(clock().getTime() / 1000);
      const nonces = Object.values(sdk.parseSignatureInput(headers['signature-input']))
        .map((entry) => entry.params?.nonce).filter(Boolean);
      for (const nonce of nonces) {
        let fresh;
        try {
          fresh = await claim(identity.aid, String(nonce), nowSeconds);
        } catch {
          return policy(event, 'Deny', 'aidr-refused',
            { aidr_status: 'refused', aidr_error: 'aidr.registry.unavailable' });
        }
        if (!fresh) {
          return policy(event, 'Deny', 'aidr-refused',
            { aidr_status: 'refused', aidr_error: 'aidr.verify.replay_detected' });
        }
      }
    }
    return policy(event, 'Allow', identity.status === 'verified' ? identity.aid : 'anonymous', contextOf(identity));
  }

  /** Stops the background refresh (tests; a Lambda instance never needs it). */
  handler.close = async () => { if (ready) (await ready).middleware.close(); };
  return handler;
}

export const handler = createHandler();
