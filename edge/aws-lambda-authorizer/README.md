# AIDR for Amazon API Gateway

A Lambda REQUEST authorizer that verifies AI agents' [AIDR](https://aidr.evolivcore.com)
identities before a request reaches your API: the registry's signature on the agent's credential,
the agent's RFC 9421 signature on this exact request, revocation, replay and your floors. It runs
the published verifier, `@evoliv/aidr-verifier`, unchanged: the same code that passes the shared
AIAF conformance vectors. Apache-2.0.

| Outcome | When | API Gateway |
|---|---|---|
| anonymous | no `Agent-Credential`, `Signature` or `Signature-Input` | allowed (`aidr_status=anonymous`); refused on verified-only paths |
| verified | identity proven, floors met | allowed; the identity in `$context.authorizer.aidr_*` |
| refused | not a valid agent / revoked or below the floors / cannot be checked | 401 or 403 (REST); 403 (HTTP API); `aidr_error` says why |

Nothing on the request path calls the registry: keys and the signed revocation list are kept in
memory and refreshed in the background (hourly and every minute), and after an instance has been
frozen it catches up before verifying. Verification is two signature checks, under a millisecond
of CPU.

## Deploy (AWS SAM)

```sh
npm install --omit=dev
sam deploy --guided            # asks for PublicOrigin, e.g. https://api.example.com
```

This creates the function and, by default, a DynamoDB table (on-demand) so a signed request cannot
be replayed on another Lambda instance. Without the table a nonce is remembered only within one
warm instance.

## Attach it

**Caching must be off and there must be no identity sources:** every signature is single-use (a
cached Allow would let a replay through), and people's requests carry none of the agent headers
but must still reach the function.

REST API (`AWS::Serverless::Api` or the console: Authorizers → Lambda, event payload *Request*):

```yaml
Auth:
  DefaultAuthorizer: AidrAuthorizer
  Authorizers:
    AidrAuthorizer:
      FunctionPayloadType: REQUEST
      FunctionArn: <AuthorizerFunctionArn output>
      Identity: { ReauthorizeEvery: 0 }
```

HTTP API:

```yaml
Auth:
  DefaultAuthorizer: AidrAuthorizer
  Authorizers:
    AidrAuthorizer:
      FunctionArn: <AuthorizerFunctionArn output>
      AuthorizerPayloadFormatVersion: "2.0"
      EnableSimpleResponses: true
      Identity: { ReauthorizeEvery: 0 }
```

Your backend reads the verified identity from the authorizer context, for example with a REST
integration's request mapping `X-AIDR-Agent: context.authorizer.aidr_aid`, or an HTTP API parameter
mapping `overwrite:header.x-aidr-agent: $context.authorizer.aidr_aid` (overwrite, so a client cannot send its own). Values: `aidr_status`, `aidr_aid`,
`aidr_org`, `aidr_org_domains`, `aidr_agal`, `aidr_oal`, `aidr_kal`, `aidr_capabilities`.

## Configuration

| Variable | |
|---|---|
| `AIDR_PUBLIC_ORIGIN` | required: your API's origin(s) as agents call it. Signatures are judged against it, never against the Host header a client sends |
| `AIDR_MODE` | `open` (default) or `verified-only` |
| `AIDR_VERIFIED_ONLY_PATHS` | JSON array of whole-path regexes for verified-only (`["/v1/data/.*"]`) |
| `AIDR_BYPASS` | JSON array of paths never verified |
| `AIDR_MIN_AGAL`, `AIDR_MIN_OAL`, `AIDR_MIN_KAL` | floors, 0–3 |
| `AIDR_REQUIRED_CAPABILITIES` | comma-separated |
| `AIDR_NONCE_TABLE` | DynamoDB table for replay protection across instances |
| `AIDR_ISSUER` | default `https://api.evolivcore.com` |

With the AWS CLI rather than SAM, `aws apigatewayv2 create-authorizer` insists on
`--identity-source`; pass the request as JSON instead (`--cli-input-json` with `"IdentitySource": []`
and `"AuthorizerResultTtlInSeconds": 0`), which API Gateway accepts.

## Test

```sh
npm test      # every shared vector case, as REST and HTTP API events; replays across instances
```

Also tested end to end on real Amazon API Gateway (2026-10-21), a REST API and an HTTP API in
us-east-1, against a registry issuing live credentials, with the DynamoDB replay table: people
pass as anonymous; a genuine agent passes with its identity in the backend's context; a replayed
request, a tampered signature, a request signed for another path and, after its revocation, the
agent itself are refused.
