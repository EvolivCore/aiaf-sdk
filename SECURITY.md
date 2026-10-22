# Security and Trust Center

[![Conformance](https://github.com/EvolivCore/aiaf-sdk/actions/workflows/conformance.yml/badge.svg)](https://github.com/EvolivCore/aiaf-sdk/actions/workflows/conformance.yml)
![RFC 9421](https://img.shields.io/badge/HTTP_signatures-RFC_9421-0b7285)
![Ed25519](https://img.shields.io/badge/keys-Ed25519-0b7285)
![Web Bot Auth](https://img.shields.io/badge/Web_Bot_Auth-compatible-0b7285)
![security.txt](https://img.shields.io/badge/security.txt-RFC_9116-2b8a3e)
![License](https://img.shields.io/badge/license-Apache--2.0-495057)

AIDR verifies AI agents by cryptography, not by trust in a network, an IP address or a user-agent
string. This page is for the security teams who evaluate it, and for researchers who find a flaw.

**Report a vulnerability: security@evolivcore.com** — please do not open a public issue.

---

## At a glance

| | |
|---|---|
| **Report to** | security@evolivcore.com (also in [`/.well-known/security.txt`](https://evolivcore.com/.well-known/security.txt), RFC 9116) |
| **Acknowledgement** | within 3 working days |
| **First assessment** | within 10 working days, then updates until fixed |
| **Critical issues** | worked on at once, any day of the week |
| **Disclosure** | coordinated with you, normally within 90 days |
| **Credit** | in the fix's release notes and security advisory, if you wish |
| **Languages** | English, Hebrew |
| **Bug bounty** | none at present |

These are response targets, not a contractual SLA. Contractual terms belong in an Enterprise
agreement.

---

## Zero trust, per request

Every agent request is verified on its own. Nothing is trusted because of where it comes from.

| Check | What it stops |
|---|---|
| Each request is signed (RFC 9421) over its method, host and path | A signature moved to another method, host or path |
| The credential is bound to the agent's own key (`cnf.jwk`, RFC 7800) | A stolen credential: useless without the private key |
| Credentials live 15 minutes at most | Long-lived tokens to steal |
| Signatures older than 300 seconds are refused; each nonce is used once | Replay |
| The credential names the site it is for (audience) | A credential captured on one site used on another |
| A signed revocation list, refreshed every 60 seconds | A revoked agent: refused everywhere within minutes |
| Fail closed: if the list is more than 11 minutes stale, agents are refused (people are not) | Riding a registry outage past a revocation |
| Gateways never pass on identity a client claims: they strip client-sent `X-AIDR-*` headers, or sign what they add | A client forging "verified" to your service |

Verification runs **offline**, inside your own infrastructure: the verifier holds the registry's
public keys and the revocation list. Nothing calls home per request, so no third party learns who
visits your site.

---

## Cryptography

| Purpose | Standard |
|---|---|
| Request signatures | RFC 9421 HTTP Message Signatures |
| Agent and issuer keys | Ed25519 (RFC 8032); ECDSA P-256 for FIPS-constrained environments |
| Credentials | JWS (RFC 7515) with proof-of-possession key binding (RFC 7800) |
| Key identifiers | JWK thumbprints (RFC 7638) |
| Cloudflare's format | Web Bot Auth profile (an IETF working-group draft), tested against Cloudflare's open-source verifier |
| Transport | TLS 1.2 or later on public hosts; TLS 1.3 only, with mutual TLS, for machine clients |
| Post-quantum | ML-DSA reserved for `aid:v2`; the identifier format makes the move additive |

The full specification: [`spec/aiaf-draft.md`](spec/aiaf-draft.md).

---

## The hosted registry

| Area | Control |
|---|---|
| Issuing key | Held in HashiCorp Vault transit: non-exportable, not deletable, never handled by application code. Vault is sealed by AWS KMS |
| Key rotation | Overlapping: every key version is published, a new one signs only after a two-hour lead, so verifiers never see an unknown key |
| Personal data | Encrypted field by field under an AWS KMS key, in the database and in every backup |
| Audit | A tamper-evident ledger with published tree heads; sign-in and admin events kept 90 days |
| Authorisation | Every change is checked against a versioned policy; anything not allowed is refused |
| Staff access | Passkeys for every sensitive action; actions on a customer organisation need two people |
| Customer access | SSO over SAML and OIDC; passkeys |
| Secrets | In AWS Systems Manager, rotated by a scripted procedure |
| Databases | Authentication on, one least-privilege user per purpose |
| Backups | Nightly, write-locked (S3 Object Lock), restore drill passed (last: 2026-10-02) |
| Abuse | Rate limits per client at the edge |
| Incidents | Customers told within 48 hours of our becoming aware that personal data may have left our control |

---

## Open-source supply chain

| | |
|---|---|
| **Read it** | Every verifier is open source (Apache-2.0). What runs at your edge is what you read here |
| **Three implementations, one result** | Python, Node.js and Go replay the same public conformance vectors on every change |
| **Publishing** | PyPI and npm releases come from GitHub Actions through trusted publishing (OIDC): no long-lived upload tokens exist |
| **Go** | Module checksums are recorded in the public Go checksum database |
| **Dependencies** | Dependabot alerts on |

---

## Supported versions

Security fixes go into the latest release of each package.

| Package | Supported |
|---|---|
| Python: `aidr-verifier`, `aidr-agent`, `aidr-crypto`, `aidr-core` | 0.2.x |
| Node.js: `@evoliv/aidr-verifier` | 0.2.x |
| Node.js: `@evoliv/aidr-agent` | 0.1.x |
| Go: `github.com/evolivcore/aiaf-sdk/go` | 0.2.x |
| Cloudflare Worker, Kong plugin, API Gateway authorizer, WordPress plugin | latest |
| Hosted registry and console | always current |

---

## On our roadmap

What a security review will ask for and we do not have yet:

| | Status |
|---|---|
| SOC 2 report | Not yet. Controls are mapped to SOC 2 and ISO 27001; an audit follows |
| Issuing key in an HSM | Not yet. Today a software key in Vault, sealed by AWS KMS |
| Witnessed key ceremony | Procedure written; not yet performed |
| External penetration test | Not yet |
| Status page | Not yet; incident updates by email |
| Bug bounty | Not yet |

We update this table as each one lands.

---

## How to report

Email **security@evolivcore.com** with:

- what is affected (host and path, package and version, or desktop app version and OS);
- steps to reproduce, and what an attacker could do with it;
- your name or handle, if you would like credit.

Please keep the details out of public issues, pull requests and posts until we have fixed the
problem or agreed a date with you.

### Severity

| Level | Examples | Our response |
|---|---|---|
| **Critical** | Minting or forging an agent identity; bypassing verification; reading another organisation's data | At once, any day. Fix released as soon as tested; Enterprise customers told first |
| **High** | A revoked agent still accepted; a privilege escalation in the console | Within the working day |
| **Medium** | Limited impact or hard preconditions | Next planned release |
| **Low** | Defence-in-depth improvements | Scheduled |

### Scope

**In scope**

- `evolivcore.com` and its subdomains: `api.` (registry and verification), `console.` (customer
  console), `login.` (sign-in), `aidr.` (product site);
- every SDK and edge plugin in this repository;
- the AIDR desktop app;
- the AIAF specification, where following it as written leads to an insecure result.

**Out of scope**

- `admin.evolivcore.com` beyond what anyone can reach without signing in;
- denial of service, load testing, and high-volume automated scanning;
- social engineering and physical attacks;
- our providers' own services (AWS, Cloudflare, Microsoft, Stripe, GitHub): report those to them;
- missing headers or settings with no demonstrated way to exploit them.

### Safe harbour

Use your own account (the Developer plan is free) and your own agents. Do not read, change or
delete other people's data; if you reach some by accident, stop, keep no copy, and tell us what you
saw. Do not keep access open longer than you need to show the problem.

We will not take action against research that follows this page and stays within the law, and we
will work with you to understand and fix what you found.
