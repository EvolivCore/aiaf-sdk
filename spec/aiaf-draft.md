# Agent Identity Assurance Framework (AIAF)

### A proposed standard for the identity, assurance and accountability of autonomous software agents

**Version:** 0.1 (Draft for public review) · **Date:** 2026-09-24
**Status:** Draft. Not a ratified standard. No change control has been transferred to a neutral body.
**Editors:** AIDR (see §14.1 — *Disclosure of interest*)
**Licence:** Apache License 2.0 — free to implement, including by competing registries (§0.3).

---

## 0. Read this section first

### 0.1 What this document is

A proposed technical framework for establishing **who is accountable** for an autonomous software
agent, **how strongly** that accountability is evidenced, and **what a website can verify** about
an agent that contacts it.

### 0.2 What this document is not

It is **not** a ratified standard, and calling it one would be the fastest way to ensure it never
becomes one. It is a draft, published for review, with the explicit intention of being handed to a
neutral standards body once it has independent implementations. §14 sets out that path and the
conditions under which this document should be abandoned.

It does not certify that an agent is safe, competent, aligned, or running any particular model. It
does not assess AI risk. It does not govern content provenance. §16 lists what it deliberately
excludes and points at the bodies that own those problems.

### 0.3 Disclosure of interest

**This draft was written by an organisation that operates a commercial agent registry.** That is a
structural conflict, and pretending otherwise would be worse than naming it. Three constraints
follow, and this document is bound by them:

1. The normative text names no vendor. It specifies what a **conforming registry** must do, never
   what AIDR does. A requirement that only one registry could satisfy is a defect, and should be
   reported as one.
2. Everything required to implement this framework — identifier syntax, credential format, wire
   protocol, revocation distribution, conformance vectors — is published under terms permitting
   unrestricted implementation, including by direct competitors.
3. Any registry may issue identifiers under this framework. Relying parties choose which registries
   to trust. A framework that presumes a single registry is a monopoly proposal, not a standard.

If this document ever stops satisfying all three, it has become marketing and should be treated as
such by its readers.

### 0.4 Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **SHOULD NOT**,
**RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

---

## 1. Introduction

### 1.1 The problem

A website receiving a request cannot presently answer three questions that determine how it should
respond:

1. Is this an autonomous agent or a person?
2. If it is an agent, **who is answerable for it**?
3. How strongly is that answer evidenced?

Today the honest answers are: a `User-Agent` string anyone can forge, an IP address that identifies
a cloud region, and nothing. Sites are left choosing between blocking everything that looks
automated — which breaks legitimate use — and allowing everything, which leaves them without
recourse when something goes wrong.

The gap is not detection. It is **accountability**: a verifiable, revocable link from a request to
a party who can be contacted, sanctioned, or sued.

### 1.2 Why human identity standards do not transfer

The instinct is to reach for NIST SP 800-63, eIDAS, or the CA model. Each fails in a specific way,
and understanding why produces the framework in §3.

**An agent has no persistent identity to proof.** NIST SP 800-63A validates evidence about a person
who exists independently, continuously, and singly. An agent is instantiated, replicated across a
thousand containers, forked mid-task, and destroyed. Asking "is this agent who it claims to be" is
a category error: there is no underlying subject for the claim to be about. What persists is the
**operator**, the **key**, and the **delegation**. Assurance must attach to those three things, not
to the agent.

**Agents cannot be enrolled, and fail differently.** SP 800-63B assumes a human who possesses
authenticators and can be phished. An agent cannot be phished, but it can be **prompt-injected** —
induced by attacker-controlled input to act against its operator's intent while holding entirely
valid credentials. This has no human analogue and no authenticator defeats it. A framework that
claims to prevent it is lying; this one is explicit that credentials prove *origin and
accountability*, never *intent* (§2.2).

**Delegation is the central problem, not an edge case.** SP 800-63C federates assertions about a
subject to a relying party. Agents introduce a dimension with no equivalent: an agent acts **for
someone else**, may spawn sub-agents that act for it, and the chain must remain bounded, scoped and
revocable. This is why §3.4 defines a delegation axis rather than treating it as metadata.

**Scale differs by six orders of magnitude.** One human holds one identity. One operator may run
millions of agent instances, each short-lived. Issuance must be cheap, automatic and bulk; more
importantly, **revocation must be bulk-capable**, because the realistic incident is "this operator's
key leaked and ten thousand instances hold it".

**No liveness, no biometrics, no in-person proofing.** Every high-assurance mechanism in human
identity depends on a body. None of it transfers.

**SPIFFE is the closest existing work and is not sufficient.** SPIFFE/SPIRE solves workload identity
*within a trust domain*: strong, attested, short-lived, and excellent at what it does. It has no
cross-organisational accountability, no public revocation, no binding to a legal entity, and no
model for a website that has never heard of the workload's operator. AIAF is what is needed at the
boundary *between* organisations; SPIFFE remains the right answer inside one.

### 1.3 Relationship to existing work

This framework composes existing standards wherever one exists. Inventing a parallel mechanism
where a published RFC already works is how a standard fails to be adopted.

| Existing work | Role in AIAF |
|---|---|
| **RFC 9421** — HTTP Message Signatures | **Normative.** The request signing mechanism. AIAF defines a profile, not a replacement. |
| **Web Bot Auth** (IETF draft work) | **Alignment target.** Signed-agent-request work already being adopted. AIAF SHOULD remain wire-compatible; where they diverge, that is a defect in this document. |
| **RFC 7515 / 7517 / 7518** — JWS, JWK, JWA | **Normative.** Credential envelope and key distribution. |
| **RFC 7800** — Proof-of-possession key semantics | **Normative.** The `cnf` claim binds a credential to the agent's key. |
| **RFC 8693** — Token Exchange, `act` claim | **Normative for delegation.** The actor-chain primitive is reused rather than reinvented (§3.4). |
| **RFC 9396** — Rich Authorization Requests | **RECOMMENDED** for expressing fine-grained delegated scope. |
| **W3C DIDs 1.0 / Verifiable Credentials 2.0** | **Optional alternative encoding.** An identifier MAY be expressed as a DID; a credential MAY be expressed as a VC. |
| **RFC 6962** — Certificate Transparency | **Normative in structure.** Registries MUST operate an append-only, publicly verifiable log (§8.4). |
| **SPIFFE/SPIRE** | Complementary; intra-trust-domain (§1.2). |
| **C2PA** | Complementary; content provenance, not actor identity (§16). |
| **IETF `aipref` work, robots.txt** | Complementary; expresses site preferences. AIAF carries an agent's *declared* conformance to them (§6.2), which is attributable but unverified. |
| **EU AI Act Art. 50** | A likely consumer. Transparency obligations for AI interaction are far easier to evidence with a verifiable agent identity than without. |
| **NIST SP 800-63** | Structural inspiration only. Not conformant; not applicable (§1.2). |

### 1.4 Terminology

| Term | Definition |
|---|---|
| **Agent** | An autonomous software process that originates requests without a human in the loop for each one. |
| **Operator** | The organisation accountable for an agent. The unit of accountability in this framework. |
| **Responsible Officer** | A named natural person at the Operator, required at OAL3. |
| **Principal** | A party on whose behalf an agent acts, who is not the Operator (typically an end user). |
| **Registry** | An entity that issues and revokes agent identifiers. |
| **Relying Party (RP)** | A service receiving agent requests and deciding how to treat them. |
| **Credential** | A short-lived signed assertion by a Registry about an agent. |
| **Reporter** | A party submitting an abuse report about an agent. |
| **Trust List** | The set of Registries an RP accepts credentials from. |

---

## 2. Trust model

### 2.1 Entities and relationships

```
                    ┌──────────────┐
                    │  PRINCIPAL   │  (end user, when the agent acts for someone)
                    └──────┬───────┘
                   delegation grant (DAL, §3.4)
                           ▼
  ┌────────────┐    ┌──────────────┐    registration    ┌──────────────┐
  │  RELYING   │◀───│    AGENT     │───────────────────▶│   REGISTRY   │
  │   PARTY    │    │ holds key K  │◀──── credential ───│              │
  └─────┬──────┘    └──────────────┘                    └──────▲───────┘
        │                    ▲                                 │
        │                    │ operates                        │ accountable
        │            ┌───────┴────────┐                        │
        │            │   OPERATOR     │────────────────────────┘
        │            │ (legal entity) │
        │            └───────▲────────┘
        │                    │ sanction
        └── abuse report ────┘  (§7)
```

The load-bearing relationship is **Operator → Registry**. Everything else derives from it: the
agent is a credential holder, the Registry is a record-keeper, and the Relying Party's recourse
runs to the Operator.

### 2.2 What can and cannot be proven

Stating this precisely is the most important paragraph in the document. A framework that overclaims
here is worse than no framework, because it induces reliance it cannot support.

| Claim | Provable | Mechanism |
|---|---|---|
| This request came from the holder of key K | **Yes** | RFC 9421 signature over bound components |
| Key K is bound to identifier A | **Yes** | Registry-signed credential, `cnf` (RFC 7800) |
| Identifier A belongs to Operator O | **Yes** | Registration + verification (§3.2) |
| Operator O is a real legal entity | **Yes, at OAL≥2** | Business-registry evidence, human review |
| A named person is answerable at O | **Yes, at OAL3** | Responsible Officer, contractual |
| Key K is in certified hardware | **Yes, at KAL3** | Remote attestation |
| A is authorised to act for Principal P | **Yes, at DAL≥2** | Signed, scoped delegation grant |
| Identifier A is valid right now | **Yes, within the revocation window** | Revocation distribution + short credential lifetime |
| This action was logged and is provable | **Yes** | Transparency log inclusion proof |
| A is running model M | **No** | Self-asserted. Unverifiable over the wire. |
| A will behave as declared | **No** | A declaration is a commitment, not a control |
| A has not been prompt-injected | **No** | A compromised agent holds valid credentials |
| A is "safe" or "aligned" | **No** | Out of scope (§16) |
| Unregistered traffic is malicious | **No** | Absence of a credential means *unidentified*, nothing more |

**The four "No" rows are not gaps to be closed later.** They are the boundary of what identity
infrastructure can do, and implementers MUST NOT present them as verified.

### 2.3 The compromised-agent assumption

Every design decision in §5 and §6 assumes that **some credentials are held by compromised or
misbehaving agents at all times**. This assumption is why credentials are short-lived, why
revocation is bulk-capable, and why sanctions attach to the Operator rather than only to the
identifier: an Operator that mints a replacement identifier after each revocation has defeated a
framework that sanctions only identifiers.

---

## 3. The assurance framework

### 3.1 Why one number is not enough

The natural design is a single 1–3 scale. It fails immediately on realistic cases:

- A hobbyist with a hardware-backed key in a secure enclave: excellent key protection, no verified
  legal entity. Trustworthy for authenticity, useless for recourse.
- A large bank running agents with software keys in a container: impeccable recourse, key material
  one container escape from theft.
- A verified enterprise agent acting on behalf of a consumer with no evidence of that consumer's
  consent: strong on both axes above, and the one that matters here is absent.

A single number forces these into the same bucket and loses the information an RP needs. AIAF
therefore defines **three independent axes**, and a composite for the common case.

| Axis | Question | Human analogue |
|---|---|---|
| **OAL** — Operator Assurance | Who is accountable, and how well evidenced? | NIST IAL (applied to the Operator, not the agent) |
| **KAL** — Key Assurance | How well is the agent's key protected and bound? | NIST AAL |
| **DAL** — Delegation Assurance | By what authority does it act for someone else? | NIST FAL — but materially extended |

### 3.2 OAL — Operator Assurance Level

Evidence about the party accountable for the agent.

| Level | Name | Requirements | What an RP may conclude |
|---|---|---|---|
| **OAL0** | Unverified | Contactable address only. No validation performed. | "Someone claimed this." No recourse. |
| **OAL1** | Domain-verified | Proven control of a DNS domain (DNS TXT or `/.well-known/`), re-verified at least every 90 days. A monitored abuse contact, tested for reachability. | "Whoever controls this domain is behind it." |
| **OAL2** | Verified legal entity | OAL1, **plus** identity of the legal entity verified against an authoritative business registry or LEI; jurisdiction recorded; evidence retained; verification approved by a human reviewer who is not the requester. Abuse contact with a published response SLA. | "There is a suable party in a known jurisdiction." |
| **OAL3** | Accountable entity | OAL2, **plus** a named **Responsible Officer** (natural person, identity-proofed at a level equivalent to NIST IAL2), a signed operating agreement accepting responsibility for agent conduct, and a financial instrument (insurance, bond, or escrow) sized to the agent's authorised actions. | "A named person and a solvent entity have contractually accepted responsibility." |

Normative requirements:

- A Registry **MUST NOT** assert OAL≥2 without human review. Automated business-registry lookup
  establishes that a company exists, not that the applicant is it.
- A Registry **MUST** demote an Operator whose abuse contact becomes unreachable, or whose domain
  control lapses, to the highest level whose requirements still hold, and **MUST** publish the
  demotion through revocation distribution (§6.3).
- OAL3 **MUST NOT** be asserted on the basis of technical evidence alone. It is a contractual
  state; the Registry attests that the contract exists.

> **On "strict liability".** A standards document cannot create liability; only contract and
> statute can. What AIAF can do — and OAL3 does — is define the technical and contractual
> preconditions under which a liability regime is *enforceable*: a known legal entity, a named
> officer, a signed agreement, and a financial instrument. Any implementation claiming that AIAF
> itself imposes liability is misrepresenting it.

### 3.3 KAL — Key Assurance Level

How well the agent's signing key is protected, and how firmly it is bound to the identifier.

Levels are distinguished by **what the evidence proves**, not by where the key is said to rest.

An earlier draft defined KAL2 by the storage medium — "non-exportable from a software-isolated
store" — which is not remotely verifiable. Software isolation leaves no cryptographic trace, so an
Operator's claim about it is an assertion, and an unverified assertion is KAL1 by definition. That
definition collapsed the level into the one below it, and is withdrawn.

| Level | Name | Requirements | Residual risk |
|---|---|---|---|
| **KAL0** | Unproven | Public key submitted; possession never demonstrated. | **Non-conforming.** Defined only so that non-conformance can be named. A Registry **MUST NOT** issue a credential at KAL0. |
| **KAL1** | Possession proven | Key generated by the Operator; proof of possession completed (§5.3); key never transmitted to the Registry. **Includes all self-asserted isolation.** | Key theft from Operator infrastructure compromises the identity until revocation. |
| **KAL2** | Attested non-exportability | KAL1, plus **cryptographic evidence, verifiable to a pinned root of trust, that the key was generated inside and cannot leave a protected module.** No runtime measurement required. Satisfied by e.g. TPM 2.0 key certification, HSM key attestation, or an enclave attestation carrying the public key. | The key cannot be exfiltrated, but code running alongside it may still invoke it. |
| **KAL3** | Attested non-exportability and runtime | KAL2, plus **a verified measurement of the code able to invoke the key**, matched against a baseline the Operator declared in advance, refreshed at least every 24 hours. | Compromise requires physical access, a break in the attestation chain, or an exploit landing after measurement. |

The split falls on a real engineering boundary: proving a key **cannot be exfiltrated** is a
different and much easier problem than proving the code **using** it is what it claims to be.

Normative requirements:

- The Operator **MUST** generate the keypair. A Registry **MUST NOT** generate, request, receive,
  or store an agent private key at any level. A Registry that holds agent private keys can
  impersonate every agent it serves, which negates the framework.
- Proof of possession (§5.3) is **REQUIRED** at every level above KAL0.
- **A Registry MUST NOT assert KAL greater than or equal to 2 on the basis of an Operator's
  assertion.** Only evidence verifiable to a pinned root of trust may raise the level.
- At KAL2 and above the attestation evidence **MUST** be bound to a Registry-issued, single-use
  nonce, and the Registry **MUST** verify that the attested key is the registered key. An
  attestation proving that a protected module exists, without binding it to the key in use, proves
  nothing about that key.
- Trust roots **MUST** be pinned. A root fetched at verification time is a root that an attacker
  who can interpose on that fetch has chosen.
- At KAL3 the attestation's validity **MUST NOT** exceed 24 hours, and the measurement **MUST** be
  compared against a baseline recorded before the attestation was presented. A measurement with no
  declared baseline evidences that *something* ran, not that the expected thing ran, and is
  therefore KAL2.
- On expiry of an attestation a Registry **MUST** demote the level. It **MUST NOT** revoke solely
  because an attestation lapsed: an attestation-service outage would otherwise become a mass
  identity outage.

**Evidence classes.** Some mechanisms — a cloud KMS that reports key origin over an authenticated
API but publishes no verifiable chain, for instance — are a trusted third party's assertion rather
than a cryptographic proof. A Registry **MAY** accept these at KAL2, and **MUST** then record and
publish the evidence class distinctly (`cryptographic` against `third_party_assertion`) so that a
Relying Party can apply its own view of what that is worth.

### 3.4 DAL — Delegation Assurance Level

By what authority does the agent act for a party other than its Operator? This axis has no direct
human-identity equivalent and is where most real-world harm will originate.

| Level | Name | Requirements | Suitable for |
|---|---|---|---|
| **DAL0** | No delegation | The agent acts only for its Operator. | Crawling, monitoring, first-party automation |
| **DAL1** | Asserted delegation | The Operator asserts that the agent acts for a Principal. No evidence from the Principal. | Nothing of consequence. An RP **SHOULD** treat DAL1 as equivalent to DAL0 for any action with an effect. |
| **DAL2** | Evidenced delegation | A delegation grant signed by the Principal (or by an IdP the RP trusts on the Principal's behalf), naming the agent identifier, **scoped** to specific action classes, **time-bound**, and independently revocable by the Principal. Single hop. | Transactions on behalf of a consenting user |
| **DAL3** | Constrained delegation | DAL2, plus: every hop in a multi-agent chain is separately signed; the chain carries an explicit, enforced depth limit; the Principal can revoke with effect within the revocation window; and high-value action classes require per-action confirmation rather than standing authority. | Financial instruction, clearing, irreversible actions |

**Encoding.** Delegation chains **MUST** be expressed using the RFC 8693 `act` (actor) claim
structure. A new format is not required and **MUST NOT** be invented:

```json
{
  "sub": "aid:v1:acme-corp:01J8Z…",
  "act": {
    "sub": "https://principal.example/users/1a2b",
    "scope": ["orders:read", "orders:create"],
    "exp": 1790000000,
    "grant": "<JWS signed by the Principal>",
    "depth": 1,
    "max_depth": 2
  }
}
```

Normative requirements:

- An agent chain **MUST** enforce `max_depth`. An RP receiving `depth > max_depth` **MUST** reject.
- A delegation grant **MUST** be independently revocable by the Principal, and revocation **MUST**
  take effect within the same window as identifier revocation (§6.3).
- Scope **MUST** be least-privilege and explicit. A grant conveying "all actions" **MUST NOT** be
  accepted above DAL1.
- An RP **MUST NOT** infer delegation authority from AgAL. A hardware-attested agent of a verified
  bank has no authority over a consumer's account without a grant from that consumer.

### 3.5 AgAL — the composite

For the common case an RP wants one number. **AgAL** is defined as a composite, and is deliberately
limited by the weaker of the two accountability axes:

```
AgAL = min(OAL, KAL)          for OAL ≥ 1 and KAL ≥ 1
AgAL = 0                      otherwise (non-conforming; MUST NOT be issued)
```

| AgAL | Composition | Plain-language meaning | Typical RP posture |
|---|---|---|---|
| **AgAL1** | OAL1 + KAL1 | Identified: a domain controller stands behind it, and it proved it holds its key. | Read access, rate-limited. Recourse is a domain abuse contact. |
| **AgAL2** | OAL2 + KAL2 | Verified publisher: a suable legal entity in a known jurisdiction, key held in isolation. | Standard transactional access. |
| **AgAL3** | OAL3 + KAL3 | Accountable enterprise: named officer, signed agreement, financial instrument, hardware-attested key with live attestation. | High-value and regulated actions. |

**DAL is orthogonal and is not folded into AgAL.** This is deliberate: collapsing it would let a
high AgAL imply an authority the agent does not have. Two rules bind them:

- Any action affecting a third party **MUST** require DAL≥2 regardless of AgAL.
- Financial instruction or clearing **SHOULD** require AgAL3 **and** DAL3.

**The composite is a floor, not a ceiling.** A `min()` means an agent cannot buy its way to AgAL3
with hardware alone, nor with paperwork alone. Both are required, because both failures are fatal:
an unattributable hardware key gives no recourse, and a verified enterprise with a stolen software
key gives no authenticity.

**AgAL0 is an outcome, not an issuance.** No Registry issues AgAL0. It is the level a Relying
Party **MUST** assign to any request that does not carry a credential it has verified under §9 —
whatever network, host, tool or proxy the request arrived from (§13.7). AgAL0 means
*unidentified*: the request is entitled to whatever the RP grants anonymous traffic, and to
nothing that depends on identity. It does not mean *malicious* (§9.9).

### 3.6 Worked examples

| Scenario | OAL | KAL | DAL | AgAL | Notes |
|---|---|---|---|---|---|
| Hobbyist crawler, software key, verified domain | 1 | 1 | 0 | **1** | Fine for read access |
| Search-engine crawler at a verified company | 2 | 2 | 0 | **2** | The common commercial case |
| Enterprise support agent acting for a signed-in customer | 2 | 2 | 2 | **2** | DAL2 is what permits acting on the account |
| Payment agent initiating a transfer | 3 | 3 | 3 | **3** | Per-action confirmation required |
| Hobbyist with a TPM-backed key, unverified entity | 0 | 3 | 0 | **0** | Excellent key, no recourse — **not issuable** |
| Verified bank, key in a plain container, no rotation | 2 | 1 | 0 | **1** | Paperwork does not substitute for key protection |
| Agent claiming to act for a user, no grant | 2 | 2 | 1 | **2** | RP **SHOULD** refuse any account-affecting action |

### 3.7 Status of this framework in the reference implementation

Stated so that no reader mistakes specification for deployment:

| Level | Reference implementation status |
|---|---|
| OAL0–OAL2 | Implemented |
| OAL3 | Implemented: a Responsible Officer proofed to IAL2 (an identity-verification provider's result, or documents under manual review), a signed operating agreement and a financial instrument, reviewed by one person and approved by another. The grant expires, and a lapsed agreement or instrument demotes the Operator to OAL2. |
| KAL1 | Implemented |
| KAL2 | Implemented for the AWS Nitro Enclaves profile (attested non-exportability) |
| KAL3 | Implemented for AWS Nitro Enclaves with a declared measurement baseline |
| DAL0–DAL1 | Implemented |
| DAL2–DAL3 | **Not implemented.** Requires grant issuance, chain validation and Principal-initiated revocation. |

An implementation **MUST NOT** advertise a level it does not enforce.

---

## 4. Identifiers

### 4.1 Syntax

```
aid:v1:acme-corp:01J8Z3QX7KFM2N5T9VB0WXYZ:k3f9
└┬┘ └┬┘ └───┬───┘ └──────────┬───────────┘ └─┬┘
 │   │      │                │               └── 4-char checksum over everything left of it
 │   │      │                └────────────────── 26-char ULID: 48-bit ms timestamp + 80 bits entropy
 │   │      └─────────────────────────────────── Operator namespace (DNS-label syntax)
 │   └────────────────────────────────────────── version
 └────────────────────────────────────────────── scheme
```

An identifier **MUST** be treated as a public value. No security property may depend on an
identifier being secret, unguessable, or unenumerable.

An identifier **MAY** additionally be expressed as `did:<method>:<namespace>:<ulid>` for
decentralised-identity interoperability. Both spellings denote the same identity.

### 4.2 Cross-registry namespace collision

Identifiers are unique **within a Registry**. Two Registries may both issue `acme-corp`, and a
naive RP that keys trust on the namespace string is vulnerable to a squatter registering
`acme-corp` at a permissive Registry.

Therefore:

- A credential at OAL≥1 **MUST** carry a `org_domains` claim listing the Operator's
  domain-control-verified domains (§6.2).
- A Relying Party making an identity-based trust decision **MUST** key it on the
  (Registry issuer, verified domain) pair, and **MUST NOT** key it on the namespace string alone.
- A Registry **MUST NOT** assert a domain in `org_domains` that it has not itself verified within
  the preceding 90 days.

This is the mechanism the Web PKI uses, for the same reason: domain control is the only namespace
anchor that already has an authority behind it.

---

## 5. Lifecycle

### 5.1 States

```
                  ┌──────────────────┐
   register ────▶ │  PENDING_PROOF   │ ──── proof expires ────▶ EXPIRED
                  └────────┬─────────┘
                    proof of possession
                           ▼
    reinstate  ┌───▶ ┌──────────┐ ◀──── renewal ────┐
        │      │     │  ACTIVE  │                   │
        │      │     └────┬─────┘ ───────────────────┘
        │      │          │
   ┌────┴──────┴──┐   ┌───▼──────┐
   │  SUSPENDED   │◀──│ sanction │──▶ ┌──────────┐
   └──────────────┘   └──────────┘    │ REVOKED  │ (terminal)
                                      └──────────┘
```

**REVOKED is terminal.** A revoked identifier **MUST NOT** be reinstated, because RPs cache
revocation state and no mechanism can reliably instruct the world to forget. Suspension is the
reversible sanction; implementations that conflate them will eventually un-revoke something in a
cache they do not control.

### 5.2 Registration

The Operator submits: a public key, an agent profile, a declared specification, and a declaration
of intended behaviour (§6.2). A Registry **MUST**:

- reject any submission containing private key material;
- validate the public key structurally before minting an identifier, so a malformed key does not
  consume an identifier;
- enforce per-Operator rate limits;
- place the agent in `PENDING_PROOF`. An agent in `PENDING_PROOF` **MUST NOT** be issued a
  credential and **MUST NOT** verify anywhere.

### 5.3 Proof of possession

The Registry issues a single-use, time-limited challenge. The Operator signs it with the agent's
private key.

The signed message **MUST** be domain-separated:

```
aiaf-pop-v1:<challenge_id>:<nonce>:<subject>
```

Without a protocol-specific prefix, a signature produced by the same key for an unrelated purpose
could be replayed as proof of possession. The challenge **MUST** be single-use and **MUST** be
marked consumed atomically with, or before, verification.

### 5.4 Issuance

On successful proof the Registry **MAY** issue:

- an **agent certificate**: a long-lived (≤90 days) binding of identifier ↔ key ↔ Operator ↔
  capabilities, held by the Operator;
- **credentials**: short-lived (**MUST** be ≤15 minutes) assertions presented to RPs.

Credential lifetime is a load-bearing control, not a tuning parameter. With a 15-minute ceiling, a
stolen credential has a bounded blast radius **even if revocation fails entirely**. A framework
whose safety depends on revocation working has no safety margin on the day revocation does not.

A Registry **MUST NOT** store credential bodies. It **MUST** retain enough metadata to revoke and
to audit, and **MUST NOT** retain enough to impersonate.

### 5.5 Presentation and verification

See §6.1 and §9.

### 5.6 Renewal and rotation

- Renewal **MUST** be automatable without human intervention.
- Key rotation **MUST** be overlapping: the new key is proven and published before the old key is
  retired. An implementation that retires first creates a window in which every request fails.
- A Registry **MUST** publish a rotated key for at least one maximum credential lifetime plus the
  revocation window before ceasing to serve the old one.

### 5.7 Suspension, revocation, expiry

| Transition | Who may initiate | Effect |
|---|---|---|
| Suspend | Operator, Registry, upheld abuse report | Reversible; credentials cease being issued |
| Revoke | Operator, Registry, upheld abuse report, key compromise | **Terminal**; identifier published as revoked permanently |
| Expire | Time | Certificate lapses; renewable |

Revocation **MUST** cascade to outstanding credentials. Revocation of an Operator **MUST** cascade
to all its agents.

---

## 6. Wire format

### 6.1 Request signing — RFC 9421 profile

An agent signs each request per RFC 9421. Conforming signatures:

- **MUST** cover, at minimum, `@method`, `@authority` and `@path`. Each is load-bearing: without
  `@method` a `GET` signature replays as a `DELETE`; without `@authority` it replays against
  another site; without `@path` against another endpoint on the same site.
- **MUST** carry `created`, and **MUST** carry `nonce` where the RP performs replay detection.
- **MUST** carry `keyid` equal to the agent identifier the credential was issued for. An RP
  **MUST** reject a mismatch, which is otherwise the route to pairing a stolen credential with an
  attacker's key.
- **MUST** use an algorithm from the registry in §17.3.
- **SHOULD** be rejected by an RP if older than 300 seconds.

```http
GET /api/products HTTP/1.1
Host: shop.example
Signature-Input: sig1=("@method" "@authority" "@path");created=1790243730;\
  keyid="aid:v1:acme-corp:01J8Z…";alg="ed25519";nonce="k9Xr…";tag="aiaf"
Signature: sig1=:MEUCIQD…:
Agent-Credential: eyJhbGciOiJFZERTQSIsInR5cCI6…
```

### 6.2 Credential

A compact JWS. Claims divide into three groups, and the division is normative because it is what
prevents a Relying Party from mistaking an assertion for a fact.

**Verified by the Registry** — top-level claims:

| Claim | Type | Requirement | Meaning |
|---|---|---|---|
| `iss` | string | MUST | Registry issuer identifier |
| `sub` | string | MUST | Agent identifier |
| `jti` | string | MUST | Unique credential identifier |
| `iat`, `nbf`, `exp` | number | MUST | `exp - iat` **MUST NOT** exceed 900 s |
| `cnf` | object | MUST | RFC 7800 key confirmation: `{"jwk": …, "kid": …}` |
| `org` | string | MUST | Operator namespace |
| `org_domains` | array | MUST at OAL≥1 | Domain-control-verified domains (§4.2) |
| `agal` | number | MUST | Composite assurance level (§3.5) |
| `oal`, `kal` | number | MUST | Component levels |
| `dal` | number | MUST when `act` present | Delegation assurance level |
| `capabilities` | array | SHOULD | Granted action classes |
| `scopes` | array | MAY | Resource scopes |
| `standing` | object | SHOULD | Aggregate counts only (§7.5) |
| `aud` | string/array | MAY | When bound to a specific RP |
| `act` | object | MAY | Delegation chain (RFC 8693, §3.4) |

**Self-asserted by the Operator** — **MUST** be nested under `declared` and **MUST NOT** appear at
the top level:

```json
"declared": {
  "agent_type": "autonomous",
  "model_family": "…",          // unverifiable — see §2.2
  "autonomy_level": "supervised",
  "human_oversight": true,
  "purposes": ["customer_support"],
  "respects_robots_txt": true,
  "contact_for_abuse": "abuse@acme.example"
}
```

A Registry **MUST NOT** place a self-asserted value at the top level, and **MUST NOT** present one
as verified. This is the single most likely place for a conforming implementation to drift into
misrepresentation, and an RP **SHOULD** treat a top-level `model_family` as evidence of a
non-conforming Registry.

### 6.3 Revocation distribution

A Registry **MUST** publish revocation state in a form a Relying Party can consume **without
contacting the Registry per request**. It **MUST** offer at least one of:

- **Signed deltas** — everything after a client-held monotonic serial. **RECOMMENDED**, because a
  current client receives an empty response and polling costs both sides almost nothing.
- **Signed filter** — a probabilistic structure over the revoked set, where a miss is definitive
  and a hit requires resolution against an authoritative check.

Both **MUST** be signed by the Registry. An unsigned revocation feed lets anyone who can interpose
on the fetch silently strip their own agent's revocation; against a signed feed the worst an
interceptor can do is serve a stale one, which the RP can detect from `iat`.

Normative:

- The maximum revocation propagation target **MUST** be published by the Registry and **SHOULD NOT**
  exceed 60 seconds.
- A delta whose `since` exceeds the client's held serial **MUST** be rejected by the client: applying
  it would silently lose the revocations in between.
- A client **MUST NOT** treat its local revocation state as authoritative unless it has ingested a
  complete snapshot.

### 6.4 Discovery

A Registry **MUST** publish `/.well-known/aiaf-registry`:

```json
{
  "issuer": "https://registry.example",
  "jwks_uri": "https://registry.example/.well-known/jwks.json",
  "revocation_delta_endpoint": "https://registry.example/v1/revocations/delta",
  "revocation_filter_endpoint": "https://registry.example/v1/revocations/filter",
  "revocation_status_endpoint": "https://registry.example/v1/revocations/status",
  "transparency_log_uri": "https://registry.example/v1/tree-head",
  "assurance_levels_supported": {"oal": [0,1,2], "kal": [1,2], "dal": [0,1]},
  "algorithms_supported": ["ed25519", "ecdsa-p256-sha256"],
  "max_credential_lifetime_seconds": 900,
  "revocation_propagation_target_seconds": 60,
  "abuse_report_endpoint": "https://registry.example/v1/abuse-reports",
  "abuse_report_sla_hours": 24
}
```

`assurance_levels_supported` is how an RP learns what a Registry actually enforces, rather than
what it claims in prose.

---

## 7. Accountability: abuse reporting and due process

A framework that can revoke an identity must specify how — otherwise revocation becomes an
unaccountable power, and the framework's worst abuse will be of the framework itself.

### 7.1 Who may report

A Registry **MUST** accept abuse reports from any party, including unauthenticated ones. Requiring
an account means the Registry only ever hears from parties who already have a relationship with it,
which excludes most of the internet an agent interacts with.

A Registry **MUST** rate-limit reporters and **SHOULD** weight them by history. An unlimited report
channel is a griefing vector against honest Operators.

### 7.2 Intake

- Evidence **MUST** be supplied by the Reporter. A Registry **MUST NOT** collect evidence by
  observing agent traffic; it is a mailbox, not a sensor. (See §12 — a Registry that surveils to
  substantiate reports has become the thing this framework exists to avoid.)
- A report **MUST** record: subject identifier, category, and reporter contact.
- Reporter identity and any reporter domain **MUST** be treated as confidential (§12.2).

### 7.3 Due process

These requirements exist because the sanction is loss of identity, which for a commercial Operator
can be loss of business.

1. **Notification.** The Operator **MUST** be notified before any sanction, except where immediate
   action is required to prevent ongoing harm (key compromise, active fraud). Where immediate
   action is taken, notification **MUST** follow within 24 hours.
2. **Response window.** The Operator **MUST** be given a stated opportunity to respond — at least
   72 hours for non-urgent categories.
3. **Independent reviewer.** The reviewer **MUST NOT** be the Reporter. Where the Registry is the
   Reporter, the reviewer **MUST** be organisationally separate from the reporting function.
4. **Proportionality.** The sanction **MUST** be the least severe adequate to the finding (§7.4).
5. **Appeal.** An Operator **MUST** be able to appeal to a reviewer who was not involved in the
   original decision.
6. **Record.** Every report, decision, sanction and appeal **MUST** be recorded in the transparency
   log (§8.4), so that the Registry's own conduct is auditable.

### 7.4 Sanction ladder

| Sanction | Reversible | Appropriate for |
|---|---|---|
| No action | — | Dismissed |
| Warning | — | First, minor, corrected |
| Assurance demotion | Yes | Verification conditions no longer hold |
| Suspension | Yes | Serious, or pending investigation |
| Revocation | **No** | Fraud, key compromise, a Tier 1 violation (§7.6), repeated upheld findings |
| Operator-level revocation | **No** | Systemic abuse; cascades to every agent |

A Registry **SHOULD NOT** revoke on a single upheld report absent fraud, key compromise or a Tier 1
violation (§7.6). The escalation is what distinguishes a sanction regime from a kill switch; Tier 1
is the one category where the harm of a second chance exceeds the harm of an unwarranted revocation,
and §7.6 is correspondingly stricter about the evidence a finding needs.

### 7.5 Publication limits

A Registry **MUST NOT** publish: reporter identity, reporter domain, report contents, or evidence.
It **MAY** publish aggregate counts of upheld reports per agent.

The reason is specific: a reporter's domain paired with an agent identifier is a record that *this
site interacted with this agent* — precisely the cross-site relationship a Registry must not
accumulate (§12.1). Publishing reporters also turns the report channel into a tool for competitors
to smear one another.

### 7.6 Tier 1 violations: unsolicited offensive activity

An agent that probes systems for weaknesses without the owner's authorisation is not misbehaving
at the margin of acceptable use. It is conducting reconnaissance, or an attack, under an identity
the framework vouched for. The sanction ladder's escalation (§7.4) exists for conduct that can be
corrected by warning. This conduct cannot be.

**Definition.** *Unsolicited offensive activity* is any of the following, directed at a system whose
owner has not authorised the Operator to test it:

- port, service or host enumeration (**port scanning**);
- probing for known vulnerabilities, misconfigurations or exposed credentials (**vulnerability
  scanning**), including automated fuzzing of inputs;
- attempts to exploit a vulnerability, bypass authentication or escalate privilege.

*Authorisation* means a written grant from the system's owner covering the target, the technique
and the time window: a penetration-test engagement, or a published vulnerability disclosure
programme whose scope includes the activity. Activity within such a grant is not a Tier 1
violation, and an Operator **SHOULD** declare offensive-security capability under `declared` so that
Relying Parties can recognise it. The abuse category is `unsolicited_scanning` (§17.7).

**Evidence.** A Tier 1 finding carries an irreversible sanction, so the evidence bar is higher than
for any other category:

1. A Tier 1 finding **MUST** rest on requests *signed by the subject agent's key* (§6.1) or
   presented with its credential. Traffic attributed to an agent by source address, user agent or
   timing alone **MUST NOT** support a Tier 1 finding: that traffic is AgAL0 (§3.5), and framing an
   Operator must not be as cheap as spoofing an address.
2. The reviewer **MUST** record which signed requests constitute the probing, and **MUST** consider
   any authorisation the Operator produces during the response window (§7.3.2).

**Sanction.** When a Tier 1 report is upheld:

1. The agent's identity **MUST** be revoked, with reason `abuse`. The reviewer **MUST NOT** substitute
   a lesser sanction: the reviewer decides *whether* the violation occurred, not what it costs. A
   Registry **SHOULD** enforce this in its authorization layer rather than by procedure, so the
   choice is not available to make.
2. The Operator **MUST** be placed under accountability review. While a review is open, the
   Operator's OAL **MUST** be treated as at most OAL1 for every credential issued to any of its
   agents: an enterprise answers for its agents' offensive actions, and Relying Parties are
   protected without having to learn of the incident.
3. A review **MUST** be closed only under multi-person control (§8.16), on a record of the
   Operator's remediation. Closing it restores the OAL the Operator's evidence supports. It does not
   reinstate the revoked identity, which is irreversible (§7.4).
4. A Registry **SHOULD** consider Operator-level revocation after a second upheld Tier 1 finding
   against the same Operator within twelve months.

**Due process is not suspended.** Notification, the response window, an independent reviewer and
appeal (§7.3) all apply. A Registry **MAY** suspend the agent at intake when a report shows
probing still in progress, under the immediate-action provision of §7.3.1. If an appeal succeeds,
the review is closed and the finding corrected in the transparency log. The identifier stays
revoked, and the Operator registers a new identity at no cost.

---

## 8. Registry conformance requirements

A **conforming Registry** MUST satisfy all of the following. This list is the definition of
conformance; nothing else in this document creates a Registry obligation.

**Key handling**
1. **MUST NOT** generate, request, receive, or store agent private keys.
2. **MUST** require proof of possession before issuing any credential.
3. **MUST** protect its own signing keys in a certified cryptographic module, non-exportable.

**Issuance**
4. **MUST NOT** issue credentials with a lifetime exceeding 900 seconds.
5. **MUST** bind each credential to the agent's key using `cnf` (RFC 7800).
6. **MUST NOT** assert an assurance level whose requirements it does not enforce.
7. **MUST** segregate self-asserted claims under `declared`.

**Revocation**
8. **MUST** publish signed revocation state consumable without per-request contact.
9. **MUST** publish and meet a revocation propagation target.
10. **MUST** cascade Operator revocation to all its agents.

**Transparency**
11. **MUST** operate an append-only log of issuance, revocation and sanction events, with publicly
    verifiable inclusion and consistency proofs (RFC 6962 construction or equivalent).
12. **MUST** publish signed log heads at least every 24 hours, externally retrievable, so that a
    third party retaining an old head can prove the log was not rewritten.

**Governance**
13. **MUST** implement the due-process requirements of §7.3.
14. **MUST** publish `/.well-known/aiaf-registry` (§6.4).
15. **MUST** publish its verification procedures for each OAL it offers.
16. **MUST** enforce separation of duties for privileged operations, and **MUST** require
    multi-person control for: OAL≥2 verification, signing-key rotation, and Operator-level
    revocation.

**Privacy**
17. **MUST NOT** require Relying Parties to report verification events as a condition of use.
18. **MUST NOT** condition an assurance level on the Operator granting the Registry access to
    agent traffic.

**Offensive activity and development identities**
19. **MUST** apply §7.6 to upheld Tier 1 reports: revocation, and an accountability review that
    caps the Operator's OAL at 1 until it is closed under multi-person control.
20. **MUST** support development identities (§13.7) and **MUST** mark every credential issued to one
    with `env: "development"` (§17.2).

> Requirements 17 and 18 exist because the commercial temptation to require telemetry is strong and
> the harm is irreversible. A Registry that knows which sites verified which agents holds a
> cross-site behavioural graph of the entire agent web. The framework forecloses it.

---

## 9. Relying Party conformance requirements

A **conforming Relying Party** MUST:

1. Verify the credential signature against a key obtained from a Registry on its Trust List.
2. Verify the credential's validity window, with clock-skew tolerance.
3. Verify the RFC 9421 request signature against the key in the credential's `cnf`, **and** verify
   that the signature's `keyid` matches the credential's `sub`.
4. Verify that the signature covers `@method`, `@authority` and `@path`.
5. Check revocation state from a signed feed, refreshed at least as often as the Registry's
   published propagation target.
6. Treat "could not determine revocation status" as **distinct** from "not revoked", and apply a
   documented policy to it (§13.3).
7. **MUST NOT** treat `declared` values as verified.
8. **MUST NOT** derive delegation authority from AgAL (§3.4).
9. **MUST NOT** treat the absence of a credential as evidence of malice.

A conforming RP **SHOULD**:

10. Enforce replay protection using the signature `nonce`.
11. Publish the minimum AgAL and DAL it requires per action class, so Operators can self-select.
12. Report abuse to the issuing Registry rather than only blocking. Blocking protects one site;
    reporting protects everyone.

A conforming RP **MUST** also:

13. Assign AgAL0 to any request without a credential it has verified (§3.5), and **MUST NOT**
    raise that level because of where the request came from: a loopback or private address, a
    corporate network or VPN, a developer tool, or a header the caller's own environment set (§13.7).
14. **MUST NOT** grant a credential carrying `env: "development"` more than it grants AgAL1, and
    **MAY** refuse such credentials entirely.

---

## 10. Operator conformance requirements

A **conforming Operator** MUST:

1. Generate agent keys itself; never transmit a private key.
2. Complete proof of possession.
3. Maintain a monitored abuse contact and respond within its published SLA.
4. Revoke promptly on suspected key compromise.
5. Ensure declarations in `declared` are accurate, and update them when behaviour changes.
6. **MUST NOT** share one agent identity across parties who are separately accountable.
7. **MUST NOT** direct an agent at any system in a manner §7.6 defines as unsolicited offensive
   activity.
8. **MUST NOT** route an agent's traffic through a local or developer environment in order to avoid
   presenting a credential, or to present agent traffic as a person's (§13.7).
9. **MUST** run agents under development only with development identities (§13.7): never with a
   production agent's key, identifier, capabilities or scopes.

A conforming Operator **SHOULD** rotate keys at least every 90 days, and **SHOULD** issue distinct
identifiers per deployment so that revocation is proportionate.

---

## 11. Multi-registry interoperability

### 11.1 No single registry

This framework **MUST NOT** be implemented in a way that presumes one Registry. Relying Parties
maintain **Trust Lists**; a Registry earns a place on one by its conformance, its transparency log,
and its published verification procedures — not by incumbency.

### 11.2 Trust list management

A Relying Party **SHOULD** obtain Trust Lists from a source it can audit, **SHOULD** pin Registry
root keys out of band, and **MUST** be able to remove a Registry without code changes.

### 11.3 Cross-registry assurance comparability

AgAL asserted by one Registry is comparable to AgAL asserted by another **only** to the extent both
publish and meet the §3 requirements. An RP **SHOULD** treat assurance levels from a Registry
without a verifiable transparency log as self-asserted, whatever the level claims.

### 11.4 Conformance test suite

A conformance test suite — machine-readable vectors covering credential verification, signature
binding, revocation, delta gap handling, and the failure cases — **MUST** be published alongside
this framework, and any implementation claiming conformance **SHOULD** publish its results.

An interoperability claim that has not been tested against shared vectors is an assertion, not a
result. The reference implementation's vectors cover two algorithms, 22 cases per suite, and are
replayed by three independent language implementations.

---

## 12. Privacy considerations

### 12.1 The registry must not become a surveillance layer

The gravest risk this framework creates is not agent abuse. It is that a Registry, sitting between
every agent and every site, accumulates a cross-site record of which agents did what where — a
capability no participant asked for and none can withdraw once built.

Therefore, normatively:

- Verification **MUST** be possible entirely offline (§6.3). A framework whose common path requires
  contacting the Registry has built the surveillance layer by construction, whatever its policy
  says.
- A Registry **MUST NOT** require RPs to report verification events (§8.17).
- A Registry **MUST NOT** condition assurance on traffic access (§8.18).

The test to apply to any proposed extension: *could a Registry answer "which sites did agent A
visit?"* If yes, the extension is defective.

### 12.2 Personal data

- Operator and Responsible Officer details are personal data. A Registry **MUST** apply appropriate
  technical measures, and **MUST** support erasure on request.
- Transparency log entries **MUST** contain identifiers and hashes, not personal data — which is
  what allows the right to erasure and an immutable log to coexist.
- Reporter identity and domain **MUST** be confidential (§7.5).

### 12.3 Principal privacy in delegation

A delegation grant identifies a Principal to the RP. A grant **SHOULD** use a pairwise or
site-specific Principal identifier where the RP does not already know them, so that delegation does
not become a cross-site correlation mechanism for end users.

---

## 13. Security considerations

### 13.1 Credential theft

The realistic and most likely failure. Mitigated by: Operator-held keys (a Registry breach yields
nothing), the 900-second credential ceiling, KAL2/KAL3 isolation, and bulk revocation. **Residual:
a compromised agent acts legitimately until detected.** This is irreducible; the mitigation is
detection and revocation speed, not prevention.

### 13.2 Registry compromise

Highest impact. Mitigated by HSM-held signing keys, multi-person control, and — decisively — the
transparency log: fraudulently issued identifiers are **publicly detectable**, which is the property
Certificate Transparency was invented to provide. It does not prevent the attack; it makes it loud.

### 13.3 Fail-open revocation

The web PKI's most-regretted decision. An implementation that treats "revocation status unknown" as
"not revoked" makes revocation optional for any adversary who can block a fetch.

Conforming implementations **MUST** distinguish the two states, **SHOULD** default to refusing, and
**MUST** document their choice. A soft-fail posture is legitimate when chosen deliberately and
stated; it is a defect when arrived at by omission.

### 13.4 Prompt injection and agent hijack

No credential mechanism addresses it. A hijacked agent presents valid credentials and signs
genuinely. AIAF's contribution is bounded and should be stated precisely: it makes the incident
*attributable* and the identity *revocable*. Implementations **MUST NOT** imply that identity
assurance mitigates hijack.

### 13.5 Sybil operators

An Operator who revokes-and-reregisters defeats identifier-level sanctions. Mitigated by
Operator-level sanction (§7.4), by OAL≥2 human review making bulk re-registration expensive, and by
publishing Operator-level standing rather than only per-agent standing.

### 13.6 Downgrade

An attacker who can influence Registry selection may steer an RP to a permissive Registry. Mitigated
by Trust Lists (§11.2), by `org_domains` anchoring on domain control (§4.2), and by RPs setting a
minimum assurance floor per action class.

### 13.7 Unverified execution environments and local proxies

Agents are built on developer machines: in an IDE, behind a local proxy, through a tunnel, calling
real services from a laptop. None of those places is verified, and none of them can vouch for what
passes through it. The requirements below close the two failure modes that follow.

**Origin conveys no identity.** A request's source — `localhost`, an RFC 1918 address, a corporate
egress range, a VPN, a request arriving through an IDE extension or a local forwarding proxy — says
nothing about which agent sent it or who answers for it. Neither does any header the sending
environment chose to set. A request that does not carry a credential the RP has verified is
therefore AgAL0 (§3.5, §9.13), however trusted the network it came from. A local proxy **MAY**
attach and sign on an agent's behalf if it holds that agent's key and signs per §6.1; the request is
then judged by its credential and signature alone, never by the proxy's location.

*Rationale.* The reference implementation learned this on its own operator console, which once
trusted identity headers from its caller. Any design that grants trust by position — "it came from
inside" — grants it to whoever reaches that position, and a developer workstation is the easiest
position there is to reach.

**Local routing is not a bypass.** An Operator **MUST NOT** use local or developer infrastructure
to relay production agent actions (§10.8). Doing so to evade identity checks makes the Operator the
author of that traffic, and it is sanctionable as `undeclared_purpose` or, where it hides probing,
under §7.6.

**Development identities.** An agent under development **MUST** use its own identity, registered
for that purpose (§10.9). A development identity:

1. **MUST** be a distinct identifier with a distinct key, never a production agent's;
2. **MUST** be ephemeral: the identity **MUST** expire no more than 30 days after registration, and
   **SHOULD** be discarded with the environment that used it;
3. **MUST NOT** hold the capabilities or scopes of the production agent it precedes, and **MUST NOT**
   carry DAL above 0;
4. **MUST** be marked `env: "development"` in every credential issued for it (§8.20, §17.2), so an RP
   can apply §9.14 without asking.

A compromised developer machine then yields a short-lived identity that no production RP grants
more than AgAL1 — not the production agent's key.

---

## 14. Governance

### 14.1 The conflict of interest, and what follows from it

A framework written by an organisation that profits from its adoption will be read — correctly — as
an attempt to define a market in its own favour. The enterprises whose adoption determines whether
this succeeds are precisely the ones most alert to that pattern, and the failure mode is not
criticism but silence.

Two structures must therefore be separated, permanently:

| The framework | The registry service |
|---|---|
| Open, freely implementable, no royalty | Commercial |
| Multi-registry by construction | One participant among several |
| Change control transferred to a neutral body (§14.2) | Governed by its operator |

The precedents are unambiguous. ACME became ubiquitous because it is an IETF RFC that any CA may
implement; Let's Encrypt is one CA among many. The CA/Browser Forum Baseline Requirements are not
owned by any CA. OAuth is owned by nobody. In each case the standard's neutrality is what allowed
the commercial participants to profit from it.

### 14.2 Path to legitimacy

This document should not be described as a standard until it has completed, in order:

1. **Public draft** — published openly under permissive terms with a patent non-assert.
2. **Reference implementation** — free, open, complete, with a conformance suite.
3. **Independent implementations** — at least two, by unaffiliated parties. Until this exists,
   this is one vendor's format.
4. **Independent registries** — at least one operated by an unaffiliated party. Until this exists,
   the multi-registry claims in §11 are untested.
5. **Standards body submission** — to the IETF (the HTTP Message Signatures and Web Bot Auth work
   is the natural home) or a W3C Community Group.
6. **Transfer of change control.** After which the authors are contributors, not owners.

**Step 6 is not a concession; it is the objective.** Authority over a standard is not retained by
holding change control — that is how a standard is prevented from becoming one. It is earned by
having written the document everyone implements, by operating the best reference implementation,
and by being the registry whose conformance others are measured against.

### 14.3 Abandonment conditions

This document **SHOULD** be withdrawn in favour of other work if: the IETF Web Bot Auth effort
produces an accountability layer covering §3 and §7; or a neutral body begins equivalent work; or
after 24 months no unaffiliated implementation exists. Persisting past these points would make it
a proprietary format wearing standards clothing.

### 14.4 Versioning

Breaking changes increment the identifier version (`aid:v2:`) and the credential `typ`. Registries
**MUST** support the previous major version for at least 12 months after publishing a new one.
Algorithm agility is provided through §17.3 rather than through version increments.

---

## 15. Conformance

An implementation claiming AIAF conformance **MUST** state: its role (Registry, Relying Party,
Operator), the version, the assurance levels it enforces (not offers), and its conformance suite
results.

"AIAF-compatible" without a stated role and level set is meaningless and **SHOULD** be treated as a
marketing claim.

---

## 16. Out of scope

Named explicitly so that scope creep has to argue against a written boundary.

| Excluded | Why | Who owns it |
|---|---|---|
| Model identity / "which model is this" | Unverifiable over the wire (§2.2) | Possibly attestation work, eventually |
| Agent safety, alignment, competence | Not an identity property | NIST AI RMF, EU AI Act, evaluation bodies |
| Content provenance | Different subject: the artefact, not the actor | C2PA |
| Crawler preferences and permissions | Site-side expression | IETF `aipref`, robots.txt |
| Rate limiting, bot mitigation | Operational, site-local | RP infrastructure |
| Payment and settlement | Regulated; requires licensing | Payment networks, regulators |
| Liability allocation | Contract and statute, not specification (§3.2) | Courts, legislators |

---

## 17. Registries of values

Values requiring interoperable registration, in the manner of an IANA considerations section.

### 17.1 HTTP header fields

| Name | Purpose |
|---|---|
| `Agent-Credential` | Carries the credential |
| `Signature-Input`, `Signature` | RFC 9421 (already registered) |

### 17.2 Credential claim names

`org`, `org_domains`, `agal`, `oal`, `kal`, `dal`, `capabilities`, `scopes`, `standing`, `declared`,
`env` (`"development"` for development identities, §13.7; absent otherwise)
— in addition to the registered JWT claims `iss`, `sub`, `jti`, `iat`, `nbf`, `exp`, `aud`, `cnf`,
`act`.

### 17.3 Signature algorithms

| RFC 9421 name | JOSE name | Status |
|---|---|---|
| `ed25519` | `EdDSA` | **REQUIRED** to implement for verification |
| `ecdsa-p256-sha256` | `ES256` | **REQUIRED** to implement for verification |
| `ml-dsa-65` | `ML-DSA-65` | Reserved for post-quantum transition |

Both current algorithms are required for *verification* because an RP cannot choose what an agent
holds, and a FIPS-constrained Operator may only be able to offer P-256 while an unconstrained one
prefers Ed25519.

### 17.4 Attestation profiles

| Profile | Evidence class | Proves | Max KAL |
|---|---|---|---|
| `aws-nitro` | cryptographic | non-exportability and runtime measurement | 3 |
| `tpm2-certify` | cryptographic | non-exportability (3 with measured boot) | 2 |
| `hsm-key-attestation` | cryptographic | non-exportability | 2 |
| `cloud-kms-assertion` | third_party_assertion | non-exportability, on the provider's word | 2 |

A Registry **MUST** publish the profiles it accepts in its discovery document (§6.4), and **MUST
NOT** accept a profile it cannot verify to a pinned root.

### 17.5 Arithmetic conventions

Every construction this framework defines **MUST** specify the width of intermediate arithmetic.
"mod m" without stating that width is under-specified: a language with arbitrary-precision
integers and one with fixed-width integers compute different results, and in a revocation filter
that means a revoked identifier verifying as healthy in one implementation while being refused in
another. This was observed in practice between the reference implementation's Python, Node and Go
SDKs, and found only because shared conformance vectors were replayed through all three.

The revocation filter index is therefore defined as `((h1 + i*h2 + i*i) mod 2^64) mod m`.

### 17.6 Revocation reason codes

`key_compromise`, `superseded`, `cessation`, `abuse`, `fraud`, `owner_request`

### 17.7 Abuse categories

`rate_abuse`, `robots_violation`, `impersonation`, `credential_sharing`, `fraud`,
`undeclared_purpose`, `unsolicited_scanning`, `other`

`unsolicited_scanning` is **Tier 1** (§7.6): upheld means revoked, and the Operator is reviewed.

---

## Appendix A — Mapping to existing frameworks

| AIAF | Nearest analogue | Relationship |
|---|---|---|
| OAL1 | Domain Validation (CA/B Forum) | Same evidence, same limits |
| OAL2 | Organisation Validation; NIST IAL2 applied to an entity | Entity-level; not a person |
| OAL3 | Extended Validation + contractual accountability | Adds a financial instrument |
| KAL1 | Software key with PoP | — |
| KAL2 | FIPS 140-3 Level 1–2 storage | Isolation without hardware attestation |
| KAL3 | FIPS 140-3 Level 3 + remote attestation | Nearest to NIST AAL3 |
| DAL2 | OAuth delegated authorisation | Adds identifier binding and independent revocation |
| DAL3 | RFC 9396 + per-action confirmation | Depth-bounded chains are the addition |
| §7 due process | CA/B Forum problem reporting | Adds notification, response window and appeal |
| §8.11–12 | Certificate Transparency | Same construction, broader event scope |

---

## Appendix B — Changes needed in the reference implementation

Deltas between this draft and the current implementation, so that the gap is a work item rather
than an ambiguity.

| Change | Section | Status |
|---|---|---|
| Add `org_domains` to credentials | §4.2, §6.2 | **Implemented** |
| Emit `oal`, `kal`, `dal` alongside the composite | §6.2 | **Implemented** (`dal` is always 0 until delegation is issued) |
| Publish `/.well-known/aiaf-registry` | §6.4 | **Implemented** |
| Rename PoP domain separator to `aiaf-pop-v1` | §5.3 | **Implemented**, with a transition: clients that send `AIDR-PoP-Context: aiaf-pop-v1` are challenged with it; until 60 days after desktop 0.2.0, clients that do not are still challenged with `aidr-pop-v1`. Each challenge is verified only against the prefix it was issued with |
| Delegation: `act` chain issuance and validation | §3.4 | Not implemented (DAL2–3) |
| Hardware attestation verification | §3.3 | Implemented for AWS Nitro (KAL2/KAL3); TPM 2.0 and HSM profiles outstanding |
| Responsible Officer and contract records | §3.2 | **Implemented** (OAL3 onboarding with dual-controlled grant and expiry) |
| Appeal workflow | §7.3 | Not implemented |
| Operator-level standing publication | §13.5 | Not implemented |
| Tier 1 sanction: revocation and OAL-capping accountability review | §7.6 | **Implemented** in the authorization layer (policy obligations `revoke_agent`, `operator_accountability_review`); review closure is dual-controlled |
| Tier 1 evidence rule (signed-request attribution) | §7.6 | Procedural: the reviewer applies it; not machine-checked |
| Suspension at intake for in-progress probing | §7.6 | Not implemented (optional, MAY) |
| Second-finding Operator-level revocation | §7.6 | Not implemented (SHOULD; manual) |
| Development identities: `env` claim, 30-day expiry, capability separation | §13.7 | Not implemented |
| RP behaviour when revocation data goes stale | §6.3 | **Implemented** in all five reference verifiers (Python, Node, Go, PHP, the Worker): agents are refused with `aidr.registry.unavailable` once the newest revocation data held was signed (`iat`) more than 660 s earlier — one 60 s refresh plus 600 s of grace — and anonymous traffic is unaffected. Pinned by shared vectors (`freshness_cases`). §6.3 does not yet state a maximum age; whether it should is open for review |
| AgAL0 for unverified requests regardless of origin | §3.5, §9.13 | Met by the reference RP SDKs, which derive identity only from a verified credential and signature and never consult the request's origin |

---

*This document is a draft published for review. It is not a standard, and the organisation that
wrote it does not intend to remain its owner (§14.2).*
