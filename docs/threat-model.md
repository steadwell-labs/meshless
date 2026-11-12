# Meshless Protocol Threat Model

This document is the working threat model for the Meshless Protocol (MLP/1). It fixes the security boundary of Draft 00, enumerates 40 concrete threats against the baseline MLP/1-HTTP profile, and states for each one what the specification requires, what remains after those requirements are met, and where the requirement lives. It is written for implementers who must make the decisions the draft leaves open, and for reviewers who need to disagree with the design on the record rather than in a hallway.

**Status:** Draft 00 — non-normative  
**Applies to:** MLP/1 · Draft 00 · 12 November 2026 (`specs/mlp-0000-core.md`)  
**Author:** Steadwell Labs  
**Companion documents:** `docs/doxx-pilot.md`, `docs/faq.md`

Section references (§n) point to the specification. Where this document and the specification disagree, the specification wins. This revision was written against the specification, before the reference implementation existed. The implementation now passes a self-written conformance suite and publishes deterministic vectors, which changes the *evidence* for some mitigations but not the method: nothing here has been validated by an independent party or a security review, and self-testing is not validation. Where a mitigation says "specified", read it as "required by the text and exercised by the reference implementation's own tests"; where it says "not tested", the suite does not cover it. See §0 for the corrections this note does and does not make.

## Severity rubric

Severity is a judgement about the threat against Draft 00 assuming the mitigation named in the same row is implemented as written. It is not a CVSS score, no vector strings are used, and the numbers are not comparable across projects. The scale is deliberately coarse so that two reviewers can disagree without arguing about decimals.

| Severity | Assigned when | Typical consequence | Examples in this document |
| --- | --- | --- | --- |
| Critical | Compromise crosses an administrative boundary and yields authority or plaintext the attacker could not otherwise obtain, with no precondition beyond holding a credential or controlling a routed component. | Full resource access as another principal; signature forgery; interception of all traffic. | T-01, T-03, T-04, T-10, T-19, T-21, T-33, T-34 |
| High | Compromise is confined to one resource, one grant chain, or one invocation class, or needs a plausible but non-default precondition such as a malicious enrolled owner or a misconfigured proxy. | Quota exhaustion, replay of one request, descriptor rollback, disclosure of one resource's metadata. | T-02, T-05, T-06, T-08, T-09, T-11, T-13, T-14, T-15, T-17, T-18, T-20, T-22, T-23, T-25, T-27, T-28, T-31, T-32, T-36, T-38 |
| Medium | Impact is bounded to metadata, availability, or a single request, or the attacker needs local access, operator error, or a control the operator chose to weaken. | Slow or noisy denial of service, correlation of one resource, loss of accounting. | T-07, T-16, T-24, T-26, T-29, T-30, T-35, T-37, T-40 |
| Low | Nuisance or information-leak level. No authority is gained and no payload is disclosed. | Enumeration hints, confusing errors. | T-39 |

Rules for reading the table:

- **Residual risk** is what remains *after* the stated mitigation. A row is not a claim that the mitigation is implemented anywhere.
- Where a row's severity would rise if a control were missing, the row says so. For example T-24 is Medium only because deduplication is mandatory.
- A threat that requires the provider to be compromised is scored by what the provider controls, not by how hard it is to compromise a particular host.
- Threats are counted per failure mode, not per code defect. Several rows can be triggered by one bug.

| Severity | Count |
| --- | --- |
| Critical | 9 |
| High | 21 |
| Medium | 9 |
| Low | 1 |
| Total | 40 |

## 1. Scope and assumptions

### 1.1 What MLP protects

| Property | Mechanism | Section | Confidence |
| --- | --- | --- | --- |
| Authority is explicit and owner-controlled | Root grants signed by the enrolled owner for a resource ID | §9.2, §6.4 | Specified, not tested |
| Authority can only narrow when delegated | Nine delegation rules, parent hash binding, chain cap of four | §9.3, §9.4 | Specified, not tested |
| Grants are not bearer credentials | Per-request proof bound to session, method, URI, body and grant | §9.6, §10.4 | Specified, not tested |
| Requests cannot be replayed | Single-use nonce, 30 second proof window, exact bindings | §10.4, §11.7 | Specified, not tested |
| Discovery is not authorization | Descriptor conveys existence and location only | §7.3 | Specified, not tested |
| Records are attributable | Provider-signed receipts bound to request and result hashes | §12.4 | Specified, not tested |
| Path is not authority | Relay and adapter cannot authorize; TLS terminates at the provider | §4, §5.1, §15 | Specified, not tested |
| Local operation needs no Internet | Baseline direct HTTPS on a LAN | §14, §15 | Specified, not tested |
| Quotas are aggregate ceilings | Atomic reservation across every ancestor link | §9.5 | Specified, not tested |

"Confidence: specified, not tested" means the requirement exists in the text and no executable vector or independent implementation demonstrates it. §17.2 requires deterministic fixtures and §17.3 requires independent interoperability before 1.0. Neither exists at this revision.

### 1.2 What MLP explicitly does not protect

These are non-goals in the specification, not gaps discovered here. An implementation that claims any of them without a separate profile is making a false claim.

| Not provided | Consequence for the reader | Where the draft says so |
| --- | --- | --- |
| Confidentiality of inputs from the provider | The provider sees prompts, tool arguments and results in plaintext. Encrypting the body does not help because the provider must execute it. | §16.3 |
| OS or hardware isolation between resources | A handler escape is a provider compromise. Draft 00 only requires least privilege and recommends sandboxing. | §3.2, §12.1 |
| Availability or latency guarantees | No SLA, no replication, no failover. A provider may return 503 at any time. | §3.2 |
| VPN, overlay or network privacy | MLP runs above connectivity and does not replace it. A private VPN does not remove the TLS requirement. | §3.2, §5.1 |
| Anonymity for any party | Resource IDs embed the owner thumbprint; relays see metadata. | §3.2, §7.1, §16.3 |
| Correctness of remote computation | Receipts attest reported execution, not correct or honest execution. | §12.4 |
| Deletion of already disclosed data | Revocation cannot recall what the provider already read. | §14, §16.3 |
| Exactly-once execution | A crash after dispatch leaves the outcome unknown. | §12.3 |
| Streaming or asynchronous jobs | Deferred to a future profile. | §12.2 |
| Confidential computing, zero knowledge, end-to-end payload encryption | Explicitly not claimed without a separate verified profile. | §16.3 |
| Post-quantum security | Ed25519 only in the baseline; listed as a future profile. | §5.1, §18 |
| Remote physical actuation | Robotics telemetry is read-only; actuation is excluded. | §16.4 |
| Legal identity or organizational membership | A key proves key control, not a person or a role. | §4 |
| Immediate global revocation | The honest guarantee is "no new invocation after the provider learns". | §14 |
| Protection from a malicious provider | The provider is the enforcement point and holds the signing key. | §14, §16.3 |

### 1.3 Assumptions

Each assumption is a precondition for the threat table's severity assignments. If an assumption does not hold, the referenced threats get worse, and no requirement in draft 00 restores them.

| ID | Assumption | If violated |
| --- | --- | --- |
| A-01 | The owner root key is generated and held on infrastructure the owner controls, ideally hardware-backed; agent keys are distinct and in OS-backed secure storage. | T-01, T-02 become ordinary account compromise with no recovery path short of re-enrollment on every provider. |
| A-02 | Enrollment uses a channel independent of the channel later used for invocation, and a human confirms the full key identifier and resource ID. | T-03, T-34: the enrollment decision is the root of all trust and cannot be repaired later. |
| A-03 | Provider and consumer clocks are within the skew allowance and the provider rejects traffic when it cannot establish time. | T-16: expiry, `nbf`, nonce lifetime and the 30 second proof window all degrade together. |
| A-04 | The provider host, its signing key, and its revocation, quota and dedupe stores are not attacker-controlled. | T-32, T-33: every downstream guarantee is void. |
| A-05 | Verifiers use an implementation that performs every check in §9.4, §10.1, §10.2 and §10.4, rather than a demo path. | T-04, T-05, T-09, T-11, T-12: verification becomes decorative. |
| A-06 | TLS terminates at the provider boundary with a configured trust anchor and no bypass switch compiled in. | T-19, T-21, T-31. |
| A-07 | Provider state (nonce, quota, revocation, dedupe, descriptor high-water marks on the consumer side) is persisted durably and atomically. | T-06, T-17, T-22, T-23, T-24. |
| A-08 | Endpoint origins are approved by local policy, and that policy is enforced by the component that opens the socket, not by the caller. | T-20, T-31, T-40. |
| A-09 | Paths, header names and media types are provisional (§18) and are not used as security boundaries. | Any control that depends on a path string is fragile against a future revision. |
| A-10 | The consumer agent's own context handling, approval flow and tool-output trust decisions are out of scope for MLP. | T-27: the protocol cannot make a gullible agent safe. |

## 2. Assets, actors and trust boundaries

### 2.1 Assets

| Asset | Where it lives | Sensitivity | If compromised |
| --- | --- | --- | --- |
| Owner root private key | Owner device, ideally offline or hardware-backed | Critical | Descriptor and root grant forgery for the resource; T-01. |
| Agent (consumer) private key | Consumer host, OS secure storage | High | Use of every unexpired grant issued to that subject; T-02. |
| Provider signing key | Provider host | Critical | Receipt forgery and descriptor spoofing in the provider role; T-33. |
| Enrollment records | Provider store and owner records | Critical | Attacker can install its own root authority; T-10, T-34. |
| Grant chains | Consumer host, transport, logs | Low confidentiality, critical integrity | Interception alone is harmless (§9.6); modification must be rejected. |
| Nonce store | Provider | Integrity and availability | Replay window; T-06, T-07. |
| Quota counters | Provider | Integrity and durability | Overspend or denial; T-22, T-23. |
| Revocation records | Provider | Integrity and durability | Revoked grant keeps working; T-36. |
| Dedupe records | Provider | Integrity | Duplicate side effects; T-24, T-25. |
| Descriptor cache and `seq` high-water mark | Consumer | Integrity | Rollback to a withdrawn endpoint; T-17. |
| Receipts | Consumer, owner, auditors | Integrity | False record of execution; T-26. |
| Invocation payloads | Provider memory, consumer memory, transport | Plaintext to the provider | Disclosure to provider or insider; T-32. |
| Network provisioning credentials | Local secret storage | Critical, must never be in grants or prompts | Tunnel or DNS takeover; T-31, T-27. |
| Metadata (identities, inventory, endpoints, timing) | Directories, relays, logs | Medium | Correlation of owner to resource and usage; T-30. |

### 2.2 Actors

| Actor | Goal | Capabilities assumed |
| --- | --- | --- |
| Owner | Keep control of the resource and withdraw authority | Holds root key, signs descriptors and root grants, revokes by `jti`, may disable the resource locally |
| Provider | Serve the resource and enforce policy | Authoritative enforcement point, holds provider key, sees plaintext, controls revocation and quota stores |
| Consumer / principal | Use the resource within granted authority | Holds a key, obtains grants, signs proofs, initiates sessions |
| Delegated agent | Act for a principal, possibly under injected input | May hold a mid-chain grant, may be manipulated by content it processes |
| Directory | Distribute descriptors, sometimes monetize attention | Untrusted; can withhold, replay, enumerate; cannot sign for an owner |
| Relay | Forward bytes | Untrusted; can drop, delay, observe metadata; must not terminate TLS |
| Transport adapter | Establish connectivity | Can choose a path, provision tunnels; must not weaken TLS or authorize |
| Network attacker | Read, modify, replay, redirect | On-path or adjacent; may control DNS, may present a certificate for a name it does not own if a CA is fooled |
| Malicious insider | Read data or misreport execution | Provider operator or hosting staff with legitimate access |
| Compromised host | Anything the process can do | Provider or consumer host under attacker control, including key material on disk |

Insider and compromised host are separated deliberately. An insider has legitimate access and can therefore act without exploiting anything; a compromised host may additionally forge signatures and rewrite stored state. The mitigations differ: the first is organizational, the second is a protocol non-goal.

### 2.3 Trust boundaries

```
        owner device                     consumer host
  +----------------------+          +--------------------------+
  | root private key     |  (1)     | agent private key        |
  | enrollment record    |--------->| grant chain, descriptor  |
  | descriptor signing   |  out of  | proof signing            |
  +----------------------+  band    +------------+-------------+
                                                |
                              (2) MLP/1-HTTP over TLS 1.3
                                                |
        +---------------------------------------v-----------------------+
        |  network: relay, adapter, directory, attacker                 |
        |  observes metadata, cannot authorize, must not terminate TLS  |
        +-------------------------------+-------------------------------+
                                        |
                                        | (3)
                          +-------------v--------------+
                          | provider boundary          |
                          | TLS terminator             |
                          | provider signing key       |
                          | policy, quota, revocation  |
                          +-------------+--------------+
                                        | (4)
                          +-------------v--------------+
                          | handler, least privilege   |
                          | egress allowlist, timeout  |
                          +----------------------------+
```

| Boundary | What crosses | Who controls it | Enforced by |
| --- | --- | --- | --- |
| B1 owner to consumer | Descriptor, grants, enrollment confirmation | Owner | Out-of-band channel, human confirmation (§6.4) |
| B2 consumer to provider | HTTP request, proof header, JSON body | Provider | TLS 1.3, proof bindings (§5.1, §10.4) |
| B3 provider to handler | Validated input, provider-managed credentials | Provider | Least privilege, sandboxing recommendation, egress allowlist (§12.1) |
| B4 directory to consumer | Descriptor bytes | Directory | Signature and `seq` checks (§8.2, §7.2) |
| B5 relay and adapter path | ciphertext, metadata | Network operator | TLS termination rule (§5.1) |
| B6 provider to consumer | Result, receipt | Provider | Provider signature, binding checks (§12.4) |
| B7 operator to infrastructure | Logs, metrics, backups | Operator | Retention policy, minimization (§16.5) |
| B8 local admin to enrollment store | Key IDs, resource IDs | Operator | Local access control, outside MLP |

The important asymmetry: B1 and B8 are the only boundaries where a human decision enters, and they are the only boundaries the protocol cannot verify. Everything else is checked by signature or by TLS. That is why the enrollment threats (T-03, T-34) are Critical and why no amount of verification downstream repairs a bad enrollment.

## 3. Threat table

Each row names the threat, the component that would have to be wrong, a STRIDE category, severity from the rubric above, the specified mitigation, the residual risk, and the governing section.

| ID | Threat | Affected component | STRIDE | Severity | Mitigation | Residual risk | Spec ref |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-01 | Stolen owner root key: attacker signs descriptors and root grants for the resource. | Owner key store, descriptor and grant issuance | Spoofing | Critical | Agent keys distinct and OS-backed; descriptors and grants expire within 24 h; revocation by `jti` and by enrollment; re-enrollment on rotation. | Attacker mints root grants until the provider revokes the enrollment. Revocation is local to each provider and there is no distribution channel for other consumers. Receipts and disclosed data are not recalled. | §6.5, §11.6, §14 |
| T-02 | Stolen agent key: attacker signs proofs and spends the grant. | Consumer runtime, proof signing | Spoofing | High | Grant binds `sub` to the agent key; per-request proof; limits cap calls, bytes and `max_ms`; owner can revoke by `jti`; sessions cap at 15 minutes. | Attacker can use the full remaining grant, including actions the human meant for a narrower task. No device binding beyond key possession. Revocation needs provider reachability. | §9.1, §9.6, §10.4, §11.3, §14 |
| T-03 | Self-signed key substitution: a verifier accepts an object because the signature verifies against a key carried in the object. | Verifier trust store, descriptor and grant verification | Spoofing | Critical | Unknown keys MUST NOT be trusted solely because they self-sign. Trust comes from enrollment records and from a descriptor signed by the enrolled owner. Embedded JWKs are checked against key identifiers. | Every MLP object is self-contained, so this is the default mistake. If the first provider key is accepted without an enrollment decision, the attacker owns the resource view. Bootstrapping remains a human act. | §4, §6.2, §6.4 |
| T-04 | Algorithm confusion, `alg: none`, header injection, key fetched from a URL. | JWS verification | Spoofing, Elevation | Critical | Protected header MUST be `alg: EdDSA`, `kid` equal to `iss`, expected `typ`; `jwk`, `jku`, `x5u`, `x5c` and `crit` MUST NOT appear; keys MUST NOT be fetched from signed URLs; unknown critical headers rejected. | A verifier that reads `alg` from the token to choose a verifier, or that lets the caller supply the key, remains exploitable. The draft fixes the checks but does not fix library configuration. | §6.3, §16.2 |
| T-05 | Thumbprint mismatch: `kid` names a trusted key but the signature was made by another key. | Key resolution | Spoofing | High | Key identifier is recomputed from the JWK and compared as a byte string, including for embedded JWKs. | A verifier that treats `kid` as an opaque index into an enrollment store, without recomputation, accepts the object. Recompute-then-compare is cheap and easy to skip. | §6.1, §6.2 |
| T-06 | Replay of a captured proof, on the same endpoint or another one. | Proof validation, nonce store | Spoofing | High | Nonce single-use and consumed atomically; proof `iat` within 30 seconds; proof bound to `method`, `uri`, `body_hash` and `grant_hash`. | A multi-process or multi-node provider without a shared atomic nonce store can accept the same proof twice on different workers. Atomicity is required; a distributed store is not specified. | §10.4, §11.7 |
| T-07 | Nonce reuse, prediction or exhaustion. | Challenge endpoint, nonce store | Spoofing, Denial | Medium | 32 random bytes; 60 second validity; bound to resource and subject; single use; issuance rate limited per source and per subject; the endpoint must not reveal whether resource or subject exists. | No rate-limit values are specified, so a flood can still consume storage and clock. The endpoint is unauthenticated by design, so it is the cheapest place to attack. | §11.2 |
| T-08 | Cross-endpoint proof replay: a proof for one route is accepted on another. | Proof `uri` binding, reverse proxy configuration | Spoofing | High | `uri` is the exact origin plus path with no query or fragment; the provider compares method and URI exactly as received. | A provider behind a path-rewriting proxy must publish the exact public origin and path. A mismatch either breaks every invocation or lets a proof for one route validate at another. Deployment is not described. | §10.4 |
| T-09 | Body substitution: the body is altered after the proof is signed. | `body_hash`, JSON parsing | Tampering | High | `body_hash` covers the exact received bytes; duplicate members, invalid UTF-8, nonfinite numbers, unsafe integers and trailing content are rejected. | Hash-of-bytes and parsed semantics diverge if anything in front of the provider normalizes JSON. Note that receipts hash canonical JSON while proofs hash exact bytes; the two must not be conflated. | §10.1, §10.4, §12.4 |
| T-10 | Grant forgery, including a self-signed root grant. | Grant issuance, provider validation | Elevation | Critical | Root grant MUST be signed by the enrolled owner key for the resource ID; every link verified against its `kid` and embedded JWK; chain capped at four; leaf `aud` and `rid` checked. | Anyone who can write the enrollment store can authorize themselves. A self-signed root is internally consistent because it carries its own `sub_jwk`; only the enrollment lookup rejects it. | §9.2, §9.4 |
| T-11 | Parent hash mismatch or chain splice: a child is attached to a different parent. | Chain validation | Tampering | High | `parent` is the hash of the exact parent compact JWS ASCII bytes; all ancestors MUST be presented; all nine delegation rules are evaluated per link. | An implementation that re-serializes a parent before hashing computes a different hash, and either rejects valid chains or accepts a splice if it hashes a normalized form. | §9.3, §9.4, §10.2 |
| T-12 | Delegation escalation: a child grant adds actions or widens a limit. | Grant chain | Elevation | Critical | Actions MUST be a subset at every hop and a subset of the descriptor actions; no wildcards or patterns; limits may not increase; validity must be contained; unknown claim semantics cause rejection. | Subset checks operate on literal strings. If a profile defines a broad action such as `tools.call`, the subset relation constrains the name but not the reach. | §9.1, §9.2, §9.3, §9.4 |
| T-13 | Delegation depth abuse: depth not decremented, delegation at zero, or a long chain. | Grant chain | Elevation, Tampering | High | Depth decrements by exactly one per hop; depth zero cannot delegate; root depth at most three; chain capped at four grants. | Depth bounds length, not breadth. A depth-one subject can mint many children; the aggregate ceiling depends on persistent per-`jti` bookkeeping at the provider. | §9.2, §9.3, §9.4, §9.5 |
| T-14 | Audience confusion: a grant for one provider is presented to another. | Grant validation | Spoofing | High | Leaf `aud` MUST equal the provider key identifier and the descriptor `provider`; audience is invariant under delegation. | `aud` identifies a provider key, not a resource. A key serving resources for several owners collapses audience separation, and `rid` becomes the only resource-level check. Key reuse across tenants is not discouraged. | §9.2, §9.3, §9.4 |
| T-15 | Resource-ID confusion across owners. | `rid` parsing, provider tables | Spoofing, Elevation | High | `rid` embeds the owner thumbprint; consumers MUST verify it against the descriptor issuer and reject on mismatch; the provider checks leaf `rid` and the enrollment binding for the root signer. | Storage keyed on the UUID alone loses the separation. The owner-component check is assigned to consumers explicitly; the provider-side comparison is implied by the enrollment lookup rather than stated as its own rule. | §7.1, §7.2, §9.4 |
| T-16 | Expired grant or clock skew abuse. | Time validation | Tampering, Elevation | Medium | Integer seconds; reliable provider clock; reject traffic when the clock is uncertain; no expiry grace; a 30 second skew allowance applies only to proof `iat`. | Operators who add a grace period for drift reopen an expiry bypass for every object. A consumer with a bad clock simply cannot establish sessions. | §10.3, §10.4 |
| T-17 | Descriptor `seq` rollback to a withdrawn endpoint. | Descriptor cache, consumer store | Tampering | High | `seq` is a nonnegative safe integer, monotonic per resource; consumers keep a high-water mark and reject a lower `seq`; equal `seq` with different bytes is rejected; descriptors expire within 24 hours. | A consumer that loses its high-water mark, for example on reinstall, accepts any unexpired descriptor. Bootstrapping and backup of the mark are undefined. | §7.2 |
| T-18 | Malicious or compromised directory. | Discovery | Tampering, Disclosure | High | A directory cannot grant authority; it MUST preserve descriptor bytes; consumers verify in full and MUST NOT connect to unapproved origins; public listing is opt-in and off by default. | A directory can withhold, delay, or replay an unexpired descriptor, and can enumerate who fetches what. Availability and metadata are unprotected. Endpoint substitution is caught only if the client verifies. | §4, §7.3, §8.2 |
| T-19 | TLS stripping, invalid certificate, downgrade to plaintext. | Transport | Spoofing, Disclosure | Critical | TLS 1.3; validation against an explicit trust anchor; no insecure fallback and no proceed-anyway path; providers answer no `3xx` and clients follow none. | Non-browser clients have no HSTS. An expiring pin breaks availability, and the pressure to disable validation is the practical risk. A build that deletes the check is undetectable from outside. | §5.1, §11.1 |
| T-20 | SSRF via descriptor `endpoint` or via redirects. | Consumer egress, provider fetch | Elevation, Disclosure | High | `endpoint` is an `https` origin with no path, query, fragment or credentials; clients MUST NOT auto-connect to discovered URLs; origins approved by local policy; DNS and redirects MUST NOT bypass egress restrictions. | An enrolled but malicious owner can point a descriptor at an internal address, and consumer policy is the only control. No IP-range denylist and no DNS-rebinding defence is required. | §7.2, §8.2, §8.3, §15 |
| T-21 | Untrusted relay terminates application TLS. | Transport, relay | Disclosure, Spoofing | Critical | TLS termination MUST occur at a trusted provider boundary; an untrusted relay MUST NOT terminate application TLS; a relay that terminates TLS is the provider for protocol purposes. | The consumer cannot tell from the protocol whether a relay terminated TLS. The only real control is a certificate anchored to a key the relay does not hold. A CA-trusted certificate for the provider name is undetectable. | §5.1 |
| T-22 | Quota bypass and concurrent quota races. | Quota store, invoke path | Elevation | High | Quota reserved atomically against the leaf and every ancestor; reject if any link lacks capacity; concurrency must not overshoot; effective limit is the minimum of every ceiling. | Atomicity is required but not defined for multi-process or multi-node providers. Whether a failed invocation returns its reservation is left to the implementation, while calls are defined to count failures. | §9.5 |
| T-23 | Quota counter loss on restart. | Quota store | Tampering, Elevation | High | Counters MUST be persisted across restart; revocations persisted before the response is returned. | A crash between reserving and persisting loses or duplicates accounting. No reconciliation procedure or recovery state is defined. The conformance case only requires survival across a clean restart. | §6.2, §9.5, §11.6, §17.1 |
| T-24 | Duplicate `request_id` re-execution. | Invoke path, idempotency store | Tampering | Medium | Deduplicate `request_id` per resource per leaf subject until grant expiry; reject a repeat with `409 duplicate_request` rather than replaying a cached result. | The window can reach 24 hours, so the store grows with traffic. Dedupe is per leaf subject, so a fresh grant resets the namespace. Severity rises to High if dedupe is missing or scoped to a session. | §12.3 |
| T-25 | Crash after dispatch leaves the outcome unknown. | Invoke path, receipt | Repudiation | High | No exactly-once claim is made or permitted; a client MUST NOT retry an unknown outcome under a new `request_id`; a retry with the same `request_id` is rejected as a duplicate. | The caller cannot distinguish never-ran from ran-then-crashed. There is no status query endpoint, so reconciliation is out of band. Side-effecting handlers can duplicate effects. | §12.3, §13 |
| T-26 | Receipt forgery or replay. | Receipts | Spoofing, Repudiation | Medium | Provider-signed receipt; clients verify the signature against the key learned from the descriptor and verify `rid`, `sub`, `jti` and `request_id` bindings; receipts carry no payloads or secrets. | A receipt proves reported execution, not correctness. Cross-request replay is prevented only by binding checks. No transparency log exists, so a provider can under-report. | §12.4 |
| T-27 | Prompt injection against an agent consumer. | Consumer agent runtime | Elevation, Disclosure | High | Grants minimize actions and limits; tool allowlist is separate from grants; provisioning credentials MUST stay out of grants, proofs and prompts; private keys MUST NOT appear in prompts. | The draft says nothing normative about how a consumer agent treats untrusted content, approval prompts, or tool output. Everything that makes injection non-fatal is implemented outside the protocol and untested by it. | §6.5, §12.2, §15, §16.1 |
| T-28 | MCP tool allowlist escape through `tools.call`. | Provider MCP handler | Elevation | High | A separate explicit tool allowlist; argument validation against each tool schema; MCP lifecycle and version negotiation upstream; a `tools.call` grant must not expose an unapproved tool; an allowlist must not be derivable from a grant. | The allowlist is not bound to grant content and is not versioned, so a tool added after issuance is reachable unless the gate is written carefully. Name aliasing and servers that chain to other servers are not addressed. | §12.2 |
| T-29 | Oversized bodies and resource exhaustion. | Gateway | Denial | Medium | 1 MiB request cap unless a profile is lower; `413 too_large`; per-grant byte and `max_ms` ceilings; rate limiting. | Parsing cost, handshake cost and concurrent handler slots are unbounded by the text. A caller staying inside its grant can still exhaust a provider with no concurrency limit. | §9.5, §11.1, §12.1, §13 |
| T-30 | Metadata leakage via directories, logs and receipts. | Discovery, logs, receipts | Disclosure | Medium | Directories minimize metadata and preserve bytes; receipts exclude payloads; errors must not reveal concealed existence; logs record IDs, actions and byte counts rather than payloads; identities and inventories unpublished by default. | `rid` embeds the owner thumbprint by construction, so resources correlate to an owner key across time and endpoints. Descriptors reveal endpoint, kind and actions. Relays see traffic shape. This is accepted by design. | §7.1, §8.2, §11.2, §12.4, §13, §16.5 |
| T-31 | Local-first mode silently falls back to the public network. | Transport adapter | Disclosure | High | Adapters preserve TLS validation, report failure rather than degrade, avoid silent public fallback, and keep provisioning credentials out of grants and prompts; offline operation must not bypass policy or route private data to a cloud service. | Enforcement lives in an adapter the protocol does not test. There is no required user-visible indicator that a request left the local path and no egress telemetry requirement, so fallback is visible only in a packet capture. | §14, §15 |
| T-32 | Malicious insider at the provider reads inputs or misreports execution. | Provider operator | Disclosure, Repudiation | High | Provider is the enforcement point; minimal logging; configurable retention; per-resource isolation; owner can revoke and disable. | An insider with provider access reads plaintext and can sign receipts for work that did not happen. Only organizational and legal controls apply. The non-claim is explicit. | §9.5, §11.6, §12.1, §16.3, §16.5 |
| T-33 | Compromised provider host, including handler breakout. | Provider host, handler | Elevation, Disclosure | Critical | Handlers run with least privilege, should be sandboxed, and must not get ambient network or filesystem access; no arbitrary URL, shell, path or header forwarding; timeout and response byte limit. | OS isolation is an explicit non-goal. A breakout reaches the provider signing key unless the deployment separates it, which the draft does not require. That yields forged receipts and signatures for every grant served. | §3.2, §12.1, §12.2 |
| T-34 | Enrollment channel compromise: QR swap, hostile operator, phishing. | Enrollment | Spoofing | Critical | Independently trusted channel; the owner records the provider key identifier at enrollment so the first descriptor is not self-asserted; confirmation shows the full key identifier and resource ID, with thumbprints grouped for comparison. | The trusted channel is unspecified. A substituted QR or a convincing fingerprint page defeats enrollment, after which every signature verifies. Comparison UX is a SHOULD, not a MUST. | §4, §6.2, §6.4 |
| T-35 | Session hijack and `sid` confusion. | Sessions | Spoofing | Medium | `sid` is 32 random bytes bound to the leaf key and exact chain; session expiry is the earlier of leaf expiry and 15 minutes; proof required on invoke and close; `sid` alone confers no authority. | A provider that resolves a session without rechecking the proof subject turns `sid` into a bearer token. Because `sid` alone is worthless by design, leakage is low impact only while that rule holds. | §11.3, §11.5, §11.7 |
| T-36 | Revocation gap while the owner is offline. | Revocation | Repudiation, Elevation | High | Provider checks persisted revocation and expiry before each invocation and should cancel active work; local policy MAY require online freshness or shorter leases; ancestor revocation invalidates descendants. | The honest guarantee is "no new invocation after the provider learns". A disconnected owner cannot shorten it, so exposure lasts until grant expiry, up to 24 hours, or session expiry, up to 15 minutes. Online freshness is optional. | §11.6, §14 |
| T-37 | Stricter owner policy is not auditable. | Provider policy | Repudiation | Medium | Owner policy MAY impose stricter limits; the effective limit is the minimum of every applicable ceiling. | The owner has no protocol-level way to verify that a provider applies its policy and no signed statement of the effective policy. Only receipts and observed usage provide evidence. | §9.5 |
| T-38 | Malicious consumer input reaches the handler. | Handler, schema validation | Tampering | High | Strict JSON parsing; per-action schema validation; timeout and response byte limit; no ambient network or filesystem access for handlers. | Validation is only as good as the schema and the validator. `tools.call` takes an open-ended argument object, so the per-tool schema is the real boundary. Parser bugs are outside the protocol. | §10.1, §12.1, §12.2 |
| T-39 | Concealed resource enumeration through the error oracle. | Challenge endpoint, errors | Disclosure | Low | `404 unknown_resource` also for concealed resources; the challenge endpoint must not reveal existence; errors must not expose internal state; 404 recommended over 403 for unauthorized callers. | Timing and status differences remain observable. A challenge endpoint that validates `rid` before rate limiting is an unauthenticated existence oracle. | §11.2, §13 |
| T-40 | Endpoint reuse and DNS rebinding against an approved origin. | Descriptor endpoint, local policy | Spoofing | Medium | Endpoint origins approved by local policy before first connection; `seq` high-water prevents rewind; TLS validated against the approved origin. | An origin is approved by name, not by address. DNS rebinding, a change of tenant, or shared hosting can move an approved name onto a different service. An approved origin is not bound to a key or address. | §5.1, §7.2, §8.2 |

## 4. Attack trees

Two scenarios are expanded because they combine several threats in one sequence and because both are reachable by an attacker who never holds a provider or owner key.

### 4.1 Agent is prompt-injected and tries to exceed its grant

The attacker controls content the agent reads, not the agent's key. Success means the agent performs an action outside the intent of the human who issued the grant.

```
Goal: exceed the grant
|
+-- A. Acquire authority it was not given
|   |
|   +-- A1. Steal a key ................................ T-01, T-02
|   |   +-- read key from disk, env, or prompt context ... blocked by OS storage (§6.5) if used
|   |   +-- read key from logs ........................... blocked by §16.5 if implemented
|   |
|   +-- A2. Mint its own grant ........................... T-03, T-10
|   |   +-- self-sign a root grant ....................... rejected: root signer must be the enrolled owner (§9.4 r2)
|   |   +-- self-sign a child of a grant it holds ........ rejected only if parent hash is over exact bytes (§9.3 r9)
|   |   +-- swap in its own sub_jwk ...................... rejected: sub must match sub_jwk thumbprint (§6.2)
|   |
|   +-- A3. Widen a child grant .......................... T-12, T-13, T-14, T-16
|   |   +-- add an action not in the parent .............. rejected: subset check (§9.3 r3)
|   |   +-- add an action not in the descriptor .......... rejected: descriptor subset (§9.2, §9.4 r6)
|   |   +-- raise a limit ................................ rejected: per-limit comparison (§9.3 r5)
|   |   +-- extend validity .............................. rejected: interval containment (§9.3 r4)
|   |   +-- change aud or rid ............................ rejected: invariance (§9.3 r1, r2)
|   |   +-- delegate at depth 0 .......................... rejected: delegate false at 0 (§9.3 r8)
|   |   +-- re-parent to a wider chain ................... rejected: parent hash (§9.3 r9)
|   |
|   +-- A4. Use a grant issued for someone else .......... T-14, T-15
|       +-- present a grant with a different aud ......... rejected: leaf aud check (§9.4 r4)
|       +-- present another owner's rid .................. rejected: rid check (§9.4 r5)
|
+-- B. Use existing authority beyond intent
|   |
|   +-- B1. Call an approved action with hostile arguments ... ALLOWED by design; handler validates (§12.1)
|   +-- B2. Escape the MCP tool allowlist ................ T-28
|   |   +-- call an unlisted tool ........................ rejected only if the allowlist gate is exact (§12.2)
|   |   +-- call a listed tool whose name aliases another . depends on the MCP server, unverified
|   +-- B3. Replay a captured proof ...................... T-06, T-08
|   |   +-- same nonce twice ............................. rejected: single use (§10.4)
|   |   +-- same proof on another route .................. rejected: uri binding (§10.4)
|   +-- B4. Re-run a side effect ......................... T-24, T-25
|   |   +-- reuse request_id ............................. rejected: 409 duplicate_request (§12.3)
|   |   +-- wait for a crash and retry with a new id ...... ADMINISTRATIVE: caller must decide (§13)
|   +-- B5. Exhaust the quota to deny the owner .......... T-22
|   |   +-- parallel calls ............................... bounded by atomic reservation (§9.5)
|   |   +-- slow calls to hold slots ..................... bounded by max_ms only (§9.5)
|   +-- B6. Outlive the grant ............................ T-36
|       +-- keep invoking after the human revokes ........ until the provider learns (§14)
|       +-- wait for the owner to go offline ............. up to grant expiry, max 24 h (§9.1)
|
+-- C. Exfiltrate what it obtains
    |
    +-- C1. Send results to an attacker endpoint ........... T-20, T-31
    |   +-- arbitrary outbound HTTPS ...................... blocked by adapter egress allowlist (§15) if enforced
    |   +-- descriptor-driven endpoint ..................... blocked by origin approval (§8.2)
    +-- C2. Encode data in the next action's arguments ...... visible to the provider only (§16.3)
    +-- C3. Put a key or token in a prompt ................. blocked by §6.5 and §15 if practiced
```

Leaf annotations show the only place a defence exists. Four leaves are marked ALLOWED, ADMINISTRATIVE, or "if enforced": hostile arguments, unknown-outcome retry, egress enforcement, and the tool allowlist aliasing case. Those are the places where the protocol hands control to an implementation that draft 00 does not test.

### 4.2 Compromised relay operator attempts to read or replay traffic

The relay is assumed hostile. It may see all bytes if it can terminate TLS, and it may inject, drop, delay, or replay.

```
Goal: read plaintext or replay a valid request
|
+-- A. Get plaintext
|   |
|   +-- A1. Terminate TLS with its own certificate ........ T-21
|   |   +-- present a certificate for the provider name ..... rejected if the client pins or anchors the provider cert
|   |   +-- rely on a user "proceed anyway" click ........... forbidden by §5.1, absent in a conforming client
|   |   +-- hold a CA-trusted cert for that name ............ UNDETECTED (residual, CA compromise)
|   |
|   +-- A2. Downgrade to HTTP .............................. rejected: no plaintext mode (§5.1)
|   +-- A3. Passive observation ............................ METADATA ONLY: size, timing, endpoints (§16.3)
|   +-- A4. Read provider-side logs ........................ OUT OF SCOPE: provider boundary
|
+-- B. Replay or inject
|   |
|   +-- B1. Replay the proof header ........................ T-06
|   |   +-- immediately .................................... rejected: nonce consumed (§10.4)
|   |   +-- with a fresh nonce ............................. impossible without the leaf key
|   +-- B2. Replay the body with a fresh proof ............. impossible without the leaf key
|   +-- B3. Rewrite the body ............................... rejected: body_hash (§10.4)
|   +-- B4. Rewrite method or URI .......................... rejected: exact comparison (§10.4)
|   +-- B5. Strip the proof header ......................... rejected: 401 before grant evaluation (§11.1)
|   +-- B6. Replay a receipt ............................... T-26
|   |   +-- to the same request_id ......................... accepted, harmless
|   |   +-- to a different request ......................... rejected: binding checks (§12.4)
|   |
|   +-- C. Redirect or deny
|       +-- C1. Answer 3xx to another host ................. rejected: no redirects (§11.1)
|       +-- C2. Poison DNS for an approved origin .......... TLS validation (§5.1)
|       +-- C3. Drop or delay traffic ...................... availability is a non-goal (§3.2)
|       +-- C4. Reorder or duplicate requests .............. request_id dedupe (§12.3)
```

The relay's only undetected read path is a CA-trusted certificate for the provider's name, which is a CA compromise rather than a protocol failure. Everything else either requires the leaf key or is a metadata observation that §16.3 concedes.

## 5. Mitigation to specification mapping

The table inverts the threat table: for each normative section, the threats it is the primary control for.

| Section | Primary control | Threats addressed |
| --- | --- | --- |
| §4 Roles and trust | Relay, directory and adapter cannot authorize; unknown keys not trusted because they self-sign | T-03, T-18, T-34 |
| §5.1 TLS profile | TLS 1.3, explicit trust anchor, no fallback, termination at the provider | T-19, T-21, T-26, T-40 |
| §6.1 Key identifiers | Recompute and byte-compare the thumbprint | T-03, T-05, T-10 |
| §6.2 Key distribution | Embedded `provider_jwk` and `sub_jwk` must match their identifiers | T-03, T-05, T-10, T-40 |
| §6.3 JWS headers | Fixed `alg`, `kid` equals `iss`, expected `typ`, forbidden header members | T-04 |
| §6.4 Enrollment | Independently trusted channel and human confirmation of full identifiers | T-03, T-34 |
| §6.5 Key management | Separate agent keys, OS storage, no keys in prompts or logs, re-enrollment on rotation | T-01, T-02, T-27 |
| §7.1 Resource identifiers | Owner thumbprint in `rid`; owner component verified against descriptor issuer | T-15, T-30 |
| §7.2 Descriptor claims | Owner signature, `seq`, expiry, `https` origin, unknown `kind` rejected | T-16, T-17, T-19, T-20, T-40 |
| §7.3 Discovery is not authorization | Descriptor conveys existence and location only | T-10, T-18 |
| §8.1 Well-known endpoint | Proof required, opt-in listing, 404 rather than an auth error | T-39 |
| §8.2 Directories | Untrusted, byte-preserving, no auto-connect, local origin approval | T-18, T-20, T-30 |
| §8.3 Local discovery | No egress bypass through DNS or redirects, no downgrade | T-20 |
| §9.1 Grant form | Literal actions, no wildcards, bounded validity, limits | T-11, T-12, T-16 |
| §9.2 Root grants | Enrolled owner signs, `aud` and actions bounded by the descriptor | T-10, T-14, T-15 |
| §9.3 Delegation | Nine narrowing rules and exact parent hash | T-11, T-12, T-13, T-14 |
| §9.4 Chain validation | Nine validation requirements, chain cap of four, unknown critical claims rejected | T-10, T-12, T-13, T-15 |
| §9.5 Quota semantics | Atomic reservation across every link, persistence, minimum of ceilings | T-22, T-23, T-29, T-37 |
| §9.6 Not a bearer credential | Proof required per request in addition to the grant | T-02, T-06 |
| §10.1 Strict JSON | Duplicate keys, nonfinite numbers, unsafe integers, trailing content rejected | T-09, T-29, T-38 |
| §10.2 Canonicalization | Byte-identical canonical payloads and original signing input | T-09, T-11 |
| §10.3 Encoding and time | Integer seconds, reliable clock, no expiry grace | T-16 |
| §10.4 Proof of possession | Nonce, 30 second window, method, URI, body and grant binding | T-06, T-07, T-08, T-09, T-35 |
| §11.1 Common requirements | Body cap, no redirects, no-store, proof before grant evaluation | T-19, T-20, T-29 |
| §11.2 Challenge | Random nonce, 60 seconds, bound and single use, rate limit, no existence leak | T-07, T-39 |
| §11.3 Sessions | `sid` bound to leaf key and chain, 15 minute cap | T-02, T-35 |
| §11.4 Invoke | Full revalidation on every call | T-24, T-36 |
| §11.5 Close | Fresh proof, session invalidation | T-35 |
| §11.6 Revoke | Owner proof, persist before responding, ancestors invalidate descendants | T-01, T-02, T-23, T-36 |
| §11.7 Binding rules | Nonce subject and `grant_hash` per operation | T-06, T-08, T-35 |
| §12.1 Processing | Ordered checks, atomic reservation, sandboxed handler, timeout | T-22, T-33, T-38 |
| §12.2 Action schemas | Fixed inference and MCP schemas, separate tool allowlist, no URL or shell forwarding | T-12, T-27, T-28, T-38 |
| §12.3 Idempotency | Dedupe per resource per leaf subject, 409 on duplicate, no exactly-once claim | T-24, T-25 |
| §12.4 Receipts | Provider signature, binding fields, no payloads in the receipt | T-25, T-26, T-30, T-32 |
| §13 Errors | Status and code mapping, no existence leak, no blind retry of unknown outcome | T-25, T-29, T-39 |
| §14 Revocation | Provider is authoritative, honest guarantee stated, no offline bypass | T-01, T-02, T-36 |
| §15 Adapter contract | Preserve TLS, report failure, no silent fallback, credentials outside prompts | T-19, T-20, T-31 |
| §16.2 Mitigations | Reject algorithm confusion, URL keys and unknown critical headers | T-04, T-27, T-31 |
| §16.3 Non-claims | No confidentiality, no zero knowledge, no recall of disclosed data | T-32, T-33 |
| §16.4 Physical actuation | No remote actuation in the baseline | Out of scope by design |
| §16.5 Data handling | Minimal logs, configurable retention, no published inventory | T-30, T-32 |
| §17.1 Test matrix | 20 required positive and negative cases | Verification for all rows |
| §17.2 Test vectors | Deterministic fixtures with fixed test keys | Verification for all rows |
| §17.3 Stability | Independent interoperability before 1.0 | Verification maturity gate |

## 6. Open problems not solved in Draft 00

These are the places where the threat table cannot point at a requirement, because the specification deliberately does not have one yet. Each entry states what is missing and what an implementation should do in the meantime. None of these is a defect report against a design that never claimed the property; they are the agenda for Draft 01.

The repository keeps a separate integrator-facing register in `docs/open-issues.md` with identifiers `O-1` through `O-15`. The entries below use `OP-n` because they are the security framing, not a second register. The mapping is:

| Here | Open issues register | Note |
| --- | --- | --- |
| OP-1 | O-1 | Same gap. This document adds the exposure window and the distribution problem. |
| OP-2 | O-5 | Streaming and long-running jobs. |
| OP-3 | O-2 | Exactly-once and unknown outcomes. |
| OP-4 | O-3 | Payload confidentiality from the provider. |
| OP-5 | O-14 | No post-quantum path. |
| OP-6 | O-15 | Actuation is excluded but not mechanically prevented. |
| OP-7 | O-8 | Durable quota and nonce state. |
| OP-8 | O-6 (related) | Rotation is re-enrollment, which is the enrollment bootstrap problem. |
| OP-9 | none | Egress and SSRF hardening has no register entry. |
| OP-10 | O-11 (related) | No confinement to a purpose; the tool allowlist is the closest control. |
| OP-11 | O-12 (related) | Receipts are unilateral; there is no transparency. |
| OP-12 | none | Vectors exist but only the author's code has been run against them. |

**OP-1. Offline revocation and revocation distribution.** The provider is the only enforcement point (§14). There is no revocation list, no signed revocation object, and no way for a consumer or a second provider to learn that a grant or enrollment was revoked. An owner who is disconnected cannot shorten exposure, which lasts until grant expiry (up to 24 hours) or session expiry (up to 15 minutes). Interim: short grants for sensitive resources, online freshness policy, and network-level isolation of the consumer. See T-01, T-02, T-36.

**OP-2. Streaming and asynchronous invocation.** Deferred to a future profile (§12.2). Without streaming, a result must fit the response byte ceiling, so large outputs are either truncated or fail. Without asynchronous jobs, a long task occupies a handler slot for its whole `max_ms`. Interim: keep handlers short and return a handle as application data, while accepting that the handle is outside the protocol's authorization model.

**OP-3. Exactly-once and unknown outcomes.** No exactly-once claim is made and none may be described (§12.3). A crash after dispatch is indistinguishable from a request that never ran. There is no status endpoint, so reconciliation is out of band. Interim: make handlers idempotent at the application layer, record `request_id` on the client, and treat a timeout as an incident rather than a retry.

**OP-4. Confidentiality from the provider.** No confidential computing, no zero-knowledge execution, and no end-to-end payload encryption (§16.3). A provider and its insiders read inputs and outputs. Interim: do not send data that the provider must not see, and do not describe the protocol as private.

**OP-5. Post-quantum signatures.** The baseline is Ed25519 only; post-quantum signatures are listed as a future profile (§18). Descriptors, grants and receipts are stored and re-verified, so recorded objects have a forgery exposure after a cryptanalytic break. Interim: bound retention of signed artifacts to the period in which they matter.

**OP-6. Physical actuation.** Excluded. Robotics telemetry is read-only and Draft 00 MUST NOT be used to move, energize or unlock physical systems (§16.4). Any actuation profile needs local interlocks and an emergency stop independent of the protocol path.

**OP-7. Distributed provider state.** Nonce consumption, quota counters, dedupe records and revocation records are all specified as atomic and persistent, without defining behaviour across multiple processes, replicas or nodes (§9.5, §10.4, §11.6, §12.3). A single-node provider is the only clearly conforming shape. Interim: run one writer per resource, or source the atomicity from a transactional store and test the concurrent cases in §17.1.

**OP-8. Enrollment trust bootstrap.** "Independently trusted channel" is defined by example rather than by procedure, and fingerprint comparison is a SHOULD (§6.4). Since enrollment is the root of all trust, this is the most consequential unspecified step. Interim: out-of-band verification of the full key identifier, recorded in a signed enrollment note.

**OP-9. Egress and SSRF hardening.** Origin approval is required, but no IP-range denylist, DNS pinning, or egress observability is specified (§7.2, §15). A malicious enrolled owner can aim a descriptor at an internal service. Interim: resolve and pin the address, deny link-local and loopback ranges, and log every new origin.

**OP-10. Tool allowlist binding.** The allowlist must be separate from grants and not derivable from them (§12.2), but it is not bound to grant content and is not versioned. A tool added after issuance is reachable unless the gate is exact. Interim: snapshot the allowlist per session and refuse tools added after the snapshot.

**OP-11. Receipt trust and transparency.** A receipt is a unilateral provider statement. There is no countersignature, no log, and no third-party attestation (§12.4). It cannot prove that work happened. Interim: treat receipts as accountability records rather than proofs, and keep independent client-side observations.

**OP-12. No independent validation of the vectors.** §17.2 requires deterministic fixtures and §17.3 requires independent interoperability before 1.0. The repository now publishes `test-vectors/mlp1-draft00.json` and a conformance suite that passes against the reference implementation. That is a self-test: the fixtures and the code that verifies them were written together, so a shared misreading of the specification would not be detected. OP-12 is therefore downgraded from "nothing exists" to "nothing has been independently reproduced", which is still the gate on any 1.0 claim.

## 7. Maintenance

This threat model is a living document, and it should be revised when any of the following changes: a conformance vector is added, an implementation is published, a profile is proposed under §18, or a reviewer demonstrates a scenario that the table does not cover.

Revision rule: a new threat gets the next free identifier, a row in §3, and an entry in §5. Identifiers are never reused, so a citation in an issue or a review comment stays valid. A threat that is retired keeps its identifier and gains a "withdrawn" note rather than being deleted.

Severity changes require a note in the pull request that explains which rubric clause changed. Adding a mitigation without adding a test in the sense of §17.1 does not lower a severity, because an untested mitigation is a claim, and this document scores claims as claims.

The two scenarios in §4 should be re-walked whenever delegation rules or endpoint binding change, because both are sensitive to changes in §9.3 and §10.4. The relay tree should be re-walked whenever the TLS termination rule in §5.1 is touched, since that single sentence carries the entire relay threat.
