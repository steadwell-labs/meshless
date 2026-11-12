# Meshless Protocol FAQ

This document answers the objections that come up first when the Meshless Protocol is described to an engineer, a security reviewer, or a platform team: what it is not, why it made the choices it made, and where Draft 00 has no answer. Answers are plain, limitations are stated as limitations, and every claim that is not in the specification is marked unverified. Where the honest answer is "the draft does not specify this", the answer says so and points at the section that would have to change.

**Status:** Draft 00 — non-normative  
**Applies to:** MLP/1 · Draft 00 · 12 November 2026 (`specs/mlp-0000-core.md`)  
**Author:** Steadwell Labs  
**Companion documents:** `docs/threat-model.md`, `docs/doxx-pilot.md`

## 1. Isn't this just a VPN?

No, and the distinction is the reason the protocol exists.

A VPN answers "can this machine reach that network". Once you are on the overlay, you can typically reach everything that is routed to you. Authorization is implicit in network membership, and it is usually all-or-nothing.

MLP answers "may this key invoke this action on this resource, how many times, for how long, and can it prove that it did". The authority is a signed grant with named actions and hard limits, and it is checked at the resource on every invocation, not at the network edge. Section 4 states the rule directly: network access and resource access are independently enforced, and reaching an endpoint grants nothing. Section 9.6 adds that a grant is not a bearer credential, so intercepting one does not let you use it.

A VPN is also a poor fit for delegation. If an agent needs to call one action on one resource for five minutes, a VPN gives it a network identity that outlives the task. A grant expires, carries a call and byte ceiling, and can be revoked by its `jti`.

MLP is not a replacement for a VPN either. It runs above whatever connectivity exists (§3.2, §15), and a private VPN does not remove the TLS requirement (§5.1). If you already have a VPN you like, keep it; MLP is the authorization layer on top.

## 2. Isn't this just OAuth, UAuth, UCAN, or MCP?

It is close to none of them, and the differences are structural rather than cosmetic. Each of these answers a different question:

| System | Question it answers | Where authority lives |
| --- | --- | --- |
| VPN | Can this machine reach that network? | Network membership |
| OAuth | May this client use this scope from this server? | The authorization server |
| UCAN | May this key invoke this capability, attenuated how far? | A signed chain, holder to holder |
| MCP | How does a model host call a tool? | The tool server's own configuration |
| MLP | May this key invoke this action on this resource, within what limits, until when, and can it prove it? | A signed grant, enforced at the provider |

**OAuth** delegates scopes from a client to a resource through an authorization server. Access tokens are typically bearer tokens, and the interesting security work happens at the authorization server. MLP has no authorization server, no account, and no bearer token: the owner signs grants directly, each request carries a proof bound to the method, URI, body and grant (§10.4), and there is no token endpoint to compromise. MLP is not an OAuth profile and does not claim to be one.

**UCAN** is the closest relative: signed capability chains with attenuation. The differences are that MLP fixes a wire profile (compact JWS over EdDSA/Ed25519, TLS 1.3, canonical JSON), adds resource descriptors with monotonic `seq`, adds per-invocation quotas and provider-signed receipts, and defines an HTTP endpoint set. UCAN is listed as an informative reference only, and no wire compatibility is claimed.

**UAuth** is not referenced anywhere in Draft 00. Any relationship is unverified and is not claimed here.

**MCP** is a different layer. MCP describes how a model host talks to tools and resources; it has no notion of an owner, a grant chain, or a receipt. MLP can carry MCP actions as a resource kind (`kind` `mcp`, actions `tools.list` and `tools.call`, §12.2), but it does not replace MCP (§3.2) and the two should be deployed together rather than chosen between.

The honest summary: MLP is closest to a signed-capability system with an HTTP binding, and it is the only one in that family that specifies quotas, receipts and a local-first transport profile in the same document.

## 3. Why not blockchain?

Because nothing in the protocol needs agreement between parties who do not trust each other.

The owner signs descriptors and grants with its own key. The provider enforces with its own state. A directory can distribute descriptors but cannot grant authority (§4). No global ordering, no consensus, no token, and no settlement is required to answer "may this key call this action". Section 1 says so explicitly, and §3.2 lists consensus and settlement as non-goals.

A ledger would add cost, latency, and permanent public metadata, which is the opposite of the minimization the draft asks for (§8.2, §16.5). It would also not solve the hard problems. A stolen key is still stolen, and a revoked grant still needs the provider to learn about it, which a chain does not fix while the owner is disconnected (§14).

The one place a public chain appears is as a possible future enrollment or proof anchor (HeartBadge or Bitcoin-anchored proofs, §18). That is a proposal for identity bootstrapping, not a requirement, and it is not implemented.

## 4. Why Ed25519 and JWS rather than something else?

Ed25519 gives small keys, deterministic signatures, and no per-signature parameter choices. There is no nonce to reuse and no curve point to validate incorrectly, which removes a class of implementation bugs that have bitten ECDSA deployments. RFC 8037 defines the JOSE binding, so existing libraries can verify an MLP object without new cryptography.

JWS compact serialization was chosen for the same reason: it is one ASCII string, easy to put in a QR code, a file, a clipboard, or an HTTP header, and easy to hash exactly for the parent chain and the `grant_hash` binding. That exact-bytes property matters, because `parent` is a hash of the parent's compact form (§9.3) and a proof commits to the leaf grant's bytes (§10.4).

The costs are real:

- JWS compact is one-shot, so streaming signatures are not available. Streaming is a future profile anyway (§12.2).
- The JOSE ecosystem has a history of algorithm confusion, so §6.3 does not let the token choose the verifier: `alg` must be `EdDSA`, `kid` must equal `iss`, `typ` must be the expected media type, and `jwk`, `jku`, `x5u`, `x5c` and `crit` are forbidden in the protected header.
- Ed25519 is not the right answer for every regulatory environment. If you need a different signature suite, Draft 00 does not have an answer: alternative algorithms are explicitly future profiles (§5.2), not a configuration option.

The choice is a baseline interoperability decision, not a claim that Ed25519 is the best possible signature scheme.

## 5. Why a 24-hour maximum grant lifetime?

Because the leaked-key window and the revocation window are the same window, and both need a ceiling.

If a key is stolen, the attacker can use every unexpired grant issued to it. If an owner is disconnected, a revoked grant keeps working until the provider learns or the grant expires (§14). A 24-hour cap bounds both, and it bounds the provider's bookkeeping too, since `request_id` dedupe runs "until the leaf grant expires" (§12.3).

The cost is operational churn. Anything that needs to run longer than 24 hours must be reissued, which means the owner's key has to be available at least daily, or a longer-lived intermediate has to be introduced deliberately. Section 9.1 also allows a much shorter lifetime, and §7.2 recommends shorter descriptor lifetimes for resources reachable from untrusted networks. A five-minute grant is a normal choice, and it is what the pilot plan uses.

Sessions are shorter still: the earlier of the leaf grant expiry and 15 minutes (§11.3). A session is a convenience for a burst of calls, not a durable authorization decision.

## 6. How is this local-first if it needs TLS?

"Local-first" means no Internet dependency and no central service, not "no cryptography". Section 14 is precise: local operation requires no Internet, but still requires valid credentials, a correct clock, and trusted TLS.

TLS is still required because the local network is not a trust boundary. A LAN with a coffee-shop access point, a shared office switch, or a compromised laptop is not a safe place to send an unauthenticated request. The proof is also bound to the origin and path (§10.4), which assumes a real transport identity.

For a LAN you have two conforming options under §5.1: a private CA whose root is distributed to the consumer, or a pinned certificate enrolled for that provider. Both are real work. A self-signed certificate with validation disabled is not one of the options; §5.1 forbids the "proceed anyway" path and any insecure fallback.

The practical cost is certificate lifecycle on devices that were never designed for it. That is a genuine adoption obstacle, and the draft does not solve it beyond naming the two allowed anchors.

## 7. What stops a provider from lying in a receipt?

Nothing cryptographic. A receipt is a signed statement by the provider that it reports having executed an invocation, and §12.4 says exactly that: it does not attest intent, correctness, or that the reported work happened.

What a receipt does give you is accountability. It binds the request hash, the result hash, the leaf grant `jti`, the subject, and the `request_id`, so a provider cannot later deny receiving a specific request, and a consumer can prove what it was told. Receipts are excluded from carrying prompts, arguments, results, credentials or internal addresses, so they are safe to retain and to share.

If you need more than a provider's word, Draft 00 has no mechanism. There is no transparency log, no countersignature, no third-party attestation, and no way to challenge a receipt. That is an open problem in the threat model, and a possible future profile (Trellis-backed receipts, §18).

The practical rule: do not grant an action whose false execution you cannot tolerate. Receipts make dishonesty visible after the fact, not impossible.

## 8. How do I revoke an agent that is offline?

Distinguish two cases, because only one of them is hard.

If the agent is offline but the provider is reachable, revocation works normally. The owner sends `POST /mlp/v1/revoke` with a fresh owner proof (§11.6), the provider persists the revocation before responding, and the agent's next request fails with 403 `revoked`. The agent being offline changes nothing, because authority is checked at the provider, not on the agent.

If the owner cannot reach the provider, revocation cannot propagate. Section 14 says this plainly: a remote owner cannot guarantee immediate revocation while disconnected, and the honest guarantee is "no new invocation is admitted after the provider learns of the revocation". Exposure then lasts until the grant expires, up to 24 hours, or until the session expires, up to 15 minutes.

What you can do about it:

- Issue short grants for anything sensitive. Five minutes bounds the window to five minutes.
- Use local policy that requires online freshness checks or shorter leases (§14). Note that the spec makes this optional, not the default.
- Isolate the resource at the network level. Network access is not authorization, but removing reachability is still a valid containment step.
- Remember that revocation cannot recall data already disclosed (§14).

Draft 00 has no revocation list, no signed revocation object, and no way for a second provider or a peer consumer to learn that a grant was revoked. That is the largest unsolved problem in the draft.

## 9. Can I run it without internet?

Yes, on a LAN or on the same device. Section 14 allows it and §15 makes direct HTTPS the baseline adapter, requiring no extra component.

What still has to be true without Internet:

- Both sides have valid credentials and unexpired grants. Grants cannot exceed 24 hours, so someone has to be able to reissue them.
- The clock is correct. There is no NTP on an isolated network, and the provider is required to reject traffic rather than serve it when its clock is uncertain (§10.3).
- A TLS trust anchor is available locally. A public CA cannot be reached to check revocation, so a private CA or a pinned certificate is the practical choice.
- Discovery is out of band. Descriptors are exchanged as files, QR codes, or clipboard content; the `.well-known` endpoint is optional and requires a proof from a configured client (§8.1).

What does not work without Internet: fetching a fresh descriptor after the current one expires, revoking from a remote location, and any directory-based discovery. None of those is required for local operation, which is the point.

## 10. Is it ready for production?

No. Draft 00 is an experimental design document. The repository contains the specification and a document skeleton; it does not yet contain a reference implementation, executable test vectors, an audit, or a single independent implementation.

Section 2 says it is not an implemented or audited standard. Section 17.3 requires independent interoperability before any 1.0 designation, and §17.2 requires deterministic fixtures that do not exist yet. The README states the same thing in its own words.

Concretely, what is missing before production use: a reference implementation that passes the §17.1 matrix, published vectors, at least one independent implementation, a security review, a revocation story that survives a disconnected owner, and operational tooling for certificate and key lifecycle.

Use it to learn, to review the design, and to build test fixtures. Do not put it in front of customer data or physical systems.

## 11. How does this relate to MCP? Does it replace it?

No. They are complementary, and the specification lists replacing MCP as a non-goal (§3.2).

MCP answers "how does a model host discover and call tools and resources". It is a tool protocol. MLP answers "who may reach which resource, for how long, with what limits, and how is that proven". It is an access protocol.

The composition is explicit in the draft: `kind` `mcp` defines two actions, `tools.list` and `tools.call` (§12.2). The provider is responsible for the upstream MCP lifecycle and version negotiation. Critically, a `tools.call` grant must not expose a tool outside a separate, explicit allowlist, and that allowlist must not be derivable from the grant. So MLP narrows who may call, and MCP's own allowlist narrows what may be called; both must hold.

An MCP server is a natural MLP resource: you keep the server, and you put a provider gateway in front of it so that reaching it requires a grant and a proof rather than network access.

## 12. How do you prevent an agent from escalating its own grants?

Structurally, with nine rules that must all hold at every hop, plus a validation step that rechecks the whole chain.

Section 9.3 says a child grant must keep the same audience and resource, must have an action subset, must fit inside the parent's validity interval, must not exceed any parent limit, must have a delegating parent, must decrement depth by exactly one, must not enable delegation at depth zero, and must hash the exact parent bytes. Section 9.4 adds that the root must be signed by the enrolled owner, the leaf audience and resource must match this provider and this invocation, the leaf actions must also be a subset of the descriptor, no link may be revoked, and the chain may not exceed four grants.

So an agent cannot widen its own authority by minting a child: a child can only be narrower. It cannot mint a root, because the root signer must be the enrolled owner. It cannot re-parent, because the parent hash covers exact bytes. It cannot go deeper than the depth it was given.

What the rules do not cover:

- Broad action semantics. If a profile defines an action like `tools.call`, the subset check constrains the name, not the reach. The per-tool allowlist is the real boundary (§12.2).
- Prompt injection. A grant cannot stop an agent from being talked into using authority it legitimately holds. That is a consumer-implementation problem the protocol does not test (threat T-27).
- Enumeration of many children. Depth bounds chain length, not breadth; the aggregate ceiling is enforced per link at the provider (§9.5).

## 13. What about NAT and firewalls?

The consumer always initiates. It opens an outbound TLS connection to the provider's `endpoint`, which is an `https` origin (§7.2). No inbound path to the consumer is required, so consumer-side NAT is a non-issue.

Provider-side NAT is the interesting case. The provider must be reachable at an origin the consumer has approved, so you need one of: a port forward, a public origin, a relay, or a tunnel provisioned through an adapter. Section 15 allows an adapter to provision tunnels, DNS and firewall policy through a service's documented APIs, with dedicated credentials that must stay out of grants and prompts.

One constraint survives all of that: TLS termination must occur at a trusted provider boundary, and an untrusted relay must not terminate application TLS (§5.1). A tunnel that terminates TLS at the edge is, for protocol purposes, the provider, which means it must be trusted like one. That is the single most important question to ask of any connectivity integration, and it is the central unknown in the doxx.net pilot.

Client-side egress rules also matter. The consumer's allowlist must include the approved origin, and DNS resolution or redirects must not be used to bypass egress restrictions (§8.3). A provider should not answer 3xx at all, and a client must not follow one (§11.1).

## 14. What does it cost, and is there a company behind it?

There is no pricing, because there is no product. Draft 00 specifies a protocol, not a service. Nothing in the path requires a commercial account, a subscription, or a vendor (§1).

The costs you actually incur are the ones you already have: compute for the provider, network for the transport, and engineering time for certificates, key management, and the gateway. If you use a tunnel service, you pay that service's rates, not a Meshless rate.

Steadwell Labs is named as the author of the draft. That is the extent of the commercial statement. There is no hosted offering, no SLA, no support contract, and no certification program described in the document. Section 18 proposes Apache-2.0 for code and CC BY 4.0 for the specification; licensing of any future implementation is a separate decision.

If someone tells you a vendor "supports MLP", ask which section they implement and whether they have published conformance results. At this revision the reference implementation passes its own conformance suite against published vectors, which is a self-test and not a certification. No independent implementation has reproduced those results, so the honest answer for everyone, including the authors, is that nothing here is certified.

## 15. How do I implement it?

In this order:

1. **Primitives.** Strict JSON parsing (§10.1), RFC 8785 canonicalization (§10.2), compact JWS with EdDSA over Ed25519, unpadded base64url, and JWK thumbprints (§6.1). Get the byte-level behaviour right first; everything else depends on exact bytes.
2. **Objects.** Descriptors (§7.2), grants (§9.1), proofs (§10.4), receipts (§12.4), with the header profile from §6.3. Enforce the forbidden header members, the `kid` equals `iss` rule, and the expected `typ` per object.
3. **Validation.** The nine chain rules (§9.3), the nine validation requirements (§9.4), the four proof bindings (§10.4), and the receipt bindings (§12.4).
4. **Endpoints.** Challenge, sessions, invoke, close, revoke (§11). Revalidate on every invoke; session establishment is not a durable decision.
5. **State.** Nonce store, quota counters, revocation records, dedupe records, all atomic and persistent (§9.5, §10.4, §11.6, §12.3).
6. **Conformance.** Run the twenty cases in §17.1, including the negative ones. Publish your fixtures, because the official vectors do not exist yet.

Two practical warnings. First, you will be co-authoring the de facto interpretation, so write down every place the text was ambiguous and publish it. Second, start with the consumer, not the provider: a consumer that verifies correctly will find provider bugs faster than a provider that signs correctly.

## 16. What is the relationship to doxx.net, HeartBadge, Trellis and CoRA?

Short version, then the detail:

| Name | Relationship in Draft 00 | Status |
| --- | --- | --- |
| doxx.net | Possible transport adapter and the Appendix A pilot | unverified; no adapter exists |
| HeartBadge | Possible enrollment mechanism or proof anchor (§18) | optional; not implemented |
| Trellis | Possible receipt profile (§18) | future profile; not baseline |
| CoRA | Not referenced anywhere in the draft | unverified; no claim made |
| UCAN | Informative reference only | no wire compatibility claimed |

**doxx.net** is a proposed connectivity integration, not a dependency. Section 15 describes an adapter that may provision tunnels, DNS and firewall policy through that service's documented APIs, and Appendix A proposes a pilot. No compatibility has been tested, no adapter exists in the repository at this revision, and no claim is made. Whether the tunnel terminates TLS at the edge is the open question that decides whether the pilot can be conforming at all. See `docs/doxx-pilot.md`.

**HeartBadge** is listed as a possible enrollment mechanism or proof anchor (§18). It is not required, not implemented, and not specified. An implementation that ignores it is fully conforming.

**Trellis** appears only as a possible future receipts profile (§18). Baseline receipts are provider-signed JWS objects and nothing else.

**CoRA** is not referenced anywhere in Draft 00. Any relationship is unverified and this document makes no claim about it. If a connection exists, it is not part of the protocol as written.

**UCAN** is an informative reference. It is the closest prior art and the draft does not claim wire compatibility with it.

## 17. What happens if a laptop with an agent key is stolen?

The attacker holds that agent's authority until the grant is revoked or expires. Scope it honestly: the grant's actions and limits are what they can do, not the whole resource, and the grant expires within 24 hours at most (§9.1).

Response, in order: revoke the grant `jti` at the provider (§11.6), confirm the revocation is persisted, revoke the enrollment if the root key was on the same device, re-enroll with a new key, and check receipts for invocations you did not make.

If the owner root key is stolen rather than an agent key, the damage is larger and one consequence is easy to miss: a resource ID embeds the owner thumbprint (§7.1), so a new root key means a new resource ID. You cannot rotate the owner key in place in Draft 00; key rotation requires re-enrollment, and a rotated key is a new subject (§6.5). Old descriptors and grants remain valid for the old resource ID until they expire, which is another reason to keep descriptor lifetimes short (§7.2).

There is no global revocation. You must revoke at every provider that holds an enrollment for the resource, and tell every consumer to drop its cached descriptor.

## 18. What if the directory is down?

Losing a directory costs discovery, not authority. A directory cannot grant access (§4), and a descriptor is a portable signed artifact that you can carry by file, QR code, or clipboard (§8).

What still works: any descriptor already cached, until it expires. Descriptor lifetime is capped at 24 hours (§7.2), so a cached copy is valid for at most a day.

What stops working: obtaining a new descriptor, which means no new endpoint after the current one expires, and no `seq` update. Consumers keep a high-water mark and reject a lower `seq`, so they will also reject a replayed old descriptor while the newer one is stored.

There is no requirement to run a directory at all. Baseline discovery is explicit exchange between the parties, and the `.well-known` endpoint is optional, off by default for public listing, and requires a proof from a configured client when it is used (§8.1).

## 19. Is it anonymous? What metadata leaks?

No. Anonymity is an explicit non-goal (§3.2), and the design leaks more than a casual reader expects.

- A resource ID embeds the owner's key thumbprint (§7.1), so every resource is correlatable to an owner key, across endpoints and across time, by anyone who sees the ID.
- A descriptor carries the endpoint, the kind, the action list, and the provider key (§7.2). It is meant to be publishable, but it is also a description of your infrastructure.
- Receipts carry the resource ID, subject key, `request_id`, action, usage and hashes (§12.4). They exclude payloads, but not the shape of your usage.
- Relays observe traffic even when they cannot read it (§16.3).
- A provider sees the consumer key identifier and the timing of every call, plus the plaintext of the payload.
- Logs, if not minimized, accumulate all of the above (§16.5).

The draft asks directories to minimize metadata (§8.2), asks implementations not to publish identities or inventories by default (§16.5), and forbids receipts from carrying prompts or arguments (§12.4). Those are real mitigations, not anonymity. If your threat model includes a global observer, MLP does not address it.

## 20. Can I use it for robots or physical devices?

Not for actuation. Section 16.4 is unambiguous: there is no remote physical actuation in the baseline, robotics telemetry is read-only, and Draft 00 must not be used to move, energize, or unlock physical systems.

Read-only sensors are a supported kind (`sensor`), though §12.2 notes that the action schema for that kind is not defined in Draft 00, so an implementation must publish its own.

If you want actuation, the protocol is not the missing piece. The requirements named in §16.4 are local safety interlocks, an independent emergency stop that does not depend on the protocol path, and hardware-level limits. Those are engineering and certification problems, and none of them is solved by a signed grant.

The blunt version: a five-minute grant that says `move` is not a safety case, and the draft says so.

## 21. What happens if the provider crashes mid-invocation?

The outcome is unknown, and Draft 00 does not pretend otherwise. Section 12.3 says a crash after dispatch may leave the outcome unknown and that MLP/1 makes no exactly-once claim and must not be described as providing one.

What the protocol gives you:

- Dedupe by `request_id` per resource per leaf subject, until the grant expires, with a repeat rejected as 409 `duplicate_request` (§12.3). If the provider recorded the request before crashing, a retry gets a 409 rather than a second execution.
- A rule against blind retries: a client must not automatically retry an invocation whose outcome is unknown under a new `request_id` (§13). Retry requires the same id and an explicit decision by the caller.

What it does not give you: a way to ask "did request X run?". There is no status endpoint, no query, and no reconciliation protocol. That is manual or application-level.

The practical mitigation is at the handler: make side effects idempotent under an application-level key, record the `request_id` on the consumer, and treat an unknown outcome as an incident rather than a retry.

## 22. Can one grant span multiple providers?

No. A grant's `aud` is a single provider key identifier, and its `rid` is a single resource (§9.1). A second provider has a different key, so the audience check fails (§9.4), and a different resource means the resource check fails.

Aggregating across providers means issuing separate grants and coordinating in the consumer. Draft 00 has no cross-provider composition, no transitive trust between providers, and no way for one provider to honour another's grant. That is a deliberate consequence of keeping the audience invariant under delegation (§9.3).

The same rule limits multi-tenant providers: if one provider key serves resources for several owners, `aud` no longer distinguishes them and `rid` is the only resource-level check. The threat model flags this; Draft 00 does not discourage key reuse across tenants.

## 23. What about post-quantum?

Not in Draft 00. The baseline is Ed25519 only, and post-quantum signatures are listed as a future profile (§18) with no hybrid mode, no algorithm identifier negotiation, and no migration path defined.

Two implications. Live traffic is protected by TLS, whose post-quantum story is independent of MLP and depends on your TLS stack. Stored objects (descriptors, grants, receipts) are a different matter: they are re-verified over time, so a future break in Ed25519 affects the authenticity of anything you retained.

If this matters to you now, the honest answer is that draft 00 has no answer, and adding one is a major-version change under §18 rather than a configuration flag.

## 24. How do I know two implementations are compatible?

Today, you do not. Section 17.3 requires independent implementation interoperability before any 1.0 designation, and §17.2 requires deterministic fixtures with fixed test keys. Neither exists at this revision, so "compatible" currently means "two implementations read the same draft the same way".

What compatibility would require:

1. Published vectors that pin exact canonical bytes, signatures, and expected outcomes.
2. Independent implementations that pass the twenty-case matrix in §17.1, including the negative cases.
3. Published results, not a demonstration.

Until then, any compatibility claim is a claim about intent. That includes claims about doxx.net, which Appendix A explicitly says must not be made before testing, and claims about any other implementation. If you need to evaluate one, run the §17.1 matrix yourself and publish what you find.

## 25. What does "Relay access, not ownership" actually mean?

It is a positioning statement about what moves across a boundary. A relay forwards bytes; it does not gain authority over what it forwards (§4). A consumer receives a scoped, expiring grant; it does not receive a copy of the resource, a share of it, or a standing right to it. The owner keeps title and keeps the ability to withdraw authority.

The normative content behind the slogan is short:

- A directory, relay, or adapter cannot cause a grant to be widened or replayed (§4).
- Reaching an endpoint grants nothing (§4).
- A grant is not a bearer credential (§9.6).
- Revocation is available to the owner independently of any consumer session (§11.6).

Nothing in the tagline promises confidentiality, availability, or anonymity. It is a claim about where authority lives, not a claim about what the network can see. The threat model lists what it does not cover, and that list is longer than the slogan.
