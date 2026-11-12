# Architecture

**Status:** Draft 00 — describes the reference implementation at `v0.0.1`.
Non-normative. Where this document and `specs/mlp-0000-core.md` disagree, the
specification wins and this document is wrong.

This is a map of the code: what each module is responsible for, how a request
travels through it, which state must survive a restart, and where the trust
boundaries are. It is written for someone about to review or replace a
component.

## 1. Shape of the system

MLP/1 separates three things that are usually tangled together in a
resource-sharing product:

| Concern | Question it answers | Where it lives |
| --- | --- | --- |
| Identity | Who is speaking? | A key, and a key identifier derived from it (§6.1) |
| Authorization | What may they do, for how long, how much? | A signed grant chain (§9) |
| Connectivity | How do the bytes get there? | A transport adapter (§15) |

The protocol's central claim is that these can vary independently. The code is
laid out so that they do:

```
packages/core         identity, authorization, encoding — no I/O at all
packages/gateway      the provider: policy, state, quotas, receipts
packages/client       the consumer: challenges, sessions, invocation
packages/transports   connectivity policy; no authority
packages/cli          operator and developer surface
```

`packages/core` importing nothing but `node:crypto` is a deliberate property.
It means the parts of the protocol that determine whether two implementations
interoperate can be read, audited, and vendored without pulling in a server.

## 2. Request lifecycle

One invocation touches every layer. The numbers are the order in which the
gateway enforces them.

```
consumer                                    provider (Gateway.handle)
   |                                                  |
   |-- POST /mlp/v1/challenge  {rid, subject} ------->|  issue nonce, 60s, bound
   |<---------------------------------- {nonce} ------|  to rid + subject
   |                                                  |
   |  build proof over: method, uri, exact body bytes,|
   |  nonce, leaf grant hash; sign with leaf key      |
   |                                                  |
   |-- POST /mlp/v1/invoke  + Meshless-Proof -------->|
   |                                                  | 1 parse body strictly
   |                                                  | 2 find session by sid
   |                                                  | 3 verify proof bindings
   |                                                  | 4 consume nonce (atomic)
   |                                                  | 5 re-verify whole chain
   |                                                  | 6 action ∈ leaf grant?
   |                                                  | 7 request_id unused?
   |                                                  | 8 validate input schema
   |                                                  | 9 reserve quota (all links)
   |                                                  |10 dispatch under max_ms
   |                                                  |11 charge response bytes
   |                                                  |12 sign receipt
   |<------------- {request_id, result, receipt} -----|
   |  verify receipt against provider key from        |
   |  the descriptor, and against this request        |
```

Steps 3 and 5 are not redundant. Step 3 proves the caller holds the leaf key;
step 5 proves the chain that leaf key sits in was ever authorized, is currently
valid, and has not been revoked. A session stores the chain precisely so that
step 5 can run on every call rather than once at session creation.

Steps 1 to 4 happen in the order shown because of §11.1: an unauthenticated
caller must not learn anything about grant structure. The gateway reads the
leaf subject from the body before verifying the chain, which is safe because a
subject key is a claim inside a signed object — an attacker can only name a key
they hold, and step 5 decides whether that key was ever authorized.

## 3. Modules

### `packages/core`

| Module | Responsibility | Spec |
| --- | --- | --- |
| `bytes.ts` | base64url, SHA-256, UUIDv4, constant-time compare | §10.3 |
| `json.ts` | strict parser, RFC 8785 canonicalization, canonicality check | §10.1, §10.2 |
| `jwk.ts` | Ed25519 keys, RFC 7638 thumbprints, key identifiers | §6.1 |
| `jws.ts` | compact JWS sign/parse/verify, header restrictions, compact hashing | §6.3 |
| `ids.ts` | resource identifier parse and construction | §7.1 |
| `descriptor.ts` | descriptor build/verify, action parsing, endpoint normalization | §7 |
| `grant.ts` | grant build/parse, chain verification, effective limits | §9 |
| `proof.ts` | proof build/verify and every request binding | §10.4 |
| `receipt.ts` | receipt build/verify and hash binding | §12.4 |
| `errors.ts` | wire codes and their HTTP status | §13 |

Two properties are worth calling out because they are easy to lose in a
refactor:

- **No module in `core` performs I/O.** There is no `fetch`, no `fs`, no clock.
  Time is always passed in. That is why the conformance suite can test expiry
  and skew without sleeping.
- **Canonicality is enforced on receive, not just on send.** `parseJws` calls
  `assertCanonical`, so a payload that is signature-valid but not byte-identical
  to its canonical form is rejected. Without that, the same authority would hash
  two ways and `parent` and `grant_hash` would stop meaning anything.

### `packages/gateway`

| Module | Responsibility |
| --- | --- |
| `ledger.ts` | durable state: enrollments, nonces, sessions, counters, revocations, request IDs, high-water marks |
| `handlers.ts` | action registry, input schemas, `infer` / MCP / echo handlers |
| `gateway.ts` | request routing, proof and chain enforcement, quota, dispatch, receipts |
| `server.ts` | HTTPS binding, TLS 1.3 floor, body cap, no redirects |

`gateway.ts` is transport-independent by design. `server.ts` reads bytes and
writes bytes; it makes no policy decision except the body cap. The conformance
suite drives `Gateway.handle` directly for message-level cases and through a
real socket for transport cases, so a test only pays for a socket when the
socket is what is being tested.

### `packages/client`

`MeshlessClient` owns a nonce per request, signs the exact bytes it is about to
send, and verifies the receipt it gets back. It refuses to construct without an
explicit trust anchor (`ca`) or a pinned certificate, and it has no option to
disable verification. It uses `node:https` rather than `fetch` for exactly that
reason.

### `packages/transports`

The adapter contract from §15, one working adapter, and one that refuses. The
refusal is the interesting part: `UnverifiedProvisioningAdapter` throws
`TransportError('unverified', ...)` for any operation, so a caller cannot
accidentally ship a doxx.net integration that has never been tested. When the
pilot in `docs/doxx-pilot.md` produces evidence, that class is replaced.

## 4. State that must survive a restart

§17.1-14 makes this a conformance requirement, not an implementation detail.

| State | Why it must persist | Consequence of losing it |
| --- | --- | --- |
| Enrollments | The owner trust root | Provider accepts only grants it cannot authenticate; or a different owner can claim the ID |
| Nonces | Replay window is 60s | A captured proof can be replayed after restart |
| Sessions | Bound to leaf key and chain | Calls fail; not a security loss, but a usability cliff |
| Quota counters | §9.5 ceilings | A caller can overspend by restarting the provider |
| Revocations | §14 | A revoked grant becomes live again |
| Request IDs | §12.3 dedupe | A retried invocation executes twice |
| Descriptor high-water | §7.2 rollback defence | An old descriptor becomes acceptable again |

`Ledger` writes a full JSON snapshot to a temporary file and renames it. The
choice is deliberate: rename is atomic on POSIX, so a crash leaves either the
old state or the new state. A provider that needs throughput should replace the
storage layer, but must keep the two semantic requirements — check-all-then-apply
for quota reservation, and consume-before-answer for nonces. A multi-process or
multi-replica provider is **not** conforming under Draft 00, because the spec
requires atomicity that a file snapshot cannot provide across processes. That is
recorded as an open issue rather than hidden.

## 5. Trust boundaries

```
        owner key                    provider key
            |                             |
            v                             v
   +------------------+          +------------------+
   | signs descriptor |          | signs receipts   |
   | signs root grant |          | enforces policy  |
   +------------------+          +------------------+
            |                             ^
   granted authority, narrowed            |
            v                             |
   +------------------+                   |
   | consumer key     |----- proof -------+
   | signs each proof |
   +------------------+
```

Four boundaries the code assumes are hostile:

1. **The relay.** It carries bytes. It cannot read proofs as authority, cannot
   mint a grant, and if it terminates TLS it is, by definition, the provider.
2. **The directory.** It distributes descriptors. `verifyDescriptor` re-derives
   every key identifier from the embedded JWKs, so a directory that substitutes
   a key changes the thumbprint and fails verification.
3. **The handler.** It runs provider-supplied code against consumer-supplied
   input. §16 requires least privilege; the reference handlers do no I/O at all,
   and a handler that does is expected to be sandboxed by its operator. The
   receipt-signing key is not passed into the handler, but Draft 00 does not
   require process separation — a real gap, recorded in `docs/open-issues.md`.
4. **The consumer.** It can send anything. Every field is schema-validated
   before quota is reserved, and the action name must match exactly; there is no
   dynamic dispatch beyond the registry.

## 6. Where failures are shown honestly

A protocol implementation is judged by what it refuses. The reference
implementation refuses in these places, with these codes:

| Condition | Code | HTTP |
| --- | --- | --- |
| Non-canonical signed payload | `invalid_proof` | 401 |
| Duplicate JSON member | `invalid_request` | 400 |
| Reused nonce | `replay` | 409 |
| Body does not match proof | `invalid_proof` | 401 |
| Chain widened at any link | `invalid_grant` | 401 |
| Revoked grant, any link | `revoked` | 403 |
| Action outside leaf grant | `denied` | 403 |
| Ancestor quota exhausted | `quota_exceeded` | 429 |
| Repeated `request_id` | `duplicate_request` | 409 |
| Resource concealed / unknown | `unknown_resource` | 404 |
| Discovery disabled | `unknown_resource` | 404 |

The 404-for-concealment choice is from §8.1 and §13: an unauthenticated caller
must not be able to distinguish "no such resource" from "not for you".

## 7. Extending it

| You want to | Change |
| --- | --- |
| Add a resource kind | `descriptor.ts` (`RESOURCE_KINDS`), a handler in `handlers.ts`, and a spec PR — the kind list is normative |
| Add an action | Register it, then issue a grant that names it and a descriptor that declares it |
| Add a transport | Implement `TransportAdapter`; it must not touch TLS validation |
| Replace storage | Keep `Ledger`'s method semantics; run the conformance suite |
| Change the wire format | Do not. That is MLP/2, and §18 governs it |

## 8. What this architecture does not do

- No streaming or long-running jobs; one request, one response, bounded by
  `max_ms` (§12.2).
- No multi-replica provider; quota atomicity is single-process (§9.5).
- No in-band key rotation; rotation is re-enrollment (§6.5).
- No confidentiality from the provider; inputs are plaintext to it (§16.3).
- No exactly-once invocation; a crash after dispatch is an unknown outcome
  (§12.3).
- No revocation push; the provider learns when it is asked, or when the grant
  expires (§14).

These are specification-level gaps, not implementation shortcuts, and each one
is in `docs/open-issues.md` with its impact.
