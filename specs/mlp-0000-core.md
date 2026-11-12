# Meshless Protocol (MLP/1)

**MLP/1 · Draft 00 · 12 November 2026**

Steadwell Labs

**Status:** Experimental working draft. Not an IETF submission. Not an implemented,
audited, or deployed standard. Implementations that interoperate today may break
without notice.

---

## 1. Abstract

Meshless is an application-layer protocol for discovering, authorizing, and
invoking resources across independently administered computing nodes. It
separates resource ownership, network connectivity, and delegated authority.

A resource is described by a signed descriptor, reached through an endpoint
chosen by its owner, and invoked under a short-lived, scoped grant that may be
delegated a bounded number of times. Every invocation is bound to a
single-use proof and produces a signed receipt.

Meshless operates without an Internet connection on a local network and over a
private network remotely. No blockchain, central registry, commercial account,
or particular AI agent is required. Nothing in the protocol requires that the
provider and the consumer be administered by the same party.

The protocol does not replace IP, VPNs, TLS, the Model Context Protocol, or
operating-system isolation. It is a resource access layer that runs above
whatever connectivity already exists.

## 2. Status and terminology

This document is a proposed experimental baseline. It is not an implemented or
audited standard.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals.

`MLP/1` denotes the proposed major wire version. Draft 00 is not a stable
release. Unknown major versions MUST be rejected (§18).

Terms used throughout:

| Term | Meaning |
| --- | --- |
| Resource | A capability hosted by a provider and identified by a resource ID. |
| Descriptor | A signed statement describing a resource: who owns it, who serves it, where it is, and which actions exist. |
| Grant | A signed, scoped, expiring authorization for one subject to invoke named actions on one resource. |
| Proof | A single-use, request-bound signature demonstrating possession of a subject key. |
| Receipt | A provider-signed record of one invocation and its outcome. |
| Chain | An ordered list of grants from a root grant to a leaf grant, inclusive. |

## 3. Goals and non-goals

### 3.1 Goals

1. Owner-controlled resources. The owner decides who may do what, for how long,
   and retains the ability to withdraw that authority.
2. Least privilege. Authority is expressed as an explicit set of actions on one
   resource with explicit hard limits, never as ambient access.
3. Portable identity. Principals are cryptographic keys, not accounts held by an
   intermediary.
4. Explicit delegation. Authority may be narrowed and passed on, but never
   widened.
5. Transport independence. The same identifiers, grants, and semantics apply
   over direct HTTPS on a LAN, over a private network, or over a future
   transport profile.
6. Local-first operation. A resource on the local network is usable with no
   Internet connection and no external service.
7. Verifiable invocation records. Consumers receive provider-signed receipts
   that bind a request to an outcome.
8. Interoperability. Existing applications, including MCP servers, can be
   exposed as resources without modification.

### 3.2 Non-goals

Meshless explicitly does not and does not claim to:

- replace IP, TLS, VPNs, overlay networks, or routing;
- replace the Model Context Protocol, identity providers, or authorization
  servers that already own a domain of authority;
- provide consensus, settlement, payment, or token issuance;
- provide operating-system or hardware isolation between resources;
- guarantee availability, latency, correctness of remote computation, or
  deletion of data already disclosed to a provider;
- provide anonymity to any party;
- hide inputs from the provider that executes them;
- authorize remote physical actuation (§16).

## 4. Roles and trust

A **principal** is a human, organization, device, or agent represented by a
cryptographic key pair.

- A **provider** hosts a resource and enforces policy on every invocation.
- A **consumer** invokes a resource on behalf of a principal.
- An **owner** controls the root authority over a resource ID.
- A **directory** distributes signed descriptors. It cannot grant authority.
- A **relay** forwards traffic. It cannot authorize resource access.
- A **transport adapter** establishes connectivity. It cannot authorize
  resource access.

Roles MAY coexist on one node. A provider is commonly also a consumer of other
resources.

Trust rules:

1. Providers MUST authenticate an owner during enrollment using an
   independently trusted channel (§6.2). Enrollment establishes which key is
   the root authority for a resource ID.
2. Possession of a key proves control of that key. It does not prove a legal
   identity, membership in an organization, or intent.
3. Unknown keys MUST NOT be trusted solely because they self-sign. A key
   presented inside a signed object is only as trustworthy as the signer of
   that object and the enrollment decision behind it.
4. Network access and resource access are independently enforced. Reaching an
   endpoint grants nothing.
5. A directory, relay, or adapter that is compromised MUST NOT be able to cause
   a grant to be widened or replayed. Compromise of these components is
   assumed in §16, not excluded.

## 5. Mandatory interoperability profile

### 5.1 MLP/1-HTTP

An implementation MUST support the following profile before claiming baseline
interoperability:

| Element | Requirement |
| --- | --- |
| Transport | HTTP over TLS 1.3 [RFC 8446] |
| Encoding | UTF-8 JSON [RFC 8259] |
| Signature | Compact JWS [RFC 7515] with EdDSA over Ed25519 [RFC 8037] |
| Canonicalization | RFC 8785 JSON Canonicalization Scheme [RFC 8785] |
| Identifier hash | SHA-256 |
| Base64url | RFC 4648 §5, unpadded |
| Time | Integer Unix seconds |

TLS certificates MUST be validated against an explicitly configured trust
anchor: a public CA root, a private CA, or a pinned certificate enrolled for
that provider. There MUST be no insecure fallback, no "proceed anyway" path,
and no plaintext mode. A private VPN or overlay network alone is insufficient;
it does not remove the TLS requirement.

TLS termination MUST occur at a trusted provider boundary. An untrusted relay
MUST NOT terminate application TLS. A relay that terminates TLS is, for the
purposes of this protocol, the provider.

### 5.2 Non-mandatory profiles

QUIC transport, libp2p transports, CBOR encoding, alternative signature
algorithms, and payload encryption are future profiles. They are not required
for baseline interoperability and MUST NOT be assumed present. Section 18
governs their addition.

## 6. Identity, keys, and enrollment

### 6.1 Key identifiers

A key identifier is the string:

```
mlp:key:<thumbprint>
```

where `<thumbprint>` is the base64url encoding, without padding, of the
SHA-256 digest of the RFC 8785 canonical form of the public Ed25519 JWK
containing exactly the members `crv`, `kty`, and `x` [RFC 7638]. For Ed25519
the JWK is `{"crv":"Ed25519","kty":"OKP","x":"<base64url public key>"}`.

Example: `mlp:key:z6Mk...` is not produced by this construction; identifiers
are 43 base64url characters after the prefix, e.g. `mlp:key:7Xk9...`.

Key identifiers are stable and are used as `iss`, `sub`, `aud`, and `kid`
values. A key identifier MUST be recomputed from the public key and MUST be
compared as a byte string.

### 6.2 Public key distribution

JWS objects carry a key identifier, not a key. To make delegation chains
verifiable without a directory, MLP/1 defines these carriers:

1. A **descriptor** MUST include `owner_jwk` and `provider_jwk`, the public
   Ed25519 JWKs of the owner and the provider. `iss` MUST equal the key
   identifier of `owner_jwk`; `provider` MUST equal that of `provider_jwk`.
2. A **grant** MUST include `sub_jwk`, the subject's public Ed25519 JWK, and
   `sub` MUST equal that JWK's key identifier.
3. A **verifier** MUST recompute the thumbprint of any embedded JWK and MUST
   reject the object if it does not match the referenced key identifier.

`owner_jwk` is required because a key identifier is a hash and cannot
reconstruct the key it names. Without it, a descriptor received as a file or a
QR code could not be checked by a party that had not already enrolled the
owner, and the descriptor exchange paths in §8 would be unimplementable. The
resource ID still binds the key: an attacker who substitutes `owner_jwk`
changes the thumbprint, which no longer matches the owner component of `rid`.

Consequently, a leaf subject's key is learned from the leaf grant, and a
provider's signing key is learned from the descriptor that authorizes it. No
online key lookup is required. Embedding keys also bounds the trust placed in
any key distribution channel: a directory that substitutes a key changes the
thumbprint and invalidates the object.

An **enrollment record** binds a resource ID to an owner root key and a
provider key, recorded by the provider through a trusted channel. Enrollment
records and revocation records MUST be persisted across restarts.

### 6.3 JWS headers

Every MLP/1 JWS object is in compact serialization, and its protected header
MUST contain:

- `alg`: the string `EdDSA`;
- `kid`: the signer's key identifier, equal to the payload's `iss`;
- `typ`: the media type for the object (`mlp-resource+jwt`,
  `mlp-grant+jwt`, `mlp-proof+jwt`, or `mlp-receipt+jwt`).

The protected header MUST contain exactly these three members and no others. A
verifier MUST reject a header that carries any additional member, including
`jwk`, `jku`, `x5u`, `x5c`, `crit`, `cty`, or `b64`, whose `alg` is anything
other than `EdDSA`, whose `typ` is not the expected value, or whose `kid` does
not equal `iss`. Verifiers MUST NOT fetch key material from a URL named in a
signed object.

A closed header is cheap and removes a class of attack: there is no
key-selection member for a verifier to consult, no payload-processing flag to
invert, and no extension point that could change what the signature covers.

### 6.4 Enrollment procedure

Enrollment is out of band with respect to this protocol. A conforming
implementation MUST provide some procedure by which:

1. the owner presents its root public key to the provider over an independently
   trusted channel (local presence, an operator command, a signed enrollment
   bundle delivered in person, or an organizational identity system);
2. the provider records the binding of resource ID to owner key;
3. the owner learns and records the provider's key identifier from the
   enrollment, so that the first descriptor it accepts is not merely
   self-asserted.

Enrollment is a human decision. Implementations SHOULD require an explicit
confirmation showing the full key identifier and resource ID, SHOULD render
thumbprints in groups of four characters for comparison, and SHOULD support
revocation of an enrollment.

### 6.5 Key management

- Agent keys SHOULD be distinct from human keys. An agent's key SHOULD live in
  OS-backed secure storage (Keychain, DPAPI, TPM, secure enclave) and SHOULD be
  marked non-exportable where the platform allows.
- Key rotation requires re-enrollment in Draft 00. There is no in-band rotation
  message. A rotated key is a new key identifier and therefore a new subject.
- On suspected compromise the owner MUST revoke outstanding grants (§11, §14),
  MUST revoke the enrollment if the root key is affected, and MUST re-enroll
  with a new key. Revocation of a key does not retroactively invalidate
  receipts or already-disclosed data.
- Private keys MUST NOT appear in descriptors, grants, proofs, receipts, logs,
  process arguments, or agent prompts.

## 7. Resource identifiers and descriptors

### 7.1 Resource identifiers

A resource ID is:

```
mlp:res:<owner-thumbprint>:<uuid>
```

where `<owner-thumbprint>` is the owner's key identifier without the
`mlp:key:` prefix, and `<uuid>` is a lowercase RFC 9562 UUIDv4 in
8-4-4-4-12 form [RFC 9562].

Resource IDs are stable across endpoint changes, provider restarts, and
transport changes. A resource ID identifies an *authorization domain*: the
owner and the resource. It does NOT identify a host, address, or process, and
MUST NOT be used as a network locator.

A consumer MUST verify that the `<owner-thumbprint>` component equals the
thumbprint of the descriptor `iss`, and MUST reject the descriptor otherwise.

### 7.2 Descriptor claims

A descriptor is a compact JWS with `typ` `mlp-resource+jwt`, signed by the
resource owner. Its payload MUST contain:

| Claim | Type | Semantics |
| --- | --- | --- |
| `v` | integer | Protocol version. MUST be `1`. |
| `rid` | string | Resource ID (§7.1). |
| `iss` | string | Owner key identifier. MUST be the signer. |
| `owner_jwk` | object | Owner public Ed25519 JWK (§6.2). |
| `provider` | string | Provider key identifier. |
| `provider_jwk` | object | Provider public Ed25519 JWK (§6.2). |
| `seq` | integer | Nonnegative safe integer, monotonically increasing per `rid`. |
| `iat` | integer | Issuance time. |
| `exp` | integer | Expiry time. MUST be ≤ `iat` + 86400. |
| `kind` | string | One of `inference`, `mcp`, `storage`, `sensor`, `compute`, `application`. |
| `actions` | array | Nonempty array of unique strings. Action names allowed on this resource. |
| `endpoint` | string | HTTPS origin, e.g. `https://host:8443`. No path, query, fragment, or credentials. |
| `meta` | object | OPTIONAL. Free-form, non-normative. MUST NOT contain secrets. |

Additional rules:

1. The owner MUST sign the descriptor. A provider signature is not a
   substitute; `iss` is the owner.
2. A consumer MUST reject a descriptor that is expired, not yet valid
   (`iat` in the future beyond 30 seconds of skew), whose `rid` owner component
   does not match `iss`, whose `iss` does not match the thumbprint of
   `owner_jwk`, whose `provider` does not match the thumbprint of
   `provider_jwk`, whose `endpoint` is not an `https` origin, or whose
   `actions` is empty, duplicated, or contains pattern syntax.
3. A consumer MUST maintain a high-water mark of `seq` per resource ID and MUST
   reject a descriptor whose `seq` is less than the stored mark. Equal `seq`
   with different bytes MUST be rejected.
4. Descriptor expiry MUST be no more than 24 hours after issuance. A shorter
   lifetime is RECOMMENDED for resources reachable from untrusted networks.
5. `kind` selects an action schema profile (§12). `kind` is advisory for
   routing; enforcement is by explicit action name. Unknown `kind` values MUST
   be rejected by baseline implementations.
6. `meta` MUST be treated as untrusted display data. An implementation MUST
   limit its size and MUST NOT act on it programmatically.

### 7.3 Discovery and authorization are separate

Possession of a valid descriptor conveys no authority. A descriptor states that
an owner authorizes *the existence and location* of a resource. Invocation
requires a grant (§9). An implementation MUST NOT treat successful discovery as
permission to invoke anything.

## 8. Discovery

Baseline discovery is the explicit exchange of signed descriptors over a
channel the participants already trust: a QR code, a file, a clipboard, a
local administrator, an out-of-band message, or a directory.

### 8.1 Well-known endpoint

A provider MAY expose:

```
GET /.well-known/meshless
```

This path is provisional and unregistered. The response is
`{"v":1,"descriptors":["<compact JWS>", ...]}` with
`Content-Type: application/json` and `Cache-Control: no-store`.

The endpoint MUST require a valid proof (§10) from a subject the provider has
been configured to serve, or MUST otherwise restrict access to a configured
allowlist. Public listing is opt-in, off by default, and MUST be a separate
operator decision from serving. A provider that does not wish to be discoverable
MUST return `404`, not an authentication error, so as not to confirm existence.

### 8.2 Directories

A directory MAY distribute descriptors. It is untrusted infrastructure:

1. It MUST preserve descriptor bytes. A directory that re-signs or re-encodes a
   descriptor destroys its value.
2. It SHOULD minimize metadata: no query logs keyed to identities, no
   per-subject association, no retention beyond what serving requires.
3. Consumers MUST NOT automatically connect to arbitrary discovered URLs.
   Endpoint origins MUST be approved by local policy (enrollment, allowlist, or
   explicit user action) before the first connection.
4. A directory MUST NOT be able to make a consumer reach an endpoint that
   local policy has not approved.

### 8.3 Local and optional discovery

LAN discovery (mDNS/DNS-SD), rendezvous services, and libp2p-based discovery are
optional extensions. When used:

- discovered descriptors MUST still be verified in full;
- DNS resolution and HTTP redirects MUST NOT be used to bypass egress
  restrictions;
- an implementation MUST NOT downgrade to HTTP or to an unverified TXT-record
  key when direct verification fails.

## 9. Capability grants

### 9.1 Form

A grant is a compact JWS with `typ` `mlp-grant+jwt`. Its payload MUST contain:

| Claim | Type | Semantics |
| --- | --- | --- |
| `v` | integer | MUST be `1`. |
| `jti` | string | Random UUIDv4, unique per grant. |
| `iss` | string | Issuer key identifier. |
| `sub` | string | Subject key identifier. |
| `sub_jwk` | object | Subject public Ed25519 JWK (§6.2). |
| `aud` | string | Provider key identifier. |
| `rid` | string | Resource ID. |
| `actions` | array | Nonempty array of unique action names. No wildcards. |
| `iat` | integer | Issuance time. |
| `nbf` | integer | Not-before time. MUST be ≥ `iat` and < `exp`. |
| `exp` | integer | Expiry time. MUST be ≤ `iat` + 86400. |
| `delegate` | boolean | Whether this grant may be delegated. |
| `depth` | integer | Remaining delegation depth, 0–3. |
| `limits` | object | `{calls, bytes, max_ms}`, each a positive safe integer. |
| `parent` | string or null | `null` for a root grant; otherwise the base64url SHA-256 of the exact parent compact JWS ASCII bytes. |

A grant MUST NOT contain wildcard actions, regular expressions, or action
patterns. Every action is a literal string that MUST appear in the descriptor's
`actions` array.

`delegate` MUST equal `depth > 0`. A grant with remaining depth is delegable; a
grant with no remaining depth is not. The two claims cannot disagree, so a
verifier never has to reconcile "may delegate" against "cannot delegate
further".

### 9.2 Root grants

A root grant ( `parent` = `null` ) MUST be signed by the resource owner whose key
identifier is the owner component of `rid`, and MUST satisfy:

- `aud` equals the descriptor `provider`;
- `actions` is a subset of the descriptor `actions`;
- `depth` ≤ 3;
- `delegate` is `true` if and only if `depth` > 0;
- the grant is issued while a valid descriptor for `rid` exists.

A root grant issued to a subject other than the owner's own key is the ordinary
case: the owner is granting a consumer.

### 9.3 Delegation

A child grant has a non-null `parent`. Its issuer MUST be the parent's `sub`,
and it MUST satisfy every one of:

1. `aud` equals the parent `aud` (audience is invariant under delegation).
2. `rid` equals the parent `rid`.
3. `actions` is a subset of the parent `actions`.
4. `[nbf, exp)` is contained in the parent's `[nbf, exp)`.
5. Each of `limits.calls`, `limits.bytes`, `limits.max_ms` is less than or
   equal to the corresponding parent limit.
6. The parent has `delegate` = `true`.
7. `depth` equals parent `depth` − 1.
8. `delegate` equals `depth > 0`, so a child with `depth` `0` has
   `delegate` `false`.
9. `parent` equals the base64url SHA-256 of the exact parent compact JWS ASCII
   bytes.

Rules 3, 4, and 5 are conjunctive at every hop, so a chain can only narrow. A
verifier MUST evaluate all nine rules for every link. A verifier MUST NOT
accept a chain in which any link is missing: all ancestors MUST be presented,
from root to leaf.

### 9.4 Validation requirements

A provider MUST reject a grant chain unless:

1. every signature verifies against the key identified by that object's `kid`,
   and every embedded JWK's thumbprint matches its key identifier;
2. the root grant is signed by the enrolled owner key for `rid`;
3. every delegation rule in §9.3 holds;
4. the leaf `aud` equals this provider's key identifier;
5. the leaf `rid` equals the resource being invoked;
6. the leaf `actions` is a subset of the descriptor `actions` for `rid`;
7. the current time is within every link's `[nbf, exp)`;
8. no link's `jti` is revoked, directly or by ancestor revocation;
9. the chain depth does not exceed 4 grants (root plus at most three
   delegations).

An implementation MUST reject an object containing an unknown claim that is
marked critical, and MUST reject an unsupported constraint. Unknown
non-critical claims that carry no semantics MAY be ignored, but an
implementation SHOULD record them.

### 9.5 Quota semantics

`limits` are hard aggregate ceilings, not per-request hints:

- `calls` counts admitted invocations, including invocations that later fail,
  time out, or are rejected for schema errors after admission;
- `bytes` counts application-body bytes: the UTF-8 length of the canonical form
  of the invocation's `input` object plus that of its `result` object. Headers,
  the proof, and transport framing are excluded. Measuring the canonical form
  rather than the raw request bytes makes the charge identical across
  implementations regardless of whitespace or member order;
- `max_ms` bounds a single invocation's wall-clock duration.

Quota is enforced **per link** including all ancestors. A provider MUST, for
each invocation, atomically reserve against the leaf and every ancestor, and
MUST reject the invocation if any link lacks remaining capacity. Counters MUST
be persisted across restart. Concurrent requests MUST NOT be able to overshoot
a ceiling; read-modify-write without atomicity is non-conforming.

An owner policy MAY impose stricter limits than a grant states. The effective
limit is the minimum of every applicable ceiling.

### 9.6 A grant is not a bearer credential

Possessing the bytes of a grant confers no authority. Each invocation requires a
proof signed by the current leaf subject's private key (§10) and a session
(§11). Grants are therefore safe to transport over channels that are
confidential but not necessarily trustworthy, and interception of a grant does
not permit its use.

## 10. Wire encoding and request authentication

### 10.1 JSON

Implementations MUST parse JSON strictly:

- duplicate member names MUST be rejected;
- invalid UTF-8 MUST be rejected;
- `NaN`, `Infinity`, and `-Infinity` MUST be rejected;
- integers outside the IEEE-754 safe integer range MUST be rejected;
- a top-level value that is not an object MUST be rejected where an object is
  required;
- trailing content after the value MUST be rejected.

### 10.2 Canonicalization

Signed JSON payloads MUST be serialized with RFC 8785 before signing. Object
members are sorted by UTF-16 code unit, numbers use the ECMAScript
`Number::toString` form, strings use JSON escaping, and no insignificant
whitespace is emitted.

A verifier MUST re-canonicalize the decoded payload and MUST reject the object
if the result is not byte-identical to the received payload bytes. This
prevents signature-valid but byte-different encodings from producing different
hashes for the same semantic object, which would otherwise break the `parent`
chain and the `grant_hash` binding.

Signatures are verified over the original JWS signing input
(`base64url(header) || "." || base64url(payload)`), never over a re-serialized
object.

### 10.3 Encoding details

- base64url without padding, without line breaks, canonical alphabet.
- JWS payloads in compact serialization only; no detached payloads, no
  multiple signatures, no unprotected header.
- Time values are integer Unix seconds.
- Providers MUST have a reliable clock. A provider whose clock is uncertain
  beyond a few seconds MUST reject traffic rather than serve it.
- Expired objects MUST be rejected with no grace period. A skew allowance
  applies only to proof `iat` (§10.4).

### 10.4 Proof of possession

Every authenticated request carries a proof JWS with `typ` `mlp-proof+jwt`,
signed by the leaf subject. Its payload MUST contain:

| Claim | Type | Semantics |
| --- | --- | --- |
| `v` | integer | MUST be `1`. |
| `iss` | string | Leaf subject key identifier. MUST be the signer. |
| `aud` | string | Provider key identifier. |
| `jti` | string | Random UUIDv4. |
| `iat` | integer | Signing time. |
| `nonce` | string | Nonce issued by this provider for this subject and resource. |
| `method` | string | Uppercase HTTP method. |
| `uri` | string | Exact requested origin plus path, with no query and no fragment. |
| `body_hash` | string | base64url SHA-256 of the exact request body bytes, or of the empty string when there is no body. |
| `grant_hash` | string | base64url SHA-256 of the exact leaf grant compact JWS ASCII bytes, or the empty string for owner-only operations (§11.6). |

The provider MUST compare `iss` against the session or chain subject, `aud`
against its own key identifier, `method` and `uri` against the request exactly
as received, `body_hash` against the exact bytes received, and `grant_hash`
against the exact leaf grant. The provider MUST accept a proof only if
`|now − iat| ≤ 30` seconds. The provider MUST consume the nonce atomically and
single-use, and MUST reject a reuse with `409 replay`.

This is a Meshless proof format inspired by DPoP [RFC 9449]. It is not DPoP and
does not claim RFC 9449 compliance.

## 11. HTTP endpoints and session lifecycle

### 11.1 Common requirements

- Requests use `POST` with `Content-Type: application/json`, except the
  well-known discovery endpoint (§8.1) which uses `GET`.
- No redirects. A provider MUST NOT answer `3xx` on any MLP path, and a client
  MUST NOT follow one.
- Maximum request body is 1 MiB unless a resource profile sets a lower limit.
- Responses are JSON with `Cache-Control: no-store`.
- Requests carry `Meshless-Proof: <compact JWS>` except where noted.
- Every POST body is proof-bound via `body_hash`, so an intermediary cannot
  alter it, but it is still plaintext to the provider.
- A request without a valid proof MUST be rejected before grant evaluation, so
  that grant structure is not disclosed to unauthenticated callers.

### 11.2 `POST /mlp/v1/challenge`

Body: `{"rid": "<resource id>", "subject": "<key id>"}`

Returns `{"nonce": "<32 random bytes, base64url>", "expires_at": <unix seconds>}`.

The nonce is valid for 60 seconds from issuance, MUST be bound to that resource
and subject, and MUST be single-use. Issuance MUST be rate-limited per source
address and per subject. The endpoint is unauthenticated by design and MUST NOT
reveal whether the resource or subject exists.

### 11.3 `POST /mlp/v1/sessions`

Body: `{"chain": ["<root grant>", "<child>", ..., "<leaf>"]}`
Header: `Meshless-Proof`.

The provider validates the chain (§9.4), the descriptor, the proof binding, and
policy, then returns `{"sid": "<32 random bytes, base64url>", "expires_at": <unix seconds>}`.

The `sid` is bound to the leaf key identifier and to the exact chain. Session
expiry is the earlier of the leaf grant `exp` and 15 minutes after creation.
Before issuing an `sid`, the provider MUST verify `grant_hash` equals the hash of
the leaf grant in that same request body.

### 11.4 `POST /mlp/v1/invoke`

Body:
`{"sid":"<sid>","request_id":"<uuidv4>","rid":"<rid>","action":"<action>","input":<object>}`
Header: `Meshless-Proof`, obtained with a fresh challenge.

On every invocation the provider MUST re-validate: session validity, chain
validity and expiry, revocation, action membership, quotas, input schema,
response size, and the proof bindings. Session establishment is not a
durable authorization decision.

Success returns `{"request_id":"<uuidv4>","result":<object>,"receipt":"<compact JWS>"}`.

### 11.5 `POST /mlp/v1/sessions/close`

Body: `{"sid":"<sid>"}`. A fresh proof is required.

Invalidates the session and cancels cancellable work. Returns
`{"closed": true}`.

### 11.6 `POST /mlp/v1/revoke`

Body: `{"rid":"<rid>","jti":"<grant jti>"}`
Header: `Meshless-Proof` signed by the enrolled owner, with `grant_hash` set to
the empty string.

The provider MUST persist the revocation **before** returning
`{"revoked": true}`. Revocation of an ancestor invalidates all descendants.
Revocation is by `jti` and therefore applies to exactly one grant in the chain.

An owner MAY additionally revoke every grant for a resource by disabling the
resource locally, and MAY revoke an enrollment (§6.4). Owner control MUST remain
available independently of any consumer session and without network access to
any third party.

### 11.7 Binding rules for proofs

| Operation | `nonce` subject | `grant_hash` |
| --- | --- | --- |
| sessions | leaf subject | leaf grant hash |
| invoke | leaf subject | leaf grant hash |
| close | leaf subject | leaf grant hash |
| revoke | owner | empty string |
| discovery | requesting subject | empty string |

The provider MUST reject a reused nonce, a nonce bound to a different subject
or resource, a proof for a different method or URI, and a body whose hash does
not match. A session identifier alone confers no authority; an `sid` presented
without a valid proof is an unauthenticated request.

## 12. Invocation and receipts

### 12.1 Processing

For each invocation the provider MUST, in order:

1. authenticate the proof and consume the nonce;
2. resolve the session and re-validate the chain and revocation state;
3. confirm the action is in the leaf grant;
4. validate the input against the action schema for the resource `kind`;
5. reserve quota atomically across the chain;
6. invoke the handler under a timeout and a response byte limit;
7. record the outcome, emit a receipt, and return.

The handler MUST run with least privilege relative to the provider: it MUST NOT
be able to reach resources the provider has not explicitly granted to it.
Implementations SHOULD sandbox handlers and MUST NOT grant a handler ambient
network or filesystem access by default.

### 12.2 Baseline action schemas

**`kind: inference`** — action `infer`
Input `{"prompt": string, "max_tokens": positive integer}`.
Result `{"text": string}`.
A provider MAY impose lower maximums than the request and MUST reject
`max_tokens` above its own ceiling with 400 `invalid_request`.

**`kind: mcp`** — actions `tools.list` and `tools.call`
- `tools.list` input `{}`, result `{"tools": [{"name": string, "description"?: string}]}`
- `tools.call` input `{"name": string, "arguments": object}`, result `{"content": <object>}`

A provider MUST enforce a separate, explicit tool allowlist and MUST validate
arguments against the tool's schema. Upstream MCP lifecycle and version
negotiation are the provider's responsibility. A grant for `tools.call` MUST
NOT expose any tool outside the allowlist, and an allowlist MUST NOT be
derivable from a grant.

**`kind: storage`, `sensor`, `compute`, `application`** require separately
specified, versioned action schemas. Draft 00 does not define them. An
implementation that exposes these kinds MUST publish its schema and MUST NOT
invent schema semantics that collide with a future revision.

No provider MUST forward arbitrary URLs, shell commands, filesystem paths, or
headers supplied by a consumer. Streaming and asynchronous jobs are deferred to
a future profile.

### 12.3 Idempotency

A provider MUST deduplicate `request_id` per resource per leaf subject until the
leaf grant expires, rejecting a repeat with `409 duplicate_request` instead of
executing twice. Rejecting a duplicate is preferred to returning the previous
result, because a cached result may be indistinguishable from a fresh one to
the caller.

A crash after dispatch may leave the outcome unknown. MLP/1 makes no
exactly-once claim and MUST NOT be described as providing one.

### 12.4 Receipts

A receipt is a compact JWS with `typ` `mlp-receipt+jwt`, signed by the
provider, containing:

| Claim | Semantics |
| --- | --- |
| `v` | MUST be `1`. |
| `rid` | Resource ID. |
| `iss` | Provider key identifier. |
| `sub` | Leaf subject key identifier. |
| `jti` | Leaf grant `jti`. |
| `request_id` | The invocation's `request_id`. |
| `action` | Action invoked. |
| `iat` | Completion time. |
| `status` | `"ok"` or `"error"`. |
| `request_hash` | base64url SHA-256 of the RFC 8785 canonical form of the input object. |
| `result_hash` | base64url SHA-256 of the canonical form of the result object, or `null` on failure. |
| `usage` | `{"calls":1,"bytes":n,"elapsed_ms":n}`. |

Receipts attest that a provider reports having executed an invocation. They do
not attest intent, correctness, or that the reported work happened.

Receipts MUST NOT contain prompts, tool arguments, results, credentials, or
internal addresses. A client MUST verify the receipt signature against the
provider key it learned from the descriptor, and MUST verify `rid`, `sub`,
`jti`, and `request_id` bindings before treating a receipt as authentic.

## 13. Errors

Errors are returned as `{"error": {"code": ..., "message": ..., "request_id"?: ...}}`.

| HTTP | `code` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, schema violation, bad parameters. |
| 401 | `invalid_proof` | Proof missing, malformed, mis-bound, stale, or badly signed. |
| 401 | `invalid_grant` | Chain invalid, expired, revoked, or chain/session mismatch. |
| 403 | `denied` | Authenticated but not permitted. |
| 403 | `revoked` | Grant or enrollment revoked. |
| 404 | `unknown_resource` | Also returned for a resource concealed from this caller. |
| 409 | `replay` | Nonce already consumed. |
| 409 | `duplicate_request` | `request_id` already processed. |
| 413 | `too_large` | Body or response exceeds a limit. |
| 429 | `quota_exceeded` | A grant or owner limit is exhausted. |
| 503 | `unavailable` | Transient provider unavailability. |
| 504 | `deadline_exceeded` | Handler exceeded `max_ms`. |

Error messages MUST NOT expose credentials, internal addresses, stack traces,
or the existence of a resource to a party not authorized to learn it. Returning
`404 unknown_resource` where a caller lacks authority is RECOMMENDED over
`403`, except where the caller is authenticated for that resource.

Clients SHOULD retry transient failures with bounded exponential backoff and
jitter. A client MUST NOT automatically retry an invocation whose execution
outcome is unknown under a new `request_id`; retry requires the same
`request_id` and an explicit decision by the caller.

## 14. Revocation and offline behavior

The provider is the authoritative enforcement point. It MUST check locally
persisted revocation and expiry before each invocation and SHOULD cancel active
work when a grant is revoked.

A remote owner cannot guarantee immediate revocation while disconnected from the
provider. Local policy MAY require online freshness checks or shorter leases for
sensitive resources. Implementations MUST NOT describe revocation as globally
immediate; the honest guarantee is "no new invocation is admitted after the
provider learns of the revocation".

Local operation on a LAN or on the same device requires no Internet, but still
requires valid credentials, a correct clock, and trusted TLS. Offline operation
MUST NOT bypass policy, MUST NOT silently route private data to a cloud service,
and MUST NOT fall back to a weaker transport.

After a disconnect, reconnection requires fresh session establishment. Queued
side-effecting operations require renewed approval by the person or policy that
authorized them. Data already disclosed to a provider cannot be recalled by
revocation.

## 15. Transport adapter contract

This section is an implementation API contract, not a wire protocol.

An adapter implements:

```
connect(endpoint, policy) -> connection
status() -> {state, endpoint, detail}
disconnect() -> void
provision(plan) -> result        // optional
```

`policy` includes allowed destinations, an egress allowlist, and an explicit
user-approval requirement for network changes. Adapters MUST:

1. preserve TLS validation end to end (§5.1);
2. report failure rather than degrade;
3. avoid silent public fallback from a private or local path;
4. keep provisioning credentials outside grants, proofs, and agent prompts.

Direct HTTPS on a LAN or an existing private network is the baseline adapter
and requires no extra component. A provider's access control remains mandatory
regardless of which adapter carried the request; a "trusted network" is not an
authorization mechanism.

A `doxx.net` adapter may provision tunnels, DNS, and firewall policy through
that service's documented APIs with dedicated credentials. Compatibility with
doxx.net MUST NOT be claimed before it has been tested and reported (§17).

## 16. Security and privacy considerations

### 16.1 Threats in scope

Stolen keys, malicious consumers, malicious providers, compromised
directories, compromised relays, replay, SSRF through descriptors or redirects,
quota races, prompt injection against agent consumers, tool misuse, metadata
leakage, and denial of service.

### 16.2 Mitigations

Key-bound proofs; short leases; explicit enrollment; signed descriptors with
owner-bound resource IDs; TLS 1.3 with an explicit trust anchor; single-use
nonces; strict body and URI binding; strict JSON parsing and canonicalization;
per-resource isolation; egress allowlists on handlers; atomic quota; rate
limits; minimal logs.

Implementations MUST reject algorithm confusion (`none`, HMAC-with-public-key,
key-type substitution), keys fetched from signed URLs, and unknown critical
headers.

### 16.3 Non-claims

Providers see plaintext inputs and outputs. MLP/1 does not provide confidential
computing, zero-knowledge execution, or end-to-end encryption of resource
payloads, and MUST NOT be described as providing them without a separate
verified profile. Relays observe metadata even when they cannot read content.
Revocation cannot recall disclosed data.

### 16.4 Physical actuation

There is no remote physical actuation in the baseline. Robotics telemetry is
read-only. A future actuation profile requires local safety interlocks, an
independent emergency stop that does not depend on the protocol path, and
hardware-level limits. Draft 00 MUST NOT be used to move, energize, or unlock
physical systems.

### 16.5 Data handling

Receipts and logs SHOULD be locally controlled with configurable retention.
Implementations SHOULD minimize what is logged: key identifiers, action names,
outcomes, and byte counts, not payloads. Identities and resource inventories
MUST NOT be published by default.

## 17. Conformance and test plan

### 17.1 Required test matrix

Consumer and provider implementations MUST pass at least:

| # | Case | Expected |
| --- | --- | --- |
| 1 | Enrolled key, valid grant | admitted |
| 2 | Unenrolled key | rejected 401 |
| 3 | Tampered JWS payload or signature | rejected 401 |
| 4 | Wrong audience, resource, or action | rejected 403/401 |
| 5 | Expired grant; not-yet-valid grant | rejected 401 |
| 6 | Nonce replay | rejected 409 |
| 7 | Body substitution after proof | rejected 401 |
| 8 | Parent hash mismatch | rejected 401 |
| 9 | Delegation escalation (wider actions, lower depth, false delegate) | rejected 401 |
| 10 | Aggregate sibling quota exhaustion | rejected 429 |
| 11 | Concurrent quota race | ceiling not exceeded |
| 12 | Revoked ancestor | rejected 403 |
| 13 | Duplicate `request_id` | rejected 409 |
| 14 | Provider restart mid-window | counters and revocations survive |
| 15 | Stale descriptor `seq` | rejected |
| 16 | Invalid TLS certificate | connection refused |
| 17 | Denied MCP tool | rejected 403 |
| 18 | Unavailable transport | reported error, no silent fallback |
| 19 | Local-only operation with no Internet | succeeds |
| 20 | Non-canonical JSON payload | rejected |

### 17.2 Test vectors

Deterministic fixtures MUST be published with the specification: fixed test
keys (never production keys), exact canonical payload bytes, signatures, and
expected outcomes. Vectors live in `test-vectors/` in this repository and are
the normative reference for signature-level interoperability.

### 17.3 Stability

Independent implementation interoperability is required before any 1.0
designation. Draft 00 does not claim interoperable independent implementations.

The repository does contain a reference implementation and the fixtures above.
They exist to make the specification falsifiable, not to define it: an
implementation that disagrees with the reference implementation and cites this
document is arguing correctly, and a reference implementation that disagrees
with this document is wrong.

## 18. Extensions and governance

Major version changes MAY break compatibility. A receiver MUST reject an
unknown major version. Optional extensions require explicit negotiation and
MUST NOT weaken any baseline check; a negotiation that would relax a check is
non-conforming.

Proposed future profiles, none required: WebAuthn enrollment, HeartBadge or
Bitcoin-anchored proofs, Trellis-backed receipts, libp2p discovery, streaming
and asynchronous invocation, remote attestation, post-quantum signatures,
metering and payments, and confidential execution.

The project maintains public proposals, a changelog, a threat model, test
vectors, and implementation reports. Code is licensed Apache-2.0 and this
specification is licensed CC BY 4.0. No IANA registrations are requested in
this draft; all names, paths, and media types are provisional.

## 19. References

**Normative**

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels —
  https://www.rfc-editor.org/rfc/rfc2119
- [RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words —
  https://www.rfc-editor.org/rfc/rfc8174
- [RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format —
  https://www.rfc-editor.org/rfc/rfc8259
- [RFC 8446] The Transport Layer Security (TLS) Protocol Version 1.3 —
  https://www.rfc-editor.org/rfc/rfc8446
- [RFC 7515] JSON Web Signature (JWS) —
  https://www.rfc-editor.org/rfc/rfc7515
- [RFC 8037] CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE —
  https://www.rfc-editor.org/rfc/rfc8037
- [RFC 7638] JSON Web Key (JWK) Thumbprint —
  https://www.rfc-editor.org/rfc/rfc7638
- [RFC 8785] JSON Canonicalization Scheme (JCS) —
  https://www.rfc-editor.org/rfc/rfc8785
- [RFC 9562] Universally Unique Identifiers (UUIDs) —
  https://www.rfc-editor.org/rfc/rfc9562
- [RFC 4648] The Base16, Base32, and Base64 Data Encodings —
  https://www.rfc-editor.org/rfc/rfc4648

**Informative**

- [RFC 9449] OAuth 2.0 Demonstrating Proof of Possession (DPoP) —
  https://www.rfc-editor.org/rfc/rfc9449
- libp2p specifications — https://github.com/libp2p/specs
- UCAN — https://ucan.xyz/
- Model Context Protocol — https://modelcontextprotocol.io/
- doxx.net Agentic Defined Network —
  https://www.doxx.net/help/features/agentic-defined-network/overview/

---

## Appendix A. Proposed doxx.net pilot (non-normative)

See `docs/doxx-pilot.md` for the expanded engineering plan. Summary: connect
two enrolled devices over a private doxx.net network; host one narrowly scoped
inference or MCP resource on one; exchange the signed descriptor; issue a
five-minute grant; invoke from the second device; then demonstrate a denied
action, revocation, and LAN operation with the external network removed. Use the
same resource ID and grant semantics on both transports. Measure setup time,
invocation overhead, revocation enforcement, and failure behavior against a
direct LAN baseline.

Do not use customer data or robot actuation. Network credentials remain in
local secret storage. Success requires recorded positive and negative results,
not a UI demonstration.

Proposed collaboration: Steadwell Labs supplies the protocol and a resource
gateway; doxx.net provides technical review and a supported connectivity
integration, subject to mutual agreement. No compatibility claim is made until
tested.

## Appendix B. Wire examples (non-normative)

`specs/examples/mcp-tools/` contains one complete two-hop invocation as files:
a descriptor, a root grant, a narrowed child grant, the request body, a proof
over that body, and a receipt, with decoded claims for each. Every byte in that
directory verifies against the clock printed in its `claims.json`.

The example is generated from `test-vectors/mlp1-draft00.json` by
`npm run examples`, so it cannot drift from the fixtures the conformance suite
uses.

## Appendix C. Changes in Draft 00

Ratified from the pre-draft working notes; recorded here rather than in
`CHANGELOG.md` because no earlier revision was published.

1. **Key distribution is now in-band and self-verifying.** Descriptors carry
   `owner_jwk` and `provider_jwk`; grants carry `sub_jwk`. Without this, a verifier could
   resolve a `kid` only by trusting a lookup it had no way to validate, and a
   grant chain could not be verified offline. See §6.2.
2. **Canonical payloads are mandatory on the wire, not just before signing.**
   Verifiers reject a payload that is not byte-identical to its canonical form.
   Otherwise two encodings of the same grant produce two `parent` hashes and
   `grant_hash` bindings for semantically identical authority.
3. **Grant actions are explicitly subsetted against the descriptor.** The
   draft constrained grants against their parent but not against the descriptor,
   so an owner could issue a grant for an action that was never declared.
4. **The audience is bound to the descriptor as well as the grant.** §9.2 and
   §9.4 now require `aud` to equal the descriptor `provider`, closing a
   grant-reuse path between providers that share a resource ID.
5. **Chain length is explicitly bounded** to four grants (root plus three
   delegations), matching the 0–3 depth range.
6. **Discovery requires a proof** and returns 404 rather than an auth error, so
   that concealment is the default.
7. **Duplicate `request_id` is rejected rather than answered from cache.**
8. **Baseline schemas for non-inference/MCP kinds are explicitly unspecified**
   rather than implied, so implementations cannot silently diverge.
