# 0001 — Public keys travel inside the objects that name them

**Status:** accepted · Draft 00 · 12 November 2026
**Affects:** §6.2, §7.2, §9.1, Appendix C item 1

## Problem

The pre-draft notes defined a key identifier as the base64url SHA-256 thumbprint
of a public JWK, and then used that identifier as `iss`, `sub`, `aud`, and `kid`
without saying where the key itself comes from.

A thumbprint is a one-way hash. A verifier holding `mlp:key:7Xk9…` cannot
reconstruct the key, and therefore cannot check any signature that references
it. Every verification path in the protocol dead-ends:

- A consumer receiving a descriptor as a file or a QR code could not verify the
  owner's signature.
- A provider receiving a grant chain could not verify the root unless the owner
  key happened to be in its enrollment store, and could not verify any child
  unless the intermediate's key was known.
- A consumer could not verify a receipt without a separate channel to the
  provider's key.
- A directory that substituted a key could not be detected, because there was
  nothing to compare it against.

The only escape was to mandate an online key lookup, which contradicts
local-first operation and re-introduces a central service into a protocol whose
purpose is to avoid one.

## Decision

Objects carry the public keys they reference, and every key is bound to its
identifier by recomputing the thumbprint:

| Object | Members | Binding requirement |
| --- | --- | --- |
| Descriptor | `owner_jwk`, `provider_jwk` | `iss` = thumbprint(`owner_jwk`), `provider` = thumbprint(`provider_jwk`) |
| Grant | `sub_jwk` | `sub` = thumbprint(`sub_jwk`) |

Verification becomes local and total: an implementation can verify any object
it receives, with no prior state beyond the resource ID.

## Why this is safe

The resource ID contains the owner thumbprint:

```
mlp:res:<owner-thumbprint>:<uuidv4>
```

Substituting `owner_jwk` changes the thumbprint, which no longer matches the
`rid`, so the descriptor fails before the signature is even interesting. The
`rid` is the anchor: an attacker cannot swap a key without also producing a
different resource.

This does not stop an attacker from minting a descriptor for their own resource
— `mlp:res:<their-thumbprint>:<uuid>` — because that is not an attack on an
existing resource, it is a different resource. A consumer's defence against
that is local policy: it approves owners and endpoint origins (§8.2), and it
maintains a descriptor `seq` high-water mark per resource.

Descriptors carry `owner_jwk` in addition to `provider_jwk` because the owner
key appears nowhere else. Without it, the file and QR exchange paths in §8 are
unimplementable for a party that has not already enrolled the owner.

## Consequences

- Objects are larger. A descriptor grows by roughly 100 bytes, a grant by about
  60. This is not a meaningful cost at the message sizes MLP/1 defines.
- A key identifier is now redundant with the key it names. That redundancy is
  the point: it is the check that detects substitution.
- Key rotation remains a new key identifier and therefore a re-enrollment
  (§6.5). Embedding keys does not make rotation easier, and does not claim to.
- An implementation MUST reject an embedded JWK that carries private material
  (`d`). A descriptor containing `d` is a leaked key, not a malformed message.

## Alternatives considered

1. **Enroll every consumer key at every provider.** Rejected: it turns the
   protocol into a registration system and makes third-party delegation
   impossible without the provider's cooperation.
2. **A key-resolution URL in the JWS header (`jku`).** Rejected: it hands
   signature verification to whoever controls the URL, and re-introduces an
   online dependency and an SSRF surface. §6.3 forbids it.
3. **A consistently-signed key log.** Rejected for Draft 00 as a central
   registry in all but name. It remains an open proposal for revocation
   distribution (see `docs/open-issues.md` O-1).
4. **Derive keys from the thumbprint** (e.g. a self-certifying name with a
   public key as the identifier). Rejected: it breaks the fixed-size identifier
   and the `mlp:` grammar, and gains nothing over embedding.
