# 0002 — Unknown claims are rejected, not ignored

**Status:** accepted · Draft 00 · 12 November 2026
**Affects:** §9.4, §10.4, §12.4, Appendix C

## Problem

§9.4 requires an implementation to reject an object containing an *unknown
critical claim*, which is the standard JOSE/extensibility posture (RFC 7515
§4.1.11, via `crit`). But MLP/1 payloads have no `crit` member: there is no way
for an issuer to mark a claim as critical, and no way for a verifier to
distinguish "this claim is decoration" from "this claim is a constraint I must
enforce".

The result is a silent security failure. Suppose a future revision adds a
grant claim `network_allow` meaning "this grant may only be used from a listed
source network". An old verifier that ignores unknown claims accepts the grant
and ignores the restriction — it enforces less authority than the issuer
intended, which is exactly the wrong direction. Contrarily, an old verifier
that rejects all unknown claims refuses every object from a newer
implementation, which is safe but impolite.

There is no correct middle. The failure mode of ignoring is a privilege
escalation; the failure mode of rejecting is a version incompatibility.

## Decision

Draft 00 rejects any unknown claim in grants, proofs, and receipts, and rejects
unknown members in `limits` and in JWS headers.

Rationale: a protocol at Draft 00 has no deployed base to break. Escalation is
the unrecoverable error and incompatibility is the recoverable one. When there
is a real deployed base and an extension mechanism with negotiation, this
decision should be revisited — with a `crit`-equivalent and a version
negotiation, not by loosening the check.

## Consequences

- Adding a claim is a major-version change (§18). That is the cost of the
  guarantee, and it is deliberate: an extension that weakens a baseline check
  is non-conforming anyway.
- The error is `invalid_grant` / `invalid_proof` with the offending member named
  in the log, not in the response.
- `meta` on a descriptor is the escape hatch for non-normative data, because it
  is defined as untrusted display data with a size cap and no semantics.

## Alternatives considered

1. **Add `crit` to MLP/1 payloads.** Rejected for Draft 00: it is a second
   extensibility mechanism to specify and test, and it does not solve the
   problem for implementations that do not understand `crit`.
2. **Ignore unknown claims and document the risk.** Rejected: it makes the
   escalation above a supported behaviour.
3. **Allow an explicit `ext` object validated by a negotiated profile.** This is
   the likely shape of the eventual answer. It needs a profile negotiation that
   Draft 00 does not have, so it is deferred rather than improvised.
