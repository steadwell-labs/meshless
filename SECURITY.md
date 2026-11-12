# Security policy

## Status

Meshless Protocol Draft 00 has **not been audited**. It is a design document
with a reference implementation in progress. No implementation in this
repository should be exposed to untrusted networks or used to protect anything
that matters.

This is not boilerplate: the protocol's own threat model lists several issues
that are unsolved by design in Draft 00, including offline revocation latency,
no confidentiality of inputs from the provider, and no exactly-once invocation.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability), or email the maintainers at Steadwell Labs
with the subject line `MLP SECURITY`.

Please include:

- the specification section or component affected;
- what an attacker gains, and what they must already control;
- a minimal reproduction, a test vector, or a sequence of protocol messages;
- whether the issue is a specification defect or an implementation defect.
  These are triaged differently: a spec defect is fixed by a proposal and can
  affect every implementation.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | 3 business days |
| Initial assessment | 10 business days |
| Fix or mitigation for critical issues | 30 days where feasible |
| Public disclosure | coordinated; default 90 days after acknowledgement |

We will credit you unless you ask us not to. We will not pursue legal action
against good-faith research against your own deployment of this code.

## Scope

In scope:

- protocol defects that let a party exceed or escape a grant;
- replay, binding, or canonicalization failures;
- key substitution or thumbprint confusion;
- quota bypass, including concurrency and restart;
- SSRF reachable through descriptors, endpoints, or redirects;
- receipt forgery or misbinding;
- any path that silently weakens TLS validation.

Out of scope for Draft 00:

- absence of features the draft explicitly defers (streaming, payments,
  attestation, post-quantum signatures);
- provider seeing plaintext (a stated non-goal, not a vulnerability);
- denial of service by an owner or provider against its own resources;
- physical actuation, which the protocol excludes entirely.

## Hardening notes for early implementers

- Run gateways behind a network boundary that is not the authorization boundary.
- Pin the provider certificate in the consumer, or use a private CA. Do not rely
  on the public CA set for a LAN deployment and do not disable verification.
- Keep grant lifetimes short. The 24-hour maximum is a ceiling, not a target.
- Persist nonces, revocations, and quota counters on durable storage; an
  in-memory ledger is not conforming.
- Never log request bodies, proofs, or private keys.
- Sandbox handlers with no ambient network or filesystem access.
