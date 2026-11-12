# Changelog

All notable changes to the specification and reference implementation.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The specification uses `MLP/1` as its wire version; drafts within a major
version may change without a version bump, which is why this file exists.

## [Unreleased]

### Added

- Founding specification `specs/mlp-0000-core.md` (MLP/1, Draft 00).
- Reference implementation, dependency-free and runnable without a build step:
  - `packages/core` — strict JSON, RFC 8785 canonicalization, JWS, JWK
    thumbprints, resource IDs, descriptors, grants, proofs, receipts.
  - `packages/gateway` — HTTP endpoints, persistent ledger, atomic quotas,
    receipts, TLS 1.3 server with no plaintext mode.
  - `packages/client` — sessions, proofs, receipt verification, pinned or
    CA-anchored TLS.
  - `packages/transports` — the §15 adapter contract, a working direct-HTTPS
    adapter, and an adapter that refuses rather than pretending.
  - `packages/cli` — `mlp` keygen, descriptor, grant, delegate, serve, call,
    inspect, demo, vectors.
- Conformance suite: 75 tests covering the §17.1 matrix over real TLS.
- `test-vectors/mlp1-draft00.json`: deterministic fixtures with fixed seeds and
  a fixed clock, plus five negative vectors.
- `specs/examples/mcp-tools/`: one two-hop invocation as verifiable files,
  generated from the vectors.
- `website/`: static site for meshless.network, with the specification page
  generated from the markdown by `website/build.mjs`.
- Repository foundation: README, licence split (Apache-2.0 code, CC BY 4.0
  spec), contributing, security, governance, trademark policy.
- `docs/`: architecture, threat model, doxx.net pilot plan, FAQ, decision
  records, open issues.

### Changed — Draft 00 corrections

These resolve defects in the pre-draft notes; see Appendix C of the
specification for reasoning and `docs/decisions/0001-key-distribution.md`.

- Descriptors carry `provider_jwk`; grants carry `sub_jwk`, so a chain is
  verifiable offline without a key lookup.
- Verifiers reject JWS payloads that are not byte-identical to their RFC 8785
  canonical form, so one authority cannot hash two ways.
- Grant `actions` are subsetted against the descriptor, not only against the
  parent grant.
- Grant `aud` is bound to the descriptor `provider`.
- Chain length is bounded to four grants (root plus three delegations).
- `/.well-known/meshless` requires a proof and returns 404 when undiscoverable.
- Duplicate `request_id` is rejected with 409 rather than answered from cache.
- Baseline action schemas are specified for `inference` and `mcp` only.

### Security

- Draft 00 is unaudited and must not be deployed against untrusted networks.
