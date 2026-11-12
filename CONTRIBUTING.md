# Contributing to Meshless

Thanks for looking. Meshless is a draft protocol, which means the most useful
contribution right now is not code — it is a well-argued objection.

## The most valuable contributions, in order

1. **A normative sentence you think is wrong**, filed as an issue with the
   concrete failure it permits or the interoperability it breaks.
2. **An independent implementation** of MLP/1 in any language, even partial.
   Two implementations that disagree are how the spec gets correct.
3. **A conformance test** that the reference implementation fails.
4. **A security review** of a specific section, with a threat and a sequence of
   steps.
5. **Documentation** that is wrong, unclear, or missing.
6. **Code** in the reference implementation.

## Before you open a pull request

- For anything normative (a MUST/SHOULD change, a new claim, a new endpoint, a
  changed hash domain), open an issue first. A pull request that changes the
  wire format without discussion will be closed, not because it is wrong but
  because a protocol has costs that a diff does not show.
- Keep changes scoped. One concern per pull request.
- Every normative change must update: the spec section, the changelog entry, the
  affected test vectors, and any conformance test that covers it.
- Code must pass `npm test` and `npm run typecheck`.
- Do not add runtime dependencies to `packages/core`. The reference
  implementation is intentionally dependency-free so that it can be read,
  audited, and run anywhere. If you believe a dependency is unavoidable, open an
  issue explaining why before writing code.

## Proposals

Substantial design changes use the proposal process:

1. Open an issue titled `proposal: <short name>`.
2. Describe the problem, the failure mode it causes today, at least two options,
   and the interoperability cost of each.
3. If accepted, add `docs/decisions/NNNN-<slug>.md` recording the decision, the
   alternatives, and the reasoning.

Decisions already made are recorded in `docs/decisions/` and in Appendix C of
the specification. Read those before proposing to reverse one.

## Commit messages

Conventional commits, imperative mood:

```
spec: bound chain length to four grants
core: reject non-canonical JWS payloads
gateway: persist quota counters across restart
docs: expand doxx.net pilot measurements
```

## Sign-off

By contributing you agree your contribution is licensed under Apache-2.0 for
code and CC BY 4.0 for specification text, and that you have the right to
contribute it. Add a `Signed-off-by:` trailer to your commits
(`git commit -s`).

## Code of conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Technical disagreement is
welcome and expected. Contempt is not.

## Security

Do not open a public issue for a vulnerability. See [`SECURITY.md`](SECURITY.md).
