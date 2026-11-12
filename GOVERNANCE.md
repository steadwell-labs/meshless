# Governance

## Current state

Meshless is a **Benevolent Dictator for Now** project. Steadwell Labs holds
editorial control of the specification and merge rights in this repository.
That is appropriate for a draft where the wire format is still changing weekly,
and it is not intended to be permanent.

## What is decided how

| Decision | Process |
| --- | --- |
| Typo, clarity, non-normative docs | Pull request, one maintainer review |
| Reference implementation change with no wire impact | Pull request, one maintainer review |
| Normative change (claims, endpoints, hashes, MUST/SHOULD) | Issue → proposal → decision record → spec + vectors + tests together |
| New optional profile | Proposal with a working implementation behind it |
| Breaking change to MLP/1 | Not permitted; this is what MLP/2 is for |
| Licensing change | Requires public discussion and unanimous maintainer support |

## Deviation policy

Independent implementations are the point. If your implementation cannot follow
a normative sentence, file an issue with the reason. A specification that only
one implementation can satisfy is a specification that is wrong.

## Toward independence

The intended path, stated now so that it can be held to later:

1. **Draft 00 (now).** Single editor. Reference implementation in progress.
2. **Draft 01.** At least two independent implementations passing shared test
   vectors. Public changelog and issue tracker. Normative changes require a
   decision record.
3. **1.0.** At least two independent, interoperable implementations; a published
   threat model; an external review of the conformance suite; a documented
   compatibility policy with a deprecation window of at least one minor version.
4. **Foundation or standards body.** If the protocol is adopted, editorial
   control should move to a neutral venue. The licence (CC BY 4.0) already
   permits that, and the trademark policy is deliberately narrow so it does not
   obstruct it.

## Activity and continuity

Steadwell Labs funds the initial work and there is no foundation, grant, or
membership model. If the project is abandoned, the specification and this
repository remain available under their licences and may be forked; the
trademark policy does not restrict forking under a different name.

## Contacts

Open an issue for anything public. For conduct or security, see
`CODE_OF_CONDUCT.md` and `SECURITY.md`.
