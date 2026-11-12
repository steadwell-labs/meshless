# Documentation

Non-normative. The specification in [`../specs/`](../specs/mlp-0000-core.md) is
the only normative document in this repository.

| Document | Read it when |
| --- | --- |
| [architecture.md](architecture.md) | You are reviewing or replacing a component of the reference implementation |
| [threat-model.md](threat-model.md) | You are assessing whether MLP/1 is safe for a decision, or arguing that it is not |
| [doxx-pilot.md](doxx-pilot.md) | You are running, funding, or refusing the two-device pilot |
| [faq.md](faq.md) | You want the objections answered before reading 1,000 lines of specification |
| [open-issues.md](open-issues.md) | You are about to rely on something this draft does not solve |
| [decisions/](decisions/) | You want to know why a normative rule is the way it is, or to reverse one |

## Status vocabulary

Used consistently across these documents:

| Term | Means |
| --- | --- |
| specified | required by the specification text |
| implemented | present in the reference implementation |
| self-tested | exercised by this repository's own suite, by its authors |
| independently reproduced | a second party ran the vectors and published a result |
| unverified | no evidence exists; do not rely on it |
| unverified (external) | a third party's behaviour or compatibility that has not been tested |

Nothing in this repository is "audited", "certified", "production-ready", or
"compatible with doxx.net". If a document here uses one of those words, that is
a bug.
