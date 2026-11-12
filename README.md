# meshless.

**Relay access, not ownership.**

The internet connected computers. Meshless connects their capabilities.

Meshless is an open, transport-agnostic protocol for discovering, authorizing,
and accessing distributed computing resources without surrendering ownership of
the underlying infrastructure.

From personal computers and edge devices to AI models, memory systems, robotics,
and private application services, Meshless provides a common framework for making
resources available through cryptographically verifiable, permissioned access.

Rather than requiring applications to depend on centralized infrastructure,
Meshless enables independently owned systems to cooperate across local and remote
networks.

Meshless is not a VPN, a cloud provider, or a new blockchain. It is a resource
access protocol designed to operate above existing networking infrastructure.

- **Specification:** [`specs/mlp-0000-core.md`](specs/mlp-0000-core.md)
- **Website:** [meshless.network](https://meshless.network)
- **Protocol identifier:** `MLP/1`
- **Version:** Draft 00
- **Status:** experimental, pre-implementation, not audited

> Draft 00 is a design document with a reference implementation in progress. It
> is not a standard, not deployed, and not safe for production use.

## The idea in one exchange

1. An **owner** enrolls a root public key with a **provider** and publishes a
   signed **descriptor**: this resource exists, this is the provider that serves
   it, these are the actions it supports.
2. The owner issues a **grant**: this subject may call these actions, at most
   this many times, this many bytes, for this long. Authority can be delegated,
   but only narrower.
3. The consumer obtains a **nonce**, proves possession of its key over the exact
   request, and **invokes**. The provider re-checks everything, every time.
4. The provider returns a signed **receipt** binding that request to that
   outcome.

Nothing in that sequence requires the two sides to share a cloud account, a
network vendor, a blockchain, or an AI platform. It works on a LAN with the
Internet unplugged.

## Design principles

- **Ownership remains with the owner.** Access to a resource does not imply
  ownership of the resource.
- **Local-first.** Internet connectivity is a capability, not a prerequisite for
  local operation.
- **Transport-agnostic.** Resources can be accessed through compatible private
  networks, peer-to-peer transports, or local connections.
- **Capability-based.** Authorization is explicit, scoped, verifiable, and
  revocable.
- **Agent-native.** Humans and autonomous agents participate through common
  protocol interfaces.
- **Open by design.** No mandatory vendor, membership, blockchain, or
  centralized registry.

## What Meshless is not

| Not | Because |
| --- | --- |
| A VPN or overlay network | It runs above connectivity and does not replace it. Network access is not authorization. |
| A cloud provider | There is no central service in the path. Descriptors can be exchanged as files. |
| A blockchain | No consensus, no tokens, no settlement. |
| MCP | MCP describes how a model calls a tool. Meshless describes who may reach which resource, for how long, with what limits, and how to prove it. An MCP server is a natural Meshless resource. |
| OAuth | There is no authorization server and no account. Authority is delegated by signature, holder to holder. |
| A security product | Draft 00 is a protocol design. It does not yet have an audit. |

## Repository layout

```
specs/            normative specification and wire examples
docs/             architecture, threat model, pilot plan, FAQ, decisions
packages/core     protocol primitives: canonical JSON, JWS, IDs, grants, proofs
packages/gateway  provider: HTTP endpoints, policy, quotas, receipts
packages/client   consumer: sessions, invocation, receipt verification
packages/transports  transport adapter contract and baseline adapters
packages/cli      `mlp` command line tool
test-vectors/     deterministic fixtures with fixed test keys
tests/            conformance suite
website/          static site for meshless.network
```

## Try the protocol

Requires Node.js 22.18+ (no runtime dependencies, no build step for the
library):

```sh
npm test                          # 75 tests: unit, conformance over TLS, vectors
node packages/cli/src/mlp.ts --help
node packages/cli/src/mlp.ts demo # the whole exchange in one process
npm run vectors                   # regenerate test-vectors/
npm run site                      # regenerate the specification page
```

## Status and roadmap

| Release | Objective | State |
| --- | --- | --- |
| `v0.0.1` | Founding specification, README, website | complete |
| `v0.1.0` | Reference implementation, local resource sharing | implemented, self-tested |
| `v0.2.0` | Experimental doxx.net transport integration | not started |

"Self-tested" is the honest word. The reference implementation passes the
conformance suite in `tests/`, and nobody else has run it. No independent
implementation has reproduced the vectors, and the protocol has had no security
review. See [`website/implementations`](website/implementations/index.html) for
the claim this project is willing to make in public.

Known gaps are tracked in [`docs/open-issues.md`](docs/open-issues.md).

## Contributing and security

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). This is a draft intended for
interoperability review; the most valuable contribution right now is a
disagreement with a normative sentence, filed as an issue with a concrete
failure case.

Report vulnerabilities per [`SECURITY.md`](SECURITY.md) — privately, not in a
public issue.

## License

Code: [Apache-2.0](LICENSE). Specification: [CC BY 4.0](LICENSE-SPEC).

Meshless is an open initiative originating at Steadwell Labs, independent of any
particular hardware, network provider, or AI platform.
