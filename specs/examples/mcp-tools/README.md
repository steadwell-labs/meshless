# Wire example: one MCP invocation, two grants deep

Non-normative, but every byte here verifies. Generated from
`test-vectors/mlp1-draft00.json` by `npm run examples`.

| File | Object |
| --- | --- |
| `descriptor.jws` | `mlp-resource+jwt`, signed by the owner |
| `root-grant.jws` | `mlp-grant+jwt`, owner to agent, depth 1 |
| `child-grant.jws` | `mlp-grant+jwt`, agent to delegate, narrower |
| `proof.jws` | `mlp-proof+jwt`, over `request.json` |
| `request.json` | the exact body the proof binds |
| `receipt.jws` | `mlp-receipt+jwt`, signed by the provider |
| `claims.json` | decoded claims for every object |

Verify with the reference implementation:

```sh
node packages/cli/src/mlp.ts inspect --jws specs/examples/mcp-tools/descriptor.jws
npm test
```

The clock is fixed at `1762958400` (12 November 2026, 12:00 UTC), so the
proof and receipts verify only against that time. That is intentional: an
example whose validity depends on when you read it is not a fixture.
