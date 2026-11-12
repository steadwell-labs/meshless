# Open issues

Known gaps in MLP/1 Draft 00. Each is a deliberate deferral, not an oversight.
Implementations must not assume any of these are solved.

| # | Issue | Impact | Where |
| --- | --- | --- | --- |
| O-1 | Revocation latency is unbounded while a provider is unreachable | A revoked grant may be honoured until the provider learns of the revocation | §14 |
| O-2 | No exactly-once invocation | A crash after dispatch leaves the outcome unknown; retry may duplicate a side effect | §12.3 |
| O-3 | No payload confidentiality from the provider | The provider sees prompts, arguments, and results in plaintext | §16.3 |
| O-4 | System clock is trusted | A skewed or attacker-set clock can extend a grant's effective life; there is no trusted time source | §10.3 |
| O-5 | No streaming or long-running jobs | Invocation is one request, one response, bounded by `max_ms` | §12.2 |
| O-6 | No in-band key rotation | Rotation requires re-enrollment and a new key identifier, breaking stable subject identity | §6.5 |
| O-7 | No certificate discovery | Consumers must obtain the provider certificate out of band or trust a public CA | §5.1 |
| O-8 | Quota enforcement is only as good as the persistence layer | A provider that loses its ledger can be made to overspend; conformance requires durable counters | §9.5 |
| O-9 | No schema registry for `storage`, `sensor`, `compute`, `application` | These kinds exist but are unusable interoperably | §12.2 |
| O-10 | LAN discovery is unspecified | mDNS/DNS-SD is mentioned but not profiled, so LAN auto-discovery will not interoperate | §8.3 |
| O-11 | Delegation has no confinement to a purpose | A delegate can use the full action set of its grant within any session, for any reason | §9.3 |
| O-12 | No proof-of-absence or unlinkability | A colluding provider and directory can correlate a subject across resources | §8.2 |
| O-13 | Errors leak a timing side channel on concealment | 404 is returned after proof verification, so response time may distinguish unknown from concealed | §13 |
| O-14 | No post-quantum path | Ed25519 is the only suite; no hybrid option is defined | §18 |
| O-15 | Physical actuation is excluded but not mechanically prevented | A provider could expose an actuation action as `application`; the protocol cannot stop it | §16.4 |
| O-16 | No delivery path for a failed-invocation receipt | §12.4 defines `status: "error"` and a null `result_hash`, but the HTTP profile returns an error object instead, so a caller has no signed record of a failure it was charged for | §12.4, §13 |
| O-17 | Provider is assumed to be a single process | Atomic quota and nonce consumption are required but unspecified across replicas; a file-backed ledger cannot satisfy them across processes | §9.5 |

## How these are handled

Issues O-1 through O-5 are the ones most likely to be hit by an early adopter.
O-16 and O-17 were found while building the reference implementation: the first
means a caller cannot prove it was charged for work that failed, the second means
a horizontally scaled provider is not conforming and the draft does not say so.
O-1 and O-2 are properties of any design without a consensus or transaction
layer, and should be documented in integrator guidance rather than fixed in the
protocol. O-3 and O-14 need a future profile. O-9 and O-10 need a working
implementation before they can be specified honestly.
