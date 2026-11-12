# doxx.net Pilot Plan

This document turns Appendix A of the Meshless Protocol specification into an executable engineering plan: two enrolled devices, one narrowly scoped resource, one five-minute grant, invoked first over a local network and then over a private doxx.net network, with recorded positive and negative results and a measured comparison against the direct-LAN baseline. It exists so that a pilot can fail honestly. It is written to be run by an engineer who did not write the protocol, and to be rejected by a reviewer who finds a step that cannot produce evidence.

**Status:** Draft 00 — non-normative, not executed  
**Plan revision:** 1  
**Applies to:** MLP/1 · Draft 00 · 12 November 2026 (`specs/mlp-0000-core.md`, Appendix A; §15)  
**Proposed by:** Steadwell Labs  
**doxx.net compatibility:** unverified. No test has been run, no integration has been reviewed by doxx.net, and no compatibility claim of any kind is made in this document.

## 0. Current state

Nothing in this plan has been executed. The repository now contains a reference
implementation and a conformance suite, which removes the first three blockers
and leaves the doxx.net path untouched. That is the honest status: the LAN half
of this plan is runnable today, and the doxx.net half has no adapter, no
credentials, and no API review.

| Item required to start | State at plan revision 2 | Blocks |
| --- | --- | --- |
| Provider gateway implementation | present but unreviewed; `packages/gateway/` (HTTP endpoints, ledger, quotas, receipts) | P1 and everything after it |
| Consumer client implementation | present but unreviewed; `packages/client/`, `packages/cli/` | P1 and everything after it |
| Deterministic test vectors (§17.2) | present; `test-vectors/mlp1-draft00.json` with 5 negative vectors | P3, P4, P5, P6 |
| Conformance suite (§17.1) | present; 75 cases passing on loopback TLS | P7, P9, P10 |
| Baseline transport adapter | present; `DirectHttpsAdapter`, plus an adapter that refuses to pretend | P1, P8 |
| doxx.net network access and dedicated credentials | not obtained, unverified | P2, P8 |
| doxx.net transport adapter | not written, no API review completed, unverified | P8 |
| Certificates and trust anchors for both paths | generated per test run on loopback; not provisioned for a real LAN or tunnel | P1, P8, NT-9 |
| Independent observer (did not write the code) | not assigned | All measurement steps |
| Scheduled test window | not scheduled | Whole plan |

Three caveats that matter more than the table:

1. **Self-measurement is not evidence.** The conformance suite was written by
   the same author as the implementation. A passing suite says the code agrees
   with itself. SC-1 through SC-13 still require the independent observer in
   P0.
2. **The LAN path has been exercised only on loopback.** A loopback run proves
   the protocol objects and the TLS stack, not that a second device on a real
   LAN can reach the provider, and not that firewall policy on either device
   behaves.
3. **Nothing on the doxx.net path exists.** No adapter, no tunnel, no
   measurement. SC-2, SC-3 and SC-11 remain BLOCKED until P2 produces an
   adapter that someone can run.

The honest summary: this plan is a specification of an experiment. Half of it
can now be run, and none of it has been. Any date attached to it is a target,
not a result. Appendix A records a proposed engineering milestone of 14
November; an event listing shows 12 November. Both dates are unverified and
neither is a commitment.

## 1. Objective

Demonstrate, with recorded evidence, that one MLP/1 resource can be invoked over two different transports using identical resource identity, identical grant semantics, and identical enforcement, and that the protocol's negative guarantees hold on both paths.

That is the whole objective. The pilot is not a product demo, not a security audit, and not a performance benchmark. It is an attempt to falsify four claims:

1. A resource ID, descriptor and grant chain are portable across transports without change.
2. A provider enforces authority identically regardless of which transport carried the request.
3. Revocation, expiry and replay rejection are observable and prompt.
4. Local operation works with the external network removed, and does not silently fall back.

If any of the four is false, the pilot has succeeded at its job by finding out.

## 2. Falsifiable success criteria

Each criterion has a threshold fixed before the run, an artifact that proves it, and a binary verdict. "It worked" is not a verdict. A criterion that cannot be measured is recorded as BLOCKED, never as PASS.

Provisional thresholds marked (provisional) must be confirmed or changed in writing before the first run and must not be changed after any measurement is seen.

| ID | Criterion | Threshold | Evidence artifact | Verdict rule |
| --- | --- | --- | --- | --- |
| SC-1 | Positive invocation on the direct LAN path | 20 of 20 sequential invocations return HTTP 200 with a receipt whose signature verifies against the descriptor `provider_jwk` | Request and response log, receipt corpus, verifier output | PASS only at 20/20; any failure is FAIL with the failure attached |
| SC-2 | Positive invocation on the doxx.net path | 20 of 20, same as SC-1, through the tunnel | Same, plus transport status output | PASS at 20/20; BLOCKED if no adapter exists |
| SC-3 | Identity portability | The same `rid`, the same grant compact JWS bytes, and the same action set are accepted on both paths; the descriptors differ only in `endpoint` and `seq` | Byte comparison of grants, descriptor diff | PASS only on byte equality of the grant |
| SC-4 | Denied action | 10 of 10 attempts at an action present in the descriptor but absent from the grant return 403 `denied`; handler execution counter is unchanged | Response log plus handler counter before and after | PASS at 10/10 with zero executions |
| SC-5 | Revoked leaf grant | After the provider returns `{"revoked":true}`, 20 of 20 subsequent invocations return 403 `revoked`; the handler counter does not advance | Revoke response, invocation log, counter | PASS at 20/20 |
| SC-6 | Revoked ancestor | Revoking a parent invalidates the leaf: 20 of 20 rejected 403 `revoked` | As SC-5, using the parent `jti` | PASS at 20/20 |
| SC-7 | Expired grant | A five-minute grant accepts at T+4:00 and rejects at T+5:05 with 401 `invalid_grant` | Timestamped invocation log | PASS if both observations hold in the same run |
| SC-8 | Proof replay | Replaying a captured proof header returns 401 `invalid_proof` or 409 `replay`, and the handler counter shows exactly one execution for the original request | Captured proof, replay request, counter | PASS only at exactly one execution |
| SC-9 | Body substitution | The same proof with an altered body returns 401 `invalid_proof`; counter unchanged | Modified request, counter | PASS at 401 with zero extra executions |
| SC-10 | Bad TLS | A provider presenting a certificate outside the configured trust anchor is refused; no plaintext HTTP is sent; the client does not fall back | Client error, packet capture summary | PASS if connection fails and capture shows no cleartext request |
| SC-11 | Local-only operation | With the external network removed, 20 of 20 LAN invocations succeed | Capture on the WAN interface, invocation log | PASS at 20/20 with zero WAN packets to non-private addresses |
| SC-12 | No silent public fallback | With the LAN target down and WAN up, the client reports transport failure and attempts no public egress | Adapter status output, capture | PASS if a failure is reported and no public connection is attempted |
| SC-13 | Restart durability | Provider restart does not restore quota or un-revoke a grant; 5 of 5 post-restart invocations reflect pre-restart state | Pre and post restart state dumps | PASS at 5/5 |
| SC-14 | Invocation overhead | Added p95 latency over the direct-HTTPS no-op baseline is at most 200 ms (provisional) | Measurement CSV and analysis script | PASS if measured and within threshold; report the measured value either way |
| SC-15 | Revocation latency | From revoke response to first rejected invocation, p95 at most 5 seconds on the same host (provisional) | Timestamped loop log | PASS if measured and within threshold |
| SC-16 | Setup time | Two devices from powered-off to first successful invocation in at most 30 minutes, one operator who has done it once (provisional) | Timed run sheet, three repetitions | PASS on the median of three |
| SC-17 | No prohibited data | Review finds zero customer data, zero production keys, zero private keys in any artifact, and zero provisioning credentials outside local secret storage | Artifact review checklist | PASS only with a signed checklist |
| SC-18 | Reproducibility | A second operator can repeat P1 through P7 from the written steps without asking the author a question | Second operator's run sheet and questions log | PASS only with zero blocking questions |

A run that satisfies the positive criteria but not the negative ones is a FAILED pilot. A run that is blocked on SC-2 because no doxx.net adapter exists is recorded as BLOCKED, and the LAN results stand on their own.

## 3. What "compatible" is not allowed to mean

The word "compatible" will be used only for a recorded result in this plan. Before the run, it must not be used at all. After the run, it may describe exactly what was measured and nothing more. Specifically, none of the following is evidence of compatibility:

- A UI that shows "connected", "paired", "tunnel up", or a green indicator.
- Two devices reaching each other over a tunnel. That is connectivity, which MLP explicitly does not provide and explicitly does not authorize (§4, §15).
- A descriptor that renders in a client.
- An invocation that succeeds with certificate validation disabled, or with a trust anchor added ad hoc during the run.
- An invocation where the grant was not enforced. If the deny and revoke cases do not fail as expected, the positive cases prove nothing.
- Passing only the positive cases. Appendix A requires recorded negative results.
- A single device playing both roles. That tests nothing about transport.
- A performance number with no direct-LAN baseline measured on the same hardware in the same window.
- An integration that speaks doxx.net's provisioning API but never carries an MLP request end to end.
- Any statement that doxx.net reviewed, endorsed, certified, or supports MLP. The proposed collaboration in Appendix A is subject to mutual agreement and has not happened.
- Any claim about production readiness, security, confidentiality, availability, or exactly-once execution.

## 4. Topology

```
        +---------------------------+            +---------------------------+
        | Device A (consumer)       |            | Device B (provider)       |
        |                           |            |                           |
        | owner root key (offline)  |            | provider signing key      |
        | agent key (OS storage)    |            | TLS terminator            |
        | grant chain, descriptor   |            | policy, quota, revocation |
        | receipt verifier          |            | handler: infer or MCP     |
        +-------------+-------------+            +-------------+-------------+
                      |                                        |
       path 1         |  MLP/1-HTTP over TLS 1.3, direct       |
       (baseline)     +----------------------------------------+
                      |                                        |
       path 2         |  MLP/1-HTTP over a doxx.net tunnel     |
       (doxx.net)     +------+-------------------------+-------+
                             |                         |
                    +--------+---------+     +---------+----------+
                    | doxx.net network |     | relay (optional)   |
                    | (provisioned)    |     | forwards bytes     |
                    +------------------+     | must not terminate |
                                             | TLS (§5.1)         |
                                             +--------------------+

        control plane, both paths:
        +-------------------------------------------------------+
        | descriptor exchange: QR, file, clipboard, or directory |
        | directory cannot grant authority (§4, §8.2)            |
        +-------------------------------------------------------+
```

Both paths terminate at the same provider process on the same resource ID. The provider's `endpoint` claim differs between the two descriptors, and nothing else about the authorization material does. That is the experiment.

## 5. Participants and prerequisites

| Role | Responsibility | Prerequisite |
| --- | --- | --- |
| Pilot lead | Owns the plan, the clock, and the go/no-go decision | Has read the specification; is not the person who wrote the provider handler |
| Provider operator | Runs Device B, issues the enrollment record, watches the handler counter | Administrative access to Device B |
| Consumer operator | Runs Device A, holds the agent key | Administrative access to Device A |
| Owner (may be the same human as consumer operator) | Holds the root key, signs the descriptor and the root grant, performs revocation | Access to the root key, ideally on a separate device |
| Independent observer | Times the run, checks artifacts, may call a failure, did not write the code | A second pair of eyes and a stopwatch |
| doxx.net technical reviewer | Optional, unconfirmed. Reviews the adapter, not the protocol | Mutual agreement, not yet in place |

Hardware and software prerequisites, all of which must be recorded with versions in the run sheet:

- Two devices with a supported OS and secure storage (Keychain, DPAPI, TPM or equivalent).
- A provider certificate valid for the endpoint hostname, and a trust anchor distributed to the consumer before the first connection. Either a private CA or a pinned certificate; §5.1 permits both and forbids bypass.
- A LAN on which the two devices can reach each other with no external network.
- Clock synchronisation. Record the offset between devices before the run; a provider whose clock is uncertain must refuse traffic (§10.3).
- The implementations and their exact commit hashes. At plan revision 1 these do not exist.
- A packet capture facility on both devices, including the WAN interface.
- A handler counter that is external to the handler logic, so "it did not execute" is observable rather than asserted.
- Local secret storage for any doxx.net provisioning credential. It must never appear in a grant, a descriptor, a receipt, a prompt, a shell history, a committed file, or a screenshot.

## 6. Procedure

Steps are ordered. A step that fails stops the run at that step; continuing past a failed precondition turns later results into noise. Every step produces an artifact named in the step, and the run sheet records the timestamp, the operator, and the artifact path.

**P0. Freeze and record.** Record the specification commit, the implementation commit for each component, the OS and runtime versions, the certificate fingerprints, and the trust anchor. Write the provisional thresholds from §2 into the run sheet and initial them. No threshold may change after this step.

**P1. Baseline the LAN path.** With both devices on the LAN only, confirm the consumer can reach the provider's TLS endpoint and that the certificate validates against the recorded anchor. Confirm that the provider refuses a request with no proof. Artifact: connection log with the verified certificate chain and the expected `401 invalid_proof` response.

**P2. Provision the doxx.net path.** Using dedicated credentials held in local secret storage, provision the tunnel and any DNS or firewall policy through the service's documented APIs. Record what was provisioned, with the credential redacted. Do not yet route an MLP request through it. Artifact: transport status output showing state, endpoint, and detail. If no doxx.net adapter exists, mark P2 BLOCKED and continue with P3 through P7 on the LAN only; the run then cannot satisfy SC-2, SC-3 or SC-11 on the doxx.net path.

**P3. Generate throwaway keys.** Generate an owner root key, an agent key, and a provider key for this run only. Record all three key identifiers. Keys are never reused from another run and never leave their device except as public JWKs. Artifact: key identifier list, with a note that private keys were not copied.

**P4. Enroll the owner with the provider.** Deliver the owner's root public key to the provider over a channel that is independent of the network path under test: local presence, an operator command on Device B, or a signed bundle carried by hand. Confirm on both sides that the full key identifier and the resource ID match, comparing thumbprints in groups. Record the resulting enrollment record. Artifact: enrollment record, plus the owner's record of the provider key identifier learned during enrollment.

**P5. Publish and exchange the descriptor.** The owner signs a descriptor with a fresh `seq` of 1, a short `exp` (one hour is enough for the run), `kind` `inference`, `actions` `["infer"]`, and the LAN `endpoint`. Deliver the compact JWS to the consumer out of band. The consumer verifies the owner signature, the `rid` owner component, the `provider` to `provider_jwk` match, and the `seq` high-water mark. Artifact: descriptor bytes, verifier output, and the stored high-water mark.

**P6. Issue grants.** The owner issues a root grant to the agent key: five minutes, `actions` `["infer"]`, `limits` with `calls` 200, `bytes` 2000000, `max_ms` 5000, `delegate` true, `depth` 2. Then issue one child grant from the agent to a second throwaway agent key with `actions` `["infer"]` and `depth` 1, for the delegation tests. Record every `jti`. Artifact: both compact JWS strings, their hashes, and a chain diagram.

**P7. Invoke on the LAN.** Challenge, session, invoke. Record the challenge nonce, the `sid`, the request body, the proof header, the response, and the receipt. Verify the receipt signature against the provider key learned from the descriptor and check its `rid`, `sub`, `jti` and `request_id` bindings. Repeat 20 times for SC-1. Artifact: the 20-request log and receipt corpus.

**P8. Republish for the doxx.net path and repeat.** Sign a second descriptor with `seq` 2 and the tunnel `endpoint`, deliver it, and verify that the consumer accepts it under the `seq` rule. Reuse the identical grant bytes from P7. Run the same challenge, session, and 20 invocations. Artifact: descriptor diff showing only `endpoint` and `seq` changed, plus the second request log.

**P9. Negative suite.** Run NT-1 through NT-15 in the order given, because several depend on state created by earlier ones. Record each expected and actual response, and the handler counter before and after. Artifact: negative test matrix with verdicts.

**P10. Restart and durability.** Reserve some quota, revoke one grant, restart the provider, and re-run the affected cases. Confirm the revocation survives, the counters survive, and no rejected request becomes admitted. Artifact: pre and post restart state dumps.

**P11. Failure injection.** Kill the provider mid-invocation, remove the network mid-session, expire or replace the certificate, and revoke during an in-flight request. For each, record the client behaviour: error code, whether it retried, and whether the retry used the same `request_id` or a new one. Artifact: failure matrix. A retry with a new `request_id` after an unknown outcome is a protocol violation (§13) and is recorded as a defect, not a test failure.

**P12. Teardown.** Destroy throwaway private keys, delete the tunnel, remove the firewall policy, remove the enrollment record, and confirm that no artifact contains prohibited data. Artifact: signed teardown checklist, which is SC-17.

## 7. Negative tests

These are the cases that decide whether the pilot means anything. Each maps to a row of the conformance matrix in §17.1.

| ID | Test | Setup | Expected | Counter check |
| --- | --- | --- | --- | --- |
| NT-1 | Denied action | Invoke an action listed in the descriptor but absent from the leaf grant | 403 `denied` | unchanged |
| NT-2 | Revoked leaf | Revoke the leaf `jti`, then invoke | 403 `revoked` | unchanged |
| NT-3 | Revoked ancestor | Revoke the root `jti`, then invoke with the leaf | 403 `revoked` | unchanged |
| NT-4 | Expired grant | Wait past `exp`, then invoke | 401 `invalid_grant` | unchanged |
| NT-5 | Not yet valid | Advance the consumer clock past `nbf` disagreement, or issue a future `nbf` | 401 `invalid_grant` | unchanged |
| NT-6 | Proof replay | Capture a proof header and resend the identical request | 409 `replay` or 401 `invalid_proof` | exactly one total execution |
| NT-7 | Body substitution | Reuse the proof with a different `input` | 401 `invalid_proof` | unchanged |
| NT-8 | URI / method mismatch | Reuse the proof against a different path or method | 401 `invalid_proof` | unchanged |
| NT-9 | Bad TLS | Present a certificate outside the trust anchor, or an expired one | connection refused, no fallback | no request reaches the handler |
| NT-10 | Wrong audience | Present the grant to a provider with a different key | 401 `invalid_grant` or 403 | unchanged |
| NT-11 | Delegation escalation | Child grant with an action outside the parent | rejected at session, 401 `invalid_grant` | unchanged |
| NT-12 | Parent hash mismatch | Alter one byte of the parent, keep the child | 401 `invalid_grant` | unchanged |
| NT-13 | Duplicate `request_id` | Repeat a completed invocation with the same id | 409 `duplicate_request` | exactly one total execution |
| NT-14 | Stale descriptor | Serve a descriptor with a lower `seq` after a higher one was stored | rejected by the consumer | n/a |
| NT-15 | No silent fallback | Take the LAN target down while the WAN is up | reported transport failure, no public egress | n/a |

NT-2 through NT-5 and NT-13 need the handler counter to be trustworthy. If the counter is derived from handler logs that the handler can suppress, the test proves nothing and the criterion is BLOCKED.

## 8. Measurement plan

Each metric has one definition, one instrument, and one procedure. Where the procedure is ambiguous, the number is not a measurement.

### 8.1 Invocation overhead

**Definition.** The additional wall-clock time, client side, from "request ready to send" to "response fully parsed", for a full MLP invocation compared with a direct HTTPS POST carrying the same body to the same provider host, for an action whose handler does nothing.

**How to measure.** On Device A, use a monotonic clock and one sample per invocation. Measure two series on the same host in the same window: (a) baseline, a single HTTPS POST to a no-op endpoint on a test build of the provider that returns `200` with the same JSON shape, never exposed in a normal deployment; (b) full MLP, challenge plus session plus invoke, all three included, since a cold invocation requires all three. Take at least 200 samples per series, sequentially, after 5 warm-up calls excluded from the statistics. Report p50 and p95 for both series and the difference, and report connection setup separately from warm reuse. Do not compare across devices or across windows.

**Instrument.** Client-side timing log with one row per invocation: series, sequence number, start, end, duration, status. Analysis script in the run repository, committed with its output hash.

**Caveat.** The baseline is not a protocol overhead measure in any general sense. It measures this implementation on this hardware on this day.

### 8.2 Setup time

**Definition.** Elapsed time from "both devices powered off, no keys, no enrollment, no tunnel" to "first successful invocation", split into four phases: enrollment, descriptor exchange, grant issuance, and transport provisioning.

**How to measure.** One operator, stopwatch, three repetitions from a clean state each time. Record phase boundaries as timestamps. Report the median of the three totals and the phase breakdown for each. Any step that required consulting the author counts as a defect against SC-18, and the question is written down.

**Instrument.** Run sheet with timestamps. The second operator's sheet is the artifact that matters; the first operator's number is not a result.

### 8.3 Revocation enforcement latency

**Definition.** The interval from the timestamp of the revoke request to the timestamp of the first invocation that is rejected because of it.

**How to measure.** Start a 1 Hz invocation loop from Device A before revocation. At T0 send `POST /mlp/v1/revoke` with a fresh owner proof and wait for `{"revoked":true}`. Keep looping. The first rejection after T0 gives the latency; the last success before it confirms the loop was live. Repeat five times with a fresh grant each time, and separately for ancestor revocation and for revocation during an in-flight invocation. Both timestamps come from the same host, so no clock comparison is needed.

**Instrument.** Loop log with per-request timestamps and status codes, plus the revoke response receipt.

**Caveat.** This measures enforcement once the provider has learned. It does not measure, and must not be reported as, revocation while the owner is disconnected (§14).

### 8.4 Failure behaviour

**Definition.** What the client does when the provider or the path fails, expressed as a matrix rather than a number.

**How to measure.** For each injected failure (provider process killed mid-invocation, network removed mid-session, certificate expired, tunnel dropped, revoke during flight), record four fields: the error surfaced to the caller, the HTTP status or transport error, whether the client retried, and whether the retry reused the `request_id`. A retry with a new `request_id` after an unknown outcome is a defect against §13. A silent fallback from the private path to the public path is a defect against §15.

### 8.5 Reporting table

Every metric is reported in this form, including the runs that did not happen.

| Metric | Unit | p50 | p95 | n | Method | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| Setup time, total | minutes | not run | not run | 0 | §8.2 | BLOCKED |
| Setup time, enrollment phase | minutes | not run | not run | 0 | §8.2 | BLOCKED |
| Invocation overhead, LAN | ms | not run | not run | 0 | §8.1 | BLOCKED |
| Invocation overhead, doxx.net | ms | not run | not run | 0 | §8.1 | BLOCKED |
| Revocation latency, leaf | seconds | not run | not run | 0 | §8.3 | BLOCKED |
| Revocation latency, ancestor | seconds | not run | not run | 0 | §8.3 | BLOCKED |
| Positive invocations, LAN | count | 0/20 | n/a | 0 | §6 P7 | BLOCKED |
| Positive invocations, doxx.net | count | 0/20 | n/a | 0 | §6 P8 | BLOCKED |
| Negative cases | count | 0/15 | n/a | 0 | §7 | BLOCKED |

## 9. Abort criteria

The pilot lead stops the run, records the reason, and does not resume until the cause is fixed and re-reviewed, if any of the following occurs. These are not judgement calls.

1. Any artifact contains customer data, a real identity, or any data not generated for the test.
2. Any private key appears in a log, a prompt, a process argument, a receipt, a descriptor, a grant, or a screenshot.
3. Any doxx.net provisioning credential is found outside local secret storage, or inside a grant, descriptor, proof, prompt, or committed file.
4. A request is observed in cleartext, or the client falls back after a TLS failure.
5. Any invocation is admitted after a revocation, or after grant expiry.
6. Any grant is accepted by a provider whose key does not equal the leaf `aud`.
7. Any claim of compatibility is made in a channel outside the report, or before SC-2 and SC-3 are recorded.
8. Any instruction, script, or configuration is issued to physical hardware, or any robot is actuated, even in a test fixture.
9. The implementation under test changes during a measurement window. Freeze, restart the window.
10. The independent observer is not present for the negative suite.

An abort is a result. It is reported in the same place as a pass, with the same detail.

## 10. Data handling rules

These rules apply to every artifact, including logs, captures, screenshots, and the report itself.

- **No customer data.** Prompts are fixed synthetic strings, committed with the run, and contain no personal data. If a real model is used, the prompt and the completion are both treated as test fixtures and reviewed before retention.
- **No robot actuation.** No command in this plan moves, energizes, unlocks, or configures physical equipment. The handler is an inference or MCP resource only. This is consistent with §16.4.
- **Network credentials only in local secret storage.** The doxx.net provisioning credential lives in the OS keychain or equivalent. It is never written to a file in the repository, never exported to an environment file, never placed in a grant, descriptor, proof, receipt, or agent prompt, and never shown in a screenshot. This is the §15 requirement, not a preference.
- **Throwaway keys.** All keys are generated for the run and destroyed at teardown. If a fixture is published for §17.2, it uses its own fixed test keys and is marked as test material.
- **Capture scope.** Packet captures are limited to the LAN interface and to private address ranges, retained for 30 days, and deleted with the teardown attestation. A capture containing a public address is reviewed before retention and redacted if it is not needed.
- **Minimal logs.** Record key identifiers, action names, outcomes, and byte counts. Do not record payloads, and do not record the private key identifiers' association with a person.
- **Screenshots.** Any screenshot that shows a key identifier is acceptable because key identifiers are public; any screenshot that could show a private key or a provisioning credential is not taken.
- **Retention.** Artifacts are retained for the review period and then deleted, except the report, the metrics CSV, the negative test matrix, and the signed checklists, which are kept with the pilot record.
- **No third-party data in the report.** doxx.net is named only as the transport under test. No claim is made about their service beyond what the run measured.

## 11. Deliverables

| ID | Deliverable | Contents | Owner |
| --- | --- | --- | --- |
| D-1 | Run sheet | Per-step timestamps, operator, artifact path, threshold initialling | Pilot lead |
| D-2 | Evidence bundle | Descriptors, grants, proofs, receipts, request logs, counter dumps, certificate fingerprints | Consumer and provider operators |
| D-3 | Negative test matrix | NT-1 through NT-15 with expected, actual, counter delta, verdict | Independent observer |
| D-4 | Metrics dataset and analysis | Raw CSV, analysis script, percentile output, method notes | Pilot lead |
| D-5 | Failure matrix | Injected failure, observed client behaviour, retry policy, defect flag | Independent observer |
| D-6 | Defect list | Each defect against a specific section, with the failing artifact and the expected text | Pilot lead |
| D-7 | Pilot report | Two to five pages: what was tested, what was measured, what failed, what is unverified | Pilot lead |
| D-8 | Teardown attestation | Keys destroyed, tunnel removed, enrollment removed, captures deleted, data review signed | Provider operator |
| D-9 | Threat model delta | Any new threat found added to `docs/threat-model.md` with the next free identifier | Pilot lead |

The report in D-7 must contain a section titled "What this does not show", listing every claim the run cannot support. At minimum it lists production readiness, confidentiality from the provider, availability, exactly-once execution, revocation while the owner is offline, and any doxx.net statement beyond the measured transport behaviour.

## 12. Decision gates

| Gate | Question | Pass condition | If it fails |
| --- | --- | --- | --- |
| G-0, before any code | Is there an implementation to test? | Provider, consumer and adapter exist and pass the §17.1 matrix locally | Do not schedule the pilot; do not announce a date |
| G-1, before the doxx.net path | Does the LAN path pass SC-1 and SC-4 through SC-10? | All negative criteria pass | Fix enforcement before testing transport; a tunnel test would only add a variable |
| G-2, after the run | Is the result reportable? | SC-1, SC-4 through SC-13 and SC-17 have verdicts, and the report names what is unverified | Report BLOCKED, not partial compatibility |
| G-3, external | May the word "compatible" be used? | SC-2 and SC-3 pass, and a doxx.net reviewer has seen the results | Say "tested against the doxx.net network on this date with these results" and nothing stronger |

## 13. Open questions

These are unresolved at plan revision 1. They are listed rather than guessed, because each one changes what a pass means.

1. Which implementation is under test? None exists at this revision. The plan assumes the reference components named in the README will exist before G-0.
2. Does the doxx.net adapter exist, and does its API permit provisioning without terminating TLS at the tunnel edge? This is the central technical unknown: if the tunnel terminates TLS, the pilot cannot be conforming (§5.1) and the result is a negative finding worth publishing.
3. What certificate authority will issue the provider certificate for the tunnel hostname? A public CA requires a public name; a private CA requires distributing an anchor to the consumer before the first connection.
4. Does the run have a scheduled window, and who is the independent observer? Both are currently unassigned.
5. Will a real model be used for `infer`, or a deterministic stub? A stub makes latency comparison meaningful; a real model makes the demo credible. This plan recommends the stub for measurement and a real model, if available, only for a recorded demonstration that is not used for metrics.
6. Is the 14 November milestone real? Appendix A says it is a proposed engineering milestone and that the event listing of 12 November is not a verified event date. Neither is confirmed.

A plan that answers question 2 with "the tunnel terminates TLS" is not a failed pilot. It is the pilot finding the thing it was built to find.
