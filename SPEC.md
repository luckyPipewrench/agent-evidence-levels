<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Agent Evidence Level (AEL)

**A measurement standard for AI-agent audit evidence.**
Version 0.1 (draft for publication). Specification: CC BY 4.0. Reference checker and fixtures: Apache-2.0.

The Agent Evidence Level grades a record of AI-agent activity, from AEL-0 to AEL-4, by what an independent party can verify, and what omission they can detect, without trusting the vendor or the operator.

## 1. Terms

| Term | Meaning |
|---|---|
| Subject | The agent system whose actions are recorded. |
| Recorder | The component that observes the subject's actions and emits records. |
| Operator | The party that deploys the recorder and holds its signing keys. |
| Run | One bounded recording session with a declared start and end. |
| Artifact | The bundle a verifier receives: records, key references, proofs, declarations. |
| Checker | A runnable program, independent of the producer, that evaluates an artifact against this standard. |
| Verifier | Whoever runs the checker. Assumed to distrust vendor and operator alike. |

## 2. Grade semantics

1. **Rungs are cumulative.** AEL-n is earned only when every criterion of AEL-0 through AEL-n holds.
2. **Minimum rule.** A grade is the minimum over the required sub-dimensions (section 4). Nothing averages. The weakest required dimension is the grade.
3. **Three outcomes per check: PASS, FAIL, UNABLE-TO-VERIFY (UV).** FAIL means the checker ran and the property was violated: affirmative evidence of tampering or nonconformance. UV means the check could not be completed (no published key, undocumented format, missing artifact, no runnable checker). UV caps the grade exactly as FAIL does, but it impeaches the verification, not the artifact. Checkers and reports MUST keep the two distinct; rounding UV to either PASS or FAIL is nonconforming.
4. **No portable verification, no grade.** A mechanism whose records only its own producer can check is Ungraded, whatever its cryptography.
5. **Reporting format.** A published grade MUST be per run and carry its annotations: `run <id>: AEL-n [+R | R-pending] (coverage: ...; custody: ...; anchor: ...; retention: ...)`. A bare "AEL-3" is a nonconforming claim, and a single headline number for a multi-run artifact is nonconforming.
6. **R suffix.** Decision-reproducibility (section 3.6) is orthogonal to the rungs and is reported as `+R` or `R-pending` at every rung.

## 3. The rungs

Per rung: what the artifact MUST contain; what the checker MUST demonstrate (every demonstration is falsifiable: a conforming fixture that passes, and a perturbed fixture the checker must reject); the claims the grade MAY make; the claims it MUST NOT make.

### AEL-0: Authentic and ordered

**Artifact MUST contain:** (a) every record signed, individually or through a signed commitment covering each record, under a verification key published out-of-band from the artifact; (b) a per-record order commitment: each record binds its predecessor's hash, or its position in a signed append-only structure; (c) a byte-precise, documented canonical form for signed payloads, sufficient for an independent implementation.

**Checker MUST demonstrate:** offline verification of every signature from the artifact plus the published key alone; rejection when any byte of any record changes; rejection when two records are transposed; rejection when an interior record is removed.

**MAY assert:** "These records were signed by the holder of key K. Their relative order is tamper-evident. Modification or interior deletion within the presented sequence is detectable."

**MUST NOT assert:** completeness in any form. "Tamper-proof," "complete audit trail," "every action recorded," "nothing bypassed the boundary." At this rung, tail truncation is silent: cut the sequence at any point and the remainder verifies. The keyholder can also fabricate an entire sequence that verifies end to end.

### AEL-1: Gap- and truncation-evident within a run

**Artifact MUST add:** (a) a signed run-open record carrying run identity; (b) contiguous per-run sequence numbers with no legitimate gaps; (c) signed heartbeat records at a declared maximum interval H, so an interval without activity is itself a signed statement; (d) a signed run-close record committing to the run's total record count and final chain head.

**Checker MUST demonstrate:** all AEL-0 demonstrations; rejection on any sequence gap; rejection when spacing between consecutive records exceeds H plus a declared tolerance; rejection when the close record's committed count differs from the presented count (fixture: remove the tail record); classification of a run with no close record as OPEN / ABNORMAL-END, a first-class outcome distinct from both PASS and FAIL.

**MAY assert:** "Within this run, interior omission, silence longer than H, and tail truncation are each detectable."

**MUST NOT assert:** cross-run completeness (deleting an entire run is silent at this rung); any property against a dishonest keyholder, who can fabricate a clean run, heartbeats and close included; bypass claims.

### AEL-2: Cross-domain omission-evident

**Artifact MUST add:** (a) records from a second recorder observing the same boundary, itself meeting AEL-1, with every recorder's records signed under a verified recorder signing key and the custody separation declared by the operator (different process and host at minimum; different operator where claimed); (b) a correspondence rule: the event classes that must appear in all recorder records, and the identifiers that match them; (c) all record sets in the artifact.

**Checker MUST demonstrate:** AEL-1 on each record set independently; that each recorder identity is bound to the records' verified signatures, including rejection when a non-empty manifest recorder key disagrees with the key that actually signed that recorder's records; that every pair of verified recorder signing keys differs; and a cross-audit that reports every covered event present on one recorder and absent from another (fixture: delete one side's copy of an event; the checker must flag the discrepancy). If no covered event classes are declared, omission detection is unverifiable and AEL-2 is not earned.

This is the first rung at which "did anything cross the boundary unrecorded" becomes a checkable question, and only for the covered event classes, and only where mediation coverage is enforced-total, so that a second observer at a lower layer (for example, a kernel-level egress observer) sees attempts the mediating recorder never saw.

**MAY assert:** "Omission of a covered event from any recorder's record is detectable, unless the verified recorder keyholders collude or the observers share the same blind spot."

**MUST NOT assert:** an unqualified "no bypass occurred" (the correct form: "no recorder observed a covered event that another recorder omitted"); anything about uncovered event classes; organizational independence beyond the declared custody. Two recorders under one operator detect a compromised or misbehaving recorder; they do not constrain the operator who controls both keyholders.

### AEL-3: Externally anchored

**Artifact MUST add:** (a) chain heads and run-close commitments registered, at a declared cadence, in an append-only log declared by the operator as externally operated, where the log supports inclusion proofs and consistency proofs; (b) the inclusion proofs; (c) the log's identity and verification key, published.

**Checker MUST demonstrate:** AEL-2 demonstrations; that `anchor.log_key` actually signed the tree head; that this verified log key differs from every verified recorder signing key; verification of every inclusion proof against the log's signed tree head; rejection of an internally-valid alternative history that conflicts with an anchored head (fixture: a re-signed variant chain); labeling of records newer than the latest anchor as UNANCHORED-WINDOW, graded at the mechanism's unanchored rung until the next anchor lands.

**MAY assert:** "History up to each anchored head cannot be rewritten, retroactively edited, or presented in two conflicting versions without detection by any holder of the anchor references."

**MUST NOT assert:** real-time honesty (a recorder that lies at record time anchors its lie); anything about events never recorded (absence anchors as faithfully as presence); protection inside the anchor-lag window.

### AEL-4: Counterparty-confirmed

**Artifact MUST add:** (a) for a declared set of confirmed flows, signed statements from the destination party, or from an observer at the destination boundary, stating what it received, including "nothing," under a declared counterparty key; (b) run binding: each statement carries the run identifier or nonce it answers, so an all-clear cannot be replayed across runs; (c) a correspondence rule mapping recorded outbound decisions to confirmations.

**Checker MUST demonstrate:** AEL-3 demonstrations; that `counterparty.key` actually signed the counterparty statements; that this verified counterparty key differs from every verified recorder signing key; rejection of a statement bound to a different run (fixture: substitute another run's confirmation); a two-way cross-audit flagging recorded-but-unconfirmed and confirmed-but-unrecorded deliveries. If no confirmed flows are declared, counterparty confirmation is unverifiable and AEL-4 is not earned.

**MAY assert:** "For the confirmed flows, what the destination received is attested under a declared counterparty key that is different from the recorder signing keys. Fabricating a clean history for those flows requires cooperation from that counterparty keyholder."

**MUST NOT assert:** anything beyond the confirmed flows; content judgments (receipt of bytes is confirmed; harmlessness is not); confirmation where the counterparty does not participate; organizational independence beyond the counterparty declaration.

### 3.6 The R suffix: decision-reproducibility

**Earned when** each record captures the complete input set of the recorded decision (policy identity, request material, and every element of runtime state the decision consulted) such that the checker re-derives the identical verdict from the record alone, with no access to the live system.

**Checker MUST demonstrate:** re-derivation of every fixture verdict; a verdict-mismatch report when any captured input is perturbed.

**With R, MAY assert:** "The recorded verdict is the deterministic output of the recorded inputs under the recorded policy; the decision itself is auditable from the record." **Without R, MUST NOT assert** that a verdict can be independently re-derived, or that the decision, as opposed to its occurrence, is auditable.

### 3.7 Retention: a mandatory annotation, never a grade

Retention is the operator's policy for how long records are intended to remain available for verification, and under whose storage custody. It is a mandatory annotation on every published grade. It is **not** a rung and **not** scored as proof, because it is a promise about the future and about storage that no checker can verify from an artifact presented today.

**Artifact MAY declare** `manifest.retention` (a period and a storage custody). The declaration is the operator's stated policy. It is not signed evidence of actual past retention, future availability, storage durability, or legal compliance.

**Checker MUST** report the declared retention value with every per-run grade, and MUST label it as an operator declaration. The v0.1 artifact format defines no stronger, verifiable retention proof.

**Checker MUST NOT** raise, lower, or otherwise award a rung based on the declared retention period or storage custody. It MUST NOT treat a declared period as proof that records were retained, will remain available, were stored on durable media, or were held by the declared custodian.

**Retention MUST NOT excuse in-artifact nonconformance.** Within a presented artifact, a sequence gap, heartbeat gap, missing close, anchor mismatch, cross-recorder discrepancy, or counterparty discrepancy stays PASS / FAIL / UV per its own check. A declared retention period never converts an in-artifact failure into an "aged-out absence."

**Absence is not cleanliness.** When a verifier asks about a run or interval for which no artifact exists and, by an externally supplied evaluation time, the material falls outside the declared retention period, the honest result is `OUTSIDE-DECLARED-RETENTION / UV` — "not available for verification under the declared policy." It MUST NOT be reported as evidence that the run was clean, complete, or properly disposed of. (v0.1's checker grades presented artifacts and does not consume an external evaluation time, so this outcome is a defined reporting principle, not yet a checker behavior.)

**Timestamps are not trusted time.** Recorder-signed `ts` values are evidence only of the recorder's signed timeline, not trusted wall-clock time. In v0.1 they support monotonicity and declared heartbeat-spacing checks; they do not prove a record's real-world age. Binding to real time would require an independent time proof (for example an RFC 3161 timestamp token or a time-bearing external log proof), which v0.1 does not define.

## 4. Sub-dimensions

A single flat grade decomposes into these dimensions. Each rung sets required minimums; the grade is the minimum across them; the remainder annotate every published grade and bound what it may claim.

| Dimension | Question it answers | Values (weakest first) | Effect |
|---|---|---|---|
| Mediation coverage | How much of the subject's action surface is forced through the recorded boundary? | declared-only / partial / mediated-only / enforced-total | Bounds claim scope. Bypass-evidence claims require enforced-total plus AEL-2. |
| Recorder custody | Whose keys sign, relative to subject and operator? | same-process / same-host / same-operator / independent | AEL-2 requires verified recorder signing keys to differ and custody separation to be declared; AEL-4 requires the declared counterparty key to differ from recorder signing keys. |
| Chain continuity | Are omission, silence, and truncation visible? | none / linked / contiguous + heartbeat + close | Gates AEL-0 and AEL-1. |
| External anchoring | Can history be rewritten or forked? | none / operator-run log / independent append-only log | Gates AEL-3. |
| Counterparty independence | Does the far end attest what arrived? | none / partial flows / declared confirmed set | Gates AEL-4. |
| Retention / durability | How long does the operator intend records to stay available? | declared period and storage custody | Mandatory annotation only (§3.7). Never gates a rung, never excuses an in-artifact failure. Absent-and-past-retention is `OUTSIDE-DECLARED-RETENTION / UV`, never proof of cleanliness. |
| Verifier portability | Can a stranger check this offline? | vendor-only / published key and format / independent implementations exist | Required at every rung. Vendor-only means Ungraded. |
| Decision-reproducibility | Can the verdict be re-derived from the record? | R-pending / +R | Suffix at every rung. |

## 5. Conformance: earned, not asserted

A grade is earned when the reference checker, run by someone other than the producer, completes the rung's demonstrations against a real artifact, including every perturbation duty: for each property there exists a fixture in which one change (a flipped byte, a removed record, a swapped confirmation) breaks the property, and the checker must reject it. A checker that accepts a perturbed fixture is nonconforming, whatever its vendor says; a vendor statement, however detailed, earns nothing. AEL v0.1 therefore ships as three deliverables in one release: this specification, the reference checker, and a per-rung fixture corpus holding at least one valid artifact plus the required failing perturbations. A standard whose bar is "earned, not asserted" that ships without a runnable checker is the same attestation it criticizes; the checker and fixtures are part of v0.1, not a follow-up.

## 6. Limits: what no rung can prove

**The completeness limit.** A record produced inside one trust domain cannot prove its own completeness to anyone outside that domain, against the party holding the domain's signing keys. The keyholder can construct an alternative history, shorter, different, or empty, sign every element of it, heartbeats and close included, and the result passes every internal check. Signed silence proves the silence was signed; it cannot prove the silence was true. AEL is a ladder rather than a checkbox for exactly this reason: rungs 0 and 1 measure internal consistency, which a keyholder can counterfeit wholesale; omission-evidence is bought only with additional signed evidence, one keyholder at a time (a second verified recorder signing key at AEL-2, a signed log tree head at AEL-3, a signed counterparty statement at AEL-4), while organizational independence remains declared by the operator rather than proven by the checker. Each purchase covers only what that signer can see. No rung is named "complete."

**Per-rung limits, restated plainly:**

- **AEL-0** does not see tail truncation, does not see fabrication, and says nothing about completeness.
- **AEL-1** does not see whole-run deletion, and holds nothing against a dishonest keyholder.
- **AEL-2** fails against collusion of the recorder keyholders, and is blind outside the covered event classes and inside shared blind spots.
- **AEL-3** does not detect a recorder that lied at record time, never sees never-recorded events, and leaves the window since the last anchor unprotected.
- **AEL-4** covers only confirmed flows with cooperating counterparties, and confirms receipt, never meaning.
- **No rung** grades whether decisions were good, whether policy was right, or whether the subject behaved well. AEL grades the evidence, never the conduct.

## 7. The field, graded

Mechanisms, never vendors. Grades assume the mechanism as commonly shipped; a specific deployment may grade higher or lower under the checker, which is the point of having one.

| Mechanism | Grade | Basis |
|---|---|---|
| Plain logs (files, JSON lines, syslog, SIEM forwarding) | Ungraded | Mutable in place; no signature, no order commitment. Forwarding to a SIEM moves a copy; the record arrives pre-trusted and stays unverifiable. |
| Local self-attested records (vendor-verifiable signatures or hash chains; no published key, format, or checker) | Ungraded (UV) | Fails verifier portability. A signature only its producer can check is attestation wearing math. |
| Operator-published signed chains (signed, hash-chained, offline-verifiable against a published key) | AEL-0 | The strongest mechanism in common circulation today. Authentic and ordered; interior deletion detectable. Tail truncation, deleted runs, and fabricated histories remain silent, because one keyholder produced everything. |
| Externally-anchored chains (heads in a transparency log; single recorder; no heartbeats or signed close) | AEL-0 (anchor: independent) | Anchoring freezes what was recorded and says nothing about what was not, so it earns the anchoring sub-dimension but not completeness. Rungs 1 and 2 are missing, so rung 3 is not earned. |
| Independently-confirmed delivery (counterparty receipts, with no graded record behind them) | Ungraded to AEL-0 overall; rung-4 property on confirmed flows only | Confirms that specific deliveries happened. With no graded record to reconcile against, it cannot support run-level claims. |

### 7.1 Self-grading registry

Concrete deployments, including the editor's own, are graded in `GRADES.md` under the same rule as every other row: a grade with no linked artifact and checker transcript is marked "asserted." The editor's row is the first entry and is stated at its most defensible floor. See `GRADES.md`.

## 8. Name, definition, and governance

**Name and collision check.** "Agent Evidence Level," abbreviated AEL, always expanded on first use. The acronym is established in unrelated fields (accessible emission limits in laser safety; exposure limits in industrial hygiene); no standard named "Agent Evidence Level" exists as of July 2026, and the nearest adjacent work grades evidence-process maturity rather than checker-verified artifacts. Graded levels are written AEL-0 through AEL-4; the search handle is the full phrase.

**One-sentence definition, for a procurement document:** "The Agent Evidence Level grades a vendor's records of AI-agent activity, from AEL-0 to AEL-4, by what an independent party can verify, and what omission they can detect, without trusting the vendor or the operator."

**Relationship to prior art.** AEL is not an audit-control framework and not a records-retention regime; it is a cryptographic evidence-grade lens for the artifacts that audit and logging mechanisms produce. It borrows established vocabulary rather than coining its own and consumes existing transparency logs at AEL-3 rather than competing with them. See `docs/PRIOR-ART.md` for the mapping (RFC 5848 signed syslog, RFC 6962/9162 and SCITT transparency, RFC 3161 trusted time, NIST SP 800-92 and SP 800-53 AU-11 for the retention neighborhood).

**Home.** The specification lives in a standalone, vendor-neutral repository: spec under CC BY 4.0, reference checker and fixtures under Apache-2.0, no product marks in the specification. Product sites point at the repository; the repository points at no product.

**GRADES.md.** The repository carries a self-grading registry. Any mechanism owner may open a pull request adding a row; a row must link an artifact and a checker transcript; rows without runnable evidence carry the label "asserted." The editor's row is held to the same rule as everyone else's.

**Endgame.** Once the vocabulary has usage independent of its editor, editorship is donated to a neutral foundation of the OpenSSF or OWASP class, with the reference checker maintained through the transition.

**Non-normative material.** Positioning and adoption guidance (including the questions a buyer should ask and how to read common marketing claims) live in `docs/RATIONALE.md`, outside the normative specification.
