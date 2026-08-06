# Rationale and adoption (non-normative)

This is background and positioning. It is not part of the standard; nothing here defines a grade or a
checker duty. The normative text is `SPEC.md`.

## The questions to ask a vendor

1. "Which AEL artifact formats and export operations does your product support?" This asks for a
   capability declaration, not a grade.
2. "Show me the signed verification package for this exact run. Which artifact, keys, checker output,
   and conformance-corpus result does it carry?"
3. "Who performed the verification, what is their relationship to you, and where can I check whether
   the result was revoked or superseded?"
4. "What AEL did that run earn, and which sub-dimension capped it?"
5. "Is the run still open, closed cleanly, or abnormally ended?" A producer-set `VERIFIED` field is
   not an answer.
6. "If a record were silently dropped, or an action bypassed the boundary, who outside your trust
   domain would detect it, and how?"

## Three different surfaces

A live health signal answers whether recording appears to be operating safely now. A capability
declaration says which artifact formats and export operations a product supports. Neither gets an
AEL number. A grade belongs to one exported run only after a verifier that is neither the producer nor
the operator checks the artifact with a checker that passes the published conformance corpus and signs
the required verification package.

This separation matters because qualifiers disappear. A dashboard copied from "self-assessed AEL-1"
soon becomes a chart labeled "AEL-1." Keeping the number out of producer declarations prevents that
loss of context.

Run closure and verification are separate facts. `OPEN`, `CLOSED`, and `ABNORMAL-END` come from the
run evidence. `VERIFIED` comes from a trusted verification record whose bindings and packaged blobs
match that run. A closed run can be pending verification, and an open snapshot can be independently
checked but cannot earn AEL-1 because it has no signed close.

An old result remains evidence of what the exact artifact demonstrated at evaluation time. It does
not become a current product grade. A buyer can require a recent checker revision, a recognized
executable digest, an unexpired result, or a live revocation check, but loss of access to the status
service means status unknown, not clean.

## The tell

"We produce tamper-proof logs" is a tell. The phrase claims the strongest property that still requires
trusting the keyholder. A mechanism that stops there is AEL-0: authentic and ordered, but silent about
truncation, deleted runs, and fabrication, because one keyholder produced everything. The grade names
that honestly; the marketing phrase does not.

## On "immutable audit trail"

External anchoring freezes what was recorded and says nothing about what was not. It is often described
as an "immutable audit trail," which overstates it: anchoring an incomplete or fabricated history makes
that history equally permanent. Anchoring earns the anchoring sub-dimension, not completeness, which is
why an anchored single-recorder chain with no heartbeats or signed close still grades AEL-0, not AEL-3.

## On evidence that was born wrong

Integrity is not truth. An agent can receive a failed tool result, sincerely produce a plausible success
claim, and have both events preserved in a perfectly signed and ordered chain. Likewise, reading back a
status file the same agent wrote does not turn that file into independent confirmation. The
`fixtures/limits/` corpus makes both failures concrete: each artifact earns AEL-1 because the checker can
verify its evidence mechanics, while `scenario.json` binds the contradictory evidence and false claim to
exact signed events without treating either as a grading input.

Both cases carry their contradiction in `ext`, and that is the honest shape of the limit rather than a
convenience. The record schema has no graded field in which a tool's semantics could be stated at all:
an event carries a class, an id, and a direction, and nothing else. So this class of falsehood is
undetectable by construction, not by omission. A checker that claimed otherwise would be claiming to
grade a field the format does not have.

This is not a checker escape hatch. It is the boundary the checker must report honestly. AEL says what
was recorded, how omission-evident that record is, and which narrow confirmations exist. It does not
certify arbitrary correspondence between a recorded claim and the world. AEL-4 strengthens specific
declared flows with counterparty confirmation; it does not make every statement in an artifact true.

## Adoption posture

Cite the vocabulary, do not pitch it. Use it where evidence is discussed: standards threads, RFP
language, and benchmark scoring ("that mechanism is AEL-0"; "this requirement should read AEL-1 or
higher, R required"). The vocabulary spreads by being useful in a sentence, with the specification one
link behind it.
