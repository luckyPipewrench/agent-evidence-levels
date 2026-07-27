# Rationale and adoption (non-normative)

This is background and positioning. It is not part of the standard; nothing here defines a grade or a
checker duty. The normative text is `SPEC.md`.

## The two questions to ask a vendor

1. "What AEL does your evidence earn when the reference checker runs on an artifact you hand me, and
   which sub-dimension caps it?"
2. "If a record were silently dropped, or an action bypassed the boundary, who outside your trust
   domain would detect it, and how?"

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
