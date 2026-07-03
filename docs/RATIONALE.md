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

## Adoption posture

Cite the vocabulary, do not pitch it. Use it where evidence is discussed: standards threads, RFP
language, and benchmark scoring ("that mechanism is AEL-0"; "this requirement should read AEL-1 or
higher, R required"). The vocabulary spreads by being useful in a sentence, with the specification one
link behind it.
