<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# AEL governability extension v0.1 (draft, design track)

Status: draft for critique. This is a **clearly-labeled extension**, not a rung
change. The AEL ladder grades what an independent party can **verify** about a
record. Governability is a different axis: whether the record says an action was
**safe to run unattended**. A record can be AEL-4 and still be a perfectly
attested log of an irreversible action an agent should never have taken without a
human. The ladder keeps grading verifiability; this extension reports
governability alongside it, labeled as exactly that.

The vocabulary is the OWASP AISVS v1.0 reversibility classification, control
C9.2.3: `read-only`, `reversible`, `external-reversible`, `irreversible`.

## 1. Why an extension, not a rung

Verifiability and governability are orthogonal. Folding a reversibility class into
a rung would let the ladder claim something it cannot check: a checker can prove a
record **carries** a class and that it is internally consistent, but it cannot
prove the class is **true**. A record that labels a wire transfer `reversible`
verifies exactly as clean as an honest one. So the class must be reported outside
the grade, with a status that says what kind of assurance is on offer.

## 2. Wire format: `ext.gov`

Per `docs/VERSIONING.md`, additive fields on the v0.1 closed-schema signed objects
live under the reserved top-level `ext` object with a documented namespace. This
extension defines the `gov` namespace on `activity` records:

```json
"ext": { "gov": { "declared_reversibility": "irreversible" } }
```

`declared_reversibility`, when present, MUST be one of the four AISVS classes. The
base reference checker continues to treat `ext` as opaque and grades nothing from
it; only the opt-in governability duty reads `ext.gov`. Because `ext` is inside
the signed payload bytes, the declared class is covered by the recorder signature.

## 3. Provenance statuses (reported outside the grade)

For each activity event the governability duty reports one status. None of them is
`PASS`/`FAIL`/`UV`, and none moves the AEL rung. There are five source statuses
plus `UNASSESSABLE` for a record that was kept but could not be classified.

- **POLICY-BOUND.** A hash-verified enforcement policy assigns the class (see
  Section 4). This is the only status that MAY lower an event's coverage below
  irreversible (Section 5). It is provenance, not truth: it does not prove the
  policy itself is correct, only that the class came from the enforcement policy at
  decision time, not from a later relabeling.
- **POLICY-SILENT.** The referenced policy hash-verifies, but it carries no class
  for this event's class. The event is not policy-bound: it is treated as
  `irreversible` for coverage, and any `ext.gov` agent declaration is advisory only
  and never lowers the gate.
- **POLICY-INVALID.** A policy was referenced but is missing, malformed,
  hash-mismatched, or maps this event class to an out-of-vocabulary or empty value.
  The base R check rejects exactly this input, so the duty must not fall back to
  the agent-declared class. Treated as `irreversible`.
- **DECLARED.** The class comes only from `ext.gov.declared_reversibility`, over an
  empty or absent `decision.policy`. The declared class is reported for information,
  but it is gated `irreversible` for coverage and never lowers the gate (Section 5).
- **UNCLASSIFIED.** No class is present from any source. Treated as `irreversible`.
- **UNASSESSABLE.** A schema-invalid activity record that was kept, not dropped
  (Section 6). Its event id and class were recovered where possible and it is gated
  `irreversible` against the recovered class. If the class was not recoverable the
  run's coverage becomes `UNASSESSABLE` (Section 5), a failing state.

When both a policy-bound class and an agent-declared class are present, the
policy-bound class wins and the softer agent-declared value is reported as ignored.
A securing runtime MUST NOT let an agent assert a class over the one the policy
assigned.

## 4. Policy binding (strong form)

An enforcement policy referenced by a decision (`policy/<policy-hash>.json`) MAY
carry a `reversibility` object mapping event class to reversibility class:

```json
{ "v": 1, "rules": [ ... ], "default": "allow",
  "reversibility": { "pay": "irreversible", "net": "reversible" } }
```

Because the decision carries the policy hash and the policy bytes hash to it, a
class derived from this map is bound to the enforcement policy at decision time.
The base R check ignores the extra field; the governability duty reads it and
reports POLICY-BOUND. This reuses the existing policy-hash machinery rather than
adding a new trust root.

## 5. AEL-2 fail-closed coverage

AEL-2's `correspondence.classes` is operator-declared, so an operator could scope
the riskiest actions out of the corresponded set and keep the grade. The
governability duty closes that with a fail-closed **coverage invariant**:

> **MUST.** Only a POLICY-BOUND (hash-verified) class MAY lower an event's coverage
> below irreversible. Every other status is irreversible for coverage. Concretely,
> an event MUST have its event class present in `correspondence.classes` unless it
> is POLICY-BOUND with a non-`irreversible` class. An event that must be covered but
> whose class is absent from the corresponded set is reported as a coverage `GAP`.

This is what makes the safety property un-removable by deleting its input. Blanking
`decision.policy` drops an event to DECLARED, which reports the agent's declared
class for information but is still gated `irreversible` for coverage, so it cannot
dodge the rule. The same holds for POLICY-SILENT, POLICY-INVALID, UNCLASSIFIED, and
UNASSESSABLE: none of them can lower the gate.

With no correspondence declared the result is `N/A`, not a false `OK`.

**Never drop a risky record.** A schema-invalid activity record is not silently
removed from the report. If its event id and class are recoverable, it is reported
UNASSESSABLE, gated `irreversible` against the recovered class, and the schema error
is attached to the finding's note. If the class is not recoverable, the run's
coverage is `UNASSESSABLE`, never `OK` and never `N/A`. `UNASSESSABLE` fails the
gate; it is not an N/A. (Signature- or canonical-unverified records remain a rung
problem and are left to the base grade, not carried into the governability report.)

**Merge across recorders is a union.** When more than one recorder reports the same
event id, the duty covers the **union** of the event classes seen for that id, so
coverage cannot flip with record order when two recorders disagree. The surviving
finding keeps the worst case: the most severe reversibility class first, then the
strongest provenance. Ranking provenance above class severity would let a
POLICY-BOUND `reversible` record from one recorder mask an UNCLASSIFIED
`irreversible` record for the same event, laundering the riskier action out of
coverage. Severity wins so the coverage rule always sees the least-reversible view.

**DUPLICATE-ID-CLASS-CONFLICT.** When two recorders report the same event id with
different `event.class` values, the duty raises a `DUPLICATE-ID-CLASS-CONFLICT`
anomaly for that id, reported in `coverage.anomalies`, **even when the union of
classes is fully covered**. Two recorders disagreeing on what an event was is a
finding in its own right, independent of whether coverage passed.

### AEL's own rule, not AISVS

The "unclassified is treated as the strictest class (`irreversible`) for coverage"
rule, and the coverage invariant that only a POLICY-BOUND class may lower the gate,
are **AEL's own rules**. They are the fail-closed default this extension defines.
AISVS C9.2.3 supplies only the four-value reversibility **vocabulary**; it does not
state that an unclassified action must be treated as irreversible, nor does it
define this coverage gate. AEL adopts the strictest-default treatment so an
unlabeled or unverifiable action cannot be laundered out of scope.

## 6. Conformance

An implementation conforms if, over the signed artifact:

1. every activity event is reported as POLICY-BOUND, POLICY-SILENT, POLICY-INVALID,
   DECLARED, UNCLASSIFIED, or UNASSESSABLE per Sections 3 and 4;
2. a class outside the four-value vocabulary, or an absent class, is treated as
   `irreversible`, and an out-of-vocabulary or empty policy value is reported
   POLICY-INVALID (never a mislabeled POLICY-BOUND);
3. a policy-bound class is never overridden by an agent-declared class;
4. the coverage invariant of Section 5 holds: only a POLICY-BOUND non-`irreversible`
   class may lower the gate; a schema-invalid record is kept as UNASSESSABLE rather
   than dropped; an unrecoverable class makes the run's coverage `UNASSESSABLE`; and
   a duplicate id with conflicting `event.class` covers the union and raises
   `DUPLICATE-ID-CLASS-CONFLICT`.

The reference corpus ships these fixtures under `fixtures/gov/`, asserted by
`TestGovernabilityCorpus`:

- `policy_bound` — a policy-bound irreversible action reports POLICY-BOUND.
- `declared` — an `ext.gov` class with no policy reports DECLARED.
- `unclassified` — no class reports UNCLASSIFIED and is treated as irreversible.
- `downgrade` — an agent-declared `reversible` over a policy-bound `irreversible`
  is ignored (the self-assertion this extension forbids).
- `irreversible_scoped_out` — an irreversible action whose class is left out of
  `correspondence.classes` is caught as a coverage GAP.
- `hash_mismatch` — a record referencing a policy whose bytes do not hash to the
  decision's committed hash fails closed to UNCLASSIFIED irreversible, never
  trusting the tampered policy's class.
- `missing_policy` — a record referencing a policy whose bytes are absent fails
  closed to UNCLASSIFIED irreversible, not to the agent-declared class.
- `merge_worstcase` — two recorders report the same event id, one POLICY-BOUND
  reversible and one UNCLASSIFIED irreversible; the merge keeps the irreversible
  worst case and the coverage rule reports a GAP.
- `declared_no_lower` — an empty/absent `decision.policy` with an agent-declared
  `reversible` class reports DECLARED but is gated irreversible for coverage, so its
  event class left out of `correspondence.classes` is caught as a GAP. This pins the
  coverage invariant: blanking the policy input cannot turn the safety property off.
- `policy_silent` — a hash-verified policy that is silent on the event's class
  reports POLICY-SILENT irreversible.
- `policy_invalid_value` — a hash-verified policy mapping the event class to an
  out-of-vocabulary value reports POLICY-INVALID irreversible, not a mislabeled
  POLICY-BOUND.
- `unassessable_recoverable` — a schema-invalid activity record with a recoverable
  event id and class is kept as UNASSESSABLE, gated irreversible, and its class
  checked against correspondence (a GAP), never dropped.
- `unassessable_unrecoverable` — a schema-invalid activity record whose event class
  cannot be recovered makes the run's coverage UNASSESSABLE.
- `dup_id_class_conflict` — two recorders report the same event id with different
  `event.class`; the union is covered and a DUPLICATE-ID-CLASS-CONFLICT anomaly is
  raised even though coverage is OK.

## 7. Running it

```sh
aelcheck --gov --keys <keysdir> <artifact>
```

The governability report prints after, and separately from, the grade line, so a
reversibility finding is never read as a rung result. Machine-readable output
(`--json --gov`) adds a top-level `governability` array beside `runs`.

## 8. Status and licensing

Draft on the design track, offered for critique. Normative text here is under
CC BY 4.0; the checker duty and fixtures are under Apache-2.0, per
`CONTRIBUTING.md`. The intent, consistent with `docs/VERSIONING.md`, is to keep
this a labeled governability extension that can be donated alongside the base
standard.
