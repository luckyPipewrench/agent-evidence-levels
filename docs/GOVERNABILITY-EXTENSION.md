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
`PASS`/`FAIL`/`UV`, and none moves the AEL rung.

- **POLICY-BOUND.** The class is derived from the signed decision's policy (see
  Section 4). This proves the classification came from the enforcement policy at
  decision time, not from a later relabeling. It is provenance, not truth: it does
  not prove the policy itself is correct.
- **DECLARED.** The class comes from `ext.gov.declared_reversibility` and is not
  bound to a policy. It is a signed claim with author provenance only.
- **UNCLASSIFIED.** No class is present, or a referenced enforcement policy cannot
  be hash-verified. The event is treated as `irreversible` for coverage (Section 5),
  so an unlabeled or unverifiable-policy action cannot dodge the coverage rule.

When both a policy-bound class and an agent-declared class are present, the
policy-bound class wins and the softer agent-declared value is reported as ignored.
A securing runtime MUST NOT let an agent assert a class over the one the policy
assigned.

A record that references an enforcement policy whose bytes are missing, malformed,
or do not hash to the decision's committed policy hash fails closed to UNCLASSIFIED
irreversible. The base R check rejects exactly this input, so the governability duty
must not fall back to the agent-declared class: falling open there would be the
self-assertion the ladder already refuses.

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
governability duty closes that with a fail-closed rule:

> Every event whose reversibility class is `irreversible`, including any
> `UNCLASSIFIED` event treated as `irreversible`, MUST have its event class present
> in `correspondence.classes`. An irreversible action whose class is absent from
> the corresponded set is reported as a coverage `GAP`.

With no correspondence declared the result is `N/A`, not a false `OK`.

When more than one recorder reports the same event id, the duty reconciles them by
keeping the worst case: the most severe reversibility class first, then the
strongest provenance. Ranking provenance above class severity would let a
POLICY-BOUND `reversible` record from one recorder mask an UNCLASSIFIED
`irreversible` record for the same event, laundering the riskier action out of
coverage. Severity wins so the coverage rule always sees the least-reversible view.

## 6. Conformance

An implementation conforms if, over the signed artifact:

1. every activity event is reported as POLICY-BOUND, DECLARED, or UNCLASSIFIED per
   Sections 3 and 4;
2. a class outside the four-value vocabulary, or an absent class, is treated as
   `irreversible`;
3. a policy-bound class is never overridden by an agent-declared class;
4. the AEL-2 coverage rule of Section 5 holds.

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
