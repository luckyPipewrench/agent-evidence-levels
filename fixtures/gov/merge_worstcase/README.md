<!-- SPDX-License-Identifier: Apache-2.0 -->

# gov/merge_worstcase (needs aelgen to generate signed records)

This fixture regression-tests bug 3: `mergeEvent` must keep the WORST CASE across
recorders (most severe class first, then strongest provenance). Before the fix,
`mergeEvent` ranked provenance above class severity, so a POLICY-BOUND `reversible`
record from one recorder masked an UNCLASSIFIED `irreversible` record for the same
event id, and coverage wrongly reported OK.

It could not be hand-authored in this PR upload because both recorders need freshly
Ed25519-signed hash-chained records under two independent keys. Generate it with
`checker/cmd/aelgen` in the full repository (the base `ael` package is required and
is not part of this partial upload).

## What the fixture must contain

Run id: `run-gov-merge-worstcase`. Manifest `correspondence.classes` MUST NOT list
the irreversible event's class, so the merged worst-case triggers a coverage GAP.

Two recorders, r1 and r2, each with one `activity` record for the SAME event id
`evt-1`:

- **r1 (POLICY-BOUND reversible).** event class `net`, dir `out`, with a `decision`
  whose `policy` is the govPolicyFixture hash. The gov policy maps `net` ->
  `reversible`, so r1 alone classifies `evt-1` as POLICY-BOUND reversible. Signed
  with the r1 key.
- **r2 (UNCLASSIFIED irreversible).** event class `net`, dir `out`, with NO decision
  and NO `ext.gov.declared_reversibility`. r2 alone classifies `evt-1` as
  UNCLASSIFIED, treated as irreversible. Signed with an independent r2 key.

Both recorders share the same `open`/`heartbeat`/`close` framing used by the other
AEL-2 fixtures (`custody: same-operator`, `coverage: enforced-total`).

## Expected merged result

`mergeEvent(policy-bound reversible, unclassified irreversible)` must keep the worst
case: revOrder[irreversible]=3 beats revOrder[reversible]=1, so the merged event is:

```json
{ "events": { "evt-1": { "status": "UNCLASSIFIED", "class": "irreversible" } },
  "coverage": "GAP", "gaps": ["evt-1"] }
```

Because the irreversible worst case survives the merge, its event class `net` is
checked against `correspondence.classes`; with `net` left out of the corresponded
set the coverage rule reports a GAP on `evt-1`. Under the pre-fix `mergeEvent` the
POLICY-BOUND reversible record would have won and coverage would have (wrongly)
reported OK — the exact masking this fixture pins down.

## How to generate it (full repo, has the base `ael` package)

Add this case to `buildCases` in `checker/cmd/aelgen/main.go`, then run
`go run ./checker/cmd/aelgen --out fixtures`.

```go
// governability merge worst-case: two recorders, same event id, POLICY-BOUND
// reversible on one and UNCLASSIFIED irreversible on the other. The merge must
// keep the irreversible worst case, which then trips the coverage GAP because
// the manifest's correspondence.classes deliberately omits the event class.
govMergeR1, err := buildRecords(priv, "run-gov-merge-worstcase", "r1", fp, []recordPlan{
    open("2026-01-01T00:00:00Z", 60, 5),
    activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", govDecision, nil),
    heartbeat("2026-01-01T00:00:30Z"),
    closePlan("2026-01-01T00:00:40Z", nil, ""),
})
if err != nil {
    return nil, err
}
govMergeR2, err := buildRecords(rec2Priv, "run-gov-merge-worstcase", "r2", rec2FP, []recordPlan{
    open("2026-01-01T00:00:01Z", 60, 5),
    activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", nil, nil),
    heartbeat("2026-01-01T00:00:31Z"),
    closePlan("2026-01-01T00:00:41Z", nil, ""),
})
if err != nil {
    return nil, err
}
```

and add to the returned `[]caseDef`:

```go
{name: "gov/merge_worstcase",
 recorderRecords: map[string][]signedRecord{"r1": govMergeR1, "r2": govMergeR2},
 recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys,
 policies: map[string][]byte{govPolicyHash: govPolicyRaw},
 manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator",
 expect: expect(2, "+R", map[string]string{"k": "PASS", "l": "PASS", "m": "PASS", "R": "PASS"}),
 govExpect: &govExpectation{
     Events:   map[string]govEventExpect{"evt-1": {Status: "UNCLASSIFIED", Class: "irreversible"}},
     Coverage: "GAP", Gaps: []string{"evt-1"}}},
```

Note: `ael2Extra` corresponds `classes: ["net"]`. Since the event class here IS
`net`, override `manifestExtra` with a correspondence set that omits `net` (for
example `classes: ["dns"]`) so the irreversible worst case is genuinely scoped out
and the GAP fires. Define alongside `ael2Extra`:

```go
govMergeCorr := map[string]any{"correspondence": map[string]any{"classes": []any{"dns"}, "match": "id"}}
```

and use `manifestExtra: govMergeCorr` in the case above.
