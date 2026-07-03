# Agent Evidence Level (AEL)

A measurement standard for AI-agent audit evidence. AEL grades a record of AI-agent activity, from
AEL-0 to AEL-4, by what an independent party can verify, and what omission they can detect, without
trusting the vendor or the operator.

- **`SPEC.md`** — the standard (CC BY 4.0).
- **`docs/ARTIFACT-FORMAT.md`** — the artifact format the checker consumes.
- **`docs/CHECKER-DESIGN.md`** — the check matrix and fixture matrix.
- **`checker/`** — the reference checker `aelcheck` and fixture generator `aelgen` (Apache-2.0).
- **`fixtures/`** — the per-rung conformance corpus: one valid artifact per rung plus the perturbed
  artifacts the checker must reject or flag (Apache-2.0).
- **`GRADES.md`** — the self-grading registry; the editor's row is first and held to the same rule.
- **`docs/VERSIONING.md`** — draft stability, compatibility, and donation posture.
- **`CONTRIBUTING.md`** — contribution rules and required validation.

## Why a checker ships with the spec

The standard's bar is "earned, not asserted": a grade counts only when a reference checker,
run by someone other than the producer, demonstrates it against a real artifact, including rejecting
a perturbed copy. A standard with that bar that shipped without a runnable checker would be the same
attestation it criticizes. So the checker and the fixture corpus are part of v0.1, not a follow-up.

## Run it

```
make build     # build aelcheck + aelgen
make gen       # regenerate the fixture corpus from a fixed test seed
make test      # go test ./...
make check     # regenerate + grade the whole corpus; assert every case matches its expect.json
```

`make check` printing, for each rung, the valid artifact graded at that rung and every perturbation
rejected or flagged, is the proof the standard is earned.

```
aelcheck --keys <keysdir> <artifact>
```

grades one artifact and prints the full grade line plus a per-check PASS / FAIL / UNABLE-TO-VERIFY
table.

## Licensing

The specification (`SPEC.md`) is CC BY 4.0. The checker and fixtures are Apache-2.0. See
`LICENSING.md`.

## Status

v0.1 draft. This repository is vendor-neutral by construction: `SPEC.md` carries no product marks;
concrete deployments (including the editor's) are graded in `GRADES.md`. On publication the module
path and repository owner move to a neutral home; the intended endgame is donation of editorship to
a neutral foundation once the vocabulary has independent usage.

See `docs/VERSIONING.md` for the draft stability and compatibility policy.
