# Agent Evidence Level (AEL)

A measurement standard for AI-agent audit evidence. AEL grades a record of AI-agent activity, from
AEL-0 to AEL-4, by what an independent party can verify, and what omission they can detect, without
trusting the vendor or the operator.

- **`SPEC.md`** — the standard (CC BY 4.0).
- **`docs/ARTIFACT-FORMAT.md`** — the artifact format the checker consumes.
- **`docs/CHECKER-DESIGN.md`** — the check matrix and fixture matrix.
- **`checker/`** — the reference checker `aelcheck` and fixture generator `aelgen` (Apache-2.0).
- **`fixtures/`** — the conformance corpus: valid per-rung artifacts, perturbed artifacts the checker
  must reject or flag, and valid limitation cases it must accept without overstating (Apache-2.0).
- **`GRADES.md`** — the evidence registry; the editor's declaration is first and held to the same rule.
- **`docs/VERSIONING.md`** — draft stability, compatibility, and donation posture.
- **`docs/RATIONALE.md`** — non-normative positioning and adoption guidance, kept out of the spec.
- **`docs/PRIOR-ART.md`** — how AEL relates to existing standards (transparency logs, audit-log and retention standards, evidence-handling), and what it deliberately does not restate.
- **`docs/EXAMPLE.md`** — a worked end-to-end example: one real artifact from bytes to a grade.
- **`schema/`** — JSON Schemas for the record payload and manifest, for independent reimplementers.
- **`CONTRIBUTING.md`** — contribution rules and required validation.

## Why a checker ships with the spec

The standard's bar is "earned, not asserted": a public grade counts only when a verifier that is
neither the producer nor the operator checks a real artifact with a checker that passes the published
conformance corpus, then publishes the signed verification package required by `SPEC.md` section 5.2.
Live health and artifact capability may be self-reported, but neither carries an AEL number. A standard
with that bar that shipped without a runnable checker would be the same attestation it criticizes. So
the checker and the fixture corpus are part of v0.1, not a follow-up.

## Run it

```
make build     # build aelcheck + aelgen
make gen       # regenerate the fixture corpus from a fixed test seed
make test      # go test ./...
make check     # regenerate + grade the whole corpus; assert every case matches its expect.json
```

`make check` printing, for each rung, the valid fixture graded at that rung and every fixture
perturbation rejected or flagged, demonstrates that the checker passes the conformance corpus. A
real run still needs the signed verification package defined in `SPEC.md` section 5.2.

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
concrete deployments (including the editor's) are graded in `GRADES.md`. The intended governance
end state is donation to a neutral body after the draft has real independent use and critique.

See `docs/VERSIONING.md` for the draft stability, compatibility, and donation policy.
