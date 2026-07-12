# AEL self-grading registry

Grades for concrete deployments and mechanisms, one row each. This registry takes pull requests.

**The rule, applied to every row including the editor's:** a row must link an artifact and a
reference-checker transcript. A row with no runnable evidence is marked **asserted** and carries no
weight. A grade is written in full per run: `run <id>: AEL-n [+R | R-pending] (coverage: ...;
custody: ...; anchor: ...; retention: ...)`. A bare number is not a grade.

## Editor's row (stated at the defensible floor)

**Editor's own deployment: `run asserted-current: AEL-0 R-pending (coverage: enforced-total on
kernel-contained hosts, mediated-only elsewhere; custody: same-operator; anchor: none; retention:
operator-configured)`.**

Earned today: signed, hash-chained decision records, offline-verifiable against a published key,
with policy-hash binding and in-chain gap and order detection. That earns AEL-0 and nothing above
it.

Missing for AEL-1, to be built: heartbeat records, and a signed run-close committing to a record
count. The current deployment writes a transcript root on clean shutdown only; a crash or a
truncation before shutdown leaves no artifact that makes the missing tail evident.

R is pending: the recorded verdict cannot yet be re-derived from the record alone, because the
decision consults live runtime state beyond the policy hash and the request fingerprint. R is
earned when records carry the full replay inputs, and not before.

Evidence: **asserted** (a production artifact + checker transcript has not yet been attached to
this row; until it is, this row is a claim, held to the same bar as any other).

If this scale graded its own editor at the top, you should distrust the scale.

## Registry

| Deployment / mechanism | Grade | Evidence | Notes |
|---|---|---|---|
| Editor's own deployment | run asserted-current: AEL-0 R-pending | asserted | See editor's row above. |

To add a row: open a pull request appending to the table with a link to your artifact bundle and
the checker transcript. For example, from the repo root after `make build`:
`./bin/aelcheck --keys fixtures/ael1/valid/keys fixtures/ael1/valid > transcript.txt`.
Use the same `--keys` form for your artifact. Rows without both links keep the **asserted** label.
