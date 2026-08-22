<!-- SPDX-License-Identifier: Apache-2.0 -->

# Verification packages

A verification package carries the exact artifact, inputs, checker results, and conformance result
for one evaluation. Its canonical `manifest.json` has a detached Ed25519 signature in
`manifest.sig`. All other package files appear in the signed `files` list with a size and SHA-256
digest.

The package root contains the artifact under `artifact/`, published artifact keys under `inputs/keys/`, package signer and status keys under `inputs/package-keys/`, result blobs, and any other replay input. A URL in a blob entry may help a reader retrieve another copy. It doesn't replace the file in the package.

## Package kinds

`evaluation-package` is an operator-signed evaluation result. Its closed schema has no `grade`,
`grades`, `verified`, or verifier-state field. A consumer displays it as `EVALUATED`, never
`VERIFIED` or an AEL grade.

`verification-record` is signed by a verifier. It carries per-run grade lines, annotations, and PASS, FAIL, or UV outcomes. The validator rejects a record when the verifier identifier equals the producer or operator identifier. It also loads the bound artifact and compares all discovered runs with the signed run list and grade entries. A favorable run can't hide another run that appears in the submitted recorder files.

The two kinds use different schemas:

- `schema/evaluation-package.schema.json`
- `schema/verification-record.schema.json`

Neither package schema permits `claimed_rung`. That field remains only in the deprecated producer
artifact manifest field described in `docs/ARTIFACT-FORMAT.md`.

## Emit an evaluation package

`aelpackage emit` runs the checker against an artifact and writes a signed evaluation package
recording what happened. It records rather than declares: the executable is digested as shipped, its
stdout, stderr, and exit status are captured from the run, and the discovered runs come from the
checker's machine output rather than from the caller.

```sh
make build
./bin/aelpackage emit \
  --artifact ./artifact --artifact-keys ./artifact/keys \
  --checker ./bin/aelcheck --source-revision "$(git rev-parse --short HEAD)" \
  --operator-key ./operator.key --operator-id my-operator --producer-id my-producer \
  --status-authority-id my-status-authority --status-key ./status.pub \
  --spec ./specification.txt --spec-version 0.1 \
  --corpus-digest-source ./fixtures/CASES.txt --corpus-version v1 \
  --conformance-command=./bin/aelgen \
  --conformance-command=--report \
  --conformance-command=--json \
  --conformance-command=--out \
  --conformance-command=./fixtures \
  --custody-acquisition declared --custody-replay available \
  --custody-review declared --custody-issuance signed \
  --coverage-scope declared --coverage-disclosure complete-package \
  --id my-package-001 --out ./package
```

The conformance command is run, not described. Its stdout becomes the packaged conformance result and its exit status becomes the recorded status, so the evidence and the verdict come from one process. Taking them as two declarations allowed a package to carry a result reporting failure alongside a declared exit of zero and still validate as `EVALUATED`.

`aelgen --report --json` produces that result: a machine-readable corpus report on stdout, diagnostics on stderr, and status 3 when any case disagrees with its expectation.

The emitter executes that command, so the trust boundary is worth stating plainly. It runs as an
argv vector with no shell, so metacharacters reach the program as literal argument bytes. It
arrives only as an operator flag and is never read from the artifact, the package, or any file the
evaluated subject can write. It runs beside the checker executable the operator also supplies, so
an operator who can choose what the emitter executes could already execute anything as themselves.
The checker never runs against the package it is being packaged into. It runs against a disposable
replica laid out identically, so its recorded arguments still replay verbatim inside the published
package. Before signing, the emitter compares static package inputs with their pre-subprocess and
replica snapshots, and compares the packaged conformance result with the direct command's captured
stdout. A write that changes either result after observation is refused instead of being signed as
though the checker evaluated it. A sandbox is still the right boundary for a command that must be
prevented from reaching unrelated same-user paths.

Every subprocess has an output detection limit, a deadline, and, on platforms with process groups,
group signalling so a wrapper that stays in its group cannot leave a child behind. Exceeding the
output limit ends the run instead of packaging a truncated result. The current file-backed capture
polls for overflow, so it detects an excess rather than enforcing a precise filesystem quota; callers
that need a hard disk bound must run the emitter in an environment that provides one. A final bounded
read still refuses an overflow that appears after the last poll, so no oversized result is signed or
held in memory. Process-group cleanup narrows resource and availability exposure rather than proving
integrity: the final byte bindings refuse a pre-signing change, and a validator rejects a later one.
A child that deliberately leaves the group still needs a process sandbox or resource boundary outside
this command.

The custody and coverage flags are declarations the operator makes and then signs, so they have no
defaults and the command refuses to run without them. A disclosure claim in particular is something
no command can observe on the operator's behalf.

The command emits evaluation packages only, and has no flag to choose the kind. A verification
record must be signed by a verifier whom the validator rejects when their identity equals the
producer or the operator, and the party running an emitter is the operator, so the only record it
could produce is one that can never validate. The grade is another party's signature to write.

The operator key is standard padded base64 holding either a 32-byte Ed25519 seed or a 64-byte
private key. A key file readable by other accounts is refused, because the package's authority rests
on that key being the operator's alone.

Exit statuses distinguish the two failures that demand opposite responses:

| Status | Meaning |
|---|---|
| 0 | The package was written and the artifact conformed. |
| 1 | No package exists; the emit itself failed. |
| 2 | Usage error. |
| 3 | The package was written and the artifact did not conform. |
| 4 | The package was written and published, but its result could not be reported. |

Status 3 is the case worth reading twice. A nonconforming artifact is still packaged, carrying its
real exit status, and the validator then displays it as `EVALUATION-FAILED`. Refusing to emit there
would turn every negative result into a missing file, which is the one outcome a reader cannot
distinguish from work nobody did.

The emitted package replays. The checker runs once, so the recorded arguments, exit status, stdout
and stderr all describe that single execution. Those arguments are relative to the package root, so a
reader can run the shipped checker against the shipped artifact and reproduce the signed machine
output byte for byte:

```sh
cd ./package && ./checker/aelcheck --json --keys inputs/keys artifact
```

## Validate a package

Build the commands, then pass the package directory and a trust root of separately trusted public
keys. Keep operator, verifier, and status-authority keys in distinct role directories; a key trusted
to authenticate an evaluation package is not thereby trusted to authenticate a verification record:

```sh
make build
./bin/aelpackage --keys ./trusted-keys validate ./verification-package
```

Each trusted key file is named `<sha256-fingerprint>.pub` and holds standard padded base64 Ed25519
public-key bytes. `trusted-keys/operators/` authenticates evaluation packages,
`trusted-keys/verifiers/` authenticates verification records, and `trusted-keys/status/`
authenticates status statements. The command validates canonical JSON, the detached manifest
signature, every content-addressed blob, path containment, package-kind rules, verifier identity,
and the complete discovered-run report.

An evaluation package exits 0 and reports `EVALUATED` after those checks. A nonzero artifact-evaluation exit reports `EVALUATION-FAILED`, and a nonzero conformance-corpus exit reports `CONFORMANCE-FAILED`; neither can support a grade. An empty conformance command is invalid because the package no longer carries the required replay instruction. A verification record is also invalid if its grade lines, annotations, or outcomes disagree with the bundled machine-readable checker result.

A verification record needs a separately signed `current` status statement and an evaluation time supplied by the relying party before it can report `VERIFIED`:

```sh
./bin/aelpackage --keys ./trusted-keys \
  --status ./record-status.json \
  --status-signature ./record-status.sig \
  --status-at 2026-01-03T12:00:00Z \
  validate ./verification-package
```

The status statement carries a format version, immutable record identifier, status-authority identifier, state, and `issued_at`; a `current` statement also carries a finite `next_update` later than `issued_at`. Its detached signature must verify under the status-authority key named by the record. `--status-at` supplies the relying party's evaluation time; the validator does not obtain a trusted clock from the package or the status statement. An optional `--max-status-age` supplies a stricter relying-party interval and never extends the signed `next_update`.

The validator reports `STATUS-UNKNOWN` when a current statement is missing `next_update`, has an invalid freshness interval, is evaluated before `issued_at`, or is evaluated at or after `next_update`. It reports `REVOKED` or `SUPERSEDED` for those states and `EXPIRED` when the package expiry is at or before the supplied evaluation time. Missing status, an invalid status signature, a missing evaluation time, or an untrusted status authority also report `STATUS-UNKNOWN`. A missing trusted package signer reports `UNTRUSTED`; malformed package data reports `INVALID`. Only `EVALUATED` and `VERIFIED` exit 0.

`schema/verification-status.schema.json` describes the separately signed statement. Revocation and supersession never change a historical record. A signed `current` statement remains acceptable only through its authority-chosen `next_update`, so offline validation bounds replay instead of claiming to eliminate it.

## Fixture coverage

`fixtures/packages/` is generator-owned with the rest of the conformance corpus. It includes valid packages of each kind plus hostile cases for changed and missing blobs, path escape, relabeled evaluation packages, grade fields on evaluation packages, first-party verifiers, omitted discovered runs, revocation and supersession, and current-status freshness boundaries.
