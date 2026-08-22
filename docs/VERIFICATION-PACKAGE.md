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
  --corpus-digest-source ./corpus-id.txt --corpus-version v1 \
  --conformance-result ./conformance.json --conformance-command "make check" \
  --id my-package-001 --out ./package
```

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

Status 3 is the case worth reading twice. A nonconforming artifact is still packaged, carrying its
real exit status, and the validator then displays it as `EVALUATION-FAILED`. Refusing to emit there
would turn every negative result into a missing file, which is the one outcome a reader cannot
distinguish from work nobody did.

The emitted package replays. Its recorded evaluation arguments are relative to the package root, so
a reader can run the shipped checker against the shipped artifact and reproduce the signed machine
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
