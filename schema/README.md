<!-- SPDX-License-Identifier: Apache-2.0 -->

# JSON Schemas (v0.1)

Machine-readable schemas for the AEL artifact objects, for independent reimplementers and for
validating fixtures. `docs/ARTIFACT-FORMAT.md` is the normative source; these schemas track it.

- `record-payload.schema.json` — the canonical JSON payload inside each signed record line.
- `manifest.schema.json` — the artifact table of contents (untrusted; see the trust-model note in
  `docs/ARTIFACT-FORMAT.md`).
- `evaluation-package.schema.json` — an operator-signed evaluation package. Its closed shape has no
  grade-bearing property.
- `verification-record.schema.json` — an eligible-verifier-signed record that may carry per-run
  grade lines, annotations, and PASS / FAIL / UV outcomes.
- `verification-status.schema.json` — a separately signed statement whose `current` state is accepted only through its authority-chosen `next_update`; it never edits the historical verification record.

The `anchors.json` and `counterparty.jsonl` payload shapes are specified in `docs/ARTIFACT-FORMAT.md`
sections 6 and 7; schemas for them are a v0.2 addition.

## `ext` sub-namespaces

`ext` is opaque to the base rung, but it is not unowned. An opt-in extension may claim a sub-namespace
and read it, so a producer must not invent a key that collides with one. Claimed so far:

- `ext.gov` — read by the governability extension; `declared_reversibility` decides DECLARED versus
  UNCLASSIFIED and therefore feeds the coverage invariant. See `docs/GOVERNABILITY-EXTENSION.md`.
- `ext.fixture` — used only by the conformance corpus under `fixtures/limits/`, to carry the narrative
  a limitation case demonstrates. AEL defines no meaning for it and nothing reads it. Do not copy it
  into production artifacts.

Note: these schemas describe structural shape. They do not and cannot express AEL's real guarantees
(signature verification over exact bytes, canonical-form equality, hash-linked ordering, the
minimum-over-sub-dimensions grade). Those live in the reference checker, which is the conformance
authority. A payload that passes the schema can still fail the checker, by design. Status freshness is the clearest current example. A schema can require `next_update` on a `current` statement, but it cannot compare two fields, so it cannot require `next_update` to be later than `issued_at`, and under Draft 2020-12 `format` is an annotation a validator may ignore. Both rules are enforced by the checker and stated normatively in `SPEC.md` section 5.2. Treating schema validity as status validity is therefore a mistake, and an implementer building only from these files would accept statements the standard rejects.
