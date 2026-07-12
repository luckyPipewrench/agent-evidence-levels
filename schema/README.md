<!-- SPDX-License-Identifier: Apache-2.0 -->

# JSON Schemas (v0.1)

Machine-readable schemas for the AEL artifact objects, for independent reimplementers and for
validating fixtures. `docs/ARTIFACT-FORMAT.md` is the normative source; these schemas track it.

- `record-payload.schema.json` — the canonical JSON payload inside each signed record line.
- `manifest.schema.json` — the artifact table of contents (untrusted; see the trust-model note in
  `docs/ARTIFACT-FORMAT.md`).

The `anchors.json` and `counterparty.jsonl` payload shapes are specified in `docs/ARTIFACT-FORMAT.md`
sections 6 and 7; schemas for them are a v0.2 addition.

Note: these schemas describe structural shape. They do not and cannot express AEL's real guarantees
(signature verification over exact bytes, canonical-form equality, hash-linked ordering, the
minimum-over-sub-dimensions grade). Those live in the reference checker, which is the conformance
authority. A payload that passes the schema can still fail the checker, by design.
