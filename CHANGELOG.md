<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## 0.1 - 2026-08-25

### Added

- Two signed package kinds with separate trust roles. An operator can issue an `evaluation-package`, whose schema can't carry a grade. An eligible verifier can issue a `verification-record` that binds per-run grades and checker outcomes to the exact artifact, inputs, checker, corpus result, and specification.
- `aelpackage emit`, which runs the checker and conformance command, captures their outputs and exit statuses, and writes a signed evaluation package that can be replayed from the packaged bytes.
- `aelpackage validate`, with separate trust directories for operator, verifier, and status-authority keys. Verification records require a separately signed status statement and a relying-party evaluation time before the validator reports `VERIFIED`.
- Retention output that labels the period and storage custody as operator declarations rather than verified properties.
- A machine-readable conformance-corpus report whose exit status distinguishes a corpus mismatch from a reporter failure.
- An end-to-end example covering a self-run check, evaluation-package emission and validation, byte-for-byte replay, and the byteflip failure path.
- A 42-case verification-package corpus with two valid controls and 40 hostile or negative cases covering package binding, trust-role separation, status handling, replay, and schema failures.

### Changed

- Self-run checker output now states that its result isn't an AEL grade and names the independent verification record required for a public grade.
