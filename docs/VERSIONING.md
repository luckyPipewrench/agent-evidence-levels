<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Versioning and Stability

AEL v0.1 is a draft for publication. It is suitable for review, experiments,
and independent evaluation, but it is not yet a stable foundation-governed
standard.

## Stability levels

- **Draft:** names, prose, checker output fields, and fixture coverage may
  change before publication.
- **Published v0.x:** editorial clarifications and additive checker output are
  allowed; incompatible artifact-format changes require a new format version.
- **Published v1.0+:** normative rung semantics, wire artifacts, and grade
  meanings are stable within the major version.

## Compatibility rules

- Artifact-format changes that can make an existing valid artifact invalid
  require incrementing `ael_format` / record `v` and documenting migration.
- Additive extension fields must be versioned and namespaced before they are
  used by any checker or downstream tool.
- For v0.1 signed closed-schema objects, that reserved additive namespace is the
  top-level `ext` object. The reference checker verifies that `ext` is an
  object and otherwise treats it as opaque signed bytes; any future semantics
  under `ext` need their own documented namespace/version before use.
- Checker output may add fields, but existing machine-readable meanings must
  not be silently redefined.
- A rung claim must not become broader without a matching checker duty and
  fixture.
- A producer declaration must not gain an AEL number through an editorial
  clarification. Allowing self-awarded grades would change the meaning of every
  rung and requires a new major specification version.
- A verification record remains bound to the specification version and digest,
  checker source revision, executable digest, and corpus identity it names. A
  later specification may supersede that result under a relying policy, but must
  not silently rewrite the historical evaluation.

## Donation target

The current editor may publish v0.x under this repository. The intended
governance end state is donation of editorship to a neutral foundation once the
vocabulary has independent use and critique, and the reference checker has
external users.

Donation MUST transfer the specification, conformance corpus, registry history,
and revocation or supersession records together. The successor's registry policy
must publish verifier eligibility and conflict-of-interest rules, preserve review
history, and apply the same evidence requirements to founding-editor submissions
as to every other producer. A change of repository owner or editor does not
authenticate old producer claims or turn them into grades.
