# Contributing to Agent Evidence Level

This repository is a draft public standard plus a reference checker and fixture
corpus. Contributions are welcome when they keep the standard vendor-neutral and
checker-verifiable.

## Contribution rules

- Do not add product-specific claims, marketing language, or vendor marks to
  `SPEC.md`.
- Do not claim a grade without an immutable artifact and an independently
  authenticated verification record satisfying `SPEC.md` section 5.2. Producer
  declarations without that record say `No grade` and remain `asserted capability`.
- Keep normative changes precise: every new falsifiable requirement needs a
  checker behavior and at least one fixture that proves rejection of a broken
  artifact.
- Keep `PASS`, `FAIL`, and `UNABLE-TO-VERIFY` distinct. Collapsing UV into
  either PASS or FAIL weakens the standard.
- Preserve public-repo hygiene: no secrets, private hostnames, private
  operational notes, or non-public personal details.

## Validation

Before opening a pull request, run:

```sh
go build ./...
go vet ./...
go test ./...
make check
```

`make check` regenerates the fixture corpus, grades every fixture, and verifies
that each result matches `expect.json`.

The `fixtures/` tree is generator-owned. Add or change cases in
`checker/cmd/aelgen`; `make gen` replaces the tree and discards hand edits. If the
generator cannot express the case you need, extend the generator or open an issue.
Hand-authoring a fixture is not a workaround: CI regenerates the tree and fails on
any difference.

## DCO and inbound licensing

By contributing, you certify the Developer Certificate of Origin 1.1 and include
`Signed-off-by: Name <email>` on commits or in the pull request. PRs must include
that sign-off before outside wording can merge.

Inbound licensing follows `LICENSING.md`: normative specification text is under
CC BY 4.0, and checker code, fixtures, and other code/data are under
Apache-2.0. Contributions may also be re-contributed or donated to a neutral
standards body under compatible permissive terms, consistent with
`docs/VERSIONING.md`.

## Licensing

Contributions to normative specification text are accepted under CC BY 4.0.
Contributions to checker code, fixtures, and other code/data are accepted under
Apache-2.0.
