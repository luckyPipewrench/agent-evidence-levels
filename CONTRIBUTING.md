# Contributing to Agent Evidence Level

This repository is a draft public standard plus a reference checker and fixture
corpus. Contributions are welcome when they keep the standard vendor-neutral and
checker-verifiable.

## Contribution rules

- Do not add product-specific claims, marketing language, or vendor marks to
  `SPEC.md`.
- Do not claim a grade without a runnable artifact and a reference-checker
  transcript. Rows without both remain `asserted`.
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

## Licensing

Contributions to normative specification text are accepted under CC BY 4.0.
Contributions to checker code, fixtures, and other code/data are accepted under
Apache-2.0.

