# AGENTS.md: Agent Evidence Level Contributor Guide

Agent Evidence Level (AEL) is a measurement standard for AI-agent audit evidence. This repository contains the standard, its reference checker, and a conformance corpus: grades are earned by running the checker against real artifacts and the required failing perturbations, not asserted in prose. Read `README.md`, `SPEC.md`, and `GRADES.md` before making claims about the standard or a concrete grade.

## Repository Layout

```
checker/
  cmd/aelcheck/     Reference checker CLI
  cmd/aelgen/       Fixture corpus generator
  internal/ael/     Checker implementation
  conformance/      Corpus conformance tests
fixtures/           Generator-owned conformance corpus and committed manifests
schema/             JSON Schemas for record payloads and manifests
```

## Build, Test, and Check

```sh
make build          # Build bin/aelcheck and bin/aelgen
make gen            # Regenerate the entire fixtures/ tree
make test           # Run all Go tests
make check          # Regenerate, run conformance, and print corpus grading: the proof
make fmt            # Format Go code with gofumpt when available, otherwise gofmt
make clean          # Remove bin/
```

Go version: 1.25 (from the `go` directive in `go.mod`).

`make check` is the real proof for a change to the checker or corpus: it first regenerates the fixtures, then checks the conformance corpus against its expected results and prints human-readable grades. Run the validation required by `CONTRIBUTING.md` before proposing a change:

```sh
go build ./...
go vet ./...
go test ./...
make check
```

## Fixture Corpus Workflow

The `fixtures/` tree is generator-owned. `make gen` builds `aelgen` and runs it against `./fixtures`; the generator starts by calling `os.RemoveAll` on that output directory. It therefore replaces the whole tree and discards hand edits.

Add or change cases in `checker/cmd/aelgen`, then run `make gen` and commit every resulting fixture change. `fixtures/CASES.txt` and `fixtures/GOV-CASES.txt` are generated manifests that pin the ordinary and governability corpora. The conformance tests compare each manifest with the on-disk corpus in both directions, so an entry missing from disk or a fixture absent from its manifest fails the suite. Adding or removing a case therefore requires regenerating and committing the corresponding manifest.

CI also requires fixtures to be generator-reproducible:

```sh
make gen
git diff --exit-code HEAD -- fixtures/
test -z "$(git status --porcelain --untracked-files=all --ignored=matching -- fixtures/)"
```

## Licensing and Contributions

`LICENSE` covers the Apache-2.0 checker, fixtures, scripts, and other code/data. Normative specification text is CC BY 4.0 under the separate `LICENSE-SPEC`; see `LICENSING.md` for the directory split.

Contributions require the Developer Certificate of Origin 1.1 sign-off: include `Signed-off-by: Name <email>` on the commit or pull request, as required by `CONTRIBUTING.md`.
