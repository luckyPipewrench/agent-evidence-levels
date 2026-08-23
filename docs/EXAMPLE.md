# A worked example, end to end

This walks the shipped AEL-1 fixture through a self-run check, a signed evaluation package, and a replay. A self-run check can describe the artifact, but it is not a grade. An eligible verifier must issue a verification record before anyone can publish an AEL number.

## 1. What the artifact is

`fixtures/ael1/valid/` is a single-recorder run: a signed `open`, some activity, and a signed `close`.

```
fixtures/ael1/valid/
  manifest.json                 # table of contents (untrusted; corroborated by signatures)
  recorders/r1.jsonl            # one signed record per line
  keys/<fingerprint>.pub        # the published key, provided out of band
```

## 2. What one record looks like

Each line in `r1.jsonl` is `base64url(payload) . base64url(signature)`:

```
eyJobWF4Ijo2MCwiaHRvbCI6NSwia2V5IjoiZWRlZTdl...  .  <ed25519 signature>
```

The first part base64url-decodes to the exact canonical JSON that was signed, for example an `open`:

```json
{"hmax":60,"htol":5,"key":"edee7ef9...b08066","prev":"0000...0000","recorder":"r1","run":"run-ael1-valid","seq":0,"ts":"...","type":"open","v":1}
```

The checker verifies the Ed25519 signature over the exact decoded bytes, then separately confirms the
bytes are canonical. Signature first, canonicality second: it never re-serializes before verifying.

## 3. Run the checker

```sh
make build
./bin/aelcheck --keys fixtures/ael1/valid/keys fixtures/ael1/valid
```

Real output (abridged):

```
a  PASS all signatures verify over stored payload bytes
b  PASS all verified payloads are canonical
d  PASS record sequence order strictly increases from seq 0
e  PASS each record links to the preceding presented record
w  PASS verified closed-schema objects satisfy required keys and have no unknown top-level keys outside ext
f  PASS each recorder opens with hmax>0
g  PASS sequence numbers are contiguous
h  PASS signed heartbeats are present when enabled and record spacing is within hmax+htol
i  PASS close commits to count and previous head
k  FAIL fewer than two recorders on the run
m  UV   no covered event classes declared; omission-detection unverifiable
n  UV   manifest anchor block is absent
...
run run-ael1-valid: AEL-1 R-pending (coverage: declared-only; custody: same-process; anchor: none; retention: operator-declared 30d/fixture)

This is a self-run evaluation result and is not an AEL grade.
A grade is earned only through a verification record issued by an eligible verifier,
who must not be the producer or the operator of the artifact evaluated here.
```

The closing notice is part of the output, not commentary on it. This command can be run by the producer or operator, so its `AEL-1` result cannot support a public grade.

## 4. Why AEL-1 and not higher

The grade is the minimum over the required sub-dimensions, cumulative from AEL-0. This artifact earns:

- **AEL-0**: signatures verify, payloads are canonical, and the records are hash-linked in order.
- **AEL-1**: a signed open, contiguous sequence, in-bound heartbeat spacing, and a signed close that
  commits to the record count.

It stops at AEL-1 because there is one recorder (`k` FAILs: AEL-2 needs a second, independently-keyed
recorder), no external anchor (AEL-3), and no counterparty confirmation (AEL-4). Those show as `FAIL`
or `UV`, and the grade caps honestly at the last fully-satisfied rung.

`R` is pending because the activity records do not carry replayable decision inputs; retention shows as
an operator declaration and never affects the grade.

## 5. Emit and validate an evaluation package

This part starts after key provisioning; it exercises the evaluation flow end to end, not the lifecycle for creating or rotating signing keys. Put the operator's standard-base64 Ed25519 private key at `./example/operator.key` with mode `0600`, its separately published public key at `./example/trust/operators/<sha256-fingerprint>.pub`, and the status authority's standard-base64 Ed25519 public key at `./example/status.pub`. The fingerprint is the lowercase SHA-256 digest of the decoded operator public-key bytes. See [Verification packages](VERIFICATION-PACKAGE.md#validate-a-package) for the role-separated trust layout.

The output directory must be absent or empty. Use a new directory, or remove the prior example output after you are done inspecting it. The package records a real checker invocation. It doesn't create a grade.

```sh
./bin/aelpackage emit \
  --artifact fixtures/ael1/valid --artifact-keys fixtures/ael1/valid/keys \
  --checker ./bin/aelcheck --source-revision "$(git rev-parse HEAD)" \
  --operator-key ./example/operator.key --operator-id example-operator --producer-id example-producer \
  --status-authority-id example-status --status-key ./example/status.pub \
  --spec SPEC.md --spec-version 0.1 --corpus-digest-source fixtures/CASES.txt --corpus-version fixtures \
  --conformance-command ./bin/aelgen --conformance-command --report --conformance-command --json --conformance-command --out --conformance-command ./example/conformance-fixtures \
  --custody-acquisition declared --custody-replay available --custody-review declared --custody-issuance signed \
  --coverage-scope declared --coverage-disclosure complete-package \
  --id ael1-example --out ./example/evaluation-package

./bin/aelpackage --keys ./example/trust validate ./example/evaluation-package
```

The validator prints `evaluation-package ael1-example: EVALUATED` and exits zero. `EVALUATED` means the signed package and its recorded evaluation validate. It isn't `VERIFIED`, and it isn't an AEL grade.

The package contains the checker, artifact, keys, and recorded command arguments. Replay the captured checker invocation from the package root:

```sh
cd ./example/evaluation-package
./checker/aelcheck --json --keys inputs/keys artifact
```

Compare the resulting JSON with `results/artifact.json`; they must match byte for byte. This manual replay proves the packaged checker reproduces the recorded result. The package validator separately binds both files by digest, so either file changing invalidates the original manifest.

## 6. Prove the failure direction

`fixtures/ael0/byteflip` changes bytes in a signed recorder stream. The direct checker run fails rather than returning a favorable result:

```sh
./bin/aelcheck --keys fixtures/ael0/byteflip/keys fixtures/ael0/byteflip
```

It exits `3` and reports `Ungraded`. Emit that same artifact with the command above after changing `--artifact`, `--artifact-keys`, `--id`, `--out`, and the conformance output directory to new byteflip-specific paths. The emitter still writes the package and exits `3`. Validating it reports `EVALUATION-FAILED` and exits `3`, preserving the negative result instead of leaving no package to inspect.

Run `make check` to regenerate and grade every fixture, including the valid artifacts and their perturbations.
