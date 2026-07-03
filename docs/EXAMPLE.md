# A worked example, end to end

This walks one real artifact from bytes to a grade, using a fixture that ships in this repo. Nothing
here is hypothetical; every command runs against `fixtures/ael1/valid`.

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

## 3. Grade it

```
export TMPDIR=$HOME/.cache/pipelock-tmp GOTMPDIR=$HOME/.cache/pipelock-tmp GOCACHE=$HOME/.cache/go-build
cd <repo>
go build -o bin/aelcheck ./checker/cmd/aelcheck
./bin/aelcheck --keys fixtures/ael1/valid/keys fixtures/ael1/valid
```

Real output (abridged):

```
a  PASS all signatures verify over stored payload bytes
b  PASS all verified payloads are canonical
d  PASS presented record order is hash-linked
w  PASS verified closed-schema objects have no unknown top-level keys outside ext
f  PASS each recorder opens with hmax>0
g  PASS sequence numbers are contiguous
h  PASS record spacing is within hmax+htol
i  PASS close commits to count and previous head
k  FAIL fewer than two recorders on the run
m  UV   no covered event classes declared; omission-detection unverifiable
n  UV   manifest anchor block is absent
...
run run-ael1-valid: AEL-1 R-pending (coverage: declared-only; custody: same-process; anchor: none; retention: 30d/fixture)
```

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

## 5. Prove it rejects tampering

Change one byte of a record and re-run: the signature no longer verifies, `a` FAILs, and the grade
drops to Ungraded. That rejection is what the fixture corpus demonstrates for every falsifiable claim in
`SPEC.md`; run `make check` to see every valid artifact graded and every perturbation rejected.
