# AEL reference checker: check matrix, rung computation, fixture matrix

Maps every falsifiable duty in `SPEC.md` to a concrete check and a fixture that breaks it. The
checker implements all checks; the fixture corpus proves each one fires.

## 1. Checks (IDs a–t + R)

Every check yields `PASS` | `FAIL` | `UV`.

### AEL-0 (authentic + ordered)
- **a `sig`** — every record signature verifies offline from artifact + `<keysdir>` only. Missing key → UV.
- **b `canon`** — each `payload_bytes` is canonical (re-serialize equals stored) and has no duplicate keys.
- **c `byteflip`** — a record with any payload byte changed must fail `a` (verifier rejects).
- **d `transpose`** — two records swapped must break the `prev`/`seq` chain (reject).
- **e `interior_del`** — an interior record removed must break `prev`/`seq` (reject).
- **w `schema`** — verified closed-schema objects reject unknown top-level keys, except for the
  reserved opaque `ext` object. This covers record payloads, counterparty payloads, anchor entries,
  and `tree_head`.

### AEL-1 (gap/truncation-evident within a run)
- **f `open`** — recorder has an `open` at seq 0 with `hmax>0` (else caps at AEL-0).
- **g `contiguous`** — seq is 0..N contiguous, no gaps (gap → FAIL).
- **h `heartbeat`** — timestamps are monotonic and spacing between consecutive records ≤
  `hmax + htol` (backwards time or exceed → FAIL).
- **i `close_count`** — `close.count` equals records present; `close.head` matches record at count-2 (tail removed → FAIL).
- **j `open_end`** — a run with no `close` classifies `OPEN/ABNORMAL-END` (first-class, not PASS/FAIL).

### AEL-2 (cross-domain omission-evident)
- **k `two_recorders`** — ≥2 recorders on the run, and every recorder on that run independently satisfies AEL-1.
- **l `keys_differ`** — establish each recorder's signing key from verified record signatures, reject a non-empty manifest recorder key that disagrees with that verified key, then require every pair of recorder signing keys on the run to differ (same verified key → FAIL custody).
- **m `cross_audit`** — for non-empty `correspondence.classes`, every covered event on any recorder is present on every other recorder (matched by `event.id`); a one-sided event → FAIL (discrepancy named). Missing or empty classes → UV because omission detection has no checkable scope.

### AEL-3 (externally anchored)
- **n `treehead`** — `anchors.tree_head.sig` verifies under `anchor.log_key` over the exact stored
  `tree_head.signed` bytes, and those bytes canonicalize to the declared log/root/size (absent → UV).
- **o `inclusion`** — every entry's Merkle inclusion proof recomputes to `tree_head.root`.
- **p `alt_history`** — a re-signed alternative chain whose anchored-seq record differs → leaf ≠ anchored leaf → FAIL (anchor mismatch).
- **q `unanchored`** — records with seq beyond the anchored head labeled `UNANCHORED-WINDOW` and capped at the unanchored rung.
- **u `log_key_independent`** — after `n` verifies that `anchor.log_key` signed the tree head, that verified log key must differ from every verified recorder signing key on the run (same key → FAIL).

### AEL-4 (counterparty-confirmed)
- **r `cp_sig`** — every counterparty statement verifies under `counterparty.key` (absent → UV).
- **s `cp_bind`** — statement `run` == artifact run AND `nonce` == run `open.cp_nonce` (mismatch → FAIL, wrong-run), and exactly one of non-empty `received.event_id` or `none:true` is present.
- **t `cp_audit`** — for non-empty `flows`, two-way match of `dir:out` activities to `received.event_id`: report `recorded-but-unconfirmed` and `confirmed-but-unrecorded` (unresolved → FAIL). Empty flows → UV because no confirmation scope is declared.
- **v `cp_key_independent`** — after `r` verifies statements under `counterparty.key`, that verified counterparty key must differ from every verified recorder signing key on the run (same key → FAIL).

### R suffix
- **R1 `replay`** — every `activity.decision` re-derives: `eval(policy, inputs) == verdict`.
- **R2 `replay_mismatch`** — a signed record whose `eval != verdict` → R FAIL (present but not reproducible). No decision on some activity → R-pending.

## 2. Rung computation (minimum over required sub-dimensions)

Per recorder then per run, compute each sub-dimension. The checker evaluates each `manifest.runs`
entry independently and emits one result per run; grade = highest n with AEL-0..n all satisfied
(cumulative) for that run. A required check that FAILs caps the grade below and reports FAIL; one
that is UV caps below and reports UV (distinct).

| Rung | Required (all must PASS) |
|---|---|
| AEL-0 | a, b, w, and chain-consistency for present records (c/d/e are the adversarial fixtures proving a/chain reject) |
| AEL-1 | AEL-0 + f, g, h, i (j governs the no-close outcome) |
| AEL-2 | AEL-1 on each recorder + k, l, m |
| AEL-3 | AEL-2 + n, o, p, q, u |
| AEL-4 | AEL-3 + r, s, t, v |

Sub-dimension → gate: verifier-portability (a not UV) required at every rung, vendor-only ⇒ Ungraded;
chain-continuity gates 0/1; recorder-custody (l) gates 2; external-anchoring (n,o,p,q,u) gates 3;
counterparty-independence (r,s,t,v) gates 4; mediation-coverage, retention = annotations (bound
claims, do not lower the number); decision-reproducibility = the R suffix.

Grade line: `run <id>: AEL-n [+R|R-pending] (coverage: <c>; custody: <c>; anchor: <a>; retention: <r>)`.

## 3. Fixture matrix

Under `fixtures/`, one directory per case. Each case has an `expect.json`:
`{"runs":[{"id":"<run>","grade":<n>|"ungraded","r":"+R"|"pending"|"fail","must":{"<check>":"PASS|FAIL|UV"}}],"note":"..."}`.
The generator (`checker/cmd/aelgen`) builds them all from a fixed test seed (Ed25519 from a labeled
constant seed — test-only material, not a secret). `make check` regenerates + runs the checker and
asserts each case matches its `expect.json`.

| Case | Valid at | Breaks | Expect |
|---|---|---|---|
| `ael0/valid` | AEL-0 | — | grade 0, r pending |
| `ael0/byteflip` | — | c | check a FAIL |
| `ael0/transpose` | — | d | chain FAIL |
| `ael0/interior_del` | — | e | chain FAIL |
| `ael0/noncanonical` | — | b | check b FAIL |
| `ael0/dupkey` | — | b | check b FAIL |
| `ael0/unpublished_key` | — | a (UV) | check a **UV** (grade ungraded, distinct from FAIL) |
| `ael0/bad_key_length` | — | a (UV) | malformed published key is treated as **UV**, not artifact FAIL |
| `ael0/tail_truncated_silent` | AEL-0 | AEL-0 limitation | tail-truncated AEL-0 chain still grades 0 |
| `ael1/valid` | AEL-1 | — | grade 1 |
| `ael1/seq_gap` | — | g | check g FAIL |
| `ael1/heartbeat_gap` | — | h | check h FAIL |
| `ael1/nonmonotonic_ts` | — | h | check h FAIL |
| `ael1/tail_truncated` | — | i | check i FAIL |
| `ael1/no_close` | AEL-0 | j | OPEN/ABNORMAL-END, grade caps at 0 |
| `ael1/unknown_field_rejected` | — | w | unknown signed top-level key FAIL |
| `ael1/ext_field_accepted` | AEL-1 | — | reserved `ext` object ignored for grading |
| `ael2/valid` | AEL-2 | — | grade 2 |
| `ael2/manifest_key_forgery` | — | l | one signing key signs both recorders while manifest declares different recorder keys; check l FAIL, grade caps at 1 |
| `ael2/empty_classes` | — | m (UV) | empty `correspondence.classes` is **UV**, grade caps at 1 |
| `ael2/one_side_deleted` | — | m | check m FAIL (discrepancy named) |
| `ael2/same_key` | — | l | check l FAIL |
| `ael2/third_recorder_shares_key` | — | l | third recorder shares r1's verified signing key; all-pairs check l FAIL |
| `ael2/third_recorder_omits_event` | — | m | third recorder omits a covered event; all-recorder cross-audit m FAIL |
| `ael3/valid` | AEL-3 | — | grade 3 |
| `ael3/treehead_noncanonical_signed` | — | n | exact signed tree-head bytes are non-canonical; check n FAIL |
| `ael3/bad_inclusion` | — | o | check o FAIL |
| `ael3/alt_history` | — | p | check p FAIL (anchor mismatch) |
| `ael3/no_logkey` | AEL-2 | n (UV) | check n **UV**, grade caps at 2 |
| `ael3/no_anchors_file` | AEL-2 | n/o/p/q (UV) | missing anchor proof is **UV**, not artifact FAIL |
| `ael3/logkey_not_independent` | — | u | check u FAIL |
| `ael3/logkey_forgery` | — | u | log key equals a recorder's verified signing key while manifest recorder key would not reveal it; check u FAIL |
| `ael3/unanchored_tail` | AEL-2 | q | check q FAIL (UNANCHORED-WINDOW), grade caps at 2 |
| `ael4/valid` | AEL-4 | — | grade 4, +R |
| `ael4/counterparty_none` | AEL-4 | — | signed `none:true` all-clear path grades 4 |
| `ael4/counterparty_empty_statement` | — | s | neither `received` nor `none:true`; check s FAIL |
| `ael4/wrong_run_confirmation` | — | s | check s FAIL |
| `ael4/no_counterparty_file` | AEL-3 | r/s/t (UV) | missing counterparty proof is **UV**, not artifact FAIL |
| `ael4/unrecorded_delivery` | — | t | check t FAIL |
| `ael4/empty_flows` | — | t (UV) | empty `counterparty.flows` is **UV**, grade caps at 3 |
| `ael4/cp_key_not_independent` | — | v | check v FAIL |
| `r/valid` | (any) | — | +R |
| `r/verdict_mismatch` | — | R2 | r fail |
| `multi_run/mixed` | AEL-2 / AEL-0 | per-run grading | run A grades AEL-2; run B missing close grades AEL-0 |

Every falsifiable claim in `SPEC.md` has a row here. `make check` printing all rows PASS/FAIL/UV as
expected is the proof the standard is earned, not asserted.
