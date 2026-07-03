# AEL artifact format v0.1

The format the reference checker consumes and the fixtures use. JSON-based, small on purpose: it
only has to exercise every check in `SPEC.md`. Documented precisely enough for an independent
reimplementation. Signature/verification obeys **exact-bytes discipline**: sign and verify over the
stored canonical bytes, never re-canonicalize on the verify path.

## 1. Layout

An **artifact** is a directory:

```
<artifact>/
  manifest.json            # canonical JSON table of contents (NOT signed; never trusted alone)
  recorders/<id>.jsonl     # one signed record per line, per recorder
  policy/<policy-hash>.json # canonical policy docs referenced by activity decisions (for R)
  anchors.json             # AEL-3 only: transparency-log inclusion proofs
  counterparty.jsonl       # AEL-4 only: signed destination confirmations
```

**Published keys are provided out-of-band, not in the artifact.** The checker is invoked
`aelcheck --keys <keysdir> <artifact>`; `<keysdir>/<fingerprint>.pub` holds a base64 (std, padded)
Ed25519 public key (32 raw bytes). A record referencing a fingerprint absent from `<keysdir>` is
**UNABLE-TO-VERIFY (UV)**, not FAIL. A malformed key file is treated as unavailable for that
fingerprint, so the dependent verification is UV rather than artifact FAIL. A `fingerprint` is the
lowercase hex SHA-256 of the 32 raw public-key bytes.

## 2. Signed record line (exact-bytes discipline)

Each `.jsonl` line is:

```
<b64url_nopad(payload_bytes)>.<b64url_nopad(signature)>
```

- `b64url_nopad` = base64url, alphabet `A-Za-z0-9-_`, **no padding**. A line not matching
  `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$` is malformed → FAIL.
- `signature` = Ed25519 signature over `payload_bytes` (the decoded bytes, exactly).
- **Verify path:** decode `payload_bytes`, `ed25519.Verify(pub, payload_bytes, sig)`. Do not parse
  or re-serialize before verifying.
- **Canonicality enforcement (separate, after signature verify):** parse `payload_bytes` with a
  strict JSON decoder that **rejects duplicate object keys**, then re-serialize with the canonical
  algorithm (§3) and require **byte-equality** with `payload_bytes`. Inequality or duplicate key →
  FAIL (non-canonical). This makes any non-canonical or key-duplicated payload fail even though its
  signature is valid.

## 3. Canonical JSON

RFC 8785 (JCS), restricted to the v0.1 value set:

- **Objects:** keys sorted ascending by UTF-16 code unit; serialized `{"k":v,...}`; no whitespace.
- **Strings:** JCS escaping (minimal escapes; control chars and `"` `\` escaped; no `\/`; `\uXXXX`
  only where required; UTF-8 output).
- **Numbers:** v0.1 permits **integers only**, range [-(2^53-1), 2^53-1], shortest decimal, no
  exponent, no leading zeros, no `+`, `-0` forbidden. A non-integer number → non-canonical → FAIL.
- **Booleans / null:** `true` / `false` / `null`.
- **Arrays:** `[v,...]`, order preserved, no whitespace.
- **Encoding:** UTF-8, no BOM, no trailing newline inside `payload_bytes`.

## 4. Record payloads

Common fields (every record):

| Field | Type | Meaning |
|---|---|---|
| `v` | int | format version, `1` |
| `type` | string | `open` \| `activity` \| `heartbeat` \| `close` |
| `run` | string | run id (identical for all records of a run) |
| `recorder` | string | recorder id (equals the `.jsonl` filename stem) |
| `key` | string | fingerprint of the published key that signs this recorder's records |
| `seq` | int | 0-based, contiguous within `(run,recorder)`; `open` is `seq 0` |
| `prev` | string | lowercase hex SHA-256 of the previous record's `payload_bytes` in this `(run,recorder)`; 64 zeros at `seq 0` |
| `ts` | string | RFC3339 UTC, `...Z` |

Type-specific:

- **`open`** adds: `hmax` (int seconds, heartbeat max interval H; `0` = heartbeats unused, caps the
  recorder at AEL-0), `htol` (int seconds tolerance), and, for AEL-4 runs, `cp_nonce` (string,
  per-run nonce bound into counterparty confirmations).
- **`activity`** adds: `event` = `{"class":<string>,"id":<string>,"dir":"out"|"in"|"internal"}`,
  and OPTIONAL `decision` = `{"policy":<policy-hash>,"request_fp":<string>,
  "inputs":<object string→(int|string|bool)>,"verdict":"allow"|"block"|"defer"}` (present enables R).
- **`heartbeat`** adds nothing; its presence within H is the liveness statement.
- **`close`** adds: `count` (int, total records in this `(run,recorder)` including `open` and
  `close`), `head` (string, hex SHA-256 of the `payload_bytes` of the record at `seq = count-2`, the
  record immediately before `close`).

**Order commitment (AEL-0):** for `seq>0`, `prev` MUST equal hex SHA-256 of the `payload_bytes` at
`seq-1`. Transposition and interior deletion both break this chain (and/or seq contiguity).

**Why tail-truncation is silent at AEL-0:** with no `close` committing to `count`, dropping the last
k records leaves a shorter still-valid chain. AEL-1's signed `close` (count + head) is what makes the
missing tail evident.

## 5. manifest.json (canonical JSON, not signed)

```
{
  "ael_format": 1,
  "runs": ["<run-id>", ...],
  "recorders": [{"id":"<id>","run":"<run-id>","key":"<fingerprint>","file":"recorders/<id>.jsonl"}, ...],
  "claimed_rung": <0..4>,
  "coverage": "declared-only|partial|mediated-only|enforced-total",
  "custody": "same-process|same-host|same-operator|independent",
  "retention": {"period_days": <int>, "custody": "<string>"},
  "correspondence": {"classes": ["<class>", ...], "match": "id"},          // AEL-2+
  "anchor": {"log": "<log-id>", "log_key": "<fingerprint>", "file": "anchors.json"},  // AEL-3+
  "counterparty": {"file": "counterparty.jsonl", "flows": ["<class>", ...], "key": "<fingerprint>"} // AEL-4+
}
```

The manifest is a table of contents. The checker trusts nothing in it that a signature does not
corroborate. `claimed_rung` is compared against the checker's **independently computed** rung.
`coverage`, `custody`, `retention` are operator **declarations** the checker echoes as annotations.
The custody facts the checker proves are limited to key separation: AEL-2 recorders sign under
**different** keys, AEL-3 `anchor.log_key` differs from recorder keys, and AEL-4
`counterparty.key` differs from recorder keys.

## 6. anchors.json (AEL-3, canonical JSON)

```
{
  "log": "<log-id>",
  "tree_head": {"size": <int>, "root": "<hex>", "sig": "<b64std>"},   // sig by log_key over canonical {"log","root","size"}
  "entries": [{"recorder":"<id>","run":"<run>","seq":<int>,"leaf":"<hex>","index":<int>,"proof":["<hex>",...]}, ...]
}
```

Merkle tree is RFC 6962: `leaf_hash = SHA-256(0x00 || data)` where `data` = the anchored record's
`payload_bytes`; `node = SHA-256(0x01 || left || right)`. The checker: verifies `tree_head.sig`
under the provided `log_key` (absent → UV); requires `log_key` to differ from recorder signing keys
(same key → FAIL); for each entry recomputes the root from `leaf`,`index`, `proof`,`size` and
requires it equals `tree_head.root`. The latest anchored `seq` per recorder is the **anchored
head**; records with higher `seq` are **UNANCHORED-WINDOW** (graded at the recorder's unanchored
rung). A re-signed alternative chain whose record at an anchored `seq` differs yields a `leaf` that
does not match the anchored `leaf` → **anchor mismatch (FAIL)**.

## 7. counterparty.jsonl (AEL-4)

Same compact `b64url(payload).b64url(sig)` line form, signed by the counterparty key. Payload:

```
{"v":1,"type":"received","run":"<run>","flow":"<class>","nonce":"<cp_nonce>",
 "received":{"event_id":"<id>"} | {"none":true}}
```

Checker: verify signature under `counterparty.key` (absent key or absent `counterparty.jsonl` → UV);
require `counterparty.key` to differ from recorder signing keys (same key → FAIL); require `run`
equals the artifact run AND `nonce` equals the run `open` record's `cp_nonce` (mismatch →
**wrong-run, rejected**); two-way audit over declared `flows` matching `activity` events
(`dir:"out"`, class in `flows`) to `received.event_id` — report `recorded-but-unconfirmed` and
`confirmed-but-unrecorded`.

## 8. policy docs & R (policy/<policy-hash>.json, canonical JSON)

```
{"v":1,"rules":[{"when":{"field":"<string>","op":"gte|eq|lt|in","value":<int|string|array>},
                 "verdict":"allow|block|defer"}, ...],
 "default":"allow|block|defer"}
```

`policy-hash` = hex SHA-256 of the canonical policy bytes; MUST equal the `decision.policy` that
references it. Evaluator: over `decision.inputs`, apply rules top-down; first match wins, else
`default`. Ops: `gte`/`lt` (integer compare), `eq` (int/string/bool equal), `in` (value in array).

**R check:** every `activity` with a `decision` must satisfy `eval(policy, inputs) == verdict`.
- All activities carry a `decision` and all re-derive → **+R**.
- Some activity lacks a `decision` → **R-pending** (nothing wrong, just not reproducible).
- A `decision` is present but `eval != verdict` (a validly-signed record whose stated inputs do not
  justify its verdict) → **R FAIL** (this is the R perturbation fixture).

## 9. Checker outputs

Per check: `PASS` | `FAIL` | `UV`. `FAIL` = ran and property violated (tamper/nonconformance). `UV`
= could not complete (missing key/format/proof). Both cap the grade; only FAIL impeaches the
artifact. A run with no `close` is `OPEN/ABNORMAL-END` (first-class, distinct from PASS/FAIL).

Final grade line: `AEL-n [+R|R-pending] (coverage: <c>; custody: <c>; anchor: <a>; retention: <r>)`
computed as the **minimum over required sub-dimensions**, cumulative from AEL-0. For each rung above
the grade, the checker prints the dimension that capped it and whether it was FAIL or UV.
