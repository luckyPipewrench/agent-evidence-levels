# AEL evidence registry

Grades for concrete deployments and mechanisms, one row each. This registry takes pull requests.

**The rule, applied to every row including the editor's:** a numeric grade requires a verification
record satisfying `SPEC.md` section 5.2, signed by a verifier that is neither the producer nor the
operator. The package carries the submitted artifact and required replay material as content-addressed
blobs. A producer declaration with no such record is marked **asserted capability** and carries **no
grade**. A grade is written in full per run: `run <id>: AEL-n [+R | R-pending] (coverage: ...;
custody: ...; anchor: ...; retention: ...)`. A bare number is not a grade.

## Editor's declaration

**Grade: none. Status: asserted capability.**

The editor declares that its deployment can emit signed, hash-linked decision records with
policy-hash binding and can provide offline verification inputs. These are producer statements about
artifact capability. They do not earn AEL-0 until an eligible verifier evaluates one exact exported
run with a checker that passes the published conformance corpus and signs the resulting verification
package.

Missing for AEL-1, to be built: heartbeat records, and a signed run-close committing to a record
count. The current deployment writes a transcript root on clean shutdown only; a crash or a
truncation before shutdown leaves no artifact that makes the missing tail evident.

R is pending: the recorded verdict cannot yet be re-derived from the record alone, because the
decision consults live runtime state beyond the policy hash and the request fingerprint. R is
earned when records carry the full replay inputs, and not before.

Evidence: **asserted capability**. No signed verification package from an eligible verifier is
attached.

If this scale graded its own editor at the top, you should distrust the scale.

## Registry

| Deployment / mechanism | Grade | Evidence | Notes |
|---|---|---|---|
| Editor's own deployment | No grade | asserted capability | See editor's declaration above. |

To add a graded row, open a pull request with an immutable link to the verification record. The signed
package must carry the exact artifact, verification inputs, artifact-evaluation result, and
conformance-corpus result as content-addressed blobs. Its manifest must identify the specification,
checker executable and source revision, verifier and relationships, and status authority. A producer-run
or operator-run `aelcheck` result is useful preparation but cannot support a public grade. Rows without
the required record may list a capability declaration only and must say **No grade**.
