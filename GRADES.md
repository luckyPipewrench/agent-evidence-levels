# AEL evidence registry

Grades for concrete deployments and mechanisms, one row each. This registry takes pull requests.

**The rule, applied to every row including the editor's:** a numeric grade requires an immutable
artifact and an independently authenticated verification record satisfying `SPEC.md` section 5.2.
A producer declaration with no such record is marked **asserted capability** and carries **no
grade**. A grade is written in full per run: `run <id>: AEL-n [+R | R-pending] (coverage: ...;
custody: ...; anchor: ...; retention: ...)`. A bare number is not a grade.

## Editor's declaration

**Grade: none. Status: asserted capability.**

The editor declares that its deployment can emit signed, hash-linked decision records with
policy-hash binding and can provide offline verification inputs. These are producer statements about
artifact capability. They do not earn AEL-0 until a separate verifier evaluates one exact exported
run, performs the required artifact-derived perturbations, and authenticates the resulting record.

Missing for AEL-1, to be built: heartbeat records, and a signed run-close committing to a record
count. The current deployment writes a transcript root on clean shutdown only; a crash or a
truncation before shutdown leaves no artifact that makes the missing tail evident.

R is pending: the recorded verdict cannot yet be re-derived from the record alone, because the
decision consults live runtime state beyond the policy hash and the request fingerprint. R is
earned when records carry the full replay inputs, and not before.

Evidence: **asserted capability**. No production artifact or independently authenticated
verification record is attached.

If this scale graded its own editor at the top, you should distrust the scale.

## Registry

| Deployment / mechanism | Grade | Evidence | Notes |
|---|---|---|---|
| Editor's own deployment | No grade | asserted capability | See editor's declaration above. |

To add a graded row, open a pull request with immutable links to the artifact and verification record.
The record must bind the artifact digest, verification-input digest, checker and specification
versions, full output, artifact-derived perturbation transcript, verifier identity and relationship,
and status authority. Running `aelcheck` yourself is useful preparation but is not an independent
verification record. Rows without the required record may list a capability declaration only and
must say **No grade**.
