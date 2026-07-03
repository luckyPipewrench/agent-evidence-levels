# Prior art and relationship to existing standards

AEL grades how verifiable a record of AI-agent activity is. It is not an audit-control framework and
not a records-retention regime. It is a cryptographic evidence-grade lens for artifacts produced by
audit and logging mechanisms. This page names the existing work AEL relates to and how, so AEL borrows
established vocabulary instead of coining its own and does not restate what these already cover.

Tags: **CITE** (reference it), **ALIGN** (borrow its vocabulary / model), **DEFER** (it owns this area;
AEL does not restate it), **AVOID** (adjacent but out of AEL's lane).

## Tamper-evident records and transparency

| Work | Tag | Relationship |
|---|---|---|
| RFC 5848 (signed syslog) | CITE + ALIGN | Closest prior art to AEL-0/AEL-1 mechanics: origin authentication, integrity, sequencing, and missing-message detection for logs. AEL acknowledges it as precedent for "signed, ordered, gap-evident." |
| RFC 6962 / RFC 9162 (Certificate Transparency) | ALIGN | The append-only-log, Merkle inclusion and consistency proof, and signed tree head model AEL-3 uses. CT proves log inclusion and history consistency, not the truth of the underlying claim, which is exactly AEL's boundary. |
| IETF SCITT | CITE + ALIGN | Whole-project neighbor: transparent registries and independently verifiable claims, with an explicit stance that it does not stop an authenticated issuer from making a false claim. Same honesty boundary AEL draws. AEL-3 can consume a SCITT/CT-style log rather than compete with it. |
| Sigstore / Rekor | ALIGN | A concrete transparency-log implementation AEL-3 anchoring can target. |
| RFC 3161 (trusted timestamping) | ALIGN | The vocabulary and trust model for real time. AEL v0.1 does not trust recorder timestamps as wall-clock time; binding to real time would use an RFC 3161 token or a time-bearing log proof. AEL must not silently smuggle a trusted-time assumption into recorder-signed timestamps. |
| in-toto / SLSA | CITE | They attest how software was built; AEL grades the runtime evidence of what a deployed agent did. Different lifecycle stage, no overlap. |

## Audit-log and records retention (the retention neighborhood)

Retention (SPEC §3.7) lives here, not in the transparency neighborhood above. AEL treats retention as an
operator declaration and does not grade it.

| Work | Tag | Relationship |
|---|---|---|
| NIST SP 800-92 (log management) | CITE + ALIGN | Best vocabulary source for the log lifecycle: generation, storage, retention, preservation, disposal. AEL borrows these terms rather than coining new ones. Operations guidance, not an AEL grade. |
| NIST SP 800-53 AU-11 (audit record retention) | CITE + ALIGN | Says retention periods are organization-defined, tied to policy, investigations, and regulation. This is the direct basis for AEL not mandating a retention duration. |
| NIST SP 800-53 AU-8 / AU-9 / AU-12 | ALIGN | Time correlation, protection of audit information, and audit record generation. AEL aligns vocabulary; it does not import control compliance into its grade. |
| ISO/IEC 27001 / 27002 (logging controls) | DEFER | An ISMS control framework, broader than AEL. Treat as a compliance neighbor, not an evidence-grade lens. |
| PCI DSS Req. 10, SOX / SEC audit-record rules, HIPAA Security Rule | CITE as examples, DEFER on obligations | Sector-specific regimes with concrete, and mutually disagreeing, retention durations (roughly one year, seven years, six years). They demonstrate that durations are legal and policy choices, not universal evidence properties, which is why AEL mandates none. |
| GDPR storage limitation (Art. 5) | CITE as counterpressure | Pushes retention the other way: do not keep identifiable data longer than necessary. A universal retention minimum would conflict with it, another reason AEL does not set one. |
| WORM / immutable storage | ALIGN, not grade | Storage-control vocabulary. "Stored on WORM" is still an operator assertion unless the artifact carries independently verifiable storage proofs, which v0.1 does not define. |

## Evidence handling

| Work | Tag | Relationship |
|---|---|---|
| NIST SP 800-86, ISO/IEC 27037 (digital evidence / chain of custody) | CITE / DEFER | Process guidance for evidence preservation. AEL grades cryptographic artifact verifiability, not legal admissibility or chain-of-custody compliance. |

## Governance / risk

| Work | Tag | Relationship |
|---|---|---|
| NIST AI RMF | ALIGN | Grades an organization's risk process (qualitative, maturity). AEL grades an artifact with a checker (verifiable, artifact-level). Complementary, different unit of analysis. |

## One-line positioning

AEL is not an audit-control framework and not a retention regime; it is a cryptographic evidence-grade
lens for the artifacts that audit and logging mechanisms produce.
