<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Prior art and relationship to existing standards

AEL grades how verifiable a record of AI-agent activity is. It is not an audit-control framework and
not a records-retention regime. It is a cryptographic evidence-grade lens for artifacts produced by
audit and logging mechanisms. This page names the existing work AEL relates to and how, so AEL borrows
established vocabulary instead of coining its own and does not restate what these already cover.

Tags: **ALIGN** (borrow its vocabulary / model), **DEFER** (it owns this area; AEL does not restate
it), **AVOID** (adjacent but out of AEL's lane).

## Tamper-evident records and transparency

| Work | Tag | Relationship |
|---|---|---|
| [RFC 5848: Signed Syslog Messages](https://www.rfc-editor.org/rfc/rfc5848) | ALIGN | Closest prior art to AEL-0/AEL-1 mechanics: origin authentication, integrity, sequencing, and missing-message detection for logs. AEL acknowledges it as precedent for "signed, ordered, gap-evident." |
| RFC 6962 / RFC 9162 (Certificate Transparency) | ALIGN | The append-only-log, Merkle inclusion and consistency proof, and signed tree head model AEL-3 uses. CT proves log inclusion and history consistency, not the truth of the underlying claim, which is exactly AEL's boundary. |
| [RFC 9943: An Architecture for Trustworthy and Transparent Digital Supply Chains](https://www.rfc-editor.org/rfc/rfc9943) (IETF SCITT) | ALIGN | Whole-project neighbor: transparent registries and independently verifiable claims, with an explicit stance that it does not stop an authenticated issuer from making a false claim. Same honesty boundary AEL draws. AEL-3 can consume a SCITT/CT-style log rather than compete with it. |
| Sigstore / Rekor | ALIGN | A concrete transparency-log implementation AEL-3 anchoring can target. |
| RFC 3161 (trusted timestamping) | ALIGN | The vocabulary and trust model for real time. AEL v0.1 does not trust recorder timestamps as wall-clock time; binding to real time would use an RFC 3161 token or a time-bearing log proof. AEL must not silently smuggle a trusted-time assumption into recorder-signed timestamps. |
| [in-toto](https://in-toto.io/) / [SLSA v1.1](https://slsa.dev/spec/v1.1/) | AVOID | They attest how software was built; AEL grades the runtime evidence of what a deployed agent did. Different lifecycle stage, no overlap. |

## Audit-log and records retention (the retention neighborhood)

Retention (SPEC §3.7) lives here, not in the transparency neighborhood above. AEL treats retention as an
operator declaration and does not grade it.

| Work | Tag | Relationship |
|---|---|---|
| [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) | ALIGN | Best vocabulary source for the log lifecycle: generation, storage, retention, preservation, disposal. AEL borrows these terms rather than coining new ones. Operations guidance, not an AEL grade. |
| [NIST SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), AU-11 | ALIGN | Says retention periods are organization-defined, tied to policy, investigations, and regulation. This is the direct basis for AEL not mandating a retention duration. |
| NIST SP 800-53 AU-8 / AU-9 / AU-12 | ALIGN | Time correlation, protection of audit information, and audit record generation. AEL aligns vocabulary; it does not import control compliance into its grade. |
| ISO/IEC 27001 / 27002 (logging controls) | DEFER | An ISMS control framework, broader than AEL. Treat as a compliance neighbor, not an evidence-grade lens. |
| [SEC audit-record retention, 17 CFR 210.2-06](https://www.ecfr.gov/current/title-17/chapter-II/part-210/section-210.2-06), and [HIPAA Security Rule documentation, 45 CFR 164.316](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | DEFER | Sector-specific regimes set concrete, and mutually disagreeing, retention duties. They demonstrate that durations are legal and policy choices, not universal evidence properties, which is why AEL mandates none. |
| [Regulation (EU) 2016/679, Article 5](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679) | DEFER | Pushes retention the other way: do not keep identifiable data longer than necessary. A universal retention minimum would conflict with it, another reason AEL does not set one. |
| WORM / immutable storage | ALIGN, not grade | Storage-control vocabulary. "Stored on WORM" is still an operator assertion unless the artifact carries independently verifiable storage proofs, which v0.1 does not define. |

## Evidence handling

| Work | Tag | Relationship |
|---|---|---|
| [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final), [ISO/IEC 27037:2012](https://www.iso.org/standard/44381.html) | DEFER | Process guidance for evidence preservation. AEL grades cryptographic artifact verifiability, not legal admissibility or chain-of-custody compliance. |

## Governance / risk

| Work | Tag | Relationship |
|---|---|---|
| NIST AI RMF | ALIGN | Grades an organization's risk process (qualitative, maturity). AEL grades an artifact with a checker (verifiable, artifact-level). Complementary, different unit of analysis. |

## One-line positioning

AEL is not an audit-control framework and not a retention regime; it is a cryptographic evidence-grade
lens for the artifacts that audit and logging mechanisms produce.
