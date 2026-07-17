// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Governability is an opt-in extension that reports, alongside but outside the
// AEL rung, whether each recorded action carried a reversibility class and where
// that class came from. It never changes the earned rung: the ladder grades what
// an outside party can verify, governability reports what the record declares
// about whether an action was safe to run unattended.
//
// The vocabulary is the OWASP AISVS v1.0 reversibility classification (C9.2.3):
// read-only, reversible, external-reversible, irreversible.
//
// The coverage invariant is AEL's own rule, not something AISVS states: only a
// POLICY-BOUND (hash-verified) class MAY lower an event's coverage below
// irreversible. Every other status is irreversible for coverage, so the safety
// property cannot be turned off by deleting its input (blanking decision.policy),
// by an agent self-asserting a softer class, or by a schema-invalid record
// silently dropping out of the report.

// GovStatus is the provenance status of a reversibility class. It is deliberately
// a distinct type from OutcomeStatus so a governability finding can never be
// mistaken for, or fold into, a rung PASS/FAIL/UV.
type GovStatus string

const (
	// GovPolicyBound: a hash-verified enforcement policy assigns the class. The
	// only status that MAY lower the coverage gate below irreversible.
	GovPolicyBound GovStatus = "POLICY-BOUND"
	// GovPolicySilent: the referenced policy hash-verified but carries no class
	// for this event's class. Irreversible for coverage; any agent declaration is
	// advisory only.
	GovPolicySilent GovStatus = "POLICY-SILENT"
	// GovPolicyInvalid: a policy was referenced but is missing, malformed,
	// hash-mismatched, or maps this event to an out-of-vocabulary/empty class.
	// Irreversible for coverage.
	GovPolicyInvalid GovStatus = "POLICY-INVALID"
	// GovDeclared: agent declaration only, covering an empty or absent
	// decision.policy. The declared class is reported but never lowers the gate.
	GovDeclared GovStatus = "DECLARED"
	// GovUnclassified: no class from any source. Irreversible for coverage.
	GovUnclassified GovStatus = "UNCLASSIFIED"
	// GovUnassessable: a schema-invalid activity record that was not dropped. Its
	// event id and class were recovered from the payload bytes; it is gated
	// irreversible against the recovered class and fails the coverage gate. If the
	// class is not recoverable the run's coverage becomes UNASSESSABLE.
	GovUnassessable GovStatus = "UNASSESSABLE"
)

// reversibility class vocabulary (AISVS C9.2.3), ordered least to most severe.
var revOrder = map[string]int{
	"read-only":           0,
	"reversible":          1,
	"external-reversible": 2,
	"irreversible":        3,
}

// normalizeClass maps a declared/derived class to the vocabulary. Anything not in
// the vocabulary (including the empty string) fails closed to irreversible.
func normalizeClass(c string) (class string, known bool) {
	if _, ok := revOrder[c]; ok {
		return c, true
	}
	return "irreversible", false
}

func isIrreversibleClass(c string) bool { return c == "irreversible" }

// GovEvent is the governability finding for one activity event.
type GovEvent struct {
	EventID    string    `json:"event_id"`
	Class      string    `json:"class"`       // effective reversibility class
	EventClass string    `json:"event_class"` // the activity event.class (audit category)
	Status     GovStatus `json:"status"`
	Note       string    `json:"note,omitempty"`
}

// GovCoverage reports the AEL-2 fail-closed coverage check: every event that is
// not a POLICY-BOUND non-irreversible class must have its event class appear in
// the operator-declared correspondence set, or an operator could scope the
// riskiest actions out of the corresponded scope and keep the grade.
//
// Status values:
//   - OK: correspondence declared and every event that must be covered is covered.
//   - GAP: at least one event that must be covered is absent from the set.
//   - N/A: no correspondence declared, nothing to check against.
//   - UNASSESSABLE: at least one event's class could not be recovered, so coverage
//     cannot be decided. This is a failing state, never OK and never N/A.
type GovCoverage struct {
	Status    string   `json:"status"` // OK | GAP | N/A | UNASSESSABLE
	Gaps      []string `json:"gaps,omitempty"`
	Anomalies []string `json:"anomalies,omitempty"`
}

// GovRun is the per-run governability report.
type GovRun struct {
	Run      string       `json:"run"`
	Events   []GovEvent   `json:"events"`
	Coverage *GovCoverage `json:"coverage,omitempty"`
}

const anomalyDuplicateIDClassConflict = "DUPLICATE-ID-CLASS-CONFLICT"

type extGov struct {
	Ext struct {
		Gov struct {
			DeclaredReversibility string `json:"declared_reversibility"`
		} `json:"gov"`
	} `json:"ext"`
}

type policyReversibility struct {
	Reversibility map[string]string `json:"reversibility"`
}

// govAccum accumulates the union of findings for one event id across recorders.
type govAccum struct {
	primary       *GovEvent       // the surviving worst-case finding
	eventClasses  map[string]bool // union of activity event.class values seen
	classConflict bool            // two recorders disagreed on event.class
	unassessable  bool            // at least one contributor was UNASSESSABLE
}

// Governability computes the per-run governability report for an artifact. It is
// read-only over already-verified signed bytes and does not touch the rung.
func Governability(art *Artifact) []GovRun {
	var runs []GovRun
	for _, run := range art.Manifest.Runs {
		runs = append(runs, governRun(art.ForRun(run), run))
	}
	return runs
}

func governRun(art *Artifact, run string) GovRun {
	byID := map[string]*govAccum{}
	var order []string
	for _, log := range art.RecorderLogs {
		for _, rec := range log.Records {
			if rec.Payload.Type != "activity" {
				continue
			}
			// Signature/canonical-unverified records are a rung problem, not a
			// governability one, and are left skipped. A schema-invalid record is
			// different: Joshua's rule is never to drop a risky record, so we keep
			// it as UNASSESSABLE below.
			if !rec.SignatureOK || !rec.CanonicalOK {
				continue
			}
			ev := classifyEvent(art, rec)
			if ev == nil {
				continue
			}
			acc, ok := byID[ev.EventID]
			if !ok {
				acc = &govAccum{eventClasses: map[string]bool{}}
				byID[ev.EventID] = acc
				order = append(order, ev.EventID)
			}
			accumulate(acc, ev)
		}
	}
	events := make([]GovEvent, 0, len(order))
	for _, id := range order {
		events = append(events, finalizeEvent(byID[id]))
	}
	out := GovRun{Run: run, Events: events}
	out.Coverage = coverage(art, byID, order)
	return out
}

// accumulate folds one finding into the per-id accumulator, keeping the worst
// case as the primary and recording the union of event.class values so a
// duplicate id with conflicting classes cannot flip coverage with record order.
func accumulate(acc *govAccum, ev *GovEvent) {
	if ev.EventClass != "" {
		if len(acc.eventClasses) > 0 && !acc.eventClasses[ev.EventClass] {
			acc.classConflict = true
		}
		acc.eventClasses[ev.EventClass] = true
	}
	if ev.Status == GovUnassessable {
		acc.unassessable = true
	}
	if acc.primary == nil {
		acc.primary = ev
		return
	}
	acc.primary = mergeEvent(acc.primary, ev)
}

// finalizeEvent produces the reported GovEvent for an id, promoting to
// UNASSESSABLE if any contributor was unassessable and annotating a
// duplicate-id class conflict.
func finalizeEvent(acc *govAccum) GovEvent {
	ev := *acc.primary
	if acc.unassessable && ev.Status != GovUnassessable {
		// A recoverable UNASSESSABLE contributor must not be masked by a clean
		// record for the same id: the risky record still gates irreversible.
		ev.Status = GovUnassessable
		ev.Class = "irreversible"
	}
	if acc.classConflict {
		if ev.Note != "" {
			ev.Note += "; "
		}
		ev.Note += anomalyDuplicateIDClassConflict + ": recorders disagree on event.class for this id"
	}
	return ev
}

// classifyEvent derives the reversibility class and its provenance for one record.
// Precedence: a policy-bound class beats an agent-declared one, because the
// securing runtime must not accept a class the agent asserts over the class the
// enforcement policy assigned.
func classifyEvent(art *Artifact, rec *Record) *GovEvent {
	// Schema-invalid activity record: never drop it. Recover event id + class from
	// the parsed payload if possible and report UNASSESSABLE, gated irreversible.
	if !rec.SchemaOK {
		return recoverUnassessable(rec)
	}

	ev := &GovEvent{EventID: rec.Payload.Event.ID, EventClass: rec.Payload.Event.Class}

	pClass, pState := policyBoundClass(art, rec)

	switch pState {
	case policyBoundOK:
		class, known := normalizeClass(pClass)
		if !known {
			// An out-of-vocabulary or empty policy value is not a valid binding.
			// The class is already irreversible; the label must be POLICY-INVALID,
			// not a mislabeled POLICY-BOUND.
			ev.Status = GovPolicyInvalid
			ev.Class = "irreversible"
			ev.Note = "policy class outside vocabulary or empty; treated as irreversible"
			return ev
		}
		ev.Status = GovPolicyBound
		ev.Class = class
		// A softer agent-declared class over a policy-bound one is ignored, and
		// said so out loud: this is the self-assertion the design forbids.
		if dClassRaw, dOK := declaredClass(rec); dOK {
			dClass, _ := normalizeClass(dClassRaw)
			if revOrder[dClass] < revOrder[class] {
				ev.Note = "agent-declared class " + dClass + " ignored; policy binds " + class
			}
		}
	case policyReferencedBad:
		// The record referenced an enforcement policy the checker cannot
		// hash-verify (missing, malformed, or hash-mismatched). The base R grade
		// rejects exactly this, so governability must not fall through to the
		// agent-declared class. Fail closed to POLICY-INVALID irreversible.
		ev.Status = GovPolicyInvalid
		ev.Class = "irreversible"
		ev.Note = "referenced policy missing, malformed, or hash-mismatched; treated as irreversible"
	case policySilent:
		// A hash-verified policy that carries no class for this event class. The
		// event is not policy-bound; an agent declaration is advisory only and
		// must never lower the gate.
		ev.Status = GovPolicySilent
		ev.Class = "irreversible"
		if dClassRaw, dOK := declaredClass(rec); dOK {
			dClass, _ := normalizeClass(dClassRaw)
			ev.Note = "verified policy silent on this event class; agent-declared " + dClass + " is advisory only"
		} else {
			ev.Note = "verified policy silent on this event class; treated as irreversible"
		}
	default: // policyNone: empty or absent decision.policy
		if dClassRaw, dOK := declaredClass(rec); dOK {
			class, known := normalizeClass(dClassRaw)
			ev.Status = GovDeclared
			ev.Class = class
			if !known {
				ev.Note = "declared class outside vocabulary, treated as irreversible"
			}
		} else {
			ev.Status = GovUnclassified
			ev.Class = "irreversible" // fail closed
		}
	}
	return ev
}

// recoverUnassessable builds the finding for a schema-invalid activity record.
// It never returns nil: even an unrecoverable class produces an UNASSESSABLE
// event so the record is never silently dropped from the report.
func recoverUnassessable(rec *Record) *GovEvent {
	ev := &GovEvent{Status: GovUnassessable, Class: "irreversible"}
	if rec.Payload.Event != nil {
		ev.EventID = rec.Payload.Event.ID
		ev.EventClass = rec.Payload.Event.Class
	}
	note := "schema-invalid activity record"
	if rec.SchemaErr != nil {
		note += ": " + rec.SchemaErr.Error()
	}
	ev.Note = note
	return ev
}

// classRecoverable reports whether a schema-invalid record yielded enough to
// decide coverage: an event id and an event class to check against the
// correspondence set. Without both, coverage for the run is UNASSESSABLE.
func classRecoverable(ev *GovEvent) bool {
	return ev.EventID != "" && ev.EventClass != ""
}

// policyState distinguishes an event with no policy binding from one whose
// referenced policy could not be hash-verified, and from a verified policy that
// is simply silent on this event class.
type policyState int

const (
	policyNone          policyState = iota // no or empty decision.policy reference
	policyReferencedBad                    // policy referenced but missing, malformed, or hash-mismatched
	policySilent                           // policy referenced and hash-verified, but silent on this event class
	policyBoundOK                          // policy referenced, hash-verified, and it classifies this event
)

// policyBoundClass returns the reversibility class for a record's event, derived
// from the signed decision's policy (a reversibility map keyed by event class),
// but ONLY after verifying the policy bytes hash to the hash the decision
// committed to. A referenced policy whose bytes are missing, malformed, or do not
// hash to the decision's policy hash returns policyReferencedBad so the caller
// fails closed, never trusting policy input the base R check would reject.
func policyBoundClass(art *Artifact, rec *Record) (string, policyState) {
	if rec.Payload.Decision == nil || rec.Payload.Decision.Policy == "" {
		return "", policyNone
	}
	want := rec.Payload.Decision.Policy
	raw, ok := art.PolicyRaw[want]
	if !ok {
		return "", policyReferencedBad // policy bytes missing
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != want {
		return "", policyReferencedBad // bytes do not hash to the decision's committed policy hash
	}
	var pr policyReversibility
	if err := json.Unmarshal(raw, &pr); err != nil {
		return "", policyReferencedBad // malformed policy
	}
	class, ok := pr.Reversibility[rec.Payload.Event.Class]
	if !ok {
		return "", policySilent // verified policy, but silent on this event class
	}
	return class, policyBoundOK
}

// declaredClass returns the agent-declared class from ext.gov.declared_reversibility.
// It reads the already-signed payload bytes; ext stays opaque to the rung.
func declaredClass(rec *Record) (string, bool) {
	var eg extGov
	if err := json.Unmarshal(rec.PayloadRaw, &eg); err != nil {
		return "", false
	}
	if eg.Ext.Gov.DeclaredReversibility == "" {
		return "", false
	}
	return eg.Ext.Gov.DeclaredReversibility, true
}

// mergeEvent reconciles two findings for the same event id across recorders,
// keeping the worst case: most severe class first, then strongest provenance.
// Ranking provenance above class severity would let a POLICY-BOUND reversible
// record from one recorder mask an UNCLASSIFIED irreversible record for the same
// event, laundering the riskier action out of coverage. Severity must win.
func mergeEvent(a, b *GovEvent) *GovEvent {
	if revOrder[b.Class] > revOrder[a.Class] {
		return b
	}
	if revOrder[b.Class] == revOrder[a.Class] && statusRank(b.Status) > statusRank(a.Status) {
		return b
	}
	return a
}

func statusRank(s GovStatus) int {
	switch s {
	case GovPolicyBound:
		return 2
	case GovDeclared:
		return 1
	default:
		return 0
	}
}

// coverage implements the AEL-2 fail-closed rule under the coverage invariant:
// only a POLICY-BOUND non-irreversible class MAY lower coverage below
// irreversible. Every other status is gated irreversible, so an event whose event
// class is not in the operator-declared correspondence set is a gap. With no
// correspondence declared there is no scope to check against, so the result is
// N/A rather than a false OK. If any event's class could not be recovered, the
// run's coverage is UNASSESSABLE, a failing state that is never OK or N/A.
func coverage(art *Artifact, byID map[string]*govAccum, order []string) *GovCoverage {
	// Collect duplicate-id class-conflict anomalies regardless of coverage outcome:
	// the conflict is its own finding even when the union is fully covered.
	var anomalies []string
	for _, id := range order {
		if byID[id].classConflict {
			anomalies = append(anomalies, id)
		}
	}
	sort.Strings(anomalies)
	var anomalyList []string
	for _, id := range anomalies {
		anomalyList = append(anomalyList, anomalyDuplicateIDClassConflict+": "+id)
	}

	// Any unrecoverable-class event makes coverage undecidable for the run.
	for _, id := range order {
		ev := finalizeEvent(byID[id])
		if ev.Status == GovUnassessable && !classRecoverable(&ev) {
			return &GovCoverage{Status: "UNASSESSABLE", Anomalies: anomalyList}
		}
	}

	if art.Manifest.Correspondence == nil || len(art.Manifest.Correspondence.Classes) == 0 {
		return &GovCoverage{Status: "N/A", Anomalies: anomalyList}
	}
	corr := stringSet(art.Manifest.Correspondence.Classes)

	// The coverage invariant: an event must be covered (gated irreversible) for
	// every status EXCEPT a POLICY-BOUND non-irreversible class. This is the union
	// check for duplicate ids: every event.class seen for the id must be covered.
	var gaps []string
	for _, id := range order {
		acc := byID[id]
		ev := finalizeEvent(acc)
		if ev.Status == GovPolicyBound && !isIrreversibleClass(ev.Class) {
			continue // the only status permitted to lower the gate
		}
		for cls := range acc.eventClasses {
			if !corr[cls] {
				gaps = append(gaps, id)
				break
			}
		}
	}
	if len(gaps) == 0 {
		return &GovCoverage{Status: "OK", Anomalies: anomalyList}
	}
	sort.Strings(gaps)
	return &GovCoverage{Status: "GAP", Gaps: gaps, Anomalies: anomalyList}
}
