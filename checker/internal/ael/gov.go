// SPDX-License-Identifier: Apache-2.0

package ael

import (
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
// A class the checker cannot tie to the signed enforcement policy is reported as
// DECLARED (author provenance only), not PASS. A class derived from the signed
// decision's policy is POLICY-BOUND (provenance to the policy at decision time,
// not a proof the class is true). An action with no class is UNCLASSIFIED and is
// treated as irreversible for coverage, so an unlabeled risky action cannot be
// laundered out of scope.

// GovStatus is the provenance status of a reversibility class. It is deliberately
// a distinct type from OutcomeStatus so a governability finding can never be
// mistaken for, or fold into, a rung PASS/FAIL/UV.
type GovStatus string

const (
	GovPolicyBound  GovStatus = "POLICY-BOUND"
	GovDeclared     GovStatus = "DECLARED"
	GovUnclassified GovStatus = "UNCLASSIFIED"
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

// GovCoverage reports the AEL-2 fail-closed coverage check: every irreversible
// (or unclassified-as-irreversible) action's event class must appear in the
// operator-declared correspondence set, or an operator could scope the riskiest
// actions out of the corresponded scope and keep the grade.
type GovCoverage struct {
	Status string   `json:"status"` // OK | GAP | N/A
	Gaps   []string `json:"gaps,omitempty"`
}

// GovRun is the per-run governability report.
type GovRun struct {
	Run      string       `json:"run"`
	Events   []GovEvent   `json:"events"`
	Coverage *GovCoverage `json:"coverage,omitempty"`
}

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
	byID := map[string]*GovEvent{}
	var order []string
	for _, log := range art.RecorderLogs {
		for _, rec := range log.Records {
			if rec.Payload.Type != "activity" || rec.Payload.Event == nil {
				continue
			}
			// Only classify records that verified and are schema-conformant; an
			// unverified record is a rung problem, not a governability one.
			if !rec.SignatureOK || !rec.CanonicalOK || !rec.SchemaOK {
				continue
			}
			ev := classifyEvent(art, rec)
			if prev, ok := byID[ev.EventID]; ok {
				byID[ev.EventID] = mergeEvent(prev, ev)
			} else {
				byID[ev.EventID] = ev
				order = append(order, ev.EventID)
			}
		}
	}
	events := make([]GovEvent, 0, len(order))
	for _, id := range order {
		events = append(events, *byID[id])
	}
	out := GovRun{Run: run, Events: events}
	out.Coverage = coverage(art, events)
	return out
}

// classifyEvent derives the reversibility class and its provenance for one record.
// Precedence: a policy-bound class beats an agent-declared one, because the
// securing runtime must not accept a class the agent asserts over the class the
// enforcement policy assigned.
func classifyEvent(art *Artifact, rec *Record) *GovEvent {
	ev := &GovEvent{EventID: rec.Payload.Event.ID, EventClass: rec.Payload.Event.Class}

	pClass, pOK := policyBoundClass(art, rec)
	dClassRaw, dOK := declaredClass(rec)

	switch {
	case pOK:
		class, known := normalizeClass(pClass)
		ev.Status = GovPolicyBound
		ev.Class = class
		if !known {
			ev.Note = "policy class outside vocabulary, treated as irreversible"
		}
		// A softer agent-declared class over a policy-bound one is ignored, and
		// said so out loud: this is the self-assertion the design forbids.
		if dOK {
			dClass, _ := normalizeClass(dClassRaw)
			if revOrder[dClass] < revOrder[class] {
				ev.Note = "agent-declared class " + dClass + " ignored; policy binds " + class
			}
		}
	case dOK:
		class, known := normalizeClass(dClassRaw)
		ev.Status = GovDeclared
		ev.Class = class
		if !known {
			ev.Note = "declared class outside vocabulary, treated as irreversible"
		}
	default:
		ev.Status = GovUnclassified
		ev.Class = "irreversible" // fail closed
	}
	return ev
}

// policyBoundClass returns the reversibility class for a record's event, derived
// from the signed decision's policy (a reversibility map keyed by event class).
// Because the decision carries the policy hash and the policy bytes hash to it,
// the class is bound to the enforcement policy at decision time.
func policyBoundClass(art *Artifact, rec *Record) (string, bool) {
	if rec.Payload.Decision == nil || rec.Payload.Decision.Policy == "" {
		return "", false
	}
	raw, ok := art.PolicyRaw[rec.Payload.Decision.Policy]
	if !ok {
		return "", false
	}
	var pr policyReversibility
	if err := json.Unmarshal(raw, &pr); err != nil {
		return "", false
	}
	class, ok := pr.Reversibility[rec.Payload.Event.Class]
	if !ok {
		return "", false
	}
	return class, true
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
// keeping the stronger provenance and, on a tie, the least-reversible class.
func mergeEvent(a, b *GovEvent) *GovEvent {
	if statusRank(b.Status) > statusRank(a.Status) {
		return b
	}
	if statusRank(b.Status) == statusRank(a.Status) && revOrder[b.Class] > revOrder[a.Class] {
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

// coverage implements the AEL-2 fail-closed rule: any irreversible or unclassified
// action whose event class is not in the operator-declared correspondence set is a
// gap. With no correspondence declared there is no scope to check against, so the
// result is N/A rather than a false OK.
func coverage(art *Artifact, events []GovEvent) *GovCoverage {
	if art.Manifest.Correspondence == nil || len(art.Manifest.Correspondence.Classes) == 0 {
		return &GovCoverage{Status: "N/A"}
	}
	corr := stringSet(art.Manifest.Correspondence.Classes)
	var gaps []string
	for _, ev := range events {
		mustCover := isIrreversibleClass(ev.Class) || ev.Status == GovUnclassified
		if mustCover && !corr[ev.EventClass] {
			gaps = append(gaps, ev.EventID)
		}
	}
	if len(gaps) == 0 {
		return &GovCoverage{Status: "OK"}
	}
	sort.Strings(gaps)
	return &GovCoverage{Status: "GAP", Gaps: gaps}
}
