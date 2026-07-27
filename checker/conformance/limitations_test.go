// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

type limitationScenario struct {
	Case                  string         `json:"case"`
	GroundTruth           map[string]any `json:"ground_truth"`
	ContradictingEvidence []signedFact   `json:"contradicting_evidence"`
	RecordedClaim         []signedFact   `json:"recorded_claim"`
	BoundFacts            []string       `json:"bound_facts"`
	ExpectedGrade         int            `json:"expected_grade"`
}

type signedFact struct {
	EventID string `json:"event_id"`
	Fact    string `json:"fact"`
	Value   any    `json:"value"`
}

// TestCorpusLimitations pins the intentionally uncomfortable result these
// fixtures exist to demonstrate: a structurally perfect, honestly graded
// evidence chain can preserve a false claim. AEL grades evidence properties,
// not general truth about the world.
func TestCorpusLimitations(t *testing.T) {
	root := filepath.Clean("../../fixtures/limits")
	cases, err := collectLimitationScenarios(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatalf("no limitation scenarios found under %s", root)
	}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, filepath.FromSlash(name))
			scenario := readLimitationScenario(t, filepath.Join(dir, "scenario.json"))
			wantCase := filepath.ToSlash(filepath.Join("limits", name))
			assertScenario(t, wantCase, scenario)

			art, err := ael.LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err != nil {
				t.Fatal(err)
			}
			seqs := map[string]int{}
			for _, fact := range scenario.ContradictingEvidence {
				seqs[fact.EventID] = assertSignedFact(t, art, fact)
			}
			for _, fact := range scenario.RecordedClaim {
				seqs[fact.EventID] = assertSignedFact(t, art, fact)
			}
			assertEvidenceOrder(t, scenario, seqs)
			report := ael.Evaluate(art)
			if len(report.Runs) != 1 {
				t.Fatalf("run count: got %d want 1", len(report.Runs))
			}
			result := report.Runs[0]
			if result.Ungraded || result.Grade != scenario.ExpectedGrade {
				t.Fatalf("grade: got %s want AEL-%d", result.GradeString(), scenario.ExpectedGrade)
			}
		})
	}
}

func collectLimitationScenarios(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "manifest.json" {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}

func assertSignedFact(t *testing.T, art *ael.Artifact, fact signedFact) int {
	t.Helper()
	foundSeq := -1
	for _, log := range art.RecorderLogs {
		for _, record := range log.Records {
			if record.Payload.Event == nil || record.Payload.Event.ID != fact.EventID {
				continue
			}
			if foundSeq >= 0 {
				t.Fatalf("event %q appears more than once", fact.EventID)
			}
			if !record.SignatureOK {
				t.Fatalf("event %q does not have a verified signature", fact.EventID)
			}
			var payload map[string]any
			if err := json.Unmarshal(record.PayloadRaw, &payload); err != nil {
				t.Fatal(err)
			}
			got := collectValues(payload["ext"], fact.Fact)
			if len(got) != 1 {
				t.Fatalf("signed event %q must carry %q exactly once in ext, found %d", fact.EventID, fact.Fact, len(got))
			}
			if !reflect.DeepEqual(got[0], fact.Value) {
				t.Fatalf("signed event %q has %q=%v, scenario claims %v", fact.EventID, fact.Fact, got[0], fact.Value)
			}
			foundSeq = record.Payload.Seq
		}
	}
	if foundSeq < 0 {
		t.Fatalf("signed event %q not found", fact.EventID)
	}
	return foundSeq
}

// collectValues returns every occurrence of key anywhere in the signed ext
// object. A first-match search would return on whichever occurrence Go's
// randomized map iteration reached first, so a scenario naming a fact that
// appears twice would pass or fail by coin flip. Collecting every occurrence and
// requiring exactly one at the call site makes a duplicate key a deterministic
// failure, which is what lets scenario.json claim it names an exact signed fact.
func collectValues(value any, key string) []any {
	var out []any
	switch value := value.(type) {
	case map[string]any:
		if got, ok := value[key]; ok {
			out = append(out, got)
		}
		for _, child := range value {
			out = append(out, collectValues(child, key)...)
		}
	case []any:
		for _, child := range value {
			out = append(out, collectValues(child, key)...)
		}
	}
	return out
}

func readLimitationScenario(t *testing.T, path string) limitationScenario {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var scenario limitationScenario
	if err := json.Unmarshal(raw, &scenario); err != nil {
		t.Fatal(err)
	}
	if scenario.Case == "" {
		t.Fatal("scenario case is empty")
	}
	return scenario
}

func assertScenario(t *testing.T, wantCase string, scenario limitationScenario) {
	t.Helper()
	if scenario.Case != wantCase {
		t.Fatalf("scenario case: got %q want %q", scenario.Case, wantCase)
	}
	if len(scenario.ContradictingEvidence) == 0 || len(scenario.RecordedClaim) == 0 {
		t.Fatal("scenario must bind contradicting evidence and a recorded claim")
	}
	if len(scenario.BoundFacts) == 0 {
		t.Fatal("scenario must bind at least one shared subject fact across evidence and claim")
	}
	assertBoundFacts(t, scenario)
	for key, truth := range scenario.GroundTruth {
		evidence, ok := factByName(scenario.ContradictingEvidence, key)
		if !ok || !reflect.DeepEqual(evidence.Value, truth) {
			t.Fatalf("contradicting evidence does not bind ground-truth fact %q=%v", key, truth)
		}
		claim, ok := factByName(scenario.RecordedClaim, key)
		if !ok {
			t.Fatalf("recorded claim does not address ground-truth fact %q", key)
		}
		if evidence.EventID == claim.EventID {
			t.Fatalf("contradicting evidence and claim use the same event %q", evidence.EventID)
		}
		if reflect.DeepEqual(claim.Value, truth) {
			t.Fatalf("scenario is not born-wrong: %s has the same value in truth and claim", key)
		}
	}
	if len(scenario.GroundTruth) == 0 {
		t.Fatal("scenario must declare at least one ground-truth fact")
	}
}

// assertBoundFacts checks that the claim and the evidence contradicting it are
// about the same subject. Counting occurrences across the two lists pooled
// together is not enough: two evidence events naming the same file satisfy a
// count of two while leaving the claim bound to nothing, which is exactly how a
// "born wrong" scenario stops demonstrating anything. Each bound fact must
// therefore appear on both sides and agree everywhere it appears.
func assertBoundFacts(t *testing.T, scenario limitationScenario) {
	t.Helper()
	for _, name := range scenario.BoundFacts {
		evidence := factsByName(scenario.ContradictingEvidence, name)
		claim := factsByName(scenario.RecordedClaim, name)
		if len(evidence) == 0 || len(claim) == 0 {
			t.Fatalf("bound fact %q must appear in both the contradicting evidence and the recorded claim (evidence=%d claim=%d)",
				name, len(evidence), len(claim))
		}
		values := append(evidence, claim...)
		for _, fact := range values[1:] {
			if !reflect.DeepEqual(fact.Value, values[0].Value) {
				t.Fatalf("bound fact %q disagrees across signed events", name)
			}
		}
	}
}

func assertEvidenceOrder(t *testing.T, scenario limitationScenario, seqs map[string]int) {
	t.Helper()
	for name := range scenario.GroundTruth {
		evidence, _ := factByName(scenario.ContradictingEvidence, name)
		claim, _ := factByName(scenario.RecordedClaim, name)
		if seqs[evidence.EventID] >= seqs[claim.EventID] {
			t.Fatalf("claim event %q must follow contradicting evidence %q", claim.EventID, evidence.EventID)
		}
	}
}

func factsByName(facts []signedFact, name string) []signedFact {
	var out []signedFact
	for _, fact := range facts {
		if fact.Fact == name {
			out = append(out, fact)
		}
	}
	return out
}

func factByName(facts []signedFact, name string) (signedFact, bool) {
	for _, fact := range facts {
		if fact.Fact == name {
			return fact, true
		}
	}
	return signedFact{}, false
}
