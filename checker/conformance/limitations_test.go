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
			if !findValue(payload["ext"], fact.Fact, fact.Value) {
				t.Fatalf("signed event %q does not contain %q=%v", fact.EventID, fact.Fact, fact.Value)
			}
			foundSeq = record.Payload.Seq
		}
	}
	if foundSeq < 0 {
		t.Fatalf("signed event %q not found", fact.EventID)
	}
	return foundSeq
}

func findValue(value any, key string, want any) bool {
	switch value := value.(type) {
	case map[string]any:
		if got, ok := value[key]; ok && reflect.DeepEqual(got, want) {
			return true
		}
		for _, child := range value {
			if findValue(child, key, want) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if findValue(child, key, want) {
				return true
			}
		}
	}
	return false
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

func assertBoundFacts(t *testing.T, scenario limitationScenario) {
	t.Helper()
	all := append(append([]signedFact{}, scenario.ContradictingEvidence...), scenario.RecordedClaim...)
	for _, name := range scenario.BoundFacts {
		var values []any
		for _, fact := range all {
			if fact.Fact == name {
				values = append(values, fact.Value)
			}
		}
		if len(values) < 2 {
			t.Fatalf("bound fact %q must appear at least twice", name)
		}
		for _, value := range values[1:] {
			if !reflect.DeepEqual(value, values[0]) {
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

func factByName(facts []signedFact, name string) (signedFact, bool) {
	for _, fact := range facts {
		if fact.Fact == name {
			return fact, true
		}
	}
	return signedFact{}, false
}
