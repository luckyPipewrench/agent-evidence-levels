// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

type govEventWant struct {
	Status string `json:"status"`
	Class  string `json:"class"`
}

type govWant struct {
	Events   map[string]govEventWant `json:"events"`
	Coverage string                  `json:"coverage"`
	Gaps     []string                `json:"gaps"`
}

// TestGovernabilityCorpus grades every fixture that ships an expect_gov.json
// through the opt-in governability duty and asserts the reported class, status,
// and AEL-2 coverage match. This is the "requirement needs a fixture that breaks
// a broken artifact" bar for the governability extension: gov/downgrade proves an
// agent-declared class cannot override a policy-bound one, and
// gov/irreversible_scoped_out proves an irreversible action scoped out of the
// correspondence set is caught as a coverage gap.
func TestGovernabilityCorpus(t *testing.T) {
	root := filepath.Clean("../../fixtures/gov")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read gov fixtures dir: %v", err)
	}
	found := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		caseDir := filepath.Join(root, e.Name())
		raw, err := os.ReadFile(filepath.Join(caseDir, "expect_gov.json"))
		if err != nil {
			continue
		}
		found++
		var want govWant
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("%s: parse expect_gov.json: %v", e.Name(), err)
		}
		art, err := ael.LoadArtifact(caseDir, filepath.Join(caseDir, "keys"))
		if err != nil {
			t.Fatalf("%s: load artifact: %v", e.Name(), err)
		}
		runs := ael.Governability(art)
		if len(runs) != 1 {
			t.Fatalf("%s: expected 1 run, got %d", e.Name(), len(runs))
		}
		run := runs[0]

		got := map[string]ael.GovEvent{}
		for _, ev := range run.Events {
			got[ev.EventID] = ev
		}
		for id, w := range want.Events {
			ev, ok := got[id]
			if !ok {
				t.Fatalf("%s: event %s absent from governability output", e.Name(), id)
			}
			if string(ev.Status) != w.Status {
				t.Fatalf("%s: event %s status = %s, want %s", e.Name(), id, ev.Status, w.Status)
			}
			if ev.Class != w.Class {
				t.Fatalf("%s: event %s class = %s, want %s", e.Name(), id, ev.Class, w.Class)
			}
		}

		if want.Coverage != "" {
			if run.Coverage == nil {
				t.Fatalf("%s: want coverage %s, got nil", e.Name(), want.Coverage)
			}
			if run.Coverage.Status != want.Coverage {
				t.Fatalf("%s: coverage = %s, want %s", e.Name(), run.Coverage.Status, want.Coverage)
			}
			if !govEqualStrings(run.Coverage.Gaps, want.Gaps) {
				t.Fatalf("%s: coverage gaps = %v, want %v", e.Name(), run.Coverage.Gaps, want.Gaps)
			}
		}
	}
	if found == 0 {
		t.Fatal("no gov fixtures with expect_gov.json found")
	}
}

func govEqualStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
