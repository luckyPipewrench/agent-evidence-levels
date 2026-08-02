// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

type govEventWant struct {
	Status string `json:"status"`
	Class  string `json:"class"`
}

type govWant struct {
	Events    map[string]govEventWant `json:"events"`
	Coverage  string                  `json:"coverage"`
	Gaps      []string                `json:"gaps"`
	Anomalies []string                `json:"anomalies"`
}

// TestGovernabilityCorpus grades every fixture that ships an expect_gov.json
// through the opt-in governability duty and asserts the reported class, status,
// and AEL-2 coverage match. This is the "requirement needs a fixture that breaks
// a broken artifact" bar for the governability extension: gov/downgrade proves an
// agent-declared class cannot override a policy-bound one, and
// gov/irreversible_scoped_out proves an irreversible action scoped out of the
// correspondence set is caught as a coverage gap.
func TestGovernabilityCorpus(t *testing.T) {
	root := filepath.Clean("../../fixtures")
	var caseDirs []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "expect_gov.json" {
			return nil
		}
		caseDirs = append(caseDirs, filepath.Dir(path))
		return nil
	}); err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	assertGovCorpusMatchesManifest(t, root, caseDirs)
	found := 0
	for _, caseDir := range caseDirs {
		rel, err := filepath.Rel(root, caseDir)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.ToSlash(rel)
		raw, err := os.ReadFile(filepath.Join(caseDir, "expect_gov.json"))
		if err != nil {
			t.Fatalf("%s: read expect_gov.json: %v", name, err)
		}
		found++
		var want govWant
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("%s: parse expect_gov.json: %v", name, err)
		}
		art, err := ael.LoadArtifact(caseDir, filepath.Join(caseDir, "keys"))
		if err != nil {
			t.Fatalf("%s: load artifact: %v", name, err)
		}
		runs := ael.Governability(art)
		if len(runs) != 1 {
			t.Fatalf("%s: expected 1 run, got %d", name, len(runs))
		}
		run := runs[0]

		got := map[string]ael.GovEvent{}
		for _, ev := range run.Events {
			got[ev.EventID] = ev
		}
		for id, w := range want.Events {
			ev, ok := got[id]
			if !ok {
				t.Fatalf("%s: event %s absent from governability output", name, id)
			}
			if string(ev.Status) != w.Status {
				t.Fatalf("%s: event %s status = %s, want %s", name, id, ev.Status, w.Status)
			}
			if ev.Class != w.Class {
				t.Fatalf("%s: event %s class = %s, want %s", name, id, ev.Class, w.Class)
			}
		}

		if want.Coverage != "" {
			if run.Coverage == nil {
				t.Fatalf("%s: want coverage %s, got nil", name, want.Coverage)
			}
			if run.Coverage.Status != want.Coverage {
				t.Fatalf("%s: coverage = %s, want %s", name, run.Coverage.Status, want.Coverage)
			}
			if !govEqualStrings(run.Coverage.Gaps, want.Gaps) {
				t.Fatalf("%s: coverage gaps = %v, want %v", name, run.Coverage.Gaps, want.Gaps)
			}
			if want.Anomalies != nil && !govEqualStrings(run.Coverage.Anomalies, want.Anomalies) {
				t.Fatalf("%s: coverage anomalies = %v, want %v", name, run.Coverage.Anomalies, want.Anomalies)
			}
		}
	}
	if found == 0 {
		t.Fatal("no gov fixtures with expect_gov.json found")
	}
}

// assertGovCorpusMatchesManifest pins the opt-in governability fixtures to the
// generator's committed list. Without it, deleting expect_gov.json silently
// removes that case's governability assertion while its ordinary corpus test
// continues to pass.
func assertGovCorpusMatchesManifest(t *testing.T, root string, caseDirs []string) {
	t.Helper()
	manifestPath := filepath.Join(root, "GOV-CASES.txt")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read governability case manifest: %v (run go run ./checker/cmd/aelgen --out ./fixtures)", err)
	}
	want := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			if want[name] {
				t.Errorf("governability case manifest %s lists case %q more than once", manifestPath, name)
				continue
			}
			want[name] = true
		}
	}
	if len(want) == 0 {
		t.Fatalf("governability case manifest %s is empty", manifestPath)
	}

	got := map[string]bool{}
	for _, caseDir := range caseDirs {
		rel, err := filepath.Rel(root, caseDir)
		if err != nil {
			t.Fatal(err)
		}
		got[filepath.ToSlash(rel)] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("case %q is listed in %s but has no expect_gov.json on disk", name, manifestPath)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("governability fixture %q is on disk but missing from %s", name, manifestPath)
		}
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
