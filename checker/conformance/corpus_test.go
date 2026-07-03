package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

type expectation struct {
	Grade any               `json:"grade"`
	R     string            `json:"r"`
	Must  map[string]string `json:"must"`
	Runs  []runExpectation  `json:"runs"`
	Note  string            `json:"note"`
}

type runExpectation struct {
	ID    string            `json:"id"`
	Grade any               `json:"grade"`
	R     string            `json:"r"`
	Must  map[string]string `json:"must"`
}

func TestCorpus(t *testing.T) {
	root := filepath.Clean("../../fixtures")
	entries, err := collectExpectations(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatalf("no fixtures found under %s; run go run ./checker/cmd/aelgen --out ./fixtures", root)
	}
	for _, entry := range entries {
		entry := entry
		t.Run(entry, func(t *testing.T) {
			caseDir := filepath.Join(root, filepath.FromSlash(entry))
			exp, err := readExpectation(filepath.Join(caseDir, "expect.json"))
			if err != nil {
				t.Fatal(err)
			}
			art, err := ael.LoadArtifact(caseDir, filepath.Join(caseDir, "keys"))
			if err != nil {
				t.Fatal(err)
			}
			report := ael.Evaluate(art)
			runExps := exp.runExpectations()
			if len(report.Runs) != len(runExps) {
				t.Fatalf("run count mismatch: got %d want %d", len(report.Runs), len(runExps))
			}
			byRun := map[string]ael.Result{}
			for _, res := range report.Runs {
				byRun[res.Run] = res
			}
			for _, runExp := range runExps {
				res, ok := byRun[runExp.ID]
				if !ok {
					t.Fatalf("missing run result %q", runExp.ID)
				}
				if got, want := gradeString(res), expectedGrade(runExp.Grade); got != want {
					t.Fatalf("run %s grade mismatch: got %s want %s\nnotes: %v", runExp.ID, got, want, res.Notes)
				}
				if res.R != runExp.R {
					t.Fatalf("run %s R mismatch: got %s want %s", runExp.ID, res.R, runExp.R)
				}
				for id, want := range runExp.Must {
					got, ok := res.Checks[id]
					if !ok {
						t.Fatalf("run %s missing check %s", runExp.ID, id)
					}
					if string(got.Status) != want {
						t.Fatalf("run %s check %s mismatch: got %s want %s\nmessage: %s", runExp.ID, id, got.Status, want, got.Message)
					}
				}
			}
		})
	}
}

func (e expectation) runExpectations() []runExpectation {
	if len(e.Runs) > 0 {
		return e.Runs
	}
	return []runExpectation{{ID: "", Grade: e.Grade, R: e.R, Must: e.Must}}
}

func collectExpectations(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "expect.json" {
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

func readExpectation(path string) (expectation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return expectation{}, err
	}
	var exp expectation
	if err := json.Unmarshal(raw, &exp); err != nil {
		return expectation{}, err
	}
	return exp, nil
}

func gradeString(res ael.Result) string {
	if res.Ungraded {
		return "ungraded"
	}
	return fmt.Sprintf("AEL%d", res.Grade)
}

func expectedGrade(v any) string {
	switch t := v.(type) {
	case float64:
		return fmt.Sprintf("AEL%d", int(t))
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}
