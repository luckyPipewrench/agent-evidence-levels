package conformance

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

// TestRetentionNeverAffectsGrade locks in SPEC §3.7: retention is a mandatory
// annotation only. Changing or clearing manifest.retention must never raise,
// lower, or otherwise change any per-run grade or R suffix. If a future change
// wires retention into the grade computation, this test fails.
func TestRetentionNeverAffectsGrade(t *testing.T) {
	root := filepath.Clean("../../fixtures")
	cases := []string{"ael2/valid", "ael3/valid", "ael4/valid"}
	variants := []ael.Retention{
		{PeriodDays: 1, Custody: "ephemeral"},
		{PeriodDays: 3650, Custody: "worm-archive"},
		{PeriodDays: 0, Custody: ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			dir := filepath.Join(root, filepath.FromSlash(c))
			base, err := ael.LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err != nil {
				t.Fatal(err)
			}
			wantGrade, baseRetention := snapshot(ael.Evaluate(base))
			if len(wantGrade) == 0 {
				t.Fatalf("%s produced no runs", c)
			}
			annotationMoved := false
			for _, v := range variants {
				art, err := ael.LoadArtifact(dir, filepath.Join(dir, "keys"))
				if err != nil {
					t.Fatal(err)
				}
				art.Manifest.Retention = v
				gotGrade, gotRetention := snapshot(ael.Evaluate(art))
				if len(gotGrade) != len(wantGrade) {
					t.Fatalf("%s retention=%v: run count changed %d -> %d", c, v, len(wantGrade), len(gotGrade))
				}
				for run, g := range wantGrade {
					if gotGrade[run] != g {
						t.Fatalf("%s retention=%v: run %q grade changed %q -> %q; retention must never change a grade", c, v, run, g, gotGrade[run])
					}
				}
				for run, ann := range gotRetention {
					if ann != baseRetention[run] {
						annotationMoved = true
					}
				}
			}
			// Guard against a vacuous pass: the checker must actually read and
			// reflect retention (as an annotation), just never grade on it.
			if !annotationMoved {
				t.Fatalf("%s: retention annotation never changed across variants; test is not exercising retention", c)
			}
		})
	}
}

func snapshot(rep ael.Report) (grade map[string]string, retention map[string]string) {
	grade = map[string]string{}
	retention = map[string]string{}
	for _, r := range rep.Runs {
		grade[r.Run] = r.GradeString() + "/" + r.RLabel()
		retention[r.Run] = strings.TrimSpace(r.Retention)
	}
	return grade, retention
}
