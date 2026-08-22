// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

// Section 2 clause 7 is explicit: a producer-run or operator-run evaluation may
// publish an authenticated result, but that result MUST NOT support a public
// AEL grade, and MUST NOT be labelled AEL-n or any equivalent numeric claim.
//
// The checker hands every caller exactly that string. `run x: AEL-1 R-pending`
// is what it prints, anyone can run it against their own artifact, and nothing
// in the output said what the result was not. A screenshot of it reads as a
// grade, which is the claim the clause forbids.
//
// Section 3 item 5 separately REQUIRES the grade line in that exact shape, so
// the fix cannot be to stop printing it. The output has to carry the standing
// it actually has.
func TestSelfRunNoticeAccompaniesEveryGradeLine(t *testing.T) {
	report := ael.Report{Runs: []ael.Result{{
		Run:       "run-under-test",
		Grade:     1,
		R:         "pending",
		Coverage:  "declared-only",
		Custody:   "same-process",
		Anchor:    "none",
		Retention: "operator-declared 30d/fixture",
	}}}

	var out bytes.Buffer
	writeSelfRunNotice(&out, report)
	notice := out.String()

	if notice == "" {
		t.Fatal("no notice was written alongside a printed grade line")
	}
	// The reader has to learn three things: this was self-run, it is not a
	// grade, and what would make it one.
	for _, required := range []string{"not an AEL grade", "verification record", "eligible verifier"} {
		if !strings.Contains(notice, required) {
			t.Errorf("notice does not state %q: %q", required, notice)
		}
	}
}

// TestSelfRunNoticeAppearsEvenWhenNothingEarnedAGrade covers the state a reader
// is most likely to misread in the other direction. An ungraded run still
// prints a line naming AEL, so the notice has to be unconditional rather than
// attached to the success path.
func TestSelfRunNoticeAppearsEvenWhenNothingEarnedAGrade(t *testing.T) {
	report := ael.Report{Runs: []ael.Result{{
		Run:      "run-ungraded",
		Ungraded: true,
		R:        "pending",
	}}}

	var out bytes.Buffer
	writeSelfRunNotice(&out, report)
	if out.Len() == 0 {
		t.Error("an ungraded run printed no notice, so the output still reads as an AEL verdict")
	}
}

// TestSelfRunNoticeNeverClaimsAGrade guards the fix against becoming the defect
// it repairs. The notice must not itself render a numeric AEL claim.
func TestSelfRunNoticeNeverClaimsAGrade(t *testing.T) {
	report := ael.Report{Runs: []ael.Result{{Run: "r", Grade: 4, R: "+R"}}}
	var out bytes.Buffer
	writeSelfRunNotice(&out, report)
	for _, forbidden := range []string{"AEL-0", "AEL-1", "AEL-2", "AEL-3", "AEL-4"} {
		if strings.Contains(out.String(), forbidden) {
			t.Errorf("notice renders %q, which is the numeric claim it exists to qualify: %q", forbidden, out.String())
		}
	}
}

// TestNoticeReachesHumanOutputAndNotMachineOutput exercises the built command
// rather than the helper.
//
// The sibling tests call writeSelfRunNotice directly, so they say nothing about
// whether the notice reaches the output a person reads, and nothing about the
// property that actually matters downstream: machine output must stay parseable.
// The emitter consumes that JSON, so prose leaking into it would corrupt
// evidence rather than merely look untidy, and a helper-level test cannot see it.
func TestNoticeReachesHumanOutputAndNotMachineOutput(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "aelcheck")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aelcheck: %v\n%s", err, out)
	}

	artifact := filepath.Join("..", "..", "..", "fixtures", "ael1", "valid")
	keys := filepath.Join(artifact, "keys")

	human, err := exec.Command(binary, "--keys", keys, artifact).Output()
	if err != nil {
		t.Fatalf("human run: %v", err)
	}
	if !strings.Contains(string(human), "not an AEL grade") {
		t.Errorf("human output carries no self-run notice:\n%s", human)
	}

	machine, err := exec.Command(binary, "--json", "--keys", keys, artifact).Output()
	if err != nil {
		t.Fatalf("machine run: %v", err)
	}
	if strings.Contains(string(machine), "not an AEL grade") {
		t.Errorf("the notice leaked into machine output:\n%s", machine)
	}
	var report struct {
		Runs []struct {
			Run string `json:"run"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(machine, &report); err != nil {
		t.Fatalf("machine output is not valid JSON: %v\n%s", err, machine)
	}
	if len(report.Runs) == 0 {
		t.Error("machine output carries no runs")
	}
}
