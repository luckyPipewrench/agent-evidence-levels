// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

// version is set by the release build with -ldflags -X. Local source builds
// deliberately identify themselves as development builds.
var version = "devel"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("aelcheck %s\n", releaseVersion())
		return
	}
	jsonOut := flag.Bool("json", false, "print machine-readable result")
	govCheck := flag.Bool("gov", false, "also report the governability extension (reversibility class per action, out of grade)")
	keysDir := flag.String("keys", "", "directory containing published <fingerprint>.pub files")
	flag.Parse()

	if *keysDir == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aelcheck [--json] --keys <keysdir> <artifact-dir>")
		os.Exit(2)
	}

	art, err := ael.LoadArtifact(flag.Arg(0), *keysDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aelcheck: %v\n", err)
		os.Exit(1)
	}
	report := ael.Evaluate(art)
	var gov []ael.GovRun
	if *govCheck {
		gov = ael.Governability(art)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		var payload any = report
		if *govCheck {
			payload = struct {
				Runs          []ael.Result `json:"runs"`
				Governability []ael.GovRun `json:"governability"`
			}{Runs: report.Runs, Governability: gov}
		}
		if err := enc.Encode(payload); err != nil {
			fmt.Fprintf(os.Stderr, "aelcheck: encode result: %v\n", err)
			os.Exit(1)
		}
		os.Exit(conformanceExit(report))
	}

	for i, res := range report.Runs {
		if len(report.Runs) > 1 {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("run %s checks:\n", res.Run)
		}
		for _, id := range ael.CheckIDs(res.Checks) {
			out := res.Checks[id]
			fmt.Printf("%-2s %-4s %s\n", id, out.Status, out.Message)
		}
		if res.OpenStatus != "" {
			fmt.Printf("status: %s\n", res.OpenStatus)
		}
		for _, note := range res.Notes {
			fmt.Printf("note: %s\n", note)
		}
		fmt.Println(res.GradeLine())
	}
	if *govCheck {
		printGovernability(gov)
	}
	writeSelfRunNotice(os.Stdout, report)
	os.Exit(conformanceExit(report))
}

func releaseVersion() string {
	if version == "" {
		return "devel"
	}
	return version
}

// writeSelfRunNotice states what the printed result is and is not.
//
// Section 2 clause 7: a producer-run or operator-run evaluation may publish an
// authenticated result, but that result MUST NOT support a public AEL grade and
// MUST NOT be labelled AEL-n or any equivalent numeric claim. This command hands
// every caller exactly that string, and anyone can run it against their own
// artifact, so without the notice a screenshot of the output reads as the claim
// the clause forbids.
//
// Section 3 item 5 separately REQUIRES the grade line in that exact shape, so
// the answer cannot be to stop printing it. The line stays and the output states
// the standing it has.
//
// The notice accompanies the HUMAN output only. Machine output feeds the package
// emitter, and the package it lands in is an evaluation-package, whose schema
// structurally cannot carry a grade and whose consumer display state is
// EVALUATED rather than VERIFIED. That path already enforces the property; the
// human path was the one handing out an unqualified rung number. Printing prose
// into the JSON would also break the one consumer that exists.
//
// The notice is unconditional. Attaching it to the graded path would leave an
// ungraded run printing a line that still names AEL with nothing qualifying it,
// and an ungraded result is the one a reader is most likely to misread in the
// other direction. It also never renders a rung number itself, because a notice
// that repeated the numeric claim would reproduce the defect it exists to
// qualify.
func writeSelfRunNotice(w io.Writer, report ael.Report) {
	if len(report.Runs) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "This is a self-run evaluation result and is not an AEL grade.")
	_, _ = fmt.Fprintln(w, "A grade is earned only through a verification record issued by an eligible verifier,")
	_, _ = fmt.Fprintln(w, "who must not be the producer or the operator of the artifact evaluated here.")
}

// Exit statuses. These are a contract: automation that only reads the status
// must not mistake "the checker ran" for "the artifact conformed".
//
//	0  every run earned a grade
//	1  the checker could not complete, so nothing was decided
//	2  usage error
//	3  the checker completed and at least one run did not earn a grade
//
// 3 is separate from 1 on purpose. Collapsing them makes a nonconforming
// artifact indistinguishable from a broken tool, and the two demand opposite
// responses: one is a finding about the artifact, the other is a finding about
// the run itself.
const exitNonconforming = 3

// conformanceExit reports the status for an evaluation that completed. A run is
// ungraded when a required check failed or could not be verified, which is the
// honest answer in both cases: nothing was earned. UV on a check that no rung
// requires does not affect this, because the grade computation already decided
// whether the missing evidence mattered.
//
// A report with no runs is nonconforming rather than clean. Nothing was
// evaluated, so nothing was earned, and returning 0 there would contradict the
// contract above. This is defensive today: artifactRuns appends an empty run ID
// when it finds none, so Evaluate always yields at least one run and a caller
// cannot currently reach this branch through the CLI. It is guarded anyway
// because the alternative is a silent fail-open the moment that fallback
// changes or another caller reaches this function directly, and a function
// whose entire job is to report nonconformance should not have a path that
// answers "clean" by default.
func conformanceExit(report ael.Report) int {
	if len(report.Runs) == 0 {
		return exitNonconforming
	}
	for _, res := range report.Runs {
		if res.Ungraded {
			return exitNonconforming
		}
	}
	return 0
}

// printGovernability renders the out-of-grade governability report. It is printed
// separately from the rung so a reversibility finding is never read as a grade.
func printGovernability(gov []ael.GovRun) {
	for _, run := range gov {
		fmt.Printf("\ngovernability %s:\n", run.Run)
		for _, ev := range run.Events {
			line := fmt.Sprintf("  %-12s %-19s %s", ev.EventID, ev.Class, ev.Status)
			if ev.Note != "" {
				line += " (" + ev.Note + ")"
			}
			fmt.Println(line)
		}
		if run.Coverage != nil {
			if len(run.Coverage.Gaps) > 0 {
				fmt.Printf("  coverage: %s (%v)\n", run.Coverage.Status, run.Coverage.Gaps)
			} else {
				fmt.Printf("  coverage: %s\n", run.Coverage.Status)
			}
		}
	}
}
