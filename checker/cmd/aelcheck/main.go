// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

func main() {
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
		return
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
