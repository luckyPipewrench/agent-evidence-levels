// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

const exitNotCurrent = 3

func main() {
	jsonOut := flag.Bool("json", false, "print machine-readable validation result")
	keysDir := flag.String("keys", "", "trust root containing operators/, verifiers/, and status/ key directories")
	statusPath := flag.String("status", "", "separately signed verification status statement")
	statusSignaturePath := flag.String("status-signature", "", "detached signature for --status")
	statusAt := flag.String("status-at", "", "RFC3339 evaluation time supplied by the relying party")
	maxStatusAge := flag.String("max-status-age", "", "optional maximum accepted age for a current status statement")
	flag.Parse()

	if *keysDir == "" || flag.NArg() != 2 || flag.Arg(0) != "validate" {
		fmt.Fprintln(os.Stderr, "usage: aelpackage [--json] --keys <trust-root> [--status <status.json> --status-signature <status.sig> --status-at <RFC3339> --max-status-age <duration>] validate <package-dir>")
		os.Exit(2)
	}
	var evaluationTime time.Time
	if *statusAt != "" {
		parsed, err := time.Parse(time.RFC3339, *statusAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aelpackage: INVALID: --status-at: %v\n", err)
			os.Exit(2)
		}
		evaluationTime = parsed
	}
	var maximumStatusAge time.Duration
	if *maxStatusAge != "" {
		parsed, err := time.ParseDuration(*maxStatusAge)
		if err != nil || parsed <= 0 {
			fmt.Fprintln(os.Stderr, "aelpackage: INVALID: --max-status-age must be a positive Go duration")
			os.Exit(2)
		}
		maximumStatusAge = parsed
	}
	result, err := ael.ValidatePackage(flag.Arg(1), *keysDir, ael.PackageValidationOptions{
		StatusPath:          *statusPath,
		StatusSignaturePath: *statusSignaturePath,
		EvaluationTime:      evaluationTime,
		MaxStatusAge:        maximumStatusAge,
	})
	if err != nil {
		state := "INVALID"
		var validationErr *ael.PackageValidationError
		if errors.As(err, &validationErr) {
			state = validationErr.State
		}
		fmt.Fprintf(os.Stderr, "aelpackage: %s: %v\n", state, err)
		os.Exit(1)
	}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "aelpackage: encode result: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("%s %s: %s\n", result.Kind, result.ID, result.DisplayState)
	}
	if exitCode := packageExitCode(result.DisplayState); exitCode != 0 {
		os.Exit(exitCode)
	}
}

func packageExitCode(displayState string) int {
	if displayState == "VERIFIED" || displayState == "EVALUATED" {
		return 0
	}
	return exitNotCurrent
}
