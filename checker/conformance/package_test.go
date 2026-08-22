// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

func TestVerificationPackageFixtures(t *testing.T) {
	root := filepath.Clean("../../fixtures/packages")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatalf("no verification package fixtures under %s", root)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		entry := entry
		t.Run(entry.Name(), func(t *testing.T) {
			fixtureRoot := filepath.Join(root, entry.Name())
			expected := readPackageExpectation(t, filepath.Join(fixtureRoot, "package-expect.json"))
			statusPath := ""
			statusSignaturePath := ""
			if entry.Name() != "valid_evaluation_package" {
				statusPath = filepath.Join(fixtureRoot, "status.json")
				statusSignaturePath = filepath.Join(fixtureRoot, "status.sig")
			}
			evaluationTime, err := time.Parse(time.RFC3339, "2026-01-03T12:00:00Z")
			if err != nil {
				t.Fatal(err)
			}
			result, err := ael.ValidatePackage(filepath.Join(fixtureRoot, "package"), filepath.Join(fixtureRoot, "trust"), ael.PackageValidationOptions{
				StatusPath:          statusPath,
				StatusSignaturePath: statusSignaturePath,
				EvaluationTime:      evaluationTime,
			})
			if want, ok := expected["diagnostic"]; ok {
				if err == nil {
					t.Fatalf("validation succeeded with display state %s, want diagnostic containing %q", result.DisplayState, want)
				}
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("diagnostic = %q, want substring %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, want := result.DisplayState, expected["display_state"]; got != want {
				t.Fatalf("display state = %q, want %q", got, want)
			}
		})
	}
}

func readPackageExpectation(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]string
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	return expected
}
