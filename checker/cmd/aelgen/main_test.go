// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// corpusFixtureRoot is the generated corpus the report grades.
const corpusFixtureRoot = "../../../fixtures"

// TestReportCasesFailsOnMismatch is the fail-direction test for the corpus
// report. Before this, reportCases computed whether each case matched, printed
// the verdict, and returned nil either way, so a corpus with a failing case
// exited 0. Automation reading only the status saw success while a case failed.
func TestReportCasesFailsOnMismatch(t *testing.T) {
	cases := []caseDef{{
		name:   "ael1/valid",
		expect: expect(3, "pending", nil), // the fixture earns AEL-1, not AEL-3
	}}
	result, err := reportCases(corpusFixtureRoot, cases, reportOptions{})
	if err != nil {
		t.Fatalf("report could not run: %v", err)
	}
	if result.Mismatched != 1 {
		t.Fatalf("mismatched = %d, want 1", result.Mismatched)
	}
	if result.ExitStatus() == 0 {
		t.Error("a corpus with a mismatching case reported success")
	}
}

// TestReportCasesSucceedsWhenCorpusAgrees keeps the fix from being a guard that
// can only fail, which would be as useless as one that can only pass.
func TestReportCasesSucceedsWhenCorpusAgrees(t *testing.T) {
	cases := []caseDef{{
		name:   "ael1/valid",
		expect: expect(1, "pending", map[string]string{"f": "PASS"}),
	}}
	result, err := reportCases(corpusFixtureRoot, cases, reportOptions{})
	if err != nil {
		t.Fatalf("report could not run: %v", err)
	}
	if result.Mismatched != 0 {
		t.Fatalf("mismatched = %d, want 0", result.Mismatched)
	}
	if result.ExitStatus() != 0 {
		t.Errorf("exit status = %d, want 0", result.ExitStatus())
	}
}

// TestReportCasesEmitsMachineReadableCorpus covers the artifact AEL-001 needs:
// a conformance result a package can carry, rather than a hand-written blob.
func TestReportCasesEmitsMachineReadableCorpus(t *testing.T) {
	cases := []caseDef{{
		name:   "ael1/valid",
		expect: expect(1, "pending", map[string]string{"f": "PASS"}),
	}}
	var out strings.Builder
	result, err := reportCases(corpusFixtureRoot, cases, reportOptions{JSON: true, Out: &out})
	if err != nil {
		t.Fatalf("report could not run: %v", err)
	}

	var decoded CorpusReport
	if err := json.Unmarshal([]byte(out.String()), &decoded); err != nil {
		t.Fatalf("machine-readable report is not valid JSON: %v\n%s", err, out.String())
	}
	if decoded.CorpusFormat != 1 {
		t.Errorf("corpus_format = %d, want 1", decoded.CorpusFormat)
	}
	if decoded.Total != 1 || decoded.Matched != 1 || decoded.Mismatched != 0 {
		t.Errorf("totals = %d/%d/%d, want 1/1/0", decoded.Total, decoded.Matched, decoded.Mismatched)
	}
	if len(decoded.Cases) != 1 || decoded.Cases[0].Name != "ael1/valid" {
		t.Fatalf("cases = %+v", decoded.Cases)
	}
	if !decoded.Cases[0].Match {
		t.Error("case reported as not matching")
	}
	if len(decoded.Cases[0].Runs) == 0 || decoded.Cases[0].Runs[0].Grade == "" {
		t.Errorf("case carries no graded run: %+v", decoded.Cases[0])
	}
	if result.Mismatched != decoded.Mismatched {
		t.Errorf("returned mismatch count %d disagrees with the emitted report %d", result.Mismatched, decoded.Mismatched)
	}
}

// TestCorpusReportRecordsMismatchHonestly holds the property the emitted
// artifact exists for: a failing corpus must say so in the file a package
// carries, not only on the terminal.
func TestCorpusReportRecordsMismatchHonestly(t *testing.T) {
	cases := []caseDef{{
		name:   "ael1/valid",
		expect: expect(3, "pending", nil),
	}}
	var out strings.Builder
	if _, err := reportCases(corpusFixtureRoot, cases, reportOptions{JSON: true, Out: &out}); err != nil {
		t.Fatalf("report could not run: %v", err)
	}
	var decoded CorpusReport
	if err := json.Unmarshal([]byte(out.String()), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Mismatched != 1 || decoded.Cases[0].Match {
		t.Errorf("emitted corpus report hides the mismatch: %+v", decoded)
	}
}
