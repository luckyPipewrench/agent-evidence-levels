// SPDX-License-Identifier: Apache-2.0

package ael

import "testing"

// Section 3.7 requires the checker to report the declared retention value with
// every per-run grade AND to label it as an operator declaration. The value
// alone satisfied only the first half: `30d/fixture` sat in a list beside
// custody and anchor, which the checker genuinely verifies, so it read as
// something established rather than something the operator asserted.
//
// Retention is a promise about future storage that no checker can verify from
// an artifact presented today, which is exactly why the label carries weight.
func TestRetentionAnnotationLabelsTheOperatorDeclaration(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		retention Retention
		want      string
	}{
		{
			name:      "period and custody declared",
			retention: Retention{PeriodDays: 30, Custody: "fixture"},
			want:      "operator-declared 30d/fixture",
		},
		{
			name:      "nothing declared",
			retention: Retention{},
			want:      "not declared",
		},
		{
			name:      "period declared without custody",
			retention: Retention{PeriodDays: 30},
			want:      "operator-declared 30d/custody-undeclared",
		},
		{
			name:      "custody declared without period",
			retention: Retention{Custody: "cold-storage"},
			want:      "operator-declared period-undeclared/cold-storage",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := retentionAnnotation(testCase.retention)
			if got != testCase.want {
				t.Errorf("retentionAnnotation(%+v) = %q, want %q", testCase.retention, got, testCase.want)
			}
		})
	}
}

// TestRetentionAnnotationIsNeverABareValue is the property the section demands,
// stated so it holds for declarations this test does not enumerate. A reader
// scanning a grade line must not be able to mistake retention for a verified
// dimension, whatever the operator put in the manifest.
func TestRetentionAnnotationIsNeverABareValue(t *testing.T) {
	for _, retention := range []Retention{
		{PeriodDays: 30, Custody: "fixture"},
		{PeriodDays: 1, Custody: "s3"},
		{PeriodDays: 3650, Custody: "tape"},
		{PeriodDays: 7},
		{Custody: "cold-storage"},
		{},
	} {
		annotation := retentionAnnotation(retention)
		if !containsAny(annotation, "declared") {
			t.Errorf("retentionAnnotation(%+v) = %q, which does not label the value as a declaration", retention, annotation)
		}
	}
}

// TestGradeLineCarriesTheLabelledRetention holds the requirement where §3.7
// actually places it: on every per-run grade, not merely available from a
// helper a caller might not use.
func TestGradeLineCarriesTheLabelledRetention(t *testing.T) {
	result := Result{
		Run:       "run-under-test",
		Grade:     1,
		R:         "pending",
		Coverage:  "declared-only",
		Custody:   "same-process",
		Anchor:    "none",
		Retention: retentionAnnotation(Retention{PeriodDays: 30, Custody: "fixture"}),
	}
	line := result.GradeLine()
	if !containsAny(line, "retention: operator-declared 30d/fixture") {
		t.Errorf("grade line does not carry the labelled retention: %q", line)
	}
}

func containsAny(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
