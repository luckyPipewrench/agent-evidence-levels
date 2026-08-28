// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

func TestConformanceExit(t *testing.T) {
	tests := []struct {
		name   string
		report ael.Report
		min    int
		want   int
	}{
		{
			// Nothing evaluated means nothing earned. The earlier version of
			// this case asserted 0 under the same name, which stated the right
			// principle and encoded the opposite of it.
			name:   "no runs earns nothing",
			report: ael.Report{},
			want:   exitNonconforming,
		},
		{
			name:   "explicitly empty run slice",
			report: ael.Report{Runs: []ael.Result{}},
			want:   exitNonconforming,
		},
		{
			name:   "graded run",
			report: ael.Report{Runs: []ael.Result{{Run: "r1", Grade: 1}}},
			want:   0,
		},
		{
			name:   "open run is distinct from final success",
			report: ael.Report{Runs: []ael.Result{{Run: "r1", Open: true}}},
			want:   exitOpen,
		},
		{
			name: "open status takes precedence over a final failure",
			report: ael.Report{Runs: []ael.Result{
				{Run: "r1", Ungraded: true},
				{Run: "r2", Open: true, Ungraded: true},
			}},
			want: exitOpen,
		},
		{
			name:   "grade below minimum",
			report: ael.Report{Runs: []ael.Result{{Run: "r1", Grade: 1}}},
			min:    2,
			want:   exitNonconforming,
		},
		{
			name:   "all runs meet minimum",
			report: ael.Report{Runs: []ael.Result{{Run: "r1", Grade: 2}, {Run: "r2", Grade: 3}}},
			min:    2,
			want:   0,
		},
		{
			name:   "open takes precedence over minimum",
			report: ael.Report{Runs: []ael.Result{{Run: "r1", Grade: 0, Open: true}}},
			min:    2,
			want:   exitOpen,
		},
		{
			name:   "ungraded run",
			report: ael.Report{Runs: []ael.Result{{Run: "r1", Ungraded: true}}},
			want:   exitNonconforming,
		},
		{
			// The failing run is not first. A loop that returned on the first
			// run instead of scanning all of them would report success here,
			// which is the shape that lets a bad run hide behind a good one.
			name: "one ungraded run among graded ones",
			report: ael.Report{Runs: []ael.Result{
				{Run: "r1"},
				{Run: "r2", Ungraded: true},
				{Run: "r3"},
			}},
			want: exitNonconforming,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := conformanceExit(tc.report, tc.min); got != tc.want {
				t.Errorf("conformanceExit = %d, want %d", got, tc.want)
			}
		})
	}
}
