// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestPackageExitCode(t *testing.T) {
	tests := []struct {
		state string
		want  int
	}{
		{state: "EVALUATED", want: 0},
		{state: "VERIFIED", want: 0},
		{state: "STATUS-UNKNOWN", want: exitNotCurrent},
		{state: "EVALUATION-FAILED", want: exitNotCurrent},
		{state: "CONFORMANCE-FAILED", want: exitNotCurrent},
		{state: "EXPIRED", want: exitNotCurrent},
		{state: "REVOKED", want: exitNotCurrent},
		{state: "SUPERSEDED", want: exitNotCurrent},
	}
	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			if got := packageExitCode(tt.state); got != tt.want {
				t.Fatalf("packageExitCode(%q) = %d, want %d", tt.state, got, tt.want)
			}
		})
	}
}
