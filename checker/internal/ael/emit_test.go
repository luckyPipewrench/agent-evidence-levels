// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// TestReadCapturedFileRefusesOverflowAfterWatchdog covers a descendant that
// keeps the direct capture descriptor after the watchdog's final stat. The
// read itself must remain bounded, or that last writer can turn an output file
// into an unbounded in-memory allocation before emission refuses it.
func TestReadCapturedFileRefusesOverflowAfterWatchdog(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "capture-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	const limit = 32

	// The ACCEPTING boundary first. Testing only the rejecting side cannot see
	// silent truncation: a bound that clipped at exactly the limit would still
	// reject limit+1 and look correct, while quietly returning short evidence
	// for a legal capture. Truncated evidence that still parses is the outcome
	// this reader exists to refuse.
	if _, err := file.Write(bytes.Repeat([]byte("x"), limit)); err != nil {
		t.Fatal(err)
	}
	accepted, err := readCapturedFile(file, limit)
	if err != nil {
		t.Fatalf("readCapturedFile refused a capture at the limit: %v", err)
	}
	if len(accepted) != limit {
		t.Fatalf("readCapturedFile returned %d bytes, want %d", len(accepted), limit)
	}

	if err := file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	if _, err := file.Write(bytes.Repeat([]byte("x"), limit+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapturedFile(file, limit); err == nil {
		t.Fatal("readCapturedFile accepted bytes written after the watchdog's last check")
	}
}
