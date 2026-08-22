// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bytes"
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
	if _, err := file.Write(bytes.Repeat([]byte("x"), limit+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapturedFile(file, limit); err == nil {
		t.Fatal("readCapturedFile accepted bytes written after the watchdog's last check")
	}
}
