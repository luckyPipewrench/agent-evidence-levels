// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadPrivateKeyRejectsOtherReadableMode(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	keyPath := filepath.Join(t.TempDir(), "operator.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(keyPath); err == nil {
		t.Fatal("readPrivateKey accepted a group-readable key")
	} else if !strings.Contains(err.Error(), "accessible to other accounts") {
		t.Errorf("readPrivateKey rejected the key for the wrong reason: %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(keyPath); err != nil {
		t.Errorf("readPrivateKey rejected mode 0600: %v", err)
	}
}

// TestRunEmitRejectsTrailingArguments covers a gap the validate verb never had:
// flag.Parse leaves unconsumed positional arguments in Args, and runEmit did not
// reject them, so a stray token proceeded to emit a package instead of showing
// usage.
//
// The assertion reads the diagnostic rather than the status alone. Every other
// early refusal also returns 2, so a status-only check passed with this guard
// disabled and proved nothing.
func TestRunEmitRejectsTrailingArguments(t *testing.T) {
	status, diagnostic := runEmitCapturingStderr(t, []string{"--artifact", "somewhere", "unexpected-token"})
	if status != 2 {
		t.Errorf("status = %d, want 2 for a trailing argument", status)
	}
	if !strings.Contains(diagnostic, "unexpected argument") {
		t.Errorf("diagnostic does not name the trailing argument: %q", diagnostic)
	}
}

// TestArgvListPreservesConformanceArguments covers the documented invocation
// form. A single quoted shell string is one executable path to exec, not a
// command line, so every intended argv element needs its own repeated flag.
func TestArgvListPreservesConformanceArguments(t *testing.T) {
	var command argvList
	flags := flag.NewFlagSet("emit", flag.ContinueOnError)
	flags.Var(&command, "conformance-command", "")
	arguments := []string{
		"--conformance-command=./bin/aelgen",
		"--conformance-command=--report",
		"--conformance-command=--json",
		"--conformance-command=--out",
		"--conformance-command=./fixtures",
		// An element containing a space is the case whitespace splitting cannot
		// express, so it is the only case that proves per-occurrence collection.
		// Without it the test passes against a Set that splits on whitespace.
		"--conformance-command=/opt/my suite/extra corpus",
	}
	if err := flags.Parse(arguments); err != nil {
		t.Fatal(err)
	}
	want := []string{"./bin/aelgen", "--report", "--json", "--out", "./fixtures", "/opt/my suite/extra corpus"}
	if !reflect.DeepEqual([]string(command), want) {
		t.Errorf("command = %#v, want %#v", []string(command), want)
	}
}

// runEmitCapturingStderr runs the emit verb with os.Stderr redirected so the
// test can tell one refusal apart from another.
func runEmitCapturingStderr(t *testing.T, arguments []string) (int, string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = writer
	status := runEmit(arguments)
	os.Stderr = original
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	captured, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return status, string(captured)
}
