// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
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
