// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

func TestGenerateTrustKeypairFingerprintAndPermissions(t *testing.T) {
	trustRoot := filepath.Join(t.TempDir(), "trust")
	result, err := generateTrustKeypair("operator", trustRoot, bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)))
	if err != nil {
		t.Fatal(err)
	}

	privateInfo, err := os.Stat(result.PrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := privateInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("private key mode = %04o, want 0600", got)
	}

	publicText, err := os.ReadFile(result.PublicPath)
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicText)))
	if err != nil {
		t.Fatalf("public key is not standard base64: %v", err)
	}
	if len(public) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(public), ed25519.PublicKeySize)
	}
	fingerprint := sha256.Sum256(public)
	wantFingerprint := hex.EncodeToString(fingerprint[:])
	if result.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint = %q, want %q", result.Fingerprint, wantFingerprint)
	}
	if got := filepath.Base(result.PublicPath); got != wantFingerprint+".pub" {
		t.Fatalf("public key file = %q, want %q", got, wantFingerprint+".pub")
	}
	if got := filepath.Base(filepath.Dir(result.PublicPath)); got != "operators" {
		t.Fatalf("public key role directory = %q, want operators", got)
	}
	if got := filepath.Dir(result.PrivatePath); got != filepath.Dir(trustRoot) {
		t.Fatalf("private key directory = %q, want %q", got, filepath.Dir(trustRoot))
	}
}

func TestGenerateTrustKeypairRoleDirectories(t *testing.T) {
	tests := []struct {
		role string
		dir  string
		fill byte
	}{
		{role: "operator", dir: "operators", fill: 0x51},
		{role: "verifier", dir: "verifiers", fill: 0x52},
		{role: "status", dir: "status", fill: 0x53},
	}
	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			trustRoot := filepath.Join(t.TempDir(), "trust")
			result, err := generateTrustKeypair(test.role, trustRoot, bytes.NewReader(bytes.Repeat([]byte{test.fill}, 64)))
			if err != nil {
				t.Fatal(err)
			}
			if got := filepath.Base(result.PrivatePath); got != test.role+".key" {
				t.Fatalf("private key file = %q, want %q", got, test.role+".key")
			}
			if got := filepath.Base(filepath.Dir(result.PublicPath)); got != test.dir {
				t.Fatalf("public key role directory = %q, want %q", got, test.dir)
			}
		})
	}
}

func TestGenerateTrustKeypairRefusesOverwrite(t *testing.T) {
	trustRoot := filepath.Join(t.TempDir(), "trust")
	if err := os.MkdirAll(trustRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(filepath.Dir(trustRoot), "operator.key")
	const sentinel = "existing private key\n"
	if err := os.WriteFile(privatePath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := generateTrustKeypair("operator", trustRoot, bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)))
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing key file") {
		t.Fatalf("overwrite error = %v, want refusal", err)
	}
	raw, readErr := os.ReadFile(privatePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(raw) != sentinel {
		t.Fatalf("existing private key changed to %q", raw)
	}
}

func TestGenerateTrustKeypairRejectsSymlinkedTrustRoot(t *testing.T) {
	base := t.TempDir()
	realRoot := filepath.Join(base, "real-trust")
	if err := os.MkdirAll(realRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(base, "trust-link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}

	_, err := generateTrustKeypair("operator", linkRoot, bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)))
	if err == nil || !strings.Contains(err.Error(), "must be a real directory, not a symlink") {
		t.Fatalf("symlinked trust root error = %v, want rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(base, "operator.key")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected generation left a private key: %v", statErr)
	}
	entries, readErr := os.ReadDir(realRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected generation wrote into the symlink target: %v", entries)
	}
}

func TestGenerateTrustKeypairRemovesPrivateKeyWhenPublicExists(t *testing.T) {
	trustRoot := filepath.Join(t.TempDir(), "trust")
	randomBytes := bytes.Repeat([]byte{0x54}, 64)
	public, _, err := ed25519.GenerateKey(bytes.NewReader(randomBytes))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(public)
	publicDirectory := filepath.Join(trustRoot, "operators")
	if err := os.MkdirAll(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(publicDirectory, hex.EncodeToString(fingerprint[:])+".pub")
	const sentinel = "existing public key\n"
	if err := os.WriteFile(publicPath, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = generateTrustKeypair("operator", trustRoot, bytes.NewReader(randomBytes))
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing key file") {
		t.Fatalf("overwrite error = %v, want refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(trustRoot), "operator.key")); !os.IsNotExist(statErr) {
		t.Fatalf("failed generation left a private key: %v", statErr)
	}
	raw, readErr := os.ReadFile(publicPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(raw) != sentinel {
		t.Fatalf("existing public key changed to %q", raw)
	}
}

func TestRunKeygenRejectsUnknownRoleWithoutCreatingDirectory(t *testing.T) {
	trustRoot := filepath.Join(t.TempDir(), "trust")
	status, diagnostic := runKeygenCapturingStderr(t, []string{"--role", "unknown", "--dir", trustRoot})
	if status != 2 {
		t.Fatalf("status = %d, want 2", status)
	}
	if !strings.Contains(diagnostic, "--role must be operator, verifier, or status") {
		t.Fatalf("diagnostic = %q", diagnostic)
	}
	if _, err := os.Stat(trustRoot); !os.IsNotExist(err) {
		t.Fatalf("bad role created trust directory: %v", err)
	}
}

func TestRunKeygenReportsOutputFailure(t *testing.T) {
	trustRoot := filepath.Join(t.TempDir(), "trust")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close failed stdout pipe: %v", err)
		}
	}()
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	status := runKeygen([]string{"--role", "operator", "--dir", trustRoot})
	if status != 1 {
		t.Fatalf("status = %d, want 1", status)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(trustRoot), "operator.key")); err != nil {
		t.Fatalf("private key was not preserved after report failure: %v", err)
	}
}

func TestKeygenPairValidatesEmittedPackage(t *testing.T) {
	temp := t.TempDir()
	trustRoot := filepath.Join(temp, "trust")
	operator, err := generateTrustKeypair("operator", trustRoot, bytes.NewReader(bytes.Repeat([]byte{0x43}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	statusKey, err := generateTrustKeypair("status", trustRoot, bytes.NewReader(bytes.Repeat([]byte{0x44}, 64)))
	if err != nil {
		t.Fatal(err)
	}

	checkerPath := filepath.Join(temp, "aelcheck")
	command := exec.Command("go", "build", "-o", checkerPath, "../aelcheck")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build aelcheck: %v\n%s", err, output)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEL_KEYGEN_CONFORMANCE_HELPER", "1")
	out := filepath.Join(temp, "package")
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	status := runEmit([]string{
		"--artifact", filepath.Join(root, "fixtures", "ael1", "valid"),
		"--artifact-keys", filepath.Join(root, "fixtures", "ael1", "valid", "keys"),
		"--checker", checkerPath,
		"--source-revision", "keygen-roundtrip",
		"--operator-key", operator.PrivatePath,
		"--operator-id", "keygen-operator",
		"--producer-id", "keygen-producer",
		"--status-authority-id", "keygen-status",
		"--status-key", statusKey.PublicPath,
		"--spec", filepath.Join(root, "SPEC.md"),
		"--corpus-digest-source", filepath.Join(root, "fixtures", "CASES.txt"),
		"--corpus-version", "keygen-test",
		"--conformance-command", testBinary,
		"--conformance-command", "-test.run=^TestKeygenConformanceHelper$",
		"--custody-acquisition", "declared",
		"--custody-replay", "available",
		"--custody-review", "declared",
		"--custody-issuance", "signed",
		"--coverage-scope", "declared",
		"--coverage-disclosure", "complete-package",
		"--id", "keygen-roundtrip",
		"--issued-at", "2026-01-02T00:00:00Z",
		"--out", out,
	})
	if status != 0 {
		t.Fatalf("emit status = %d, want 0", status)
	}
	result, err := ael.ValidatePackage(out, trustRoot, ael.PackageValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "EVALUATED" {
		t.Fatalf("display state = %q, want EVALUATED", result.DisplayState)
	}
}

func TestKeygenConformanceHelper(t *testing.T) {
	if os.Getenv("AEL_KEYGEN_CONFORMANCE_HELPER") != "1" {
		return
	}
	fmt.Print(`{"cases":[]}`)
	os.Exit(0)
}

func runKeygenCapturingStderr(t *testing.T, arguments []string) (int, string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = original }()
	status := runKeygen(arguments)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	captured, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return status, string(captured)
}
