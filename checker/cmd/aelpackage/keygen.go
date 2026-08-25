// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type keygenResult struct {
	Fingerprint string
	PrivatePath string
	PublicPath  string
}

func runKeygen(arguments []string) int {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	role := flags.String("role", "", "key role: operator, verifier, or status")
	dir := flags.String("dir", "", "trust root containing role-separated public keys")
	if err := flags.Parse(arguments); err != nil {
		fmt.Fprintf(os.Stderr, "aelpackage keygen: %v\n", err)
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "aelpackage keygen: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if strings.TrimSpace(*dir) == "" {
		fmt.Fprintln(os.Stderr, "aelpackage keygen: --dir is required")
		return 2
	}
	if _, err := keygenRoleDirectory(*role); err != nil {
		fmt.Fprintf(os.Stderr, "aelpackage keygen: %v\n", err)
		return 2
	}

	result, err := generateTrustKeypair(*role, *dir, rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aelpackage keygen: %v\n", err)
		return 1
	}
	if _, err := fmt.Printf("fingerprint: %s\nprivate key: %s\npublic key: %s\n", result.Fingerprint, result.PrivatePath, result.PublicPath); err != nil {
		fmt.Fprintf(os.Stderr, "aelpackage keygen: keys written, but report output failed: %v\n", err)
		return 1
	}
	return 0
}

func generateTrustKeypair(role, trustRoot string, random io.Reader) (keygenResult, error) {
	roleDirectory, err := keygenRoleDirectory(role)
	if err != nil {
		return keygenResult{}, err
	}
	privatePath := filepath.Join(filepath.Dir(filepath.Clean(trustRoot)), role+".key")

	public, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return keygenResult{}, fmt.Errorf("generate ed25519 key: %w", err)
	}
	fingerprintBytes := sha256.Sum256(public)
	fingerprint := hex.EncodeToString(fingerprintBytes[:])
	publicDirectory := filepath.Join(trustRoot, roleDirectory)
	publicPath := filepath.Join(publicDirectory, fingerprint+".pub")
	if err := os.MkdirAll(publicDirectory, 0o755); err != nil {
		return keygenResult{}, fmt.Errorf("create %s trust directory: %w", role, err)
	}
	if info, err := os.Lstat(publicDirectory); err != nil {
		return keygenResult{}, fmt.Errorf("inspect %s trust directory: %w", role, err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return keygenResult{}, fmt.Errorf("%s trust directory must be a real directory", role)
	}

	privateText := []byte(base64.StdEncoding.EncodeToString(private) + "\n")
	if err := writeKeyFileExclusive(privatePath, privateText, 0o600); err != nil {
		return keygenResult{}, fmt.Errorf("write private key: %w", err)
	}
	publicText := []byte(base64.StdEncoding.EncodeToString(public) + "\n")
	if err := writeKeyFileExclusive(publicPath, publicText, 0o644); err != nil {
		if cleanupErr := os.Remove(privatePath); cleanupErr != nil {
			return keygenResult{}, fmt.Errorf("write public key: %v; remove incomplete private key: %w", err, cleanupErr)
		}
		return keygenResult{}, fmt.Errorf("write public key: %w", err)
	}

	return keygenResult{Fingerprint: fingerprint, PrivatePath: privatePath, PublicPath: publicPath}, nil
}

func keygenRoleDirectory(role string) (string, error) {
	switch role {
	case "operator":
		return "operators", nil
	case "verifier":
		return "verifiers", nil
	case "status":
		return "status", nil
	default:
		return "", fmt.Errorf("--role must be operator, verifier, or status")
	}
}

func writeKeyFileExclusive(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("refusing to overwrite existing key file %s", path)
		}
		return err
	}
	written := false
	defer func() {
		if !written {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	written = true
	return nil
}
