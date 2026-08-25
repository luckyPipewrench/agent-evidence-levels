// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadArtifactRejectsUnsupportedAELFormat(t *testing.T) {
	for _, format := range []string{"0", "2"} {
		t.Run("ael_format "+format, func(t *testing.T) {
			dir := t.TempDir()
			raw := `{"ael_format":` + format + `,"recorders":[],"runs":["run-a"]}`
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(raw), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err == nil {
				t.Fatal("LoadArtifact accepted an unsupported ael_format")
			}
			if !strings.Contains(err.Error(), "unsupported ael_format "+format) {
				t.Fatalf("error %q does not name the unsupported format", err.Error())
			}
		})
	}
}

func TestLoadArtifactRejectsNonCanonicalManifest(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "whitespace",
			raw:  "{\n  \"ael_format\":1,\n  \"runs\":[\"run-a\"],\n  \"recorders\":[]\n}\n",
			want: "manifest.json is not canonical",
		},
		{
			name: "duplicate key",
			raw:  `{"ael_format":1,"recorders":[],"runs":["run-a"],"runs":["run-b"]}`,
			want: "duplicate object key",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(tc.raw), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err == nil {
				t.Fatal("LoadArtifact accepted a non-canonical manifest")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
