// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLIVersionReporting(t *testing.T) {
	const releaseVersion = "v9.8.7-test"
	root := versionTestRoot(t)
	for _, command := range []string{"aelcheck", "aelgen", "aelpackage"} {
		for _, tc := range []struct {
			name    string
			ldflags string
			want    string
		}{
			{name: "source build", want: "devel"},
			{name: "release build", ldflags: "-X main.version=" + releaseVersion, want: releaseVersion},
			{name: "empty release value", ldflags: "-X main.version=", want: "devel"},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				binary := filepath.Join(t.TempDir(), command)
				args := []string{"build", "-o", binary}
				if tc.ldflags != "" {
					args = append(args, "-ldflags", tc.ldflags)
				}
				args = append(args, "./checker/cmd/"+command)
				build := exec.Command("go", args...)
				build.Dir = root
				if output, err := build.CombinedOutput(); err != nil {
					t.Fatalf("build %s: %v\n%s", command, err, output)
				}

				output, err := exec.Command(binary, "--version").CombinedOutput()
				if err != nil {
					t.Fatalf("run %s --version: %v\n%s", command, err, output)
				}
				if got, want := string(output), command+" "+tc.want+"\n"; got != want {
					t.Fatalf("%s --version = %q, want %q", command, got, want)
				}
			})
		}
	}
}

func TestReleaseBuildsInjectCLIVersion(t *testing.T) {
	root := versionTestRoot(t)
	config, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	for _, command := range []string{"aelcheck", "aelgen", "aelpackage"} {
		t.Run(command, func(t *testing.T) {
			start := strings.Index(string(config), "\n  - id: "+command+"\n")
			if start < 0 {
				t.Fatalf("release configuration has no %s build", command)
			}
			block := string(config[start:])
			if end := strings.Index(block[1:], "\n  - id: "); end >= 0 {
				block = block[:end+1]
			}
			if !strings.Contains(block, "main: ./checker/cmd/"+command) {
				t.Fatalf("%s build does not use its command source", command)
			}
			if !strings.Contains(block, "-X main.version={{ .Version }}") {
				t.Fatalf("%s build does not inject the release version", command)
			}
		})
	}
}

func versionTestRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate version test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}
