package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

func main() {
	jsonOut := flag.Bool("json", false, "print machine-readable result")
	keysDir := flag.String("keys", "", "directory containing published <fingerprint>.pub files")
	flag.Parse()

	if *keysDir == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aelcheck [--json] --keys <keysdir> <artifact-dir>")
		os.Exit(2)
	}

	art, err := ael.LoadArtifact(flag.Arg(0), *keysDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aelcheck: %v\n", err)
		os.Exit(1)
	}
	res := ael.Evaluate(art)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "aelcheck: encode result: %v\n", err)
			os.Exit(1)
		}
		return
	}

	for _, id := range ael.CheckIDs(res.Checks) {
		out := res.Checks[id]
		fmt.Printf("%-2s %-4s %s\n", id, out.Status, out.Message)
	}
	if res.OpenStatus != "" {
		fmt.Printf("status: %s\n", res.OpenStatus)
	}
	for _, note := range res.Notes {
		fmt.Printf("note: %s\n", note)
	}
	fmt.Println(res.GradeLine())
}
