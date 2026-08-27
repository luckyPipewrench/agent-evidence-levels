// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeCompactBase64RejectsNonCanonicalTrailingBits(t *testing.T) {
	if _, err := decodeCompactBase64("AA"); err != nil {
		t.Fatalf("canonical segment rejected: %v", err)
	}
	if _, err := decodeCompactBase64("AB"); err == nil {
		t.Fatal("non-canonical segment with non-zero trailing bits was accepted")
	}
}

func TestParseRecordLineRejectsPadding(t *testing.T) {
	rec, err := ParseRecordLine("AA==.AA", "recorders/r1.jsonl", 1)
	if err != nil {
		t.Fatal(err)
	}
	if rec.LineErr == nil {
		t.Fatal("padded compact line was accepted")
	}
}

func TestRecordSchemaRejectsNumericBoundaryViolations(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "negative hmax",
			raw:  `{"hmax":-1,"htol":0,"key":"0000000000000000000000000000000000000000000000000000000000000000","prev":"0000000000000000000000000000000000000000000000000000000000000000","recorder":"r1","run":"run-a","seq":0,"ts":"2026-01-01T00:00:00Z","type":"open","v":1}`,
			want: "hmax must be an integer >= 0",
		},
		{
			name: "negative htol",
			raw:  `{"hmax":10,"htol":-1,"key":"0000000000000000000000000000000000000000000000000000000000000000","prev":"0000000000000000000000000000000000000000000000000000000000000000","recorder":"r1","run":"run-a","seq":0,"ts":"2026-01-01T00:00:00Z","type":"open","v":1}`,
			want: "htol must be an integer >= 0",
		},
		{
			name: "negative sequence",
			raw:  `{"hmax":10,"htol":0,"key":"0000000000000000000000000000000000000000000000000000000000000000","prev":"0000000000000000000000000000000000000000000000000000000000000000","recorder":"r1","run":"run-a","seq":-1,"ts":"2026-01-01T00:00:00Z","type":"open","v":1}`,
			want: "seq must be an integer >= 0",
		},
		{
			name: "unsupported record format",
			raw:  `{"hmax":10,"htol":0,"key":"0000000000000000000000000000000000000000000000000000000000000000","prev":"0000000000000000000000000000000000000000000000000000000000000000","recorder":"r1","run":"run-a","seq":0,"ts":"2026-01-01T00:00:00Z","type":"open","v":2}`,
			want: "v must be 1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRecordPayloadSchema([]byte(tc.raw), "open"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("schema error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRecordSchemaParityConstraintFamilies(t *testing.T) {
	tests := []struct {
		name   string
		typ    string
		mutate func(map[string]any)
		want   string
	}{
		{name: "empty run", typ: "open", mutate: func(v map[string]any) { v["run"] = "" }, want: "run must be a non-empty string"},
		{name: "empty recorder", typ: "open", mutate: func(v map[string]any) { v["recorder"] = "" }, want: "recorder must be a non-empty string"},
		{name: "invalid key", typ: "open", mutate: func(v map[string]any) { v["key"] = "upper" }, want: "key must be a lowercase sha-256 hex string"},
		{name: "invalid predecessor", typ: "open", mutate: func(v map[string]any) { v["prev"] = "bad" }, want: "prev must be a lowercase sha-256 hex string"},
		{name: "invalid timestamp", typ: "open", mutate: func(v map[string]any) { v["ts"] = "tomorrow" }, want: "ts must be RFC3339 date-time"},
		{name: "open missing htol", typ: "open", mutate: func(v map[string]any) { delete(v, "htol") }, want: "missing required top-level key \"htol\""},
		{name: "open hmax must not be null", typ: "open", mutate: func(v map[string]any) { v["hmax"] = nil }, want: "hmax must be an integer >= 0"},
		{name: "open carries activity event", typ: "open", mutate: func(v map[string]any) { v["event"] = map[string]any{"class": "tool", "dir": "out", "id": "e1"} }, want: "unknown top-level key \"event\""},
		{name: "open cp nonce wrong type", typ: "open", mutate: func(v map[string]any) { v["cp_nonce"] = 1 }, want: "cp_nonce must be a string"},
		{name: "activity missing event", typ: "activity", mutate: func(v map[string]any) { activityPayload(v); delete(v, "event") }, want: "missing required top-level key \"event\""},
		{name: "activity invalid event direction", typ: "activity", mutate: func(v map[string]any) { activityPayload(v); v["event"].(map[string]any)["dir"] = "sideways" }, want: "event.dir must be one of out, in, internal"},
		{name: "activity unknown event field", typ: "activity", mutate: func(v map[string]any) { activityPayload(v); v["event"].(map[string]any)["extra"] = true }, want: "event has unknown key \"extra\""},
		{name: "activity invalid decision policy", typ: "activity", mutate: func(v map[string]any) {
			activityPayload(v)
			v["decision"] = validDecision()
			v["decision"].(map[string]any)["policy"] = "not-a-digest"
		}, want: "policy must be a lowercase sha-256 hex string"},
		{name: "activity non-scalar decision input", typ: "activity", mutate: func(v map[string]any) {
			activityPayload(v)
			v["decision"] = validDecision()
			v["decision"].(map[string]any)["inputs"].(map[string]any)["nested"] = map[string]any{}
		}, want: "decision.inputs.nested: must be a string, integer, or boolean"},
		{name: "activity null decision input", typ: "activity", mutate: func(v map[string]any) {
			activityPayload(v)
			v["decision"] = validDecision()
			v["decision"].(map[string]any)["inputs"].(map[string]any)["none"] = nil
		}, want: "decision.inputs.none: must be a string, integer, or boolean"},
		{name: "activity invalid decision verdict", typ: "activity", mutate: func(v map[string]any) {
			activityPayload(v)
			v["decision"] = validDecision()
			v["decision"].(map[string]any)["verdict"] = "maybe"
		}, want: "decision.verdict must be one of allow, block, defer"},
		{name: "heartbeat carries hmax", typ: "heartbeat", mutate: func(v map[string]any) { heartbeatPayload(v); v["hmax"] = 1 }, want: "unknown top-level key \"hmax\""},
		{name: "close count below minimum", typ: "close", mutate: func(v map[string]any) { closePayload(v); v["count"] = 1 }, want: "count must be an integer >= 2"},
		{name: "close count must not be null", typ: "close", mutate: func(v map[string]any) { closePayload(v); v["count"] = nil }, want: "count must be an integer >= 2"},
		{name: "close invalid head", typ: "close", mutate: func(v map[string]any) { closePayload(v); v["head"] = "bad" }, want: "head must be a lowercase sha-256 hex string"},
		{name: "ext must be object", typ: "open", mutate: func(v map[string]any) { v["ext"] = "opaque" }, want: "ext: ext must be an object"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := validOpenPayload()
			tc.mutate(payload)
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRecordPayloadSchema(raw, tc.typ); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("schema error = %v, want %q", err, tc.want)
			}
		})
	}
}

func validOpenPayload() map[string]any {
	return map[string]any{
		"hmax": 10, "htol": 0,
		"key":      "0000000000000000000000000000000000000000000000000000000000000000",
		"prev":     "0000000000000000000000000000000000000000000000000000000000000000",
		"recorder": "r1", "run": "run-a", "seq": 0, "ts": "2026-01-01T00:00:00Z", "type": "open", "v": 1,
	}
}

func activityPayload(v map[string]any) {
	delete(v, "hmax")
	delete(v, "htol")
	v["type"] = "activity"
	v["event"] = map[string]any{"class": "tool", "dir": "out", "id": "e1"}
}

func heartbeatPayload(v map[string]any) {
	delete(v, "hmax")
	delete(v, "htol")
	v["type"] = "heartbeat"
}

func closePayload(v map[string]any) {
	delete(v, "hmax")
	delete(v, "htol")
	v["type"] = "close"
	v["count"] = 2
	v["head"] = "0000000000000000000000000000000000000000000000000000000000000000"
}

func validDecision() map[string]any {
	return map[string]any{
		"policy":     "0000000000000000000000000000000000000000000000000000000000000000",
		"request_fp": "request", "inputs": map[string]any{"count": 1}, "verdict": "allow",
	}
}
