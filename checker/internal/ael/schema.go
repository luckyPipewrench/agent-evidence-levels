// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type signedTreeHead struct {
	Log  string `json:"log"`
	Root string `json:"root"`
	Size int    `json:"size"`
}

func validateRecordPayloadSchema(raw []byte, typ string) error {
	obj, err := objectFields(raw, "record payload")
	if err != nil {
		return err
	}
	known := map[string]bool{"v": true, "type": true, "run": true, "recorder": true, "key": true, "seq": true, "prev": true, "ts": true, "ext": true}
	for _, field := range []string{"v", "type", "run", "recorder", "key", "seq", "prev", "ts"} {
		if err := requireField(obj, field); err != nil {
			return err
		}
	}
	actualType, err := requiredString(obj, "type", false)
	if err != nil {
		return err
	}
	if actualType != typ {
		return fmt.Errorf("record type %q does not match parsed type %q", actualType, typ)
	}
	switch typ {
	case "open":
		known["hmax"] = true
		known["htol"] = true
		known["cp_nonce"] = true
		for _, field := range []string{"hmax", "htol"} {
			if err := requireField(obj, field); err != nil {
				return err
			}
		}
	case "activity":
		known["event"] = true
		known["decision"] = true
		if err := requireField(obj, "event"); err != nil {
			return err
		}
	case "heartbeat":
	case "close":
		known["count"] = true
		known["head"] = true
		for _, field := range []string{"count", "head"} {
			if err := requireField(obj, field); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown record type %q", typ)
	}
	for field := range obj {
		if !known[field] {
			return fmt.Errorf("unknown top-level key %q", field)
		}
	}
	if err := validateExactIntegerField(raw, "v", 1); err != nil {
		return err
	}
	if _, err := requiredString(obj, "run", true); err != nil {
		return err
	}
	if _, err := requiredString(obj, "recorder", true); err != nil {
		return err
	}
	if err := requiredSHA256Hex(obj, "key"); err != nil {
		return err
	}
	if err := validateMinimumIntegerField(raw, "seq", 0); err != nil {
		return err
	}
	if err := requiredSHA256Hex(obj, "prev"); err != nil {
		return err
	}
	if err := requiredRFC3339(obj, "ts"); err != nil {
		return err
	}
	if value, ok := obj["ext"]; ok {
		if _, err := objectFields(value, "ext"); err != nil {
			return fmt.Errorf("ext: %w", err)
		}
	}
	switch typ {
	case "open":
		for _, field := range []string{"hmax", "htol"} {
			if err := validateMinimumIntegerField(raw, field, 0); err != nil {
				return err
			}
		}
		if _, ok := obj["cp_nonce"]; ok {
			if _, err := requiredString(obj, "cp_nonce", false); err != nil {
				return err
			}
		}
	case "close":
		if err := validateMinimumIntegerField(raw, "count", 2); err != nil {
			return err
		}
		if err := requiredSHA256Hex(obj, "head"); err != nil {
			return err
		}
	}
	if typ == "activity" {
		if err := validateEventSchema(obj["event"]); err != nil {
			return err
		}
		if decision, ok := obj["decision"]; ok {
			if err := validateDecisionSchema(decision); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateManifestSchema covers the format's load-bearing structural limits.
// The manifest remains an open declaration schema, but these bounds are part of
// its wire contract and must not be accepted more broadly by the checker.
func validateManifestSchema(raw []byte) error {
	obj, err := objectFields(raw, "manifest")
	if err != nil {
		return err
	}
	for _, field := range []string{"ael_format", "runs", "recorders"} {
		if err := requireField(obj, field); err != nil {
			return err
		}
	}
	if err := validateExactIntegerField(raw, "ael_format", ArtifactFormatVersion); err != nil {
		return err
	}
	if err := validateStringArray(obj["runs"], "runs", 1); err != nil {
		return err
	}
	recorders, err := arrayFields(obj["recorders"], "recorders")
	if err != nil || len(recorders) == 0 {
		return fmt.Errorf("recorders must be a non-empty array")
	}
	for i, recorder := range recorders {
		if err := validateManifestRecorder(recorder); err != nil {
			return fmt.Errorf("recorders[%d]: %w", i, err)
		}
	}
	if _, ok := obj["claimed_rung"]; ok {
		if err := validateIntegerRangeField(raw, "claimed_rung", 0, 4); err != nil {
			return err
		}
	}
	if retention, ok := obj["retention"]; ok {
		retentionObject, err := objectFields(retention, "retention")
		if err != nil {
			return err
		}
		if _, ok := retentionObject["period_days"]; ok {
			if err := validateMinimumIntegerField(retention, "period_days", 0); err != nil {
				return fmt.Errorf("retention: %w", err)
			}
		}
		if _, ok := retentionObject["custody"]; ok {
			if _, err := requiredString(retentionObject, "custody", false); err != nil {
				return fmt.Errorf("retention: %w", err)
			}
		}
	}
	if coverage, ok := obj["coverage"]; ok {
		if err := validateEnumRaw(coverage, "coverage", "declared-only", "partial", "mediated-only", "enforced-total"); err != nil {
			return err
		}
	}
	if custody, ok := obj["custody"]; ok {
		if err := validateEnumRaw(custody, "custody", "same-process", "same-host", "same-operator", "independent"); err != nil {
			return err
		}
	}
	if correspondence, ok := obj["correspondence"]; ok {
		if err := validateCorrespondenceSchema(correspondence); err != nil {
			return err
		}
	}
	if anchor, ok := obj["anchor"]; ok {
		if err := validateAnchorDeclSchema(anchor); err != nil {
			return err
		}
	}
	if counterparty, ok := obj["counterparty"]; ok {
		if err := validateCounterpartyDeclSchema(counterparty); err != nil {
			return err
		}
	}
	return nil
}

func validateManifestRecorder(raw json.RawMessage) error {
	obj, err := objectFields(raw, "recorder")
	if err != nil {
		return err
	}
	for _, field := range []string{"id", "run", "file"} {
		if _, err := requiredString(obj, field, false); err != nil {
			return err
		}
	}
	if _, ok := obj["key"]; ok {
		if _, err := requiredString(obj, "key", false); err != nil {
			return err
		}
	}
	return nil
}

func validateCorrespondenceSchema(raw json.RawMessage) error {
	obj, err := objectFields(raw, "correspondence")
	if err != nil {
		return err
	}
	for _, field := range []string{"classes", "match"} {
		if err := requireField(obj, field); err != nil {
			return err
		}
	}
	if err := validateStringArray(obj["classes"], "classes", 0); err != nil {
		return err
	}
	return validateEnumRaw(obj["match"], "match", "id")
}

func validateAnchorDeclSchema(raw json.RawMessage) error {
	obj, err := objectFields(raw, "anchor")
	if err != nil {
		return err
	}
	for _, field := range []string{"log", "log_key", "file"} {
		if err := requireField(obj, field); err != nil {
			return err
		}
	}
	if _, err := requiredString(obj, "log", false); err != nil {
		return err
	}
	if err := requiredSHA256Hex(obj, "log_key"); err != nil {
		return err
	}
	_, err = requiredString(obj, "file", false)
	return err
}

func validateCounterpartyDeclSchema(raw json.RawMessage) error {
	obj, err := objectFields(raw, "counterparty")
	if err != nil {
		return err
	}
	for _, field := range []string{"file", "flows", "key"} {
		if err := requireField(obj, field); err != nil {
			return err
		}
	}
	if _, err := requiredString(obj, "file", false); err != nil {
		return err
	}
	if err := validateStringArray(obj["flows"], "flows", 0); err != nil {
		return err
	}
	return requiredSHA256Hex(obj, "key")
}

func validateEventSchema(raw json.RawMessage) error {
	obj, err := closedObjectFields(raw, "event", map[string]bool{"class": true, "id": true, "dir": true})
	if err != nil {
		return err
	}
	for _, field := range []string{"class", "id", "dir"} {
		if err := requireField(obj, field); err != nil {
			return err
		}
	}
	if _, err := requiredString(obj, "class", false); err != nil {
		return err
	}
	if _, err := requiredString(obj, "id", false); err != nil {
		return err
	}
	return validateEnumRaw(obj["dir"], "event.dir", "out", "in", "internal")
}

func validateDecisionSchema(raw json.RawMessage) error {
	obj, err := closedObjectFields(raw, "decision", map[string]bool{"policy": true, "request_fp": true, "inputs": true, "verdict": true})
	if err != nil {
		return err
	}
	for _, field := range []string{"policy", "request_fp", "inputs", "verdict"} {
		if err := requireField(obj, field); err != nil {
			return err
		}
	}
	if err := requiredSHA256Hex(obj, "policy"); err != nil {
		return err
	}
	if _, err := requiredString(obj, "request_fp", false); err != nil {
		return err
	}
	inputs, err := objectFields(obj["inputs"], "decision.inputs")
	if err != nil {
		return err
	}
	for key, value := range inputs {
		if err := validateDecisionInputValue(value); err != nil {
			return fmt.Errorf("decision.inputs.%s: %w", key, err)
		}
	}
	return validateEnumRaw(obj["verdict"], "decision.verdict", "allow", "block", "defer")
}

func validateDecisionInputValue(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return err
	}
	switch value := value.(type) {
	case string, bool:
		return nil
	case json.Number:
		if _, err := value.Int64(); err == nil {
			return nil
		}
		return fmt.Errorf("must be a string, integer, or boolean")
	default:
		return fmt.Errorf("must be a string, integer, or boolean")
	}
}

func objectFields(raw []byte, name string) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return obj, nil
}

func closedObjectFields(raw []byte, name string, known map[string]bool) (map[string]json.RawMessage, error) {
	obj, err := objectFields(raw, name)
	if err != nil {
		return nil, err
	}
	for field := range obj {
		if !known[field] {
			return nil, fmt.Errorf("%s has unknown key %q", name, field)
		}
	}
	return obj, nil
}

func arrayFields(raw []byte, name string) ([]json.RawMessage, error) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, fmt.Errorf("%s must be an array", name)
	}
	return values, nil
}

func validateStringArray(raw json.RawMessage, name string, minimum int) error {
	values, err := arrayFields(raw, name)
	if err != nil || len(values) < minimum {
		if minimum > 0 {
			return fmt.Errorf("%s must be a non-empty array", name)
		}
		return fmt.Errorf("%s must be an array", name)
	}
	for i, value := range values {
		var text string
		if isJSONNull(value) || json.Unmarshal(value, &text) != nil {
			return fmt.Errorf("%s[%d] must be a string", name, i)
		}
	}
	return nil
}

func requireField(obj map[string]json.RawMessage, field string) error {
	if _, ok := obj[field]; !ok {
		return fmt.Errorf("missing required top-level key %q", field)
	}
	return nil
}

func requiredString(obj map[string]json.RawMessage, field string, nonEmpty bool) (string, error) {
	raw, ok := obj[field]
	if !ok {
		return "", fmt.Errorf("missing required top-level key %q", field)
	}
	var value string
	if isJSONNull(raw) || json.Unmarshal(raw, &value) != nil || (nonEmpty && value == "") {
		if nonEmpty {
			return "", fmt.Errorf("%s must be a non-empty string", field)
		}
		return "", fmt.Errorf("%s must be a string", field)
	}
	return value, nil
}

func requiredSHA256Hex(obj map[string]json.RawMessage, field string) error {
	value, err := requiredString(obj, field, false)
	if err != nil || !sha256HexRE.MatchString(value) {
		return fmt.Errorf("%s must be a lowercase sha-256 hex string", field)
	}
	return nil
}

func requiredRFC3339(obj map[string]json.RawMessage, field string) error {
	value, err := requiredString(obj, field, false)
	if err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("%s must be RFC3339 date-time", field)
	}
	return nil
}

func validateEnumRaw(raw json.RawMessage, field string, allowed ...string) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s must be one of %s", field, strings.Join(allowed, ", "))
	}
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of %s", field, strings.Join(allowed, ", "))
}

func validateExactIntegerField(raw []byte, field string, want int64) error {
	got, err := integerField(raw, field)
	if err != nil || got != want {
		return fmt.Errorf("%s must be %d", field, want)
	}
	return nil
}

func validateMinimumIntegerField(raw []byte, field string, minimum int64) error {
	got, err := integerField(raw, field)
	if err != nil || got < minimum {
		return fmt.Errorf("%s must be an integer >= %d", field, minimum)
	}
	return nil
}

func validateIntegerRangeField(raw []byte, field string, minimum, maximum int64) error {
	got, err := integerField(raw, field)
	if err != nil || got < minimum || got > maximum {
		return fmt.Errorf("%s must be an integer between %d and %d", field, minimum, maximum)
	}
	return nil
}

func integerField(raw []byte, field string) (int64, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return 0, err
	}
	value, ok := obj[field]
	if !ok {
		return 0, fmt.Errorf("missing field")
	}
	if isJSONNull(value) {
		return 0, fmt.Errorf("null field")
	}
	dec := json.NewDecoder(bytes.NewReader(value))
	dec.UseNumber()
	var number json.Number
	if err := dec.Decode(&number); err != nil {
		return 0, err
	}
	return number.Int64()
}

func isJSONNull(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateTreeHeadObjectSchema(raw []byte) error {
	return validateObjectSchema(raw, map[string]bool{
		"size": true, "root": true, "sig": true, "signed": true, "ext": true,
	}, []string{"size", "root", "sig", "signed"})
}

func validateAnchorSchemas(raw []byte) error {
	var root struct {
		TreeHead json.RawMessage   `json:"tree_head"`
		Entries  []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	if len(root.TreeHead) == 0 {
		return fmt.Errorf("tree_head is absent")
	}
	if err := validateTreeHeadObjectSchema(root.TreeHead); err != nil {
		return fmt.Errorf("tree_head: %w", err)
	}
	for i, entry := range root.Entries {
		if err := validateObjectSchema(entry, map[string]bool{
			"recorder": true, "run": true, "seq": true, "leaf": true,
			"index": true, "proof": true, "ext": true,
		}, []string{"recorder", "run", "seq", "leaf", "index", "proof"}); err != nil {
			return fmt.Errorf("entries[%d]: %w", i, err)
		}
	}
	return nil
}

func parseSignedTreeHead(raw []byte) (signedTreeHead, error) {
	if err := validateObjectSchema(raw, map[string]bool{
		"log": true, "root": true, "size": true, "ext": true,
	}, []string{"log", "root", "size"}); err != nil {
		return signedTreeHead{}, err
	}
	var head signedTreeHead
	if err := json.Unmarshal(raw, &head); err != nil {
		return signedTreeHead{}, err
	}
	return head, nil
}

func validateObjectSchema(raw []byte, known map[string]bool, required []string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	for _, key := range required {
		if _, ok := obj[key]; !ok {
			return fmt.Errorf("missing required top-level key %q", key)
		}
	}
	for key, val := range obj {
		if !known[key] {
			return fmt.Errorf("unknown top-level key %q", key)
		}
		if key == "ext" && !isJSONObject(val) {
			return fmt.Errorf("ext must be an object")
		}
	}
	return nil
}

func validateNestedObjectSchema(raw []byte, field string, known map[string]bool, required []string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	val, ok := obj[field]
	if !ok {
		return nil
	}
	if !isJSONObject(val) {
		return fmt.Errorf("%s must be an object", field)
	}
	if err := validateObjectSchema(val, known, required); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func isJSONObject(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) >= 2 && raw[0] == '{' && raw[len(raw)-1] == '}'
}

func validateCounterpartyReceiptChoice(raw []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	rawReceived, hasReceived := obj["received"]
	rawNone, hasNone := obj["none"]
	if hasReceived && hasNone {
		return fmt.Errorf("must contain exactly one of received or none:true")
	}
	if hasReceived {
		var body struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(rawReceived, &body); err != nil {
			return fmt.Errorf("received: %w", err)
		}
		if body.EventID == "" {
			return fmt.Errorf("received.event_id must be non-empty")
		}
		return nil
	}
	if hasNone {
		var none bool
		if err := json.Unmarshal(rawNone, &none); err != nil {
			return fmt.Errorf("none: %w", err)
		}
		if !none {
			return fmt.Errorf("none must be true")
		}
		return nil
	}
	return fmt.Errorf("must contain exactly one of received or none:true")
}

func decodeStdBase64Field(name, value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if base64.StdEncoding.EncodeToString(raw) != strings.TrimSpace(value) {
		return nil, fmt.Errorf("%s is not canonical base64", name)
	}
	return raw, nil
}
