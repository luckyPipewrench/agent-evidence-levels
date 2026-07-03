package ael

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type signedTreeHead struct {
	Log  string `json:"log"`
	Root string `json:"root"`
	Size int    `json:"size"`
}

func validateRecordPayloadSchema(raw []byte, typ string) error {
	known := map[string]bool{
		"v": true, "type": true, "run": true, "recorder": true, "key": true,
		"seq": true, "prev": true, "ts": true, "ext": true,
	}
	switch typ {
	case "open":
		known["hmax"] = true
		known["htol"] = true
		known["cp_nonce"] = true
	case "activity":
		known["event"] = true
		known["decision"] = true
	case "heartbeat":
	case "close":
		known["count"] = true
		known["head"] = true
	default:
		return fmt.Errorf("unknown record type %q", typ)
	}
	return validateClosedObjectSchema(raw, known)
}

func validateTreeHeadObjectSchema(raw []byte) error {
	return validateClosedObjectSchema(raw, map[string]bool{
		"size": true, "root": true, "sig": true, "signed": true, "ext": true,
	})
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
		if err := validateClosedObjectSchema(entry, map[string]bool{
			"recorder": true, "run": true, "seq": true, "leaf": true,
			"index": true, "proof": true, "ext": true,
		}); err != nil {
			return fmt.Errorf("entries[%d]: %w", i, err)
		}
	}
	return nil
}

func parseSignedTreeHead(raw []byte) (signedTreeHead, error) {
	if err := validateClosedObjectSchema(raw, map[string]bool{
		"log": true, "root": true, "size": true, "ext": true,
	}); err != nil {
		return signedTreeHead{}, err
	}
	var head signedTreeHead
	if err := json.Unmarshal(raw, &head); err != nil {
		return signedTreeHead{}, err
	}
	return head, nil
}

func validateClosedObjectSchema(raw []byte, known map[string]bool) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
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
