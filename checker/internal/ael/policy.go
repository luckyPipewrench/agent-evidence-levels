// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type PolicyDoc struct {
	V       int          `json:"v"`
	Rules   []PolicyRule `json:"rules"`
	Default string       `json:"default"`
	Hash    string       `json:"-"`
}

type PolicyRule struct {
	When    PolicyWhen `json:"when"`
	Verdict string     `json:"verdict"`
}

type PolicyWhen struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}

func ParsePolicy(raw []byte) (*PolicyDoc, error) {
	canon, err := Canonicalize(raw)
	if err != nil {
		return nil, fmt.Errorf("policy canonicalize: %w", err)
	}
	if !bytes.Equal(canon, raw) {
		return nil, fmt.Errorf("policy is not canonical")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc PolicyDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	doc.Hash = hex.EncodeToString(sum[:])
	return &doc, nil
}

func (p *PolicyDoc) Eval(inputs map[string]any) (string, error) {
	for _, rule := range p.Rules {
		ok, err := matchWhen(rule.When, inputs)
		if err != nil {
			return "", err
		}
		if ok {
			return rule.Verdict, nil
		}
	}
	return p.Default, nil
}

func matchWhen(w PolicyWhen, inputs map[string]any) (bool, error) {
	got, ok := inputs[w.Field]
	if !ok {
		return false, nil
	}
	switch w.Op {
	case "gte", "lt":
		gi, ok := asInt(got)
		if !ok {
			return false, nil
		}
		wi, ok := asInt(w.Value)
		if !ok {
			return false, fmt.Errorf("%s value for %s is not an integer", w.Op, w.Field)
		}
		if w.Op == "gte" {
			return gi >= wi, nil
		}
		return gi < wi, nil
	case "eq":
		return scalarEqual(got, w.Value), nil
	case "in":
		arr, ok := w.Value.([]any)
		if !ok {
			return false, fmt.Errorf("in value for %s is not an array", w.Field)
		}
		for _, item := range arr {
			if scalarEqual(got, item) {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unsupported policy op %q", w.Op)
	}
}

func scalarEqual(a, b any) bool {
	if ai, ok := asInt(a); ok {
		if bi, ok := asInt(b); ok {
			return ai == bi
		}
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	default:
		return false
	}
}

func asInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		i := int64(t)
		return i, float64(i) == t
	case json.Number:
		i, err := parseCanonicalInteger(t.String())
		return i, err == nil
	default:
		return 0, false
	}
}
