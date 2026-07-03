package ael

import (
	"encoding/json"
	"fmt"
	"sort"
)

type OutcomeStatus string

const (
	Pass OutcomeStatus = "PASS"
	Fail OutcomeStatus = "FAIL"
	UV   OutcomeStatus = "UV"
)

type Outcome struct {
	Status  OutcomeStatus `json:"status"`
	Message string        `json:"message,omitempty"`
}

type Result struct {
	Grade      int                `json:"-"`
	Ungraded   bool               `json:"-"`
	R          string             `json:"r"`
	Checks     map[string]Outcome `json:"checks"`
	Coverage   string             `json:"coverage"`
	Custody    string             `json:"custody"`
	Anchor     string             `json:"anchor"`
	Retention  string             `json:"retention"`
	Open       bool               `json:"open"`
	OpenStatus string             `json:"open_status,omitempty"`
	Notes      []string           `json:"notes,omitempty"`
}

func (r Result) MarshalJSON() ([]byte, error) {
	type wire Result
	w := struct {
		Grade any `json:"grade"`
		wire
	}{
		wire: wire(r),
	}
	if r.Ungraded {
		w.Grade = "ungraded"
	} else {
		w.Grade = r.Grade
	}
	return json.Marshal(w)
}

func (r Result) GradeString() string {
	if r.Ungraded {
		return "Ungraded"
	}
	return fmt.Sprintf("AEL-%d", r.Grade)
}

func (r Result) RLabel() string {
	switch r.R {
	case "+R":
		return "+R"
	case "fail":
		return "R-fail"
	default:
		return "R-pending"
	}
}

func (r Result) GradeLine() string {
	return fmt.Sprintf("%s %s (coverage: %s; custody: %s; anchor: %s; retention: %s)",
		r.GradeString(), r.RLabel(), emptyAsUnknown(r.Coverage), emptyAsUnknown(r.Custody),
		emptyAsUnknown(r.Anchor), emptyAsUnknown(r.Retention))
}

func CheckIDs(checks map[string]Outcome) []string {
	ids := make([]string, 0, len(checks))
	for id := range checks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return checkOrder(ids[i]) < checkOrder(ids[j])
	})
	return ids
}

func checkOrder(id string) int {
	order := map[string]int{
		"a": 1, "b": 2, "c": 3, "d": 4, "e": 5,
		"f": 6, "g": 7, "h": 8, "i": 9, "j": 10,
		"k": 11, "l": 12, "m": 13, "n": 14, "o": 15,
		"p": 16, "q": 17, "r": 18, "s": 19, "t": 20,
		"R": 21,
	}
	if n, ok := order[id]; ok {
		return n
	}
	return 1000
}

func emptyAsUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
