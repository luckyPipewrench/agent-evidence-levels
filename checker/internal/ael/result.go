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
	Run        string             `json:"run"`
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

type Report struct {
	Runs []Result `json:"runs"`
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
	return fmt.Sprintf("run %s: %s %s (coverage: %s; custody: %s; anchor: %s; retention: %s)",
		emptyAsUnknown(r.Run), r.GradeString(), r.RLabel(), emptyAsUnknown(r.Coverage), emptyAsUnknown(r.Custody),
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
		"w": 6, "f": 7, "g": 8, "h": 9, "i": 10, "j": 11,
		"k": 12, "l": 13, "m": 14, "n": 15, "o": 16,
		"p": 17, "q": 18, "u": 19, "r": 20, "s": 21,
		"t": 22, "v": 23, "R": 24,
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
