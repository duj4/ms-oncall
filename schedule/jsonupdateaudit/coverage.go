// Package jsonupdateaudit defines the independent v1 Schedule JSON update
// contract. A Schedule survives. Coverage identities exist within this event;
// they are never persistent TemporarySchedule or FixedShift identities.
package jsonupdateaudit

import (
	"cmp"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"sort"
	"time"
)

var ErrInvalid = errors.New("invalid schedule JSON update audit")

// Coverage uses UTC Unix nanoseconds as canonical decimal strings and half-open [Start, End) intervals.
// UserID is empty for temporary coverage and a canonical UUID for fixed_shift.
// Temporary coverage is independent of User coverage, including empty shifts.
type Coverage struct {
	Kind   string `json:"kind"`
	UserID string `json:"user_id"`
	Start  string `json:"start_ns"`
	End    string `json:"end_ns"`
}

type Effect struct {
	Coverage
	Change string `json:"change"`
	Source string `json:"source"`
}

const MaxCoverage = 10000

func compare(a, b Coverage) int {
	if n := cmp.Compare(a.Kind, b.Kind); n != 0 {
		return n
	}
	if n := cmp.Compare(a.UserID, b.UserID); n != 0 {
		return n
	}
	if n := instantCompare(a.Start, b.Start); n != 0 {
		return n
	}
	return instantCompare(a.End, b.End)
}

func same(a, b Coverage) bool { return a.Kind == b.Kind && a.UserID == b.UserID }

// Canonical unions equivalent coverage; input order and segmentation carry no
// business identity. Invalid intervals are rejected, never silently omitted.
func Canonical(in []Coverage) ([]Coverage, error) {
	if len(in) > MaxCoverage {
		return nil, ErrInvalid
	}
	in = slices.Clone(in)
	for _, c := range in {
		if !c.valid() {
			return nil, ErrInvalid
		}
	}
	slices.SortFunc(in, compare)
	out := make([]Coverage, 0, len(in))
	for _, c := range in {
		if len(out) > 0 && same(out[len(out)-1], c) && instantCompare(c.Start, out[len(out)-1].End) <= 0 {
			out[len(out)-1].End = instantMax(out[len(out)-1].End, c.End)
		} else {
			out = append(out, c)
		}
	}
	return out, nil
}

func coverageKey(a, b Coverage) int {
	if n := cmp.Compare(a.Kind, b.Kind); n != 0 {
		return n
	}
	return cmp.Compare(a.UserID, b.UserID)
}

func difference(a, b []Coverage, change string) []Effect {
	out := make([]Effect, 0)
	j := 0
	for _, c := range a {
		for j < len(b) && (coverageKey(b[j], c) < 0 || same(b[j], c) && instantCompare(b[j].End, c.Start) <= 0) {
			j++
		}
		start := c.Start
		for k := j; k < len(b) && same(b[k], c) && instantCompare(b[k].Start, c.End) < 0; k++ {
			d := b[k]
			if instantCompare(d.End, start) <= 0 {
				continue
			}
			if instantCompare(d.Start, start) > 0 {
				v := c
				v.Start = start
				v.End = d.Start
				out = append(out, Effect{v, change, "EXPLICIT"})
			}
			start = instantMax(start, d.End)
			if instantCompare(start, c.End) >= 0 {
				break
			}
		}
		if instantCompare(start, c.End) < 0 {
			c.Start = start
			out = append(out, Effect{c, change, "EXPLICIT"})
		}
	}
	return out
}

// Diff is the complete symmetric coverage difference, with removals first.
// Split, merge and replacement are represented by these intervals plus the
// complete canonical Before/After, without inventing an element identity.
func Diff(before, after []Coverage) ([]Effect, error) {
	b, err := Canonical(before)
	if err != nil {
		return nil, err
	}
	a, err := Canonical(after)
	if err != nil {
		return nil, err
	}
	return append(difference(b, a, "coverage_removed"), difference(a, b, "coverage_added")...), nil
}

func ValidateSnapshot(in []Coverage) error {
	c, err := Canonical(in)
	if err != nil || in == nil || !reflect.DeepEqual(in, c) {
		return ErrInvalid
	}

	var temporary []Coverage
	for _, v := range in {
		if v.Kind == "temporary" {
			temporary = append(temporary, v)
		}
	}
	for _, v := range in {
		if v.Kind != "fixed_shift" {
			continue
		}
		end := sort.Search(len(temporary), func(i int) bool { return instantCompare(temporary[i].Start, v.Start) > 0 })
		if end == 0 || instantCompare(temporary[end-1].End, v.End) < 0 {
			return ErrInvalid
		}
	}

	return nil
}

// Instant preserves JSON's nanosecond precision across the complete Go time
// range; PostgreSQL timestamps alone would round away part of the boundary.
func Instant(t time.Time) string {
	n := new(big.Int).Mul(big.NewInt(t.Unix()), big.NewInt(1000000000))
	return n.Add(n, big.NewInt(int64(t.Nanosecond()))).String()
}
func instantCompare(a, b string) int {
	x, ok := new(big.Int).SetString(a, 10)
	if !ok {
		return -1
	}
	y, ok := new(big.Int).SetString(b, 10)
	if !ok {
		return 1
	}
	return x.Cmp(y)
}
func instantMax(a, b string) string {
	if instantCompare(a, b) < 0 {
		return b
	}
	return a
}
func validInstant(a string) bool {
	x, ok := new(big.Int).SetString(a, 10)
	return ok && x.String() == a && instantCompare(a, "-62135596800000000000") >= 0 && instantCompare(a, "253402300799999999999") <= 0
}
func Time(a string) time.Time {
	n, _ := new(big.Int).SetString(a, 10)
	if n == nil {
		return time.Time{}
	}
	sec, nano := new(big.Int), new(big.Int)
	sec.QuoRem(n, big.NewInt(1000000000), nano)
	return time.Unix(sec.Int64(), nano.Int64()).UTC()
}
