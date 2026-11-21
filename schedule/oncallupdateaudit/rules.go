// Package oncallupdateaudit defines the independent OnCall JSON Update v1
// persistence contract. Local rule identity is scoped to one surviving Schedule.
package oncallupdateaudit

import (
	"errors"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalid = errors.New("invalid on-call JSON update audit")

const Operation = "setScheduleOnCallNotificationRules"

// Rule excludes derived NextNotification and all destination payloads. Empty
// Time/Weekdays denotes on-change; otherwise Time is HH:MM and Sunday comes first.
type Rule struct {
	ID       string `json:"rule_id"`
	Channel  string `json:"channel_id"`
	Time     string `json:"time"`
	Weekdays string `json:"weekdays"`
}

type Effect struct {
	RuleID string `json:"rule_id"`
	Change string `json:"change"`
	Source string `json:"source"`
}

func ValidateSnapshot(schedule uuid.UUID, rules []Rule) error {
	if schedule == uuid.Nil || rules == nil || len(rules) > 50 {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for i, r := range rules {
		local, err := strconv.Atoi(strings.TrimPrefix(r.ID, schedule.String()+":"))
		if err != nil || local < 0 || local >= 50 || r.ID != schedule.String()+":"+strconv.Itoa(local) || i > 0 && rules[i-1].ID >= r.ID {
			return ErrInvalid
		}
		id, err := uuid.Parse(r.Channel)
		if err != nil || id == uuid.Nil || id.String() != r.Channel {
			return ErrInvalid
		}
		if r.Time == "" {
			if r.Weekdays != "" {
				return ErrInvalid
			}
		} else {
			if len(r.Time) != 5 || r.Time[2] != ':' || r.Time[:2] < "00" || r.Time[:2] > "23" || r.Time[3:] < "00" || r.Time[3:] > "59" {
				return ErrInvalid
			}
			for _, c := range r.Time[:2] + r.Time[3:] {
				if c < '0' || c > '9' {
					return ErrInvalid
				}
			}
			if len(r.Weekdays) != 7 || !strings.Contains(r.Weekdays, "1") {
				return ErrInvalid
			}
			for _, c := range r.Weekdays {
				if c != '0' && c != '1' {
					return ErrInvalid
				}
			}
		}
		// Preserve the existing duplicate key, which deliberately omits weekdays.
		key := r.Channel + ":" + r.Time
		if seen[key] {
			return ErrInvalid
		}
		seen[key] = true
	}
	return nil
}

func Canonical(schedule uuid.UUID, in []Rule) ([]Rule, error) {
	out := append([]Rule{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, ValidateSnapshot(schedule, out)
}

// Diff compares complete event-local configurations, never array positions or
// an assumed permanent RuleID lifecycle. Same ID may have several true effects.
func Diff(schedule uuid.UUID, before, after []Rule) ([]Effect, error) {
	if ValidateSnapshot(schedule, before) != nil || ValidateSnapshot(schedule, after) != nil {
		return nil, ErrInvalid
	}
	b, a := make(map[string]Rule), make(map[string]Rule)
	for _, r := range before {
		b[r.ID] = r
	}
	for _, r := range after {
		a[r.ID] = r
	}
	out := []Effect{}
	add := func(id, change string) { out = append(out, Effect{id, change, "EXPLICIT"}) }
	for id, old := range b {
		next, ok := a[id]
		if !ok {
			add(id, "rule_removed")
			continue
		}
		if old.Channel != next.Channel {
			add(id, "channel_replaced")
		}
		if old.Time != next.Time {
			add(id, "trigger_replaced")
			continue
		}
		if old.Weekdays == next.Weekdays {
			continue
		}
		removed, added := false, false
		for i := range old.Weekdays {
			removed = removed || old.Weekdays[i] == '1' && next.Weekdays[i] == '0'
			added = added || old.Weekdays[i] == '0' && next.Weekdays[i] == '1'
		}
		if removed {
			add(id, "trigger_trimmed")
		}
		if added {
			add(id, "trigger_expanded")
		}
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			add(id, "rule_added")
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Change < out[j].Change
	})
	return out, nil
}

func Destructive(effects []Effect) bool {
	return slices.ContainsFunc(effects, func(e Effect) bool { return e.Change != "rule_added" && e.Change != "trigger_expanded" })
}

func Equal(a, b []Rule) bool { return reflect.DeepEqual(a, b) }
