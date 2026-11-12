package deleteaudit

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

const (
	Schedule     = "schedule"
	Rotation     = "rotation"
	Rule         = "schedule_rule"
	Override     = "user_override"
	Favorite     = "favorite"
	Participant  = "rotation_participant"
	Action       = "escalation_policy_action"
	Temporary    = "temporary_schedule"
	FixedShift   = "fixed_shift"
	OnCallRule   = "on_call_notification_rule"
	History      = "schedule_on_call_history"
	MaxEffects   = 16384
	MaxJSONBytes = 8 * 1024 * 1024
)

type Receipt struct{ ID, OrganizationID uuid.UUID }

// Details contain only safe business identities/configuration. Referenced roots
// are context: their inclusion never asserts that they were deleted.
type RuleDetail struct {
	ScheduleID             uuid.UUID `json:"schedule_id"`
	ScheduleOrganizationID uuid.UUID `json:"schedule_organization_id"`
	TargetKind             string    `json:"target_kind"`
	TargetID               uuid.UUID `json:"target_id"`
	Start                  string    `json:"start"`
	End                    string    `json:"end"`
	Weekdays               string    `json:"weekdays"`
}
type OverrideDetail struct {
	AddUserID    *uuid.UUID `json:"add_user_id"`
	RemoveUserID *uuid.UUID `json:"remove_user_id"`
	Start        time.Time  `json:"start"`
	End          time.Time  `json:"end"`
}
type FavoriteDetail struct {
	OwnerUserID         uuid.UUID  `json:"owner_user_id"`
	OwnerOrganizationID *uuid.UUID `json:"owner_organization_id,omitempty"`
	OwnerOrgResolution  string     `json:"owner_org_resolution"`
}
type ParticipantDetail struct {
	UserID   uuid.UUID `json:"user_id"`
	Position int32     `json:"position"`
}
type ActionDetail struct {
	PolicyID             uuid.UUID `json:"policy_id"`
	PolicyOrganizationID uuid.UUID `json:"policy_organization_id"`
	StepID               uuid.UUID `json:"step_id"`
}

// FragmentIdentity is explicitly event-time, never a persistent business UUID.
// Ordinals refer to the locked envelope at the time of this event.
type FragmentIdentity struct {
	EnvelopeID    int64 `json:"envelope_id"`
	Ordinal       int   `json:"ordinal"`
	ParentOrdinal *int  `json:"parent_ordinal,omitempty"`
}
type TemporaryDetail struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type ShiftDetail struct {
	UserID uuid.UUID `json:"user_id"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
}
type OnCallRuleDetail struct {
	LocalID   int32     `json:"local_id"`
	ChannelID uuid.UUID `json:"channel_id"`
	Time      *string   `json:"time"`
	Weekdays  *string   `json:"weekdays"`
}
type HistoryDetail struct {
	UserID uuid.UUID  `json:"user_id"`
	Start  time.Time  `json:"start"`
	End    *time.Time `json:"end"`
}
type RotationState struct {
	ID            int64     `json:"id"`
	ParticipantID uuid.UUID `json:"participant_id"`
	Position      int32     `json:"position"`
	Version       int32     `json:"version"`
	ShiftStart    time.Time `json:"shift_start"`
}
type Effect struct {
	EffectID             uuid.UUID          `json:"effect_id"`
	ResourceType         string             `json:"resource_type"`
	RootID               uuid.UUID          `json:"root_id"`
	TargetOrganizationID uuid.UUID          `json:"target_organization_id"`
	Relation             string             `json:"relation"`
	Change               string             `json:"change"`
	Provenance           string             `json:"provenance"`
	DeletionMechanism    string             `json:"deletion_mechanism"`
	Cause                string             `json:"cause"`
	ResourceUUID         *uuid.UUID         `json:"resource_uuid,omitempty"`
	ResourceNumericID    *int64             `json:"resource_numeric_id,omitempty"`
	Fragment             *FragmentIdentity  `json:"event_time_identity,omitempty"`
	Rule                 *RuleDetail        `json:"rule,omitempty"`
	Override             *OverrideDetail    `json:"override,omitempty"`
	Favorite             *FavoriteDetail    `json:"favorite,omitempty"`
	Participant          *ParticipantDetail `json:"participant,omitempty"`
	Action               *ActionDetail      `json:"action,omitempty"`
	Temporary            *TemporaryDetail   `json:"temporary,omitempty"`
	Shift                *ShiftDetail       `json:"shift,omitempty"`
	OnCallRule           *OnCallRuleDetail  `json:"on_call_rule,omitempty"`
	History              *HistoryDetail     `json:"history,omitempty"`
}

func finite(t time.Time) bool      { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }
func interval(s, e time.Time) bool { return finite(s) && finite(e) && e.After(s) }
func validID(p *uuid.UUID) bool    { return p != nil && *p != uuid.Nil }

var clockPattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9](\.[0-9]{1,9})?)?$|^24:00:00$`)
var weekdayPattern = regexp.MustCompile(`^[01]{7}$`)

func Relation(root, kind string) string {
	if kind == Participant {
		return "rotation.participant"
	}
	return root + "." + kind
}

func (f Effect) Identity() string {
	prefix := f.ResourceType + ":"
	if f.ResourceUUID != nil {
		return prefix + f.ResourceUUID.String()
	}
	if f.ResourceNumericID != nil {
		return prefix + strconv.FormatInt(*f.ResourceNumericID, 10)
	}
	if f.Fragment != nil {
		return fmt.Sprintf("%s%s:%d:%d:%v", prefix, f.RootID, f.Fragment.EnvelopeID, f.Fragment.Ordinal, parentOrdinal(f.Fragment.ParentOrdinal))
	}
	return ""
}
func parentOrdinal(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
func canonicalEffects(in []Effect) []Effect {
	out := append([]Effect{}, in...)
	slices.SortFunc(out, func(a, b Effect) int {
		if a.Identity() < b.Identity() {
			return -1
		}
		if a.Identity() > b.Identity() {
			return 1
		}
		return 0
	})
	return out
}
func stateJSON(s *RotationState) string { b, _ := json.Marshal(s); return string(b) }
func (e Event) Units() int {
	n := len(e.Effects)
	if e.BeforeState != nil {
		n++
	}
	return n
}
func (e Event) JSONBytes() int {
	b, _ := json.Marshal(e.Canonical().Effects)
	if e.BeforeState == nil {
		return len(b)
	}
	return len(b) + len(stateJSON(e.BeforeState))
}

func (e Event) validateEffects() error {
	if e.Units() > MaxEffects || e.JSONBytes() > MaxJSONBytes {
		return ErrCapacity
	}
	if e.BeforeState != nil {
		s := e.BeforeState
		if e.RootType != Rotation || s.ID <= 0 || s.ParticipantID == uuid.Nil || s.Position < 0 || s.Version < 1 || !finite(s.ShiftStart) {
			return ErrInvalid
		}
		found := false
		for _, f := range e.Effects {
			if f.ResourceType == Participant && validID(f.ResourceUUID) && *f.ResourceUUID == s.ParticipantID && f.Participant != nil && f.Participant.Position == s.Position {
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	seen, ids := map[string]bool{}, map[uuid.UUID]bool{}
	temporaries := map[string]TemporaryDetail{}
	onCallIDs := map[int32]bool{}
	for _, f := range e.Effects {
		if f.EffectID == uuid.Nil || f.RootID != e.RootID || f.TargetOrganizationID != e.TargetOrganizationID || f.Provenance != "CASCADE" || f.Cause != e.RootType+"_delete" || f.Relation != Relation(e.RootType, f.ResourceType) || f.Identity() == "" || seen[f.Identity()] || ids[f.EffectID] {
			return ErrInvalid
		}
		seen[f.Identity()], ids[f.EffectID] = true, true
		want := Effect{EffectID: f.EffectID, ResourceType: f.ResourceType, RootID: f.RootID, TargetOrganizationID: f.TargetOrganizationID, Relation: f.Relation, Change: "deleted", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: f.Cause}
		switch f.ResourceType {
		case Rule:
			d := f.Rule
			if !validID(f.ResourceUUID) || d == nil || d.ScheduleID == uuid.Nil || d.ScheduleOrganizationID == uuid.Nil || d.TargetID == uuid.Nil || !clockPattern.MatchString(d.Start) || !clockPattern.MatchString(d.End) || !weekdayPattern.MatchString(d.Weekdays) || (d.TargetKind != "user" && d.TargetKind != Rotation) {
				return ErrInvalid
			}
			if e.RootType == Schedule && d.ScheduleID != e.RootID || e.RootType == Rotation && (d.TargetKind != Rotation || d.TargetID != e.RootID) {
				return ErrInvalid
			}
			// Internal System preserves historical cross-Org compatibility, while the
			// existing Human dependency guard remains the authority for rejection.
			if e.ActorKind == "human" && d.ScheduleOrganizationID != e.TargetOrganizationID {
				return ErrInvalid
			}
			want.ResourceUUID, want.Rule = f.ResourceUUID, d
		case Override:
			d := f.Override
			if e.RootType != Schedule || !validID(f.ResourceUUID) || d == nil || !interval(d.Start, d.End) || d.AddUserID == nil && d.RemoveUserID == nil || d.AddUserID != nil && !validID(d.AddUserID) || d.RemoveUserID != nil && !validID(d.RemoveUserID) || validID(d.AddUserID) && validID(d.RemoveUserID) && *d.AddUserID == *d.RemoveUserID {
				return ErrInvalid
			}
			want.ResourceUUID, want.Override = f.ResourceUUID, d
		case Favorite:
			d := f.Favorite
			if f.ResourceNumericID == nil || *f.ResourceNumericID <= 0 || d == nil || d.OwnerUserID == uuid.Nil {
				return ErrInvalid
			}
			switch d.OwnerOrgResolution {
			case "unknown":
				if d.OwnerOrganizationID != nil {
					return ErrInvalid
				}
			case "known_normal", "known_default":
				if !validID(d.OwnerOrganizationID) || (d.OwnerOrgResolution == "known_default") != (d.OwnerOrganizationID.String() == organization.DefaultOrganizationID) {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
			want.ResourceNumericID, want.Favorite, want.Change = f.ResourceNumericID, d, "relationship_removed"
		case Participant:
			d := f.Participant
			if e.RootType != Rotation || !validID(f.ResourceUUID) || d == nil || d.UserID == uuid.Nil || d.Position < 0 {
				return ErrInvalid
			}
			want.ResourceUUID, want.Participant, want.Change = f.ResourceUUID, d, "relationship_removed"
		case Action:
			d := f.Action
			if !validID(f.ResourceUUID) || d == nil || d.PolicyID == uuid.Nil || d.PolicyOrganizationID == uuid.Nil || d.StepID == uuid.Nil || e.ActorKind == "human" && d.PolicyOrganizationID != e.TargetOrganizationID {
				return ErrInvalid
			}
			want.ResourceUUID, want.Action = f.ResourceUUID, d
		case Temporary, FixedShift, OnCallRule:
			if e.RootType != Schedule || f.Fragment == nil || f.Fragment.EnvelopeID <= 0 || f.Fragment.Ordinal < 0 {
				return ErrInvalid
			}
			want.Fragment, want.DeletionMechanism = f.Fragment, "envelope_cascade"
			switch f.ResourceType {
			case Temporary:
				if f.Temporary == nil || f.Fragment.ParentOrdinal != nil || !interval(f.Temporary.Start, f.Temporary.End) {
					return ErrInvalid
				}
				want.Temporary = f.Temporary
				temporaries[fmt.Sprintf("%d:%d", f.Fragment.EnvelopeID, f.Fragment.Ordinal)] = *f.Temporary
			case FixedShift:
				if f.Shift == nil || f.Fragment.ParentOrdinal == nil || *f.Fragment.ParentOrdinal < 0 || f.Shift.UserID == uuid.Nil || !interval(f.Shift.Start, f.Shift.End) {
					return ErrInvalid
				}
				want.Shift = f.Shift
			case OnCallRule:
				d := f.OnCallRule
				if d == nil || f.Fragment.ParentOrdinal != nil || d.ChannelID == uuid.Nil || d.LocalID < 0 || onCallIDs[d.LocalID] || d.Time != nil && !clockPattern.MatchString(*d.Time) || d.Weekdays != nil && !weekdayPattern.MatchString(*d.Weekdays) {
					return ErrInvalid
				}
				onCallIDs[d.LocalID] = true
				want.OnCallRule = d
			}
		case History:
			d := f.History
			if e.RootType != Schedule || f.ResourceNumericID == nil || *f.ResourceNumericID <= 0 || d == nil || d.UserID == uuid.Nil || !finite(d.Start) || d.End != nil && !interval(d.Start, *d.End) {
				return ErrInvalid
			}
			want.ResourceNumericID, want.History = f.ResourceNumericID, d
		default:
			return ErrInvalid
		}
		if !reflect.DeepEqual(want, f) {
			return ErrInvalid
		}
	}
	for _, f := range e.Effects {
		if f.ResourceType == FixedShift {
			d, ok := temporaries[fmt.Sprintf("%d:%d", f.Fragment.EnvelopeID, *f.Fragment.ParentOrdinal)]
			if !ok || f.Shift.Start.Before(d.Start) || f.Shift.End.After(d.End) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// Both groups share one budget. Shifts are distinct units, and state contributes
// a unit and bytes. No row or nested fragment is silently truncated.
func ValidateBatch(events []Event) error {
	units, size := 0, 0
	roots, children, ids := map[string]bool{}, map[string]bool{}, map[uuid.UUID]bool{}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		root := e.RootType + ":" + e.RootID.String()
		if roots[root] {
			return ErrInvalid
		}
		roots[root] = true
		units += e.Units()
		size += e.JSONBytes()
		if units > MaxEffects || size > MaxJSONBytes {
			return ErrCapacity
		}
		for _, f := range e.Effects {
			if children[f.Identity()] || ids[f.EffectID] {
				return ErrInvalid
			}
			children[f.Identity()], ids[f.EffectID] = true, true
		}
	}
	return nil
}
