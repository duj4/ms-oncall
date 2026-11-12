package deleteaudit

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Projection lists every permitted snapshot field, its scalar type, and the
// original primary/unique identity. Uppercase scalar kinds are nullable.
// No profile, destination, authentication subject, or credential is selected.
type Projection struct {
	Key    string
	Fields map[string]string
}

var projections = map[string]Projection{
	"schedule_rule":                {"id", map[string]string{"id": "u", "schedule_id": "u", "target_user_id": "u", "start": "c", "end": "c", "weekdays": "w", "is_active": "b", "row_version": "x"}},
	"rotation_participant":         {"id", map[string]string{"id": "u", "rotation_id": "u", "user_id": "u", "position": "j", "ordinal": "o", "row_version": "x"}},
	"rotation_participant_count":   {"rotation_id", map[string]string{"rotation_id": "u", "participant_count": "j"}},
	"rotation_state":               {"id", map[string]string{"id": "i", "rotation_id": "u", "participant_id": "u", "position": "j", "shift_start": "t", "version": "j", "row_version": "x"}},
	"user_override":                {"id", map[string]string{"id": "u", "schedule_id": "u", "add_user_id": "U", "remove_user_id": "U", "start": "t", "end": "t", "row_version": "x"}},
	"contact_method":               {"id", map[string]string{"id": "u", "user_id": "u", "type": "DEST|EMAIL|PUSH|SLACK_DM|SMS|VOICE|WEBHOOK", "disabled": "b", "pending": "b", "private": "b", "row_version": "x"}},
	"notification_rule":            {"id", map[string]string{"id": "u", "user_id": "u", "parent_cm_id": "u", "delay_minutes": "j", "row_version": "x"}},
	"user_favorite":                {"id", map[string]string{"id": "i", "user_id": "u", "target_user_id": "U", "target_service_id": "U", "target_schedule_id": "U", "target_rotation_id": "U", "target_escalation_policy_id": "U", "row_version": "x"}},
	"escalation_policy_action":     {"id", map[string]string{"id": "u", "step_id": "u", "policy_id": "u", "user_id": "u", "row_version": "x"}},
	"schedule_on_call_history":     {"id", map[string]string{"id": "i", "schedule_id": "u", "user_id": "u", "start": "t", "end": "T", "row_version": "x"}},
	"ep_step_on_call_history":      {"id", map[string]string{"id": "i", "step_id": "u", "policy_id": "u", "user_id": "u", "start": "t", "end": "T", "row_version": "x"}},
	"user_organization_assignment": {"user_id", map[string]string{"user_id": "u", "organization_id": "u", "classification": "NORMAL|DEFAULT", "organization_role": "ORG_ADMIN|ORG_MEMBER|NONE", "row_version": "x"}},
	"auth_subject":                 {"id", map[string]string{"id": "i", "user_id": "u", "cm_id": "U", "row_version": "x"}},
	"user_session":                 {"id", map[string]string{"id": "u", "user_id": "u", "row_version": "x"}},
	"basic_auth_link":              {"user_id", map[string]string{"user_id": "u", "id": "i", "row_version": "x"}},
	"user_status_contact_setting":  {"user_id", map[string]string{"user_id": "u", "contact_method_id": "U", "row_version": "x"}},
}

type Effect struct {
	EffectID             uuid.UUID       `json:"effect_id"`
	ResourceType         string          `json:"resource_type"`
	ResourceKey          string          `json:"resource_key"`
	TransitionSlot       string          `json:"transition_slot"`
	TriggerUserID        uuid.UUID       `json:"trigger_user_id"`
	TargetOrganizationID *uuid.UUID      `json:"target_organization_id"`
	OrgResolution        string          `json:"org_resolution"`
	Change               string          `json:"change"`
	Provenance           string          `json:"provenance"`
	DeletionMechanism    string          `json:"deletion_mechanism"`
	Before               json.RawMessage `json:"before"`
	After                json.RawMessage `json:"after"`
}

// Decimal integers never enter a float64, including negative bigint IDs.
var integer = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
var safeTime = regexp.MustCompile(`^(infinity|-infinity|[0-9]{4,6}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|\+00(:00)?)( BC)?)$`)

func scalar(raw json.RawMessage, kind string) bool {
	if bytes.Equal(raw, []byte("null")) {
		return kind == "U" || kind == "I" || kind == "T"
	}
	switch kind {
	case "u", "U":
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return false
		}
		id, err := uuid.Parse(s)
		return err == nil && id != uuid.Nil && id.String() == s
	case "i", "I", "x", "j", "o", "w":
		if !integer.Match(raw) {
			return false
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return false
		}
		switch kind {
		case "x":
			return n > 0 && n <= 4294967295
		case "j":
			return n >= -2147483648 && n <= 2147483647
		case "o":
			return n >= 0
		case "w":
			return n >= 0 && n <= 127
		}
		return true
	case "b":
		return bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false"))
	case "c":
		var s string
		return json.Unmarshal(raw, &s) == nil && clockTime.MatchString(s)
	case "t", "T":
		var s string
		return json.Unmarshal(raw, &s) == nil && len(s) <= 48 && safeTime.MatchString(s)
	default:
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return false
		}
		for _, v := range strings.Split(kind, "|") {
			if s == v {
				return true
			}
		}
		return false
	}
}

func snapshot(raw json.RawMessage, p Projection) (map[string]json.RawMessage, error) {
	var v map[string]json.RawMessage
	if len(raw) > MaxLeafBytes || json.Unmarshal(raw, &v) != nil || len(v) != len(p.Fields) {
		return nil, ErrInvalid
	}
	for k, kind := range p.Fields {
		field, ok := v[k]
		if !ok || !scalar(field, kind) {
			return nil, ErrInvalid
		}
	}
	return v, nil
}

func (e Effect) Validate(root uuid.UUID) error {
	p, ok := projections[e.ResourceType]
	if !ok || e.EffectID == uuid.Nil || root == uuid.Nil || e.TriggerUserID != root || !ValidOrganization(e.TargetOrganizationID, e.OrgResolution) || e.TransitionSlot != "row" {
		return ErrInvalid
	}
	b, err := snapshot(e.Before, p)
	if err != nil {
		return err
	}
	var key string
	if p.Fields[p.Key] == "i" {
		key = string(b[p.Key])
	} else if json.Unmarshal(b[p.Key], &key) != nil {
		return ErrInvalid
	}
	if e.ResourceKey != key {
		return ErrInvalid
	}
	sameUser := func(raw json.RawMessage) bool { var id uuid.UUID; return json.Unmarshal(raw, &id) == nil && id == root }
	switch e.ResourceType {
	case "schedule_rule":
		if !sameUser(b["target_user_id"]) {
			return ErrInvalid
		}
	case "user_override":
		if !sameUser(b["add_user_id"]) && !sameUser(b["remove_user_id"]) {
			return ErrInvalid
		}
	case "contact_method", "escalation_policy_action", "schedule_on_call_history", "ep_step_on_call_history", "user_organization_assignment", "user_session", "basic_auth_link":
		if !sameUser(b["user_id"]) {
			return ErrInvalid
		}
	case "user_favorite":
		if !sameUser(b["user_id"]) && !sameUser(b["target_user_id"]) {
			return ErrInvalid
		}
	case "user_status_contact_setting":
		if sameUser(b["user_id"]) {
			return ErrInvalid
		}
	}
	deleted := bytes.Equal(e.After, []byte("null"))
	switch e.ResourceType {
	case "rotation_participant":
		if deleted {
			if e.Change != "relationship_removed" || e.Provenance != "IMPLICIT_APPLICATION_DELETE" || e.DeletionMechanism != "explicit_sql" {
				return ErrInvalid
			}
		} else {
			a, err := snapshot(e.After, p)
			if err != nil {
				return err
			}
			if e.Change != "relationship_reassigned" || e.Provenance != "IMPLICIT_APPLICATION_UPDATE" || e.DeletionMechanism != "application_update" || bytes.Equal(a["user_id"], b["user_id"]) {
				return ErrInvalid
			}
			for _, k := range []string{"id", "rotation_id", "position", "ordinal"} {
				if !bytes.Equal(a[k], b[k]) {
					return ErrInvalid
				}
			}
		}
	case "rotation_participant_count", "rotation_state":
		if deleted {
			if e.ResourceType != "rotation_state" || e.Change != "deleted" || e.Provenance != "IMPLICIT_TRIGGER_DELETE" || e.DeletionMechanism != "trigger_delete" {
				return ErrInvalid
			}
		} else {
			a, err := snapshot(e.After, p)
			if err != nil {
				return err
			}
			if e.Change != "state_updated" || e.Provenance != "IMPLICIT_TRIGGER_UPDATE" || e.DeletionMechanism != "trigger_update" || !bytes.Equal(a[p.Key], b[p.Key]) || bytes.Equal(e.Before, e.After) {
				return ErrInvalid
			}
		}
	case "user_status_contact_setting":
		a, err := snapshot(e.After, p)
		if err != nil {
			return err
		}
		if e.Change != "relationship_cleared" || e.Provenance != "IMPLICIT_FK_SET_NULL" || e.DeletionMechanism != "fk_set_null" || bytes.Equal(b["contact_method_id"], []byte("null")) || !bytes.Equal(a["contact_method_id"], []byte("null")) || !bytes.Equal(a["user_id"], b["user_id"]) {
			return ErrInvalid
		}
	default:
		change := "deleted"
		if e.ResourceType == "user_favorite" || e.ResourceType == "user_organization_assignment" {
			change = "relationship_removed"
		}
		if !deleted || e.Change != change || e.Provenance != "IMPLICIT_FK_CASCADE" || e.DeletionMechanism != "fk_cascade" {
			return ErrInvalid
		}
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return ErrInvalid
	}
	return checkJSONBytes(raw, MaxLeafBytes)
}

func DecodeEffect(raw []byte) (Effect, error) {
	var e Effect
	if err := checkJSONBytes(raw, MaxLeafBytes); err != nil {
		return e, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil {
		return e, ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return e, ErrInvalid
	}
	return e, nil
}

var clockTime = regexp.MustCompile(`^(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,6})?|24:00:00(\.0{1,6})?)$`)

// ValidateSnapshot proves a closed, exact original identity before an explicit
// CMNR target can be excluded from User's implicit effect collection.
func ValidateSnapshot(typ, key string, raw json.RawMessage) error {
	p, ok := projections[typ]
	if !ok {
		return ErrInvalid
	}
	b, err := snapshot(raw, p)
	if err != nil {
		return err
	}
	var actual string
	if p.Fields[p.Key] == "i" {
		actual = string(b[p.Key])
	} else if json.Unmarshal(b[p.Key], &actual) != nil {
		return ErrInvalid
	}
	if actual != key {
		return ErrInvalid
	}
	return nil
}
