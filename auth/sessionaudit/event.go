// Package sessionaudit records explicit revocation of independent, non-credential
// Session identities. It grants no authority and never commits a transaction.
package sessionaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
	useraudit "github.com/target/goalert/user/deleteaudit"
)

var (
	ErrInvalid     = errors.New("invalid user_session.revoke evidence")
	ErrUnavailable = errors.New("user_session.revoke audit persistence unavailable")
)

type Count int64

func (n Count) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatInt(int64(n), 10)) }
func (n *Count) UnmarshalJSON(raw []byte) error {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ErrInvalid
	}
	v, e := strconv.ParseInt(s, 10, 64)
	if e != nil || v < 0 || strconv.FormatInt(v, 10) != s {
		return ErrInvalid
	}
	*n = Count(v)
	return nil
}

type Event struct {
	SchemaVersion      int        `json:"schema_version"`
	EventID            uuid.UUID  `json:"event_id"`
	RequestID          uuid.UUID  `json:"request_id"`
	ExecutionID        uuid.UUID  `json:"execution_id"`
	AttemptID          uuid.UUID  `json:"attempt_id"`
	RecordKind         string     `json:"record_kind"`
	Operation          string     `json:"operation"`
	SelectionMode      string     `json:"selection_mode"`
	ActorKind          string     `json:"actor_kind"`
	ActorID            *uuid.UUID `json:"actor_id"`
	InitiatorKind      string     `json:"initiator_kind"`
	InitiatorUserID    *uuid.UUID `json:"initiator_user_id"`
	HomeOrganizationID *uuid.UUID `json:"home_organization_id"`
	AuthoritySource    string     `json:"authority_source"`
	AuthorityRole      string     `json:"authority_role"`
	OrganizationRole   string     `json:"organization_role"`
	AffectedCount      Count      `json:"affected_count"`
	Outcome            string     `json:"outcome"`
	Reason             string     `json:"reason_code"`
	OccurredAt         time.Time  `json:"occurred_at"`
	RecordedAt         time.Time  `json:"recorded_at"`
}

type Detail struct {
	EventID              uuid.UUID  `json:"event_id"`
	Ordinal              Count      `json:"effect_ordinal"`
	SessionAuditID       uuid.UUID  `json:"session_audit_id"`
	TargetUserID         *uuid.UUID `json:"target_user_id"`
	TargetOrganizationID *uuid.UUID `json:"target_organization_id"`
	TargetOrgResolution  string     `json:"target_org_resolution"`
	Provenance           string     `json:"provenance"`
	DeletionMechanism    string     `json:"deletion_mechanism"`
	Cause                string     `json:"cause"`
}

func ID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
func sameID(a, b *uuid.UUID) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func (e Event) Validate() error {
	if e.SchemaVersion != 1 || e.EventID == uuid.Nil || e.RequestID == uuid.Nil || e.ExecutionID == uuid.Nil || e.AttemptID == uuid.Nil || e.Operation != "user_session.revoke" || e.SelectionMode != "selected_sessions" && e.SelectionMode != "other_sessions_of_current_user" || e.AffectedCount < 0 {
		return ErrInvalid
	}
	for _, t := range []time.Time{e.OccurredAt, e.RecordedAt} {
		if t.IsZero() || t.Year() < 1 || t.Year() > 9999 || t.Location() != time.UTC || t.Nanosecond()%1000 != 0 {
			return ErrInvalid
		}
	}
	for _, id := range []*uuid.UUID{e.ActorID, e.InitiatorUserID, e.HomeOrganizationID} {
		if id != nil && *id == uuid.Nil {
			return ErrInvalid
		}
	}
	success := e.RecordKind == "success_witness"
	if e.InitiatorKind != e.ActorKind || !sameID(e.InitiatorUserID, e.ActorID) {
		return ErrInvalid
	}
	switch e.ActorKind {
	case "human":
		if e.ActorID == nil || e.HomeOrganizationID == nil || e.AuthoritySource != "current_local_user_organization_at_admission" {
			return ErrInvalid
		}
		if e.HomeOrganizationID.String() == organization.DefaultOrganizationID {
			if e.OrganizationRole != "NONE" || e.AuthorityRole != "platform_admin" && e.AuthorityRole != "none" {
				return ErrInvalid
			}
		} else if e.OrganizationRole != "ORG_MEMBER" && e.OrganizationRole != "ORG_ADMIN" || e.AuthorityRole != "platform_admin" && (e.AuthorityRole != "org_admin" || e.OrganizationRole != "ORG_ADMIN") && (e.AuthorityRole != "org_member" || e.OrganizationRole != "ORG_MEMBER") {
			return ErrInvalid
		}
	case "internal_system":
		if e.ActorID != nil || e.HomeOrganizationID != nil || e.AuthoritySource != "trusted_internal_system" || e.AuthorityRole != "internal_system" || e.OrganizationRole != "unknown" || e.SelectionMode != "selected_sessions" {
			return ErrInvalid
		}
	case "unknown":
		if success || e.ActorID != nil || e.HomeOrganizationID != nil || e.AuthoritySource != "unknown" || e.AuthorityRole != "unknown" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if success {
		if e.AffectedCount <= 0 || e.Outcome != "committed" || e.Reason != "revoked" {
			return ErrInvalid
		}
		return nil
	}
	if e.RecordKind != "attempt_observation" || e.AffectedCount != 0 {
		return ErrInvalid
	}
	valid := false
	switch e.Outcome {
	case "denied":
		valid = e.Reason == "authority_denied" || e.Reason == "context_missing"
	case "validation_failed":
		valid = e.Reason == "invalid_input"
	case "tx_failed":
		switch e.Reason {
		case "begin_failed", "mutation_failed", "attribution_failed", "receipt_invalid", "audit_write_failed", "commit_rejected", "capacity_exhausted", "transaction_ownership_unavailable":
			valid = true
		}
	case "commit_unknown":
		valid = e.Reason == "commit_unconfirmed"
	case "rollback_unconfirmed":
		valid = e.Reason == "rollback_unconfirmed"
	}
	if !valid {
		return ErrInvalid
	}
	return nil
}
func (d Detail) Validate(e Event) error {
	if e.Validate() != nil || e.RecordKind != "success_witness" || d.EventID != e.EventID || d.Ordinal < 0 || d.Ordinal >= e.AffectedCount || d.SessionAuditID == uuid.Nil || !useraudit.ValidOrganization(d.TargetOrganizationID, d.TargetOrgResolution) || d.TargetUserID == nil && (d.TargetOrganizationID != nil || d.TargetOrgResolution != "unknown") || d.Provenance != "EXPLICIT" || d.DeletionMechanism != "explicit_sql" {
		return ErrInvalid
	}
	if e.SelectionMode == "selected_sessions" && d.Cause != "explicit_target" || e.SelectionMode == "other_sessions_of_current_user" && (d.Cause != "end_other_self_sessions" || !sameID(d.TargetUserID, e.ActorID)) {
		return ErrInvalid
	}
	if e.ActorKind == "human" && e.HomeOrganizationID.String() == organization.DefaultOrganizationID && d.TargetOrgResolution != "known_normal" {
		return ErrInvalid
	}
	return nil
}

// Both objects are flat closed records. Compare every canonical scalar and count
// keys before decoding so omitted/null/duplicate/unknown keys cannot coerce values.
func decode(raw []byte, value any) error {
	if len(raw) > 4096 {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ErrInvalid
	}
	var actual, expected map[string]json.RawMessage
	if json.Unmarshal(raw, &actual) != nil || json.Unmarshal(canonical, &expected) != nil || len(actual) != len(expected) {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return ErrInvalid
	}
	count := 0
	for d.More() {
		if _, err = d.Token(); err != nil {
			return ErrInvalid
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return ErrInvalid
		}
		count++
	}
	if count != len(expected) {
		return ErrInvalid
	}
	for k, v := range expected {
		if !bytes.Equal(bytes.TrimSpace(actual[k]), v) {
			return ErrInvalid
		}
	}
	return nil
}
func DecodeEvent(raw []byte) (Event, error) {
	var e Event
	if decode(raw, &e) != nil || e.Validate() != nil {
		return Event{}, ErrInvalid
	}
	return e, nil
}
func DecodeDetail(raw []byte, e Event) (Detail, error) {
	var d Detail
	if decode(raw, &d) != nil || d.Validate(e) != nil {
		return Detail{}, ErrInvalid
	}
	return d, nil
}
