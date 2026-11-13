// Package authsubjectdeleteaudit records closed AuthSubject deletion evidence.
// It grants no authority and never commits the caller's business transaction.
package authsubjectdeleteaudit

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/user/deleteaudit"
)

var (
	ErrInvalid     = errors.New("invalid auth_subject.delete evidence")
	ErrUnavailable = errors.New("auth_subject.delete audit persistence unavailable")
	ErrCapture     = errors.New("auth_subject.delete capture failed")
	ErrDelete      = errors.New("auth_subject.delete deletion failed")
	ErrPostcheck   = errors.New("auth_subject.delete postcheck failed")
)

// Identity is always a canonical decimal string in JSON, including zero and
// negative identities. No floating point conversion is permitted.
type Identity int64

func (id Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(id), 10))
}
func (id *Identity) UnmarshalJSON(raw []byte) error {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ErrInvalid
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != s {
		return ErrInvalid
	}
	*id = Identity(n)
	return nil
}

type Before struct {
	Version    int        `json:"version"`
	ID         Identity   `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	CMID       *uuid.UUID `json:"cm_id"`
	RowVersion uint32     `json:"row_version"`
}

type Event struct {
	SchemaVersion        int        `json:"schema_version"`
	EventID              uuid.UUID  `json:"event_id"`
	RequestID            uuid.UUID  `json:"request_id"`
	ExecutionID          uuid.UUID  `json:"execution_id"`
	AttemptID            uuid.UUID  `json:"attempt_id"`
	RecordKind           string     `json:"record_kind"`
	Operation            string     `json:"operation"`
	RootType             string     `json:"root_type"`
	RootID               *Identity  `json:"root_id"`
	RootOwnerUserID      *uuid.UUID `json:"root_owner_user_id"`
	ParentCMID           *uuid.UUID `json:"parent_cm_id"`
	ActorKind            string     `json:"actor_kind"`
	ActorID              *uuid.UUID `json:"actor_id"`
	HomeOrganizationID   *uuid.UUID `json:"home_organization_id"`
	AuthoritySource      string     `json:"authority_source"`
	AuthorityRole        string     `json:"authority_role"`
	OrganizationRole     string     `json:"organization_role"`
	TargetOrganizationID *uuid.UUID `json:"target_organization_id"`
	TargetOrgResolution  string     `json:"target_org_resolution"`
	BeforeContext        *Before    `json:"before_context"`
	Provenance           string     `json:"provenance"`
	DeletionMechanism    string     `json:"deletion_mechanism"`
	Cause                string     `json:"cause"`
	Outcome              string     `json:"outcome"`
	Reason               string     `json:"reason_code"`
	OccurredAt           time.Time  `json:"occurred_at"`
	RecordedAt           time.Time  `json:"recorded_at"`
}

func ID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func (e Event) Validate() error {
	if e.SchemaVersion != 1 || e.EventID == uuid.Nil || e.RequestID == uuid.Nil || e.ExecutionID == uuid.Nil || e.AttemptID == uuid.Nil || e.Operation != "auth_subject.delete" || e.RootType != "auth_subject" || !deleteaudit.ValidOrganization(e.TargetOrganizationID, e.TargetOrgResolution) {
		return ErrInvalid
	}
	for _, t := range []time.Time{e.OccurredAt, e.RecordedAt} {
		if t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
			return ErrInvalid
		}
	}
	for _, id := range []*uuid.UUID{e.ActorID, e.HomeOrganizationID, e.TargetOrganizationID} {
		if id != nil && *id == uuid.Nil {
			return ErrInvalid
		}
	}
	success := e.RecordKind == "success_witness"
	switch e.ActorKind {
	case "human":
		if e.ActorID == nil || e.HomeOrganizationID == nil || e.AuthoritySource != "current_local_user_organization_at_admission" {
			return ErrInvalid
		}
		if e.HomeOrganizationID.String() == organization.DefaultOrganizationID {
			if e.OrganizationRole != "NONE" || e.AuthorityRole != "platform_admin" && e.AuthorityRole != "none" {
				return ErrInvalid
			}
		} else {
			if e.OrganizationRole != "ORG_ADMIN" && e.OrganizationRole != "ORG_MEMBER" {
				return ErrInvalid
			}
			switch e.AuthorityRole {
			case "platform_admin":
			case "org_admin":
				if e.OrganizationRole != "ORG_ADMIN" {
					return ErrInvalid
				}
			case "org_member":
				if e.OrganizationRole != "ORG_MEMBER" {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
		if success && (e.AuthorityRole != "platform_admin" || e.HomeOrganizationID.String() == organization.DefaultOrganizationID && e.TargetOrgResolution != "known_normal") {
			return ErrInvalid
		}
	case "internal_system":
		if e.ActorID != nil || e.HomeOrganizationID != nil || e.AuthoritySource != "trusted_internal_system" || e.AuthorityRole != "internal_system" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	case "unknown":
		if success || e.ActorID != nil || e.HomeOrganizationID != nil || e.AuthoritySource != "unknown" || e.AuthorityRole != "unknown" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if e.RootID == nil && (e.RootOwnerUserID != nil || e.ParentCMID != nil || e.TargetOrganizationID != nil || e.TargetOrgResolution != "unknown") || e.RootID != nil && e.RootOwnerUserID == nil {
		return ErrInvalid
	}
	if success {
		b := e.BeforeContext
		if e.RootID == nil || b == nil || b.Version != 1 || b.ID != *e.RootID || b.UserID != *e.RootOwnerUserID || b.RowVersion == 0 || !sameID(b.CMID, e.ParentCMID) || e.Outcome != "committed" || e.Reason != "deleted" || e.Provenance != "EXPLICIT" || e.DeletionMechanism != "explicit_sql" || e.Cause != "explicit_target" {
			return ErrInvalid
		}
	} else {
		if e.RecordKind != "attempt_observation" || e.BeforeContext != nil || e.Provenance != "" || e.DeletionMechanism != "" || e.Cause != "" {
			return ErrInvalid
		}
		valid := false
		switch e.Outcome {
		case "denied":
			valid = e.Reason == "authority_denied" || e.Reason == "guard_denied"
		case "validation_failed":
			valid = e.Reason == "invalid_input"
		case "tx_failed":
			switch e.Reason {
			case "begin_failed", "capture_failed", "delete_failed", "receipt_invalid", "postcheck_failed", "audit_write_failed", "commit_rejected", "transaction_ownership_unavailable", "panic":
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
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > 4096 {
		return ErrInvalid
	}
	return nil
}

func sameID(a, b *uuid.UUID) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// Decode rejects omitted, duplicate, unknown and differently typed keys. The
// canonical comparison also applies recursively to the closed before object.
func Decode(raw []byte) (Event, error) {
	var e Event
	if len(raw) > 4096 {
		return e, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF || e.Validate() != nil {
		return Event{}, ErrInvalid
	}
	canonical, _ := json.Marshal(e)
	var original, expected map[string]json.RawMessage
	if json.Unmarshal(raw, &original) != nil || json.Unmarshal(canonical, &expected) != nil || len(original) != len(expected) {
		return Event{}, ErrInvalid
	}
	// Count every key before decoding to prevent duplicate-key last-value wins.
	if !uniqueKeys(raw) {
		return Event{}, ErrInvalid
	}
	for k := range expected {
		if _, ok := original[k]; !ok {
			return Event{}, ErrInvalid
		}
	}
	if e.BeforeContext != nil {
		var before map[string]json.RawMessage
		if json.Unmarshal(original["before_context"], &before) != nil || len(before) != 5 {
			return Event{}, ErrInvalid
		}
		for _, k := range []string{"version", "id", "user_id", "cm_id", "row_version"} {
			if _, ok := before[k]; !ok {
				return Event{}, ErrInvalid
			}
		}
		var owner string
		if json.Unmarshal(before["user_id"], &owner) != nil || owner != e.BeforeContext.UserID.String() {
			return Event{}, ErrInvalid
		}
	}
	return e, nil
}

func uniqueKeys(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var visit func() bool
	visit = func() bool {
		t, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		if delim != '{' && delim != '[' {
			return false
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				k, err := d.Token()
				if err != nil {
					return false
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return false
				}
				seen[s] = true
			}
			if !visit() {
				return false
			}
		}
		_, err = d.Token()
		return err == nil
	}
	return visit()
}

// Receipt is transaction-bound, single-use, and cannot retain authentication
// predicates. Only verified, matching locked and returned rows can construct it.
type Receipt struct {
	tx    *sql.Tx
	event Event
	used  bool
}

func NewReceipt(tx *sql.Tx, e Event, locked, returned Before, owner uuid.UUID, absent bool) (*Receipt, error) {
	if tx == nil || !absent || locked.Version != 1 || returned.Version != 1 || locked.ID != returned.ID || locked.UserID != returned.UserID || locked.UserID != owner || locked.RowVersion != returned.RowVersion || !sameID(locked.CMID, returned.CMID) {
		return nil, ErrInvalid
	}
	e.RootID = &returned.ID
	e.RootOwnerUserID = &returned.UserID
	e.ParentCMID = returned.CMID
	e.BeforeContext = &locked
	e.RecordKind = "success_witness"
	e.Provenance = "EXPLICIT"
	e.DeletionMechanism = "explicit_sql"
	e.Cause = "explicit_target"
	e.Outcome = "committed"
	e.Reason = "deleted"
	if e.Validate() != nil {
		return nil, ErrInvalid
	}
	// Own the DTO pointers independently of the caller's mutable values.
	raw, _ := json.Marshal(e)
	owned, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	return &Receipt{tx: tx, event: owned}, nil
}
