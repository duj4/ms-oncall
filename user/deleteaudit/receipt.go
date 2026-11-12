package deleteaudit

import (
	"github.com/google/uuid"
)

// ExplicitIntent is admission intent only. It makes no existence or authority
// claim and retains the first raw family position for duplicate inputs.
type ExplicitIntent struct {
	ResourceType string
	ID           uuid.UUID
	Ordinal      int
}

// Receipt is bounded: one header and at most 100 explicit CMNR witnesses.
// Complete child inventories remain in the transaction's temporary relations.
type Receipt struct {
	CaptureHighUnits, ActiveJSONHighBytes int
	EffectPages                           int64
	Event                                 Event
	DeletedUserID                         uuid.UUID
	DeletedRole                           string
	DeletedRowVersion                     uint32
	Witnesses                             []ExplicitWitness
}

type ExplicitWitness struct {
	EventID              uuid.UUID  `json:"event_id"`
	ResourceType         string     `json:"resource_type"`
	ResourceID           uuid.UUID  `json:"resource_id"`
	IntentOrdinal        int        `json:"intent_ordinal"`
	OwnerID              uuid.UUID  `json:"owner_id"`
	ParentCMID           *uuid.UUID `json:"parent_cm_id"`
	TargetOrganizationID *uuid.UUID `json:"target_organization_id"`
	TargetOrgResolution  string     `json:"target_org_resolution"`
	RowVersion           uint32     `json:"row_version"`
	CauseUserID          uuid.UUID  `json:"cause_user_id"`
	CauseEventID         uuid.UUID  `json:"cause_event_id"`
	RequestID            uuid.UUID  `json:"request_id"`
	ExecutionID          uuid.UUID  `json:"execution_id"`
	AttemptID            uuid.UUID  `json:"attempt_id"`
	OwnerFK              bool       `json:"owner_fk"`
	ContactMethodFK      bool       `json:"contact_method_fk"`
	Verified             bool       `json:"verified"`
}

func (r Receipt) Validate() error {
	e := r.Event
	b := e.BeforeContext
	if e.Validate() != nil || e.RecordKind != "success_witness" || b == nil || r.DeletedUserID != b.UserID || r.DeletedRole != b.UserRole || r.DeletedRowVersion != b.RowVersion || len(r.Witnesses) != len(e.RelatedExplicitEvents) {
		return ErrInvalid
	}
	seen := map[uuid.UUID]bool{}
	for _, w := range r.Witnesses {
		if w.Validate() != nil || w.CauseUserID != b.UserID || w.CauseEventID != e.EventID || w.RequestID != e.RequestID || w.ExecutionID != e.ExecutionID || w.AttemptID != e.AttemptID || seen[w.EventID] {
			return ErrInvalid
		}
		found := false
		for _, ref := range e.RelatedExplicitEvents {
			if ref.EventID == w.EventID && ref.ResourceType == w.ResourceType && ref.ResourceID == w.ResourceID {
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
		if w.OwnerID == b.UserID && (value(w.TargetOrganizationID) != value(e.TargetOrganizationID) || w.TargetOrgResolution != e.TargetOrgResolution) {
			return ErrInvalid
		}
		seen[w.EventID] = true
	}
	return nil
}

func (w ExplicitWitness) Validate() error {
	if !w.Verified || w.EventID == uuid.Nil || w.ResourceID == uuid.Nil || w.OwnerID == uuid.Nil || w.RowVersion == 0 || w.CauseUserID == uuid.Nil || w.CauseEventID == uuid.Nil || w.RequestID == uuid.Nil || w.ExecutionID == uuid.Nil || w.AttemptID == uuid.Nil || w.CauseEventID == w.EventID || w.IntentOrdinal < 0 || w.IntentOrdinal >= 50 || !ValidOrganization(w.TargetOrganizationID, w.TargetOrgResolution) || (!w.OwnerFK && !w.ContactMethodFK) || w.OwnerFK != (w.OwnerID == w.CauseUserID) {
		return ErrInvalid
	}
	switch w.ResourceType {
	case "contact_method":
		if w.ParentCMID != nil || !w.OwnerFK || w.ContactMethodFK {
			return ErrInvalid
		}
	case "notification_rule":
		if w.ParentCMID == nil || *w.ParentCMID == uuid.Nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// DeleteResult retains trusted target identities even if a later root fails.
// Targets are non-assertive carriers; only verified Receipts authorize success.
type DeleteResult struct {
	Targets  []Event
	Receipts []Receipt
}
