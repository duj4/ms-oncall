package deleteaudit

import (
	"encoding/json"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

const (
	MaxEffects   = 16384
	MaxJSONBytes = 8 * 1024 * 1024
	Step         = "escalation_policy_step"
	Action       = "escalation_policy_action"
	Favorite     = "escalation_policy_favorite"
)

// Effect describes the deleted child/configuration or removed favorite relation.
// TargetID is an action reference, never a claim that its target was deleted.
// Only the fields belonging to the selected type are encoded.
type Effect struct {
	EffectID             uuid.UUID  `json:"effect_id"`
	ResourceType         string     `json:"resource_type"`
	RootID               uuid.UUID  `json:"root_id"`
	TargetOrganizationID uuid.UUID  `json:"target_organization_id"`
	Relation             string     `json:"relation"`
	Change               string     `json:"change"`
	Provenance           string     `json:"provenance"`
	DeletionMechanism    string     `json:"deletion_mechanism"`
	Cause                string     `json:"cause"`
	ResourceUUID         *uuid.UUID `json:"resource_uuid,omitempty"`
	ResourceNumericID    *int64     `json:"resource_numeric_id,omitempty"`
	StepNumber           *int       `json:"step_number,omitempty"`
	ParentStepID         *uuid.UUID `json:"parent_step_id,omitempty"`
	TargetKind           string     `json:"target_kind,omitempty"`
	TargetID             *uuid.UUID `json:"target_id,omitempty"`
	OwnerUserID          *uuid.UUID `json:"owner_user_id,omitempty"`
	OwnerOrganizationID  *uuid.UUID `json:"owner_organization_id,omitempty"`
	OwnerOrgResolution   string     `json:"owner_org_resolution,omitempty"`
}

func validID(id *uuid.UUID) bool { return id != nil && *id != uuid.Nil }

func (f Effect) identity() string {
	if f.ResourceUUID != nil {
		return f.ResourceType + ":" + f.ResourceUUID.String()
	}
	if f.ResourceNumericID != nil {
		return f.ResourceType + ":" + strconv.FormatInt(*f.ResourceNumericID, 10)
	}
	return ""
}

func canonicalEffects(in []Effect) []Effect {
	out := append([]Effect{}, in...)
	slices.SortFunc(out, func(a, b Effect) int {
		if a.identity() < b.identity() {
			return -1
		}
		if a.identity() > b.identity() {
			return 1
		}
		return 0
	})
	return out
}

func (e Event) validateEffects() error {
	if len(e.Effects) > MaxEffects {
		return ErrCapacity
	}
	steps := map[uuid.UUID]bool{}
	seen, ids := map[string]bool{}, map[uuid.UUID]bool{}
	for _, f := range e.Effects {
		if f.EffectID == uuid.Nil || f.RootID != e.RootID || f.TargetOrganizationID != e.TargetOrganizationID || f.Provenance != "CASCADE" || f.DeletionMechanism != "fk_cascade" || f.Cause != "escalation_policy_delete" || seen[f.identity()] || ids[f.EffectID] {
			return ErrInvalid
		}
		seen[f.identity()], ids[f.EffectID] = true, true
		if f.ResourceType != Favorite && (f.ResourceNumericID != nil || f.OwnerUserID != nil || f.OwnerOrganizationID != nil || f.OwnerOrgResolution != "") {
			return ErrInvalid
		}
		switch f.ResourceType {
		case Step:
			if !validID(f.ResourceUUID) || f.StepNumber == nil || *f.StepNumber < 0 || *f.StepNumber > 2147483647 || f.ParentStepID != nil || f.TargetKind != "" || f.TargetID != nil || f.Relation != "escalation_policy.step" || f.Change != "deleted" {
				return ErrInvalid
			}
			steps[*f.ResourceUUID] = true
		case Action:
			if !validID(f.ResourceUUID) || !validID(f.ParentStepID) || f.StepNumber != nil || !validID(f.TargetID) || f.Relation != "escalation_policy.step.action" || f.Change != "deleted" {
				return ErrInvalid
			}
			switch f.TargetKind {
			case "user", "schedule", "rotation", "notification_channel":
			default:
				return ErrInvalid
			}
		case Favorite:
			if f.ResourceUUID != nil || f.ResourceNumericID == nil || *f.ResourceNumericID <= 0 || f.StepNumber != nil || f.ParentStepID != nil || f.TargetKind != "" || f.TargetID != nil || !validID(f.OwnerUserID) || f.Relation != "escalation_policy.favorite" || f.Change != "relationship_removed" {
				return ErrInvalid
			}
			switch f.OwnerOrgResolution {
			case "unknown":
				if f.OwnerOrganizationID != nil {
					return ErrInvalid
				}
			case "known_normal", "known_default":
				if !validID(f.OwnerOrganizationID) || (f.OwnerOrgResolution == "known_default") != (f.OwnerOrganizationID.String() == organization.DefaultOrganizationID) {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	for _, f := range e.Effects {
		if f.ResourceType == Action && !steps[*f.ParentStepID] {
			return ErrInvalid
		}
	}
	raw, err := json.Marshal(canonicalEffects(e.Effects))
	if err != nil {
		return ErrInvalid
	}
	if len(raw) > MaxJSONBytes {
		return ErrCapacity
	}
	return nil
}

// ValidateBatch limits the entire EP group, with no truncation. Both the Go JSON
// encoding and PostgreSQL's effects::text byte count must fit the same budget;
// the controller checks the latter after staging the INSERTs, before Commit.
func ValidateBatch(events []Event) error {
	count, size := 0, 0
	roots, ids := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	children := map[string]bool{}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		if roots[e.RootID] {
			return ErrInvalid
		}
		roots[e.RootID] = true
		raw, _ := json.Marshal(e.Canonical().Effects)
		count += len(e.Effects)
		size += len(raw)
		if count > MaxEffects || size > MaxJSONBytes {
			return ErrCapacity
		}
		for _, f := range e.Effects {
			if children[f.identity()] || ids[f.EffectID] {
				return ErrInvalid
			}
			children[f.identity()], ids[f.EffectID] = true, true
		}
	}
	return nil
}
