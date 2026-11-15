package deleteaudit

import (
	"encoding/json"

	"github.com/google/uuid"
)

const (
	PolicyUpdate = "updateEscalationPolicy"
	StepUpdate   = "updateEscalationPolicyStep"
)

// RootType identifies the real operation subject. A Step Update never claims
// deletion of its surviving parent Policy or Step.
func (e Event) RootType() string {
	if e.SchemaVersion == 2 && e.Operation == StepUpdate {
		return Step
	}
	return "escalation_policy"
}

func (e Event) validateUpdateEffects() error {
	if len(e.Effects) > MaxEffects {
		return ErrCapacity
	}
	steps, seen, ids := map[uuid.UUID]bool{}, map[string]bool{}, map[uuid.UUID]bool{}
	for _, f := range e.Effects {
		if f.EffectID == uuid.Nil || !validID(f.ResourceUUID) || f.RootID != e.RootID || f.TargetOrganizationID != e.TargetOrganizationID || seen[f.identity()] || ids[f.EffectID] || f.ResourceNumericID != nil || f.OwnerUserID != nil || f.OwnerOrganizationID != nil || f.OwnerOrgResolution != "" || f.Change != "deleted" {
			return ErrInvalid
		}
		seen[f.identity()], ids[f.EffectID] = true, true
		explicit := f.Provenance == "EXPLICIT" && f.DeletionMechanism == "explicit_sql" && f.Cause == "update_induced"
		cascade := f.Provenance == "CASCADE" && f.DeletionMechanism == "fk_cascade" && f.Cause == "step_delete"
		switch f.ResourceType {
		case Step:
			if e.Operation != PolicyUpdate || !explicit || f.StepNumber == nil || *f.StepNumber < 0 || *f.StepNumber > 2147483647 || f.ParentStepID != nil || f.TargetKind != "" || f.TargetID != nil || f.Relation != "escalation_policy.step" {
				return ErrInvalid
			}
			steps[*f.ResourceUUID] = true
		case Action:
			if !validID(f.ParentStepID) || !validID(f.TargetID) || f.StepNumber != nil || f.Relation != "escalation_policy.step.action" {
				return ErrInvalid
			}
			if e.Operation == PolicyUpdate && !cascade || e.Operation == StepUpdate && (!explicit || *f.ParentStepID != e.RootID) {
				return ErrInvalid
			}
			switch f.TargetKind {
			case "user", "schedule", "rotation", "notification_channel":
			default:
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	for _, f := range e.Effects {
		if e.Operation == PolicyUpdate && f.ResourceType == Action && !steps[*f.ParentStepID] {
			return ErrInvalid
		}
	}
	raw, err := json.Marshal(canonicalEffects(e.Effects))
	if err != nil {
		return ErrInvalid
	}
	// PGVERIFY1 (PostgreSQL 17.11) verified the exact JSONB text expansion
	// of these closed v2 projections: Step has 11 keys, Action has 13.
	// Object separators add 21/25 spaces, plus N-1 array separators:
	// D = C + 22*S + 26*A - 1 (U02 has S=0). Empty [] stays 2 bytes.
	// Only apply this after semantic validation. Fields, enums, numeric ranges
	// or PostgreSQL version changes require renewed formula verification;
	// this is not a size model for v1 or arbitrary raw JSON.
	// Counts are already bounded by MaxEffects, so overhead cannot overflow
	// even on 32-bit int. Subtract from the budget rather than adding to C.
	overhead := 0
	if len(e.Effects) != 0 {
		overhead = 22*len(steps) + 26*(len(e.Effects)-len(steps)) - 1
	}
	if len(raw) > MaxJSONBytes-overhead {
		return ErrCapacity
	}
	return nil
}
