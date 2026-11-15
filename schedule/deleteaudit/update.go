package deleteaudit

import (
	"reflect"

	"github.com/google/uuid"
)

const ScheduleTargetUpdate = "updateScheduleTarget"

// RuleDeleteDetail is the minimal persisted identity of a directly deleted
// Rule. Schedule and Target survive. No fictional ScheduleTarget UUID exists.
type RuleDeleteDetail struct {
	ScheduleID uuid.UUID `json:"schedule_id"`
	TargetKind string    `json:"target_kind"`
	TargetID   uuid.UUID `json:"target_id"`
}

func (e Event) validateScheduleTargetUpdate() error {
	if e.Operation != ScheduleTargetUpdate || e.RootType != Schedule || e.EffectsVersion != 2 || e.BeforeState != nil {
		return ErrInvalid
	}
	// Reuse the exact accepted identity/authority/outcome projection. This local
	// copy validates header fields only; no Update is persisted as a Root Delete.
	header := e
	header.SchemaVersion, header.EffectsVersion = 1, 1
	header.Operation, header.Effects = "schedule.delete", nil
	if e.RecordKind == "success_witness" {
		if len(e.Effects) == 0 || e.Reason != "children_deleted" || e.Cause != "update_induced" {
			return ErrInvalid
		}
		header.Reason, header.Cause = "deleted", "explicit_target"
	} else if len(e.Effects) != 0 {
		return ErrInvalid
	}
	if err := header.Validate(); err != nil {
		return err
	}
	if len(e.Effects) > MaxEffects || e.JSONBytes() > MaxJSONBytes {
		return ErrCapacity
	}
	seen, ids := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	var selected *RuleDeleteDetail
	for _, f := range e.Effects {
		d := f.RuleDeletion
		if f.EffectID == uuid.Nil || !validID(f.ResourceUUID) || d == nil || d.ScheduleID != e.RootID || d.TargetID == uuid.Nil || d.TargetKind != "user" && d.TargetKind != Rotation || seen[*f.ResourceUUID] || ids[f.EffectID] {
			return ErrInvalid
		}
		if selected != nil && *selected != *d {
			return ErrInvalid
		}
		selected = d
		seen[*f.ResourceUUID], ids[f.EffectID] = true, true
		want := Effect{EffectID: f.EffectID, ResourceType: Rule, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID,
			Relation: "schedule.schedule_rule", Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced", ResourceUUID: f.ResourceUUID, RuleDeletion: d}
		if !reflect.DeepEqual(want, f) {
			return ErrInvalid
		}
	}
	return nil
}
