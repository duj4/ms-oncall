package authsubjectdeleteaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

const columns = `schema_version,event_id,request_id,execution_id,attempt_id,record_kind,operation,root_type,root_id,root_owner_user_id,parent_cm_id,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,target_organization_id,target_org_resolution,before_context,provenance,deletion_mechanism,cause,outcome,reason_code,occurred_at,recorded_at`

// Append uses a plain INSERT: every conflicting event/attempt fails the whole
// transaction. It never silently accepts a different payload or commits.
func Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if tx == nil {
		return ErrUnavailable
	}
	if err := e.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return ErrInvalid
	}
	selects := strings.Split(columns, ",")
	for i, col := range selects {
		selects[i] = "r." + col
		if col == "before_context" {
			selects[i] = "coalesce(r.before_context,'null'::jsonb)"
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO auth_subject_delete_audit_events (`+columns+`) SELECT `+strings.Join(selects, ",")+` FROM jsonb_populate_record(NULL::auth_subject_delete_audit_events,$1::jsonb) r`, string(raw))
	if err != nil {
		return ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrUnavailable
	}
	return nil
}

func AppendReceipt(ctx context.Context, tx *sql.Tx, r *Receipt, binding Event) error {
	if r == nil || tx == nil || r.tx != tx || r.used {
		return ErrInvalid
	}
	e := r.event
	if e.EventID != binding.EventID || e.RequestID != binding.RequestID || e.ExecutionID != binding.ExecutionID || e.AttemptID != binding.AttemptID || e.ActorKind != binding.ActorKind || !sameID(e.ActorID, binding.ActorID) || !sameID(e.HomeOrganizationID, binding.HomeOrganizationID) || e.AuthoritySource != binding.AuthoritySource || e.AuthorityRole != binding.AuthorityRole || e.OrganizationRole != binding.OrganizationRole {
		return ErrInvalid
	}
	r.used = true // attempted append is sticky, even when INSERT fails
	return Append(ctx, tx, e)
}
