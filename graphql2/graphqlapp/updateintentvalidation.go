package graphqlapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/user"
	"github.com/target/goalert/validation/validate"
)

// Validate the desired set as well as the removal set. In particular a mixed
// update must not promise execution with a missing/foreign replacement target.
// Existing Store admission is reused; no provider mapping or external call is
// permitted in this adapter. Ordinary updates still use their original path.
func (a *App) validateUpdateActions(ctx context.Context, tx *sql.Tx, input graphql2.UpdateEscalationPolicyStepInput, org uuid.UUID, locked bool) (string, error) {
	if len(input.Actions) > ds.DefaultBudget().MaxDependencies {
		return "", previewLimit()
	}
	existing, err := a.PolicyStore.FindAllStepActionsTx(ctx, tx, uuid.MustParse(input.ID))
	if err != nil {
		return "", safePreviewError(err)
	}
	groups := map[ds.ResourceKind][]string{}
	newTargets := map[ds.Resource]bool{}
	for _, action := range input.Actions {
		retained := slices.ContainsFunc(existing, func(old gadb.DestV1) bool { return reflect.DeepEqual(old, action) })
		var kind ds.ResourceKind
		var id string
		switch action.Type {
		case user.DestTypeUser:
			kind, id = ds.ResourceUser, action.Arg(user.FieldUserID)
		case schedule.DestTypeSchedule:
			kind, id = ds.ResourceSchedule, action.Arg(schedule.FieldScheduleID)
		case rotation.DestTypeRotation:
			kind, id = ds.ResourceRotation, action.Arg(rotation.FieldRotationID)
		default:
			if !retained {
				return "", previewUnavailable()
			} // would require a mapping/opaque provider capability
			continue
		}
		parsed, err := validate.ParseUUID("ID", id)
		if err != nil {
			return "", previewUnavailable()
		}
		id = parsed.String()
		if !slices.Contains(groups[kind], id) {
			groups[kind] = append(groups[kind], id)
		}
		if !retained {
			target := ds.Resource{Kind: kind, ID: id}
			if newTargets[target] {
				return "", previewUnavailable()
			}
			newTargets[target] = true
			if a.DestReg == nil {
				return "", previewUnavailable()
			}
			info, err := a.DestReg.TypeInfo(ctx, action.Type)
			if err != nil || !info.IsEPTarget() {
				return "", previewUnavailable()
			}
		}
	}
	states := []string{}
	for _, kind := range []ds.ResourceKind{ds.ResourceUser, ds.ResourceSchedule, ds.ResourceRotation} {
		ids := groups[kind]
		if len(ids) == 0 {
			continue
		}
		slices.Sort(ids)
		table := map[ds.ResourceKind]string{ds.ResourceUser: "users", ds.ResourceSchedule: "schedules", ds.ResourceRotation: "rotations"}[kind]
		if locked {
			if err := lockUpdateRows(ctx, tx, `SELECT id::text FROM `+table+` WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE NOWAIT`, pq.Array(ids)); err != nil {
				return "", err
			}
			if kind == ds.ResourceUser {
				if err := lockUpdateRows(ctx, tx, `SELECT user_id::text FROM user_organization_assignments WHERE user_id=ANY($1::uuid[]) ORDER BY user_id FOR SHARE NOWAIT`, pq.Array(ids)); err != nil {
					return "", err
				}
			}
		}
		query := `SELECT count(*),COALESCE(jsonb_agg(jsonb_build_array(id,organization_id,time_zone) ORDER BY id),'[]'::jsonb)::text FROM schedules WHERE id=ANY($1::uuid[])`
		switch kind {
		case ds.ResourceUser:
			query = `SELECT count(*),COALESCE(jsonb_agg(jsonb_build_array(u.id,u.role,a.effective_organization_id,a.organization_role,a.mapping_outcome,a.matched_count) ORDER BY u.id),'[]'::jsonb)::text FROM users u LEFT JOIN user_organization_assignments a ON a.user_id=u.id WHERE u.id=ANY($1::uuid[])`
		case ds.ResourceRotation:
			query = `SELECT count(*),COALESCE(jsonb_agg(jsonb_build_array(id,organization_id,time_zone,type) ORDER BY id),'[]'::jsonb)::text FROM rotations WHERE id=ANY($1::uuid[])`
		}
		var count int
		var state string
		if err := tx.QueryRowContext(ctx, query, pq.Array(ids)).Scan(&count, &state); err != nil || count != len(ids) {
			return "", previewUnavailable()
		}
		states = append(states, state)
	}
	var scope *uuid.UUID
	if !permission.System(ctx) {
		scope = &org
	}
	for _, action := range input.Actions {
		if err := (*Mutation)(a).validateEscalationPolicyActionTargetTx(ctx, tx, action, scope); err != nil {
			return "", previewUnavailable()
		}
	}
	raw, _ := json.Marshal(states)
	return hexDigest(raw), nil
}
