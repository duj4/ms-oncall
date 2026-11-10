package contactmethod

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
	audit "github.com/target/goalert/user/cmnrdeleteaudit"
	"github.com/target/goalert/validation/validate"
)

// DeleteForAuditTx captures only safe, locked identities and actual FK effects.
// The supplied transaction remains caller-owned, including on capture failure.
func (s *Store) DeleteForAuditTx(ctx context.Context, tx *sql.Tx, ids ...string) (audit.DeleteResult, error) {
	var result audit.DeleteResult
	authority, err := executioncontext.CheckCMNRMutationAuthority(ctx)
	if err != nil {
		return result, err
	}
	if tx == nil {
		return result, audit.ErrUnavailable
	}
	if len(ids) == 0 {
		return result, nil
	}
	uids, err := validate.ParseManyUUID("ContactMethodID", ids, 50)
	if err != nil {
		return result, err
	}
	return deleteCMNRTargetsResult(ctx, tx, authority, uids, true)
}

// AuthorizeCMNROwnerSnapshots reuses the same authority and lock ordering as
// AuthorizeCMNROwners. The returned Organization comes from that authorization,
// rather than a second mutable post-delete lookup.
func AuthorizeCMNROwnerSnapshots(ctx context.Context, tx *sql.Tx, a executioncontext.CMNRMutationAuthority, cms map[uuid.UUID]uuid.UUID) (map[uuid.UUID]executioncontext.CMNROrganizationSnapshot, error) {
	owners := make([]uuid.UUID, 0, len(cms))
	for _, owner := range cms {
		owners = append(owners, owner)
	}
	slices.SortFunc(owners, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	result := map[uuid.UUID]executioncontext.CMNROrganizationSnapshot{}
	for _, owner := range slices.Compact(owners) {
		org, err := a.AuthorizeUserSnapshot(ctx, tx, owner)
		if err != nil {
			return result, err
		}
		// System authorization imposes no new Normal requirement. This read is
		// attribution only and may legitimately remain unknown.
		if org.Resolution == "unknown" {
			org, err = executioncontext.SnapshotCMNROrganization(ctx, tx, owner)
			if err != nil {
				return result, err
			}
		}
		result[owner] = org
	}
	return result, nil
}

func deleteCMNRTargetsResult(ctx context.Context, tx *sql.Tx, authority executioncontext.CMNRMutationAuthority, ids []uuid.UUID, capture bool) (result audit.DeleteResult, err error) {
	cms, err := LockCMNRContactMethods(ctx, tx, ids)
	if err != nil {
		return result, err
	}
	lockedIDs := make([]uuid.UUID, 0, len(cms))
	for id := range cms {
		lockedIDs = append(lockedIDs, id)
	}
	slices.SortFunc(lockedIDs, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range lockedIDs {
		result.Targets = append(result.Targets, audit.Target{ID: id, OwnerID: cms[id], OrgResolution: "unknown"})
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,user_id,contact_method_id FROM user_notification_rules
	 WHERE contact_method_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, pq.Array(lockedIDs))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var n audit.Target
		if err = rows.Scan(&n.ID, &n.OwnerID, &n.ParentCMID); err != nil {
			break
		}
		if cms[n.ParentCMID] != n.OwnerID {
			err = permission.NewAccessDenied("")
			break
		}
		if capture {
			if len(result.CascadeRules) >= audit.MaxEffects {
				err = audit.ErrCapacity
				break
			}
			n.OrgResolution = "unknown"
			result.CascadeRules = append(result.CascadeRules, n)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return result, err
	}
	if !capture {
		if err = AuthorizeCMNROwners(ctx, tx, authority, cms); err != nil {
			return result, err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM user_contact_methods WHERE id=ANY($1::uuid[])`, pq.Array(lockedIDs))
		return result, err
	}
	orgs, err := AuthorizeCMNROwnerSnapshots(ctx, tx, authority, cms)
	for i := range result.Targets {
		if o, ok := orgs[result.Targets[i].OwnerID]; ok {
			result.Targets[i].OrganizationID, result.Targets[i].OrgResolution = o.ID, o.Resolution
		}
	}
	if err != nil {
		return result, err
	}
	for i := range result.CascadeRules {
		o := orgs[result.CascadeRules[i].OwnerID]
		result.CascadeRules[i].OrganizationID, result.CascadeRules[i].OrgResolution = o.ID, o.Resolution
	}
	type captured struct {
		cm     uuid.UUID
		effect audit.Effect
	}
	var extra []captured
	rows, err = tx.QueryContext(ctx, `SELECT id,user_id,cm_id FROM auth_subjects WHERE cm_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, pq.Array(lockedIDs))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var id int64
		var owner, cm uuid.UUID
		if err = rows.Scan(&id, &owner, &cm); err != nil {
			break
		}
		if len(extra)+len(result.CascadeRules) >= audit.MaxEffects {
			err = audit.ErrCapacity
			break
		}
		extra = append(extra, captured{cm, audit.Effect{EffectID: uuid.New(), ResourceType: "auth_subject", ResourceNumericID: &id, OwnerUserID: owner, Relation: "contact_method.auth_subject", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE"}})
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return result, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,alert_status_log_contact_method_id FROM users WHERE alert_status_log_contact_method_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, pq.Array(lockedIDs))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var id, cm uuid.UUID
		if err = rows.Scan(&id, &cm); err != nil {
			break
		}
		if len(extra)+len(result.CascadeRules) >= audit.MaxEffects {
			err = audit.ErrCapacity
			break
		}
		extra = append(extra, captured{cm, audit.Effect{EffectID: uuid.New(), ResourceType: "user_status_contact_setting", ResourceUUID: &id, OwnerUserID: id, Relation: "user.alert_status_log_contact_method", Change: "relationship_cleared", Provenance: "IMPLICIT_FK_SET_NULL"}})
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return result, err
	}
	owners := []uuid.UUID{}
	for _, v := range extra {
		if _, ok := orgs[v.effect.OwnerUserID]; !ok {
			owners = append(owners, v.effect.OwnerUserID)
		}
	}
	slices.SortFunc(owners, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	for _, owner := range slices.Compact(owners) {
		org, err := executioncontext.SnapshotCMNROrganization(ctx, tx, owner)
		if err != nil {
			return result, err
		}
		orgs[owner] = org
	}
	rows, err = tx.QueryContext(ctx, `DELETE FROM user_contact_methods WHERE id=ANY($1::uuid[]) RETURNING id`, pq.Array(lockedIDs))
	if err != nil {
		return result, err
	}
	deleted := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		deleted[id] = true
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return result, err
	}
	for i := range result.Targets {
		result.Targets[i].Deleted = deleted[result.Targets[i].ID]
	}
	// Verify post-DELETE state under the retained row/parent locks. A captured
	// object is not automatically a deleted object (e.g. a suppressing trigger).
	for i := range result.CascadeRules {
		n := &result.CascadeRules[i]
		if !deleted[n.ParentCMID] {
			continue
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_notification_rules WHERE id=$1)`, n.ID).Scan(&exists); err != nil {
			return result, err
		}
		n.Deleted = !exists
	}
	for _, v := range extra {
		if !deleted[v.cm] {
			continue
		}
		f := v.effect
		var changed bool
		if f.ResourceType == "auth_subject" {
			err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT FROM auth_subjects WHERE id=$1)`, *f.ResourceNumericID).Scan(&changed)
		} else {
			err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM users WHERE id=$1 AND alert_status_log_contact_method_id IS NULL)`, *f.ResourceUUID).Scan(&changed)
		}
		if err != nil {
			return result, err
		}
		if !changed {
			continue
		}
		o := orgs[f.OwnerUserID]
		f.TargetOrganizationID, f.OrgResolution = audit.NullableID(o.ID), o.Resolution
		for i := range result.Targets {
			if result.Targets[i].ID == v.cm {
				result.Targets[i].Effects = append(result.Targets[i].Effects, f)
				break
			}
		}
	}
	return result, nil
}
