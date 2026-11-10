package graphqlapp

import (
	"context"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

type serviceChild struct {
	root   uuid.UUID
	effect deleteaudit.Effect
}
type serviceKeyReceipt struct{ resource, root, org uuid.UUID }

// Only confirmed aborts of original business SQL bypass the integrity flag.
// Audit Append failures are deliberately handled separately and always block.
func (a *serviceDeleteAttempt) captureError(err error) error {
	if err != nil {
		pg := sqlutil.MapError(err)
		if pg == nil || pg.Code != "40001" && pg.Code != "40P01" {
			a.auditFailed = true
		}
	}
	return err
}

func (a *serviceDeleteAttempt) capture(ctx context.Context, ids []string, scope *uuid.UUID) (err error) {
	if _, err := validate.ParseManyUUID("ServiceID", ids, 50); err != nil {
		return err
	}
	defer func() { err = a.captureError(err) }()
	q := `SELECT id FROM services WHERE id=ANY($1::uuid[])`
	args := []any{sqlutil.UUIDArray(ids)}
	if scope != nil {
		q += ` AND organization_id=$2`
		args = append(args, *scope)
	}
	rows, err := a.tx.QueryContext(ctx, q+` ORDER BY id FOR UPDATE`, args...)
	if err != nil {
		return err
	}
	var roots []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		roots = append(roots, id)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	// A new statement after every root lock wait resolves current attribution.
	rows, err = a.tx.QueryContext(ctx, `SELECT id,organization_id FROM services WHERE id=ANY($1::uuid[]) ORDER BY id`, pq.Array(roots))
	if err != nil {
		return err
	}
	for rows.Next() {
		e := a.event
		if err = rows.Scan(&e.ServiceID, &e.TargetOrganizationID); err != nil {
			break
		}
		if scope != nil && e.TargetOrganizationID != *scope {
			err = deleteaudit.ErrInvalid
			break
		}
		e.EventID = uuid.New()
		a.targets = append(a.targets, e)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	if len(a.targets) != len(roots) {
		return deleteaudit.ErrInvalid
	}
	for _, typ := range []string{deleteaudit.IntegrationKey, deleteaudit.Alert, deleteaudit.ServiceFavorite} {
		if err := a.captureChildren(ctx, roots, typ); err != nil {
			return err
		}
	}
	owners := []uuid.UUID{}
	for _, c := range a.children {
		if c.effect.OwnerUserID != nil {
			owners = append(owners, *c.effect.OwnerUserID)
		}
	}
	slices.SortFunc(owners, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	orgs := map[uuid.UUID]executioncontext.CMNROrganizationSnapshot{}
	for _, owner := range slices.Compact(owners) {
		o, err := executioncontext.SnapshotCMNROrganization(ctx, a.tx, owner)
		if err != nil {
			return err
		}
		orgs[owner] = o
	}
	for i := range a.children {
		f := &a.children[i].effect
		if f.OwnerUserID != nil {
			o := orgs[*f.OwnerUserID]
			f.OwnerOrgResolution = o.Resolution
			if o.ID != uuid.Nil {
				id := o.ID
				f.OwnerOrganizationID = &id
			}
		}
	}
	return nil
}

func serviceChildTable(typ string) (table, identity, parent string) {
	switch typ {
	case deleteaudit.IntegrationKey:
		return "integration_keys", "audit_resource_id", "service_id"
	case deleteaudit.Alert:
		return "alerts", "id", "service_id"
	case deleteaudit.ServiceFavorite:
		return "user_favorites", "id", "tgt_service_id"
	default:
		panic("invalid internal service effect type")
	}
}

func (a *serviceDeleteAttempt) captureChildren(ctx context.Context, roots []uuid.UUID, typ string) error {
	table, identity, parent := serviceChildTable(typ)
	// SQL identifiers come exclusively from the closed internal whitelist.
	rows, err := a.tx.QueryContext(ctx, `SELECT `+identity+` FROM `+table+` WHERE `+parent+`=ANY($1::uuid[]) ORDER BY `+identity+` FOR UPDATE`, pq.Array(roots))
	if err != nil {
		return err
	}
	var uuids []uuid.UUID
	var nums []int64
	for rows.Next() {
		if typ == deleteaudit.IntegrationKey {
			var id uuid.UUID
			err = rows.Scan(&id)
			uuids = append(uuids, id)
		} else {
			var id int64
			err = rows.Scan(&id)
			nums = append(nums, id)
		}
		if err != nil {
			break
		}
		if len(a.children)+len(uuids)+len(nums)+len(a.keyReceipts) > deleteaudit.MaxEffects {
			err = deleteaudit.ErrCapacity
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	// Re-read membership after child-lock waits. Rows that legally moved away
	// before capture are excluded; moves between locked roots use their new root.
	q := `SELECT ` + identity + `,` + parent
	args := []any{pq.Array(nums), pq.Array(roots)}
	switch typ {
	case deleteaudit.IntegrationKey:
		q += `,COALESCE(id=ANY($3::uuid[]),false)`
		args[0] = pq.Array(uuids)
		args = append(args, pq.Array(a.plan.explicitKeys))
	case deleteaudit.ServiceFavorite:
		q += `,user_id`
	}
	q += ` FROM ` + table + ` WHERE ` + identity + `=ANY($1) AND ` + parent + `=ANY($2::uuid[]) ORDER BY ` + identity
	rows, err = a.tx.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		f := deleteaudit.Effect{EffectID: uuid.New(), ResourceType: typ, OwnerOrgResolution: "not_applicable", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "service_delete", Change: "deleted"}
		var root uuid.UUID
		switch typ {
		case deleteaudit.IntegrationKey:
			var id uuid.UUID
			var explicit bool
			err = rows.Scan(&id, &root, &explicit)
			f.ResourceUUID = &id
			f.Relation = "service.integration_key"
			if explicit {
				f.Provenance = "EXPLICIT"
			}
		case deleteaudit.Alert:
			var id int64
			err = rows.Scan(&id, &root)
			f.ResourceNumericID = &id
			f.Relation = "service.alert"
		case deleteaudit.ServiceFavorite:
			var id int64
			var owner uuid.UUID
			err = rows.Scan(&id, &root, &owner)
			f.ResourceNumericID, f.OwnerUserID, f.Relation, f.Change = &id, &owner, "service.favorite", "relationship_removed"
		}
		if err != nil {
			break
		}
		found := false
		for _, e := range a.targets {
			if e.ServiceID == root {
				f.TargetOrganizationID = e.TargetOrganizationID
				found = true
				break
			}
		}
		if !found {
			err = deleteaudit.ErrInvalid
			break
		}
		a.children = append(a.children, serviceChild{root, f})
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	var count int
	if err := a.tx.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE `+parent+`=ANY($1::uuid[])`, pq.Array(roots)).Scan(&count); err != nil {
		return err
	}
	n := 0
	for _, c := range a.children {
		if c.effect.ResourceType == typ {
			n++
		}
	}
	if n != count {
		return deleteaudit.ErrInvalid
	}
	return nil
}

func (a *serviceDeleteAttempt) witness(ctx context.Context) (err error) {
	defer func() { err = a.captureError(err) }()
	deleted := map[uuid.UUID]uuid.UUID{}
	for _, r := range a.deletedRoots {
		if _, exists := deleted[r.ID]; exists {
			return deleteaudit.ErrInvalid
		}
		found := false
		for _, e := range a.targets {
			if e.ServiceID == r.ID && e.TargetOrganizationID == r.OrganizationID {
				found = true
				break
			}
		}
		if !found {
			return deleteaudit.ErrInvalid
		}
		deleted[r.ID] = r.OrganizationID
	}
	for _, e := range a.targets {
		var exists, unchanged bool
		if err := a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM services WHERE id=$1),EXISTS(SELECT FROM services WHERE id=$1 AND organization_id=$2)`, e.ServiceID, e.TargetOrganizationID).Scan(&exists, &unchanged); err != nil {
			return err
		}
		_, didDelete := deleted[e.ServiceID]
		if didDelete && exists || !didDelete && !unchanged {
			return deleteaudit.ErrInvalid
		}
	}
	for _, c := range a.children {
		table, id, parent := serviceChildTable(c.effect.ResourceType)
		var identity any = c.effect.ResourceNumericID
		if c.effect.ResourceUUID != nil {
			identity = *c.effect.ResourceUUID
		}
		var exists, unchanged bool
		q := `SELECT EXISTS(SELECT FROM ` + table + ` WHERE ` + id + `=$1),EXISTS(SELECT FROM ` + table + ` WHERE ` + id + `=$1 AND ` + parent + `=$2`
		args := []any{identity, c.root}
		if c.effect.OwnerUserID != nil {
			q += ` AND user_id=$3`
			args = append(args, *c.effect.OwnerUserID)
		}
		if err := a.tx.QueryRowContext(ctx, q+`)`, args...).Scan(&exists, &unchanged); err != nil {
			return err
		}
		_, didDelete := deleted[c.root]
		if didDelete && exists || !didDelete && !unchanged {
			return deleteaudit.ErrInvalid
		}
	}
	for root := range deleted {
		for _, typ := range []string{deleteaudit.IntegrationKey, deleteaudit.Alert, deleteaudit.ServiceFavorite} {
			table, _, parent := serviceChildTable(typ)
			var exists bool
			if err := a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM `+table+` WHERE `+parent+`=$1)`, root).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return deleteaudit.ErrInvalid
			}
		}
	}
	for _, e := range a.targets {
		if _, ok := deleted[e.ServiceID]; !ok {
			continue
		}
		e.Outcome, e.Reason = "committed", "deleted"
		for _, c := range a.children {
			if c.root == e.ServiceID {
				e.Effects = append(e.Effects, c.effect)
			}
		}
		for _, r := range a.keyReceipts {
			if r.root != e.ServiceID {
				continue
			}
			if r.org != e.TargetOrganizationID {
				return deleteaudit.ErrInvalid
			}
			var exists bool
			if err := a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM integration_keys WHERE audit_resource_id=$1)`, r.resource).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return deleteaudit.ErrInvalid
			}
			id := r.resource
			e.Effects = append(e.Effects, deleteaudit.Effect{EffectID: uuid.New(), ResourceType: deleteaudit.IntegrationKey, ResourceUUID: &id, OwnerOrgResolution: "not_applicable", TargetOrganizationID: e.TargetOrganizationID, Relation: "service.integration_key", Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target"})
		}
		a.successes = append(a.successes, e.Canonical())
	}
	if err := deleteaudit.ValidateBatch(a.successes); err != nil {
		return err
	}
	for _, e := range a.successes {
		if err := deleteaudit.Append(ctx, a.tx, e); err != nil {
			a.auditFailed = true
			return err
		}
	}
	return nil
}

func (a *serviceDeleteAttempt) verifyBudget(ctx context.Context) (err error) {
	defer func() { err = a.captureError(err) }()
	if err := deleteaudit.ValidateBatch(a.successes); err != nil {
		return err
	}
	var count, size, roots int
	err = a.tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(jsonb_array_length(effects)),0),coalesce(sum(octet_length(effects::text)),0)
	 FROM service_delete_audit_events WHERE attempt_id=$1 AND execution_id=$2 AND outcome='committed'`, a.event.AttemptID, a.event.ExecutionID).Scan(&roots, &count, &size)
	if err != nil {
		return err
	}
	if roots != len(a.successes) {
		return deleteaudit.ErrInvalid
	}
	want := 0
	for _, e := range a.successes {
		want += len(e.Effects)
	}
	if count != want {
		return deleteaudit.ErrInvalid
	}
	if count > deleteaudit.MaxEffects || size > deleteaudit.MaxJSONBytes {
		return deleteaudit.ErrCapacity
	}
	return nil
}
