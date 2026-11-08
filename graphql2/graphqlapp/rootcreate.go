package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/label"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/rootcreateaudit"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

type creationTargetKey struct{}
type creationTarget struct {
	organizationID uuid.UUID
	tx             *sql.Tx
}

// Only a verified parent or Create transaction establishes this immutable,
// transaction-bound target. Client input and sibling mutation trees cannot.
func withCreationTarget(ctx context.Context, tx *sql.Tx, id uuid.UUID) context.Context {
	return context.WithValue(ctx, creationTargetKey{}, creationTarget{id, tx})
}
func inheritedCreationTarget(ctx context.Context) (uuid.UUID, bool) {
	if ctx == nil {
		return uuid.Nil, false
	}
	v, ok := ctx.Value(creationTargetKey{}).(creationTarget)
	tx, _ := ctx.Value(txKey).(*sql.Tx)
	return v.organizationID, ok && tx != nil && v.tx == tx && v.organizationID != uuid.Nil && v.organizationID.String() != organization.DefaultOrganizationID
}

type rootCreatePlan struct {
	ctx                                                      context.Context
	db                                                       *sql.DB
	ec                                                       *executioncontext.ExecutionContext
	identityErr                                              error
	target                                                   uuid.UUID
	nested, joined, audited, attempted, finalized, committed bool
	conn                                                     *sql.Conn
	tx                                                       *sql.Tx
	event                                                    rootcreateaudit.Event
}

func newRootCreatePlan(ctx context.Context, db *sql.DB, typ string) *rootCreatePlan {
	p := &rootCreatePlan{ctx: ctx, db: db}
	p.ec, p.identityErr = executioncontext.CheckHumanAuthority(ctx)
	_, p.nested = inheritedCreationTarget(ctx)
	if p.identityErr == nil && p.ec.Privileges().PlatformAdmin() && !p.nested {
		p.audited = true
		home, _ := p.ec.HomeOrganizationID()
		p.event = rootcreateaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorID: uuid.MustParse(p.ec.ActualActorID()), HomeOrganizationID: home, OrganizationRole: string(p.ec.Privileges().OrganizationRole()), RootType: typ, Outcome: "validation_failed", Reason: "invalid_fields", OccurredAt: time.Now()}
		if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
			p.event.RequestID = id
		}
	}
	return p
}

func (p *rootCreatePlan) scope(explicit *string, favorite *bool) (*uuid.UUID, error) {
	if p.identityErr != nil {
		return nil, p.identityErr
	}
	priv := p.ec.Privileges()
	if !priv.PlatformAdmin() && priv.OrganizationRole() != organization.OrganizationRoleAdmin {
		return nil, permission.NewAccessDenied("Root Create authority is required")
	}
	home, _ := p.ec.HomeOrganizationID()
	target := home
	parent, inherited := inheritedCreationTarget(p.ctx)
	if inherited {
		target = parent
	}
	if !inherited && priv.PlatformAdmin() && explicit == nil {
		return nil, validation.NewFieldError("targetOrganizationID", "explicit Normal target is required")
	}
	if explicit != nil {
		id, err := validate.ParseUUID("targetOrganizationID", *explicit)
		if err != nil {
			return nil, err
		}
		if inherited && id != parent {
			return nil, validation.NewFieldError("targetOrganizationID", "conflicts with the verified parent target")
		}
		if !priv.PlatformAdmin() && id != home {
			return nil, permission.NewAccessDenied("Root Create target is outside Home")
		}
		target = id
	}
	if _, err := organization.NewStore(p.db).FindNormalByID(p.ctx, target); err != nil {
		return nil, validation.NewFieldError("targetOrganizationID", "Normal target is unavailable")
	}
	p.target = target
	p.event.TargetOrganizationID = target
	if favorite != nil && *favorite && target != home {
		return nil, validation.NewFieldError("favorite", "Foreign Create cannot create a personal favorite")
	}
	return &p.target, nil
}

// withTx owns exactly one creation tree. Nested callbacks inherit the same
// verified scope and transaction; only the top-level owner commits and audits.
func (p *rootCreatePlan) withTx(ctx context.Context, fn func(context.Context, *sql.Tx) error, id func() string) error {
	if p.target == uuid.Nil {
		return permission.NewAccessDenied("verified Create target is required")
	}
	run := func(ctx context.Context, tx *sql.Tx) error {
		var target uuid.UUID
		if err := tx.QueryRowContext(ctx, `SELECT o.id FROM organizations o JOIN normal_organizations n
		 ON n.organization_id=o.id AND n.organization_classification=o.classification
		 WHERE o.id=$1 AND o.classification='NORMAL' AND o.id<>$2
		 FOR SHARE OF o,n`, p.target, organization.DefaultOrganizationID).Scan(&target); err != nil {
			return err
		}
		ctx = withCreationTarget(context.WithValue(ctx, txKey, tx), tx, target)
		if err := fn(ctx, tx); err != nil {
			return err
		}
		if p.audited {
			p.event.RootID = uuid.MustParse(id())
			p.event.Outcome, p.event.Reason = "committed", "created"
			if err := rootcreateaudit.Append(ctx, tx, p.event); err != nil {
				return err
			}
		}
		return nil
	}
	if tx, ok := ctx.Value(txKey).(*sql.Tx); ok {
		target, valid := inheritedCreationTarget(ctx)
		// Preserve the existing server-owned transaction entry point for an
		// ordinary OrgAdmin's top-level Home Create. Its target was independently
		// authorized above; it cannot carry PlatformAdmin Global authority.
		if !valid && !p.nested && p.ec != nil && !p.ec.Privileges().PlatformAdmin() && p.ec.Privileges().OrganizationRole() == organization.OrganizationRoleAdmin {
			home, normal := p.ec.EffectiveOrganizationID()
			if normal && home == p.target {
				p.joined = true
				return run(ctx, tx)
			}
		}
		if !valid || target != p.target {
			return permission.NewAccessDenied("nested Create requires its verified parent transaction")
		}
		p.joined = true
		return run(ctx, tx)
	}
	var err error
	p.conn, err = p.db.Conn(ctx)
	if err != nil {
		return err
	}
	p.tx, err = p.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := run(ctx, p.tx); err != nil {
		return err
	}
	p.attempted = true
	err, p.finalized = commitServiceUpdate(ctx, p.tx)
	p.committed = err == nil
	return err
}

func rootCreateSafeError(err error) error {
	if errors.Is(err, label.ErrDisabled) {
		return label.ErrDisabled
	}
	if err == nil || permission.IsPermissionError(err) || validation.IsValidationError(err) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return validation.NewFieldError("input", "target or reference is unavailable")
	}
	return errors.New("root Create transaction failed")
}

func (p *rootCreatePlan) finish(operationErr error) error {
	if p.nested || p.joined {
		return rootCreateSafeError(operationErr)
	}
	rb, released := releaseServiceUpdate(p.conn, p.tx, p.finalized)
	if p.committed {
		if !released {
			p.auditFault("committed_resource_release_unconfirmed")
		}
		return nil
	}
	if operationErr == nil {
		operationErr = errors.New("root Create transaction interrupted")
	}
	if !p.audited {
		return rootCreateSafeError(operationErr)
	}
	p.event.EventID = uuid.New()
	p.event.OccurredAt = time.Now()
	p.event.Outcome, p.event.Reason = "validation_failed", "invalid_fields"
	if permission.IsPermissionError(operationErr) {
		p.event.Outcome, p.event.Reason = "denied", "authority_denied"
	}
	if !validation.IsValidationError(operationErr) && !permission.IsPermissionError(operationErr) && !errors.Is(operationErr, sql.ErrNoRows) {
		p.event.Outcome, p.event.Reason = "tx_failed", "write_failed"
	}
	if p.attempted {
		outcome, _ := serviceUpdateCommitOutcome(operationErr)
		if outcome == "commit_unknown" {
			p.event.Outcome, p.event.Reason = "commit_unknown", "commit_unconfirmed"
		}
	} else {
		p.event.RootID = uuid.Nil
		if p.tx != nil && rb != nil {
			p.event.Outcome, p.event.Reason = "rollback_unconfirmed", "rollback_unconfirmed"
		}
	}
	if !released {
		p.auditFault("resource_release_unconfirmed")
		return fmt.Errorf("%w; Create audit persistence unavailable", rootCreateSafeError(operationErr))
	}
	if err := rootcreateaudit.RecordFailure(p.db, p.event); err != nil {
		p.auditFault("persistence_unavailable")
		return fmt.Errorf("%w; Create audit persistence unavailable", rootCreateSafeError(operationErr))
	}
	return rootCreateSafeError(operationErr)
}

func (p *rootCreatePlan) auditFault(fault string) {
	ctx := log.WithFields(context.Background(), log.Fields{"AuditOperation": p.event.RootType + ".create", "AuditFault": fault, "AuditEventID": p.event.EventID.String(), "AuditAttemptID": p.event.AttemptID.String(), "AuditRequestID": p.event.RequestID.String()})
	log.Log(ctx, rootcreateaudit.ErrUnavailable)
}

func validateNestedParent(field string, explicit *string, parent string) error {
	if explicit != nil && *explicit != parent {
		return validation.NewFieldError(field, "conflicts with the actual parent")
	}
	return nil
}
