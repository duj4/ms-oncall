package notificationrule

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

// Store allows the lookup and management of NotificationRules.
type Store struct {
	db *sql.DB

	insert      *sql.Stmt
	delete      *sql.Stmt
	findAll     *sql.Stmt
	deleteOwned *sql.Stmt
}

// NewDB will create a DB backend from a sql.DB. An error will be returned if statements fail to prepare.
func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	prep := &util.Prepare{DB: db, Ctx: ctx}
	p := prep.P
	s := &Store{db: db}

	s.insert = p("INSERT INTO user_notification_rules (id,user_id,delay_minutes,contact_method_id) VALUES ($1,$2,$3,$4)")
	s.findAll = p("SELECT id,user_id,delay_minutes,contact_method_id FROM user_notification_rules WHERE user_id = $1")
	s.delete = p("DELETE FROM user_notification_rules WHERE id = any($1)")
	// Lock the complete existing set before checking ownership, including when
	// another transaction has changed a target while this statement was waiting.
	s.deleteOwned = p(`WITH targets AS MATERIALIZED (
		SELECT id, user_id FROM user_notification_rules
		WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE
	), ownership AS (
		SELECT count(*) FILTER (WHERE user_id <> $2::uuid) = 0 AS allowed FROM targets
	), deleted AS (
		DELETE FROM user_notification_rules
		WHERE id IN (SELECT id FROM targets) AND user_id = $2::uuid
			AND (SELECT allowed FROM ownership)
		RETURNING id
	)
	SELECT allowed FROM ownership`)

	return s, prep.Err
}

// Insert implements the NotificationRuleStore interface by inserting the new NotificationRule into the database.
// A new ID is always created.
func (s *Store) Insert(ctx context.Context, n *NotificationRule) (*NotificationRule, error) {
	return s.CreateTx(ctx, nil, n)
}

// CreateTx implements the NotificationRuleStore interface by inserting the new NotificationRule into the database.
// A new ID is always created.
func (s *Store) CreateTx(ctx context.Context, tx *sql.Tx, n *NotificationRule) (*NotificationRule, error) {
	err := permission.LimitCheckAny(ctx, permission.System, permission.Admin, permission.MatchUser(n.UserID))
	if err != nil {
		return nil, err
	}

	n, err = n.Normalize(false)
	if err != nil {
		return nil, err
	}

	n.ID = uuid.New().String()

	_, err = wrapTx(ctx, tx, s.insert).ExecContext(ctx, n.ID, n.UserID, n.DelayMinutes, n.ContactMethodID)
	if err != nil {
		return nil, err
	}

	return n, nil
}

func wrapTx(ctx context.Context, tx *sql.Tx, stmt *sql.Stmt) *sql.Stmt {
	if tx == nil {
		return stmt
	}

	return tx.StmtContext(ctx, stmt)
}

// DeleteTx will delete notification rules with the provided ids.
func (s *Store) DeleteTx(ctx context.Context, tx *sql.Tx, ids ...string) error {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}

	if len(ids) == 0 {
		return nil
	}

	err = validate.ManyUUID("NotificationRuleID", ids, 50)
	if err != nil {
		return err
	}

	if permission.Admin(ctx) {
		_, err = wrapTx(ctx, tx, s.delete).ExecContext(ctx, sqlutil.UUIDArray(ids))
		return err
	}

	owner, err := uuid.Parse(permission.UserID(ctx))
	if err != nil || owner == uuid.Nil {
		return permission.NewAccessDenied("")
	}

	var allowed bool
	err = wrapTx(ctx, tx, s.deleteOwned).QueryRowContext(ctx, sqlutil.UUIDArray(ids), owner).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return permission.NewAccessDenied("")
	}
	return nil
}

// FindAll implements the NotificationRuleStore interface.
func (s *Store) FindAll(ctx context.Context, userID string) ([]NotificationRule, error) {
	err := validate.UUID("UserID", userID)
	if err != nil {
		return nil, err
	}

	err = permission.LimitCheckAny(ctx, permission.All)
	if err != nil {
		return nil, err
	}

	rows, err := s.findAll.QueryContext(ctx, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	notificationrules := []NotificationRule{}
	for rows.Next() {
		var n NotificationRule
		err = rows.Scan(&n.ID, &n.UserID, &n.DelayMinutes, &n.ContactMethodID)
		if err != nil {
			return nil, err
		}
		notificationrules = append(notificationrules, n)
	}

	return notificationrules, nil
}
