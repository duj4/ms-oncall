package notificationrule

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user/contactmethod"
	"github.com/target/goalert/util"
	"github.com/target/goalert/validation/validate"
)

// Store allows the lookup and management of NotificationRules.
type Store struct {
	db *sql.DB

	insert  *sql.Stmt
	findAll *sql.Stmt
}

// NewDB will create a DB backend from a sql.DB. An error will be returned if statements fail to prepare.
func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	prep := &util.Prepare{DB: db, Ctx: ctx}
	p := prep.P
	s := &Store{db: db}

	s.insert = p("INSERT INTO user_notification_rules (id,user_id,delay_minutes,contact_method_id) VALUES ($1,$2,$3,$4)")
	s.findAll = p("SELECT id,user_id,delay_minutes,contact_method_id FROM user_notification_rules WHERE user_id = $1")

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
	authority, err := executioncontext.CheckCMNRMutationAuthority(ctx)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return nil, permission.NewAccessDenied("")
	}
	n, err = n.Normalize(false)
	if err != nil {
		return nil, err
	}

	n.ID = uuid.New().String()

	var db gadb.DBTX = s.db
	if tx != nil {
		db = tx
	}
	err = executioncontext.WithCMNRTransaction(ctx, db, func(tx *sql.Tx) error {
		cms, err := contactmethod.LockCMNRContactMethods(ctx, tx, []uuid.UUID{n.ContactMethodID})
		if err != nil {
			return err
		}
		owner := uuid.MustParse(n.UserID)
		if owner == uuid.Nil || cms[n.ContactMethodID] != owner {
			return permission.NewAccessDenied("")
		}
		if err := authority.AuthorizeUser(ctx, tx, owner); err != nil {
			return err
		}
		_, err = wrapTx(ctx, tx, s.insert).ExecContext(ctx, n.ID, n.UserID, n.DelayMinutes, n.ContactMethodID)
		return err
	})
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
	authority, err := executioncontext.CheckCMNRMutationAuthority(ctx)
	if err != nil {
		return err
	}

	if len(ids) == 0 {
		return nil
	}

	uids, err := validate.ParseManyUUID("NotificationRuleID", ids, 50)
	if err != nil {
		return err
	}

	var db gadb.DBTX = s.db
	if tx != nil {
		db = tx
	}
	return executioncontext.WithCMNRTransaction(ctx, db, func(tx *sql.Tx) error {
		return deleteCMNRTargets(ctx, tx, authority, uids)
	})
}

func deleteCMNRTargets(ctx context.Context, tx *sql.Tx, authority executioncontext.CMNRMutationAuthority, ids []uuid.UUID) error {
	// Discover parents only to establish CM-before-NR lock order. Discovery is
	// never an authorization result. Re-read every NR under its own row lock,
	// then reject a changed/missing parent outside the locked CM set.
	rows, err := tx.QueryContext(ctx, `SELECT contact_method_id FROM user_notification_rules WHERE id=ANY($1::uuid[])`, pq.Array(ids))
	if err != nil {
		return err
	}
	var cmIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		cmIDs = append(cmIDs, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	cms, err := contactmethod.LockCMNRContactMethods(ctx, tx, cmIDs)
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,user_id,contact_method_id FROM user_notification_rules
		WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, pq.Array(ids))
	if err != nil {
		return err
	}
	lockedIDs := make([]uuid.UUID, 0, len(ids))
	owners := make(map[uuid.UUID]uuid.UUID)
	for rows.Next() {
		var id, owner, cm uuid.UUID
		if err := rows.Scan(&id, &owner, &cm); err != nil {
			_ = rows.Close()
			return err
		}
		if owner == uuid.Nil || cms[cm] != owner {
			_ = rows.Close()
			return permission.NewAccessDenied("")
		}
		lockedIDs = append(lockedIDs, id)
		owners[cm] = owner
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	if err := contactmethod.AuthorizeCMNROwners(ctx, tx, authority, owners); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM user_notification_rules WHERE id=ANY($1::uuid[])`, pq.Array(lockedIDs))
	return err
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
