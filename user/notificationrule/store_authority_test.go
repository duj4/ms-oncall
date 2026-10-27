package notificationrule

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/permission"
)

func TestNRMutationMissingHumanAuthorityBeforeDatabase(t *testing.T) {
	user, session := uuid.NewString(), uuid.NewString()
	r, err := auth.NewRequester(user, session)
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithRequester(permission.UserSourceContext(context.Background(), user, permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session}), r)
	s := &Store{} // A DB access would panic: admission failure must happen first.
	if _, err := s.CreateTx(ctx, nil, &NotificationRule{UserID: user}); !permission.IsPermissionError(err) {
		t.Fatal("NR Create accepted Human Admin without ExecutionContext")
	}
	for _, ids := range [][]string{nil, {uuid.NewString()}} {
		if err := s.DeleteTx(ctx, nil, ids...); !permission.IsPermissionError(err) {
			t.Fatal("NR Delete accepted missing Human authority")
		}
	}
}

// Keep this path offline while detecting any connection attempt before denial.
type nrAuthorityConnector struct{ attempts atomic.Int32 }

func (c *nrAuthorityConnector) Connect(context.Context) (driver.Conn, error) {
	c.attempts.Add(1)
	return nil, errors.New("unexpected database access")
}
func (c *nrAuthorityConnector) Driver() driver.Driver { return c }
func (c *nrAuthorityConnector) Open(string) (driver.Conn, error) {
	return c.Connect(context.Background())
}

func TestNRMutationExplicitNonHumanSourceBeforeDatabase(t *testing.T) {
	owner, cmID, nrID := uuid.NewString(), uuid.New(), uuid.NewString()
	for _, sourceType := range []permission.SourceType{
		permission.SourceTypeGQLAPIKey,
		permission.SourceTypeUIK,
		permission.SourceTypeContactMethod,
		permission.SourceType(999),
	} {
		for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
			for _, operation := range []string{"create", "insert", "delete nil", "delete empty", "delete target"} {
				t.Run(sourceType.String()+"/"+string(role)+"/"+operation, func(t *testing.T) {
					connector := new(nrAuthorityConnector)
					db := sql.OpenDB(connector)
					defer db.Close()
					s := &Store{db: db}
					ctx := permission.UserSourceContext(context.Background(), owner, role,
						&permission.SourceInfo{Type: sourceType, ID: "test-source"})
					var err error
					switch operation {
					case "create", "insert":
						n := &NotificationRule{UserID: owner, ContactMethodID: cmID, DelayMinutes: 1}
						var created *NotificationRule
						if operation == "create" {
							created, err = s.CreateTx(ctx, nil, n)
						} else {
							created, err = s.Insert(ctx, n)
						}
						if created != nil {
							t.Error("rejected NR Create returned a rule")
						}
					case "delete nil":
						err = s.DeleteTx(ctx, nil)
					case "delete empty":
						err = s.DeleteTx(ctx, nil, []string{}...)
					case "delete target":
						err = s.DeleteTx(ctx, nil, nrID)
					}
					if !permission.IsPermissionError(err) || permission.IsUnauthorized(err) {
						t.Errorf("NR mutation: error = %v, want access denied", err)
					}
					if connector.attempts.Load() != 0 {
						t.Error("NR mutation accessed database before rejecting source")
					}
				})
			}
		}
	}
}
