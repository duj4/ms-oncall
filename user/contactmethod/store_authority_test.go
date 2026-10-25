package contactmethod

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

func TestCMDeleteMissingHumanAuthorityBeforeDatabase(t *testing.T) {
	user, session := uuid.NewString(), uuid.NewString()
	r, err := auth.NewRequester(user, session)
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithRequester(permission.UserSourceContext(context.Background(), user, permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session}), r)
	for _, ids := range [][]string{nil, {uuid.NewString()}} {
		if err := NewStore(nil).Delete(ctx, nil, ids...); !permission.IsPermissionError(err) {
			t.Fatal("CM Delete accepted Human Admin without ExecutionContext")
		}
	}
}

// This connector never opens a real database. Count attempts as well as
// checking the permission error so a later database failure cannot pass.
type cmAuthorityConnector struct{ attempts atomic.Int32 }

func (c *cmAuthorityConnector) Connect(context.Context) (driver.Conn, error) {
	c.attempts.Add(1)
	return nil, errors.New("unexpected database access")
}
func (c *cmAuthorityConnector) Driver() driver.Driver { return c }
func (c *cmAuthorityConnector) Open(string) (driver.Conn, error) {
	return c.Connect(context.Background())
}

func TestCMDeleteExplicitNonHumanSourceBeforeDatabase(t *testing.T) {
	owner := uuid.NewString()
	for _, sourceType := range []permission.SourceType{
		permission.SourceTypeGQLAPIKey,
		permission.SourceTypeUIK,
		permission.SourceTypeContactMethod,
		permission.SourceType(999),
	} {
		for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
			for _, input := range []struct {
				name string
				ids  []string
			}{{"nil", nil}, {"empty", []string{}}, {"target", []string{uuid.NewString()}}} {
				t.Run(sourceType.String()+"/"+string(role)+"/"+input.name, func(t *testing.T) {
					connector := new(cmAuthorityConnector)
					db := sql.OpenDB(connector)
					defer db.Close()
					ctx := permission.UserSourceContext(context.Background(), owner, role,
						&permission.SourceInfo{Type: sourceType, ID: "test-source"})
					err := NewStore(nil).Delete(ctx, db, input.ids...)
					if !permission.IsPermissionError(err) || permission.IsUnauthorized(err) {
						t.Errorf("CM Delete: error = %v, want access denied", err)
					}
					if connector.attempts.Load() != 0 {
						t.Error("CM Delete accessed database before rejecting source")
					}
				})
			}
		}
	}
}
