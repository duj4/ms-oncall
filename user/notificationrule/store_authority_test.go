package notificationrule

import (
	"context"
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
