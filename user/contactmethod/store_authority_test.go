package contactmethod

import (
	"context"
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
