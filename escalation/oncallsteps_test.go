package escalation

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/permission"
)

func TestOnCallStepsValidationBeforeQuery(t *testing.T) {
	ctx := permission.SystemContext(context.Background(), "test")
	zero := uuid.Nil
	for _, tc := range []struct {
		name string
		ctx  context.Context
		user string
		org  *uuid.UUID
		want string
	}{
		{"permission", context.Background(), "bad", &zero, ""},
		{"malformed user nil scope", ctx, "bad", nil, "invalid value for 'UserID': must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
		{"malformed user before zero scope", ctx, "bad", &zero, "invalid value for 'UserID': must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
		{"zero organization", ctx, uuid.NewString(), &zero, "invalid value for 'OrganizationID': must be specified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No prepared statements: any query attempt would panic.
			steps, err := new(Store).FindAllOnCallStepsForUserTx(tc.ctx, nil, tc.user, tc.org)
			require.Nil(t, steps)
			if tc.want == "" {
				require.True(t, permission.IsPermissionError(err))
			} else {
				require.EqualError(t, err, tc.want)
			}
		})
	}
}
