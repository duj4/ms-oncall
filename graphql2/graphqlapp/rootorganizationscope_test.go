package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
)

func TestRootStoreOrganizationIDPrincipalClassification(t *testing.T) {
	userID := uuid.MustParse("6eca7879-1e50-4d0a-8b4f-fae8f4562573")
	sessionID := uuid.MustParse("765cf5bf-bba0-4f44-b3a3-029c243ba408")
	requester, err := auth.NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatal(err)
	}

	authProviderContext := func() context.Context {
		return permission.UserSourceContext(
			context.Background(),
			userID.String(),
			permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID.String()},
		)
	}

	t.Run("AuthProvider missing Requester fails closed", func(t *testing.T) {
		organizationID, err := rootStoreOrganizationID(authProviderContext())
		if organizationID != nil || !permission.IsPermissionError(err) {
			t.Fatalf("rootStoreOrganizationID = (%v, %v), want fail-closed permission error", organizationID, err)
		}
	})

	t.Run("AuthProvider Requester missing ExecutionContext fails closed", func(t *testing.T) {
		ctx := auth.WithRequester(authProviderContext(), requester)
		organizationID, err := rootStoreOrganizationID(ctx)
		if organizationID != nil || !permission.IsPermissionError(err) {
			t.Fatalf("rootStoreOrganizationID = (%v, %v), want fail-closed permission error", organizationID, err)
		}
	})

	t.Run("AuthProvider and Requester identity mismatch fails closed", func(t *testing.T) {
		ctx := permission.UserSourceContext(
			context.Background(),
			userID.String(),
			permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()},
		)
		ctx = auth.WithRequester(ctx, requester)
		organizationID, err := rootStoreOrganizationID(ctx)
		if organizationID != nil || !permission.IsPermissionError(err) {
			t.Fatalf("rootStoreOrganizationID = (%v, %v), want fail-closed permission error", organizationID, err)
		}
	})

	t.Run("invalid ExecutionContext cannot enable compatibility fallback", func(t *testing.T) {
		ctx := auth.WithRequester(authProviderContext(), requester)
		ctx = executioncontext.WithExecutionContext(ctx, executioncontext.ExecutionContext{})
		organizationID, err := rootStoreOrganizationID(ctx)
		if organizationID != nil || !permission.IsPermissionError(err) {
			t.Fatalf("rootStoreOrganizationID = (%v, %v), want fail-closed permission error", organizationID, err)
		}
	})

	t.Run("Requester with non-AuthProvider source fails closed", func(t *testing.T) {
		ctx := permission.UserSourceContext(
			context.Background(),
			userID.String(),
			permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()},
		)
		ctx = auth.WithRequester(ctx, requester)
		organizationID, err := rootStoreOrganizationID(ctx)
		if organizationID != nil || !permission.IsPermissionError(err) {
			t.Fatalf("rootStoreOrganizationID = (%v, %v), want fail-closed permission error", organizationID, err)
		}
	})

	t.Run("GQL API key remains non-human compatibility", func(t *testing.T) {
		ctx := permission.UserSourceContext(
			context.Background(),
			userID.String(),
			permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()},
		)
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil || organizationID != nil {
			t.Fatalf("rootStoreOrganizationID = (%v, %v), want explicit unscoped compatibility", organizationID, err)
		}
	})

	t.Run("trusted context without human source remains compatibility", func(t *testing.T) {
		organizationID, err := rootStoreOrganizationID(permission.SystemContext(context.Background(), "test"))
		if err != nil || organizationID != nil {
			t.Fatalf("rootStoreOrganizationID = (%v, %v), want explicit unscoped compatibility", organizationID, err)
		}
	})
}
