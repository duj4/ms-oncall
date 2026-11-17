package graphqlapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

type previewTestSigner struct{}

func (previewTestSigner) Sign(b []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte("synthetic-test-key-not-a-credential"))
	_, _ = h.Write(b)
	return h.Sum(nil), nil
}
func (s previewTestSigner) Verify(b, sig []byte) (bool, bool) {
	want, _ := s.Sign(b)
	return hmac.Equal(want, sig), false
}

func TestDeletionPreviewInput(t *testing.T) {
	id := uuid.NewString()
	valid := graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: []graphql2.DeletionResourceInput{{Type: graphql2.DeletionTargetTypeService, ID: id}}}
	_, size, err := previewTargets(valid, nil)
	require.NoError(t, err)
	require.Equal(t, 50, size)
	for _, op := range graphql2.AllDeletionOperation {
		if op == graphql2.DeletionOperationDeleteResources {
			continue
		}
		input := valid
		input.Operation = op
		_, _, err := previewTargets(input, nil)
		require.Equal(t, previewUnavailable(), err)
	}
	for _, size := range []int{-1, 0, 101} {
		_, _, err := previewTargets(valid, &size)
		require.Error(t, err)
	}
	for _, raw := range []graphql2.DeletionResourceInput{{Type: "USER_SESSION", ID: id}, {Type: graphql2.DeletionTargetTypeService, ID: "bad"}, {Type: graphql2.DeletionTargetTypeService, ID: uuid.Nil.String()}} {
		input := valid
		input.Targets = []graphql2.DeletionResourceInput{raw}
		_, _, err := previewTargets(input, nil)
		require.Error(t, err)
	}
	valid.Targets = append(valid.Targets, valid.Targets[0])
	_, _, err = previewTargets(valid, nil)
	require.Error(t, err)
	valid.Targets = make([]graphql2.DeletionResourceInput, 101)
	_, _, err = previewTargets(valid, nil)
	require.Equal(t, previewLimit(), err)
}

func TestDeletionPreviewImpactDescription(t *testing.T) {
	for _, tc := range []struct {
		relation ds.RelationshipKind
		change   ds.DeletionChangeKind
		word     string
	}{
		{ds.RelationshipNotificationConfiguration, ds.ChangeDeleted, "deleted"},
		{ds.RelationshipFavorite, ds.ChangeDeleted, "deleted"},
		{ds.RelationshipUserOrganization, ds.ChangeDeleted, "deleted"},
		{ds.RelationshipRetainedPolicy, ds.ChangePreserved, "preserved"},
		{ds.RelationshipKeyCreator, ds.ChangeRelationRemoved, "relationship would be removed"},
	} {
		d := ds.DeletionImpact{Dependency: ds.Dependency{Relationship: tc.relation}, Decision: ds.Decision{Policy: ds.PolicyInformational, Change: tc.change}}
		require.Contains(t, deletionImpactDescription(d), tc.word)
		if tc.change != ds.ChangePreserved {
			require.NotContains(t, deletionImpactDescription(d), "preserved")
		}
	}
	d := ds.DeletionImpact{Decision: ds.Decision{Policy: ds.PolicyBlock, Change: ds.ChangePreserved}}
	require.Contains(t, deletionImpactDescription(d), "blocking dependency")
}

func TestDeletionPreviewCursorSecurity(t *testing.T) {
	targets := []ds.Resource{{Kind: ds.ResourceService, ID: uuid.NewString()}}
	binding := newDeletionPreviewCursor(targets, strings.Repeat("a", 64), strings.Repeat("b", 64))
	binding.Position = strings.Repeat("c", 64)
	signer := previewTestSigner{}
	raw, err := encodeDeletionPreviewCursor(signer, binding)
	require.NoError(t, err)
	got, err := decodeDeletionPreviewCursor(signer, raw)
	require.NoError(t, err)
	require.Equal(t, binding, *got)
	payload, signature, _ := strings.Cut(raw, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err)
	require.NotContains(t, string(decoded), targets[0].ID)
	require.NotContains(t, string(decoded), "organization")
	for _, invalid := range []string{"", "!", strings.Repeat("x", 2049), payload + ".invalid", base64.RawURLEncoding.EncodeToString(bytes.Replace(decoded, []byte("DELETE_RESOURCES"), []byte("UPDATE_ROTATION"), 1)) + "." + signature} {
		got, err := decodeDeletionPreviewCursor(signer, invalid)
		require.Error(t, err)
		require.Nil(t, got)
	}
	for _, change := range []func(*deletionPreviewCursor){func(c *deletionPreviewCursor) { c.Scope = "" }, func(c *deletionPreviewCursor) { c.Position = "123" }, func(c *deletionPreviewCursor) { c.Operation = "UNKNOWN" }} {
		other := binding
		change(&other)
		raw, err := encodeDeletionPreviewCursor(signer, other)
		require.NoError(t, err)
		_, err = decodeDeletionPreviewCursor(signer, raw)
		require.Error(t, err)
	}
}

type previewErrorConnector struct{ failure error }

func (c previewErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return previewErrorConn(c), nil
}
func (previewErrorConnector) Driver() driver.Driver { return sd2Driver{} }

type previewErrorConn struct{ failure error }

func (c previewErrorConn) Prepare(string) (driver.Stmt, error) { return nil, c.failure }
func (previewErrorConn) Close() error                          { return nil }
func (c previewErrorConn) Begin() (driver.Tx, error)           { return nil, c.failure }
func (c previewErrorConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return nil, c.failure
}

func TestDeletionPreviewHTTPErrorCodes(t *testing.T) {
	codes := []ds.ErrorCode{ds.DeletionBlocked, ds.DeletionConfirmationRequired, ds.DeletionDependencyChanged, ds.DeletionUnavailable, ds.DeletionPreviewLimitExceeded}
	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			db := sql.OpenDB(previewErrorConnector{errors.Join(errors.New("SYNTHETIC_PRIVATE_SQL_DETAIL"), &ds.DeletionSafetyError{Code: code})})
			defer db.Close()
			app := App{DB: db, PreviewSigner: previewTestSigner{}}
			body, _ := json.Marshal(map[string]any{"query": `query { deletionPreview(input:{operation:DELETE_RESOURCES,targets:[{type:SERVICE,id:"` + uuid.NewString() + `"}]}) {complete} }`})
			ctx := (config.Config{}).Context(permission.SystemContext(context.Background(), "DeletionPreviewTest"))
			req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			app.Handler().ServeHTTP(w, req)
			require.Contains(t, w.Body.String(), string(code))
			require.NotContains(t, w.Body.String(), "SYNTHETIC_PRIVATE")
			require.NotContains(t, w.Body.String(), "complete\":true")
			require.Zero(t, db.Stats().InUse)
		})
	}
	// Raw database diagnostics and unrecognized typed codes are scrubbed identically.
	for _, failure := range []error{&pgconn.PgError{Message: "SYNTHETIC_PRIVATE_SQL", Detail: "SYNTHETIC_PRIVATE_DEST"}, &ds.DeletionSafetyError{Code: "SYNTHETIC_PRIVATE"}} {
		result := deletionPreviewGraphQLError(context.Background(), failure)
		require.Equal(t, graphql2.ErrorCodeDeletionUnavailable, result.Extensions["code"])
		require.NotContains(t, result.Error(), "SYNTHETIC_PRIVATE")
	}
}

func TestDeletionPreviewRejectsUntrustedAuthority(t *testing.T) {
	for _, ctx := range []context.Context{context.Background(), permission.UserContext(context.Background(), uuid.NewString(), permission.RoleUser), permission.UserContext(context.Background(), uuid.NewString(), permission.RoleAdmin)} {
		_, err := newPreviewAuthority(ctx)
		require.Error(t, err)
	}
}

func TestDeletionPreviewRejectsInheritedTransaction(t *testing.T) {
	ctx := context.WithValue(permission.SystemContext(context.Background(), "DeletionPreviewTest"), txKey, new(sql.Tx))
	db := sql.OpenDB(previewErrorConnector{errors.New("unexpected BeginTx")})
	defer db.Close()
	q := (*Query)(&App{DB: db, PreviewSigner: previewTestSigner{}})
	p, err := q.DeletionPreview(ctx, graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: []graphql2.DeletionResourceInput{{Type: graphql2.DeletionTargetTypeService, ID: uuid.NewString()}}}, nil, nil)
	require.Nil(t, p)
	require.Equal(t, previewUnavailable(), err)
	require.Zero(t, db.Stats().OpenConnections)
}
