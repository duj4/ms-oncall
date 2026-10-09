package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func favoriteIsolationID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("favorite-isolation:"+name)).String()
}

func favoriteIsolationTargets(side string) []assignment.Target {
	return []assignment.Target{
		assignment.ServiceTarget(favoriteIsolationID("service-" + side)),
		assignment.ScheduleTarget(favoriteIsolationID("schedule-" + side)),
		assignment.RotationTarget(favoriteIsolationID("rotation-" + side)),
		assignment.EscalationPolicyTarget(favoriteIsolationID("policy-" + side)),
		assignment.UserTarget(favoriteIsolationID("target-user-" + side)),
	}
}

func favoriteIsolationHarness(t *testing.T, crossOrganization bool) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, "", "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	db := h.App().DB()
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := db.ExecContext(t.Context(), query, args...)
		require.NoError(t, err)
	}
	orgB := harness.SmokeOrganizationID
	if crossOrganization {
		orgB = favoriteIsolationID("org-b")
		exec(`INSERT INTO organizations(id, classification, display_name, canonical_name)
			VALUES ($1, 'NORMAL', 'Favorite Isolation B', 'favorite-isolation.b')`, orgB)
		exec(`INSERT INTO normal_organizations(organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
			VALUES ($1, 'NORMAL', 'favorite-isolation:b', 'Etc/UTC')`, orgB)
	}
	for _, name := range []string{"a", "b", "c", "target-user-x", "target-user-y"} {
		exec(`INSERT INTO users(id, name, email, role) VALUES ($1, $2, '', 'user')`, favoriteIsolationID(name), name)
		org := harness.SmokeOrganizationID
		if name == "b" {
			org = orgB
		}
		exec(`INSERT INTO user_organization_assignments(user_id, effective_organization_id,
			effective_organization_classification, effective_normal_organization_id, organization_role,
			mapping_outcome, authoritative_evaluated_at, source_config_version, matched_count)
			VALUES ($1, $2, 'NORMAL', $2, 'ORG_MEMBER', 'EXACTLY_ONE', now(), 'favorite-isolation-test', 1)`,
			favoriteIsolationID(name), org)
	}
	for _, side := range []string{"x", "y"} {
		exec(`INSERT INTO escalation_policies(id, name, organization_id) VALUES ($1, $2, $3)`,
			favoriteIsolationID("policy-"+side), "favorite-policy-"+side, harness.SmokeOrganizationID)
		exec(`INSERT INTO services(id, name, escalation_policy_id, organization_id) VALUES ($1, $2, $3, $4)`,
			favoriteIsolationID("service-"+side), "favorite-service-"+side, favoriteIsolationID("policy-"+side), harness.SmokeOrganizationID)
		exec(`INSERT INTO schedules(id, name, time_zone, organization_id) VALUES ($1, $2, 'Etc/UTC', $3)`,
			favoriteIsolationID("schedule-"+side), "favorite-schedule-"+side, harness.SmokeOrganizationID)
		exec(`INSERT INTO rotations(id, name, type, start_time, time_zone, organization_id)
			VALUES ($1, $2, 'daily', now(), 'Etc/UTC', $3)`,
			favoriteIsolationID("rotation-"+side), "favorite-rotation-"+side, harness.SmokeOrganizationID)
	}
	var version string
	require.NoError(t, db.QueryRowContext(t.Context(), `SHOW server_version`).Scan(&version))
	t.Logf("PostgreSQL %s; A=%s org=%s; B=%s org=%s", version,
		favoriteIsolationID("a"), harness.SmokeOrganizationID, favoriteIsolationID("b"), orgB)
	return h
}

func favoriteIsolationHuman(t *testing.T, h *harness.Harness, name string) context.Context {
	t.Helper()
	id, session := favoriteIsolationID(name), uuid.NewString()
	ctx := permission.UserSourceContext(h.Config().Context(t.Context()), id, permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(id, session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	authority, err := c.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, authority)
}

type favoriteIsolationRow struct {
	ID         int64
	Owner      string
	TargetType string
	TargetID   string
	Row        string
}

func favoriteIsolationRows(t *testing.T, db gadb.DBTX) []favoriteIsolationRow {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT id, user_id,
		CASE WHEN tgt_service_id IS NOT NULL THEN 'service'
			WHEN tgt_schedule_id IS NOT NULL THEN 'schedule'
			WHEN tgt_rotation_id IS NOT NULL THEN 'rotation'
			WHEN tgt_escalation_policy_id IS NOT NULL THEN 'escalation_policy'
			ELSE 'user' END,
		coalesce(tgt_service_id, tgt_schedule_id, tgt_rotation_id, tgt_escalation_policy_id, tgt_user_id),
		to_jsonb(f)::text FROM user_favorites f ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	result := make([]favoriteIsolationRow, 0)
	for rows.Next() {
		var row favoriteIsolationRow
		require.NoError(t, rows.Scan(&row.ID, &row.Owner, &row.TargetType, &row.TargetID, &row.Row))
		result = append(result, row)
	}
	require.NoError(t, rows.Err())
	return result
}

func favoriteIsolationWithout(rows []favoriteIsolationRow, user string, target assignment.Target) []favoriteIsolationRow {
	return slices.DeleteFunc(slices.Clone(rows), func(row favoriteIsolationRow) bool {
		return row.Owner == favoriteIsolationID(user) && row.TargetID == target.TargetID()
	})
}

func favoriteIsolationAssertRows(t *testing.T, db gadb.DBTX, want []favoriteIsolationRow) {
	t.Helper()
	got := favoriteIsolationRows(t, db)
	t.Logf("Favorite rows: want=%+v; actual=%+v", want, got)
	require.Equal(t, want, got, "only the requested User/target relationship may change")
}

func favoriteIsolationResources(t *testing.T, db gadb.DBTX) string {
	t.Helper()
	var snapshot string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT jsonb_build_object(
		'users', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM users r),
		'services', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM services r),
		'schedules', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM schedules r),
		'rotations', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM rotations r),
		'policies', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM escalation_policies r)
	)::text`).Scan(&snapshot))
	return snapshot
}

// Foreign-root rows are seeded only to prove deletion containment. They select
// no product policy or new authority to create or access foreign-root favorites.
func favoriteIsolationSeed(t *testing.T, h *harness.Harness, db gadb.DBTX, users ...string) {
	t.Helper()
	permission.SudoContext(t.Context(), func(ctx context.Context) {
		for _, name := range users {
			for _, side := range []string{"x", "y"} {
				for _, target := range favoriteIsolationTargets(side) {
					require.NoError(t, h.App().FavoriteStore.Set(ctx, db, favoriteIsolationID(name), target))
				}
			}
		}
	})
}

func TestUserFavoriteUnsetIsolation(t *testing.T) {
	for _, crossOrg := range []bool{false, true} {
		name := "same-organization"
		if crossOrg {
			name = "cross-organization"
		}
		t.Run(name, func(t *testing.T) {
			h := favoriteIsolationHarness(t, crossOrg)
			ctx := favoriteIsolationHuman(t, h, "a")
			for _, target := range favoriteIsolationTargets("x") {
				t.Run(target.TargetType().String(), func(t *testing.T) {
					db := h.App().DB()
					initial := favoriteIsolationRows(t, db)
					tx, err := db.BeginTx(t.Context(), nil)
					require.NoError(t, err)
					defer func() {
						require.NoError(t, tx.Rollback(), "rollback isolated Favorite fixture")
						favoriteIsolationAssertRows(t, db, initial)
						t.Log("transaction rollback restored the pre-fixture Favorite rows")
					}()
					favoriteIsolationSeed(t, h, tx, "a", "b")
					before := favoriteIsolationRows(t, tx)
					require.Len(t, before, 20)
					t.Logf("BEGIN; before=%+v; Unset(A, %s %s)", before, target.TargetType(), target.TargetID())
					resources := favoriteIsolationResources(t, tx)
					require.NoError(t, h.App().FavoriteStore.Unset(ctx, tx, favoriteIsolationID("a"), target))
					want := favoriteIsolationWithout(before, "a", target)
					require.Len(t, want, 19)
					favoriteIsolationAssertRows(t, tx, want)
					require.NoError(t, h.App().FavoriteStore.Unset(ctx, tx, favoriteIsolationID("a"), target), "repeat Unset is successful")
					favoriteIsolationAssertRows(t, tx, want)
					// C has no Favorites; matching another User's target must be a no-op.
					permission.SudoContext(t.Context(), func(ctx context.Context) {
						require.NoError(t, h.App().FavoriteStore.Unset(ctx, tx, favoriteIsolationID("c"), target))
					})
					favoriteIsolationAssertRows(t, tx, want)
					// An unrelated authenticated User cannot request B's deletion.
					require.Error(t, h.App().FavoriteStore.Unset(ctx, tx, favoriteIsolationID("b"), target))
					require.Error(t, h.App().FavoriteStore.Unset(t.Context(), tx, favoriteIsolationID("b"), target))
					favoriteIsolationAssertRows(t, tx, want)
					permission.SudoContext(t.Context(), func(ctx context.Context) {
						require.NoError(t, h.App().FavoriteStore.Unset(ctx, tx, favoriteIsolationID("b"), target))
					})
					favoriteIsolationAssertRows(t, tx, favoriteIsolationWithout(want, "b", target))
					require.Equal(t, resources, favoriteIsolationResources(t, tx), "referenced resource rows must stay unchanged")
				})
			}
		})
	}
}

func TestGraphQLFavoriteUnsetIsolation(t *testing.T) {
	h := favoriteIsolationHarness(t, true)
	db := h.App().DB()
	favoriteIsolationSeed(t, h, db, "a", "b")
	before := favoriteIsolationRows(t, db)
	resources := favoriteIsolationResources(t, db)
	target := assignment.ScheduleTarget(favoriteIsolationID("schedule-x"))
	query := fmt.Sprintf(`mutation { setFavorite(input: {target: {type: schedule, id: %q}, favorite: false}) }`, target.TargetID())
	for range 2 {
		result := h.GraphQLQueryUserT(t, favoriteIsolationID("a"), query)
		require.Empty(t, result.Errors)
		var data struct{ SetFavorite bool }
		require.NoError(t, json.Unmarshal(result.Data, &data))
		require.True(t, data.SetFavorite)
		favoriteIsolationAssertRows(t, db, favoriteIsolationWithout(before, "a", target))
	}
	require.Equal(t, resources, favoriteIsolationResources(t, db), "GraphQL must preserve referenced resources")
}

func TestUserFavoriteUnsetConcurrentIsolation(t *testing.T) {
	h := favoriteIsolationHarness(t, true)
	db := h.App().DB()
	favoriteIsolationSeed(t, h, db, "a", "b", "c")
	want := favoriteIsolationRows(t, db)
	resources := favoriteIsolationResources(t, db)
	for _, target := range favoriteIsolationTargets("x") {
		t.Run(target.TargetType().String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			start := make(chan struct{})
			ready := make(chan struct{}, 2)
			results := make(chan error, 2)
			for _, name := range []string{"a", "b"} {
				userCtx := favoriteIsolationHuman(t, h, name)
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				userCtx, userCancel := context.WithDeadline(userCtx, deadline)
				defer userCancel()
				go func() {
					// Independent transactions on reserved connections guarantee
					// two DB sessions, without requiring a timing-dependent overlap.
					tx, err := db.BeginTx(ctx, &sql.TxOptions{})
					if err != nil {
						ready <- struct{}{}
						results <- err
						return
					}
					defer func() { _ = tx.Rollback() }()
					ready <- struct{}{}
					select {
					case <-start:
					case <-ctx.Done():
						results <- ctx.Err()
						return
					}
					if err = h.App().FavoriteStore.Unset(userCtx, tx, favoriteIsolationID(name), target); err == nil {
						err = tx.Commit()
					}
					results <- err
				}()
			}
			// Always release and join both workers before a failing assertion.
			for range 2 {
				select {
				case <-ready:
				case <-ctx.Done():
				}
			}
			close(start)
			var errs []error
			for range 2 {
				errs = append(errs, <-results)
			}
			for _, err := range errs {
				require.NoError(t, err)
			}
			want = favoriteIsolationWithout(favoriteIsolationWithout(want, "a", target), "b", target)
			favoriteIsolationAssertRows(t, db, want)
			require.Equal(t, resources, favoriteIsolationResources(t, db))
		})
	}
}
