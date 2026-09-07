package organization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresUserAssignmentStorePersistenceAndNoAutomaticAssignment(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Assignment Store Organization",
		CanonicalName:       "assignment.store.organization",
		CorporateMappingKey: "corp:assignment-store",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	defaultOrg, err := store.FindDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}

	users := make([]uuid.UUID, 5)
	for index := range users {
		users[index] = insertAssignmentTestUser(t, ctx, db, fmt.Sprintf("Assignment User %d", index))
		if _, err := store.FindUserOrganizationAssignment(ctx, users[index]); !errors.Is(err, ErrUserAssignmentNotFound) {
			t.Fatalf("new User %d assignment lookup error = %v, want ErrUserAssignmentNotFound", index, err)
		}
	}

	evaluatedAt := time.Date(2026, time.September, 1, 14, 0, 0, 0, time.UTC)
	inputs := []CreateUserOrganizationAssignmentInput{
		{UserID: users[0], UserOrganizationAssignmentValues: createAssignmentTestValues(normal.ID, ClassificationNormal, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, evaluatedAt, "store-member-版本-v1")},
		{UserID: users[1], UserOrganizationAssignmentValues: createAssignmentTestValues(normal.ID, ClassificationNormal, OrganizationRoleAdmin, MappingOutcomeExactlyOne, 1, evaluatedAt, "store-admin-v1")},
		{UserID: users[2], UserOrganizationAssignmentValues: createAssignmentTestValues(defaultOrg.ID, ClassificationDefault, OrganizationRoleNone, MappingOutcomeZero, 0, evaluatedAt, "store-zero-v1")},
		{UserID: users[3], UserOrganizationAssignmentValues: createAssignmentTestValues(defaultOrg.ID, ClassificationDefault, OrganizationRoleNone, MappingOutcomeMultiple, math.MaxInt32, evaluatedAt, "store-multiple-v1")},
	}
	for index, input := range inputs {
		created, err := store.CreateUserOrganizationAssignment(ctx, input)
		if err != nil {
			t.Fatalf("create valid assignment %d: %v", index, err)
		}
		if created.UserID != input.UserID {
			t.Fatalf("created assignment %d = %#v", index, created)
		}
		found, err := store.FindUserOrganizationAssignment(ctx, input.UserID)
		if err != nil {
			t.Fatal(err)
		}
		assertUserOrganizationAssignmentEqual(t, found, created)
	}

	if _, err := store.CreateUserOrganizationAssignment(ctx, inputs[0]); !errors.Is(err, ErrUserAssignmentConflict) {
		t.Fatalf("duplicate assignment create error = %v, want ErrUserAssignmentConflict", err)
	}
	if _, err := store.FindUserOrganizationAssignment(ctx, users[4]); !errors.Is(err, ErrUserAssignmentNotFound) {
		t.Fatalf("unassigned existing User lookup error = %v, want ErrUserAssignmentNotFound", err)
	}
	var unassignedRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.user_organization_assignments WHERE user_id = $1`, users[4]).Scan(&unassignedRows); err != nil {
		t.Fatal(err)
	}
	if unassignedRows != 0 {
		t.Fatalf("User creation automatically produced %d assignments", unassignedRows)
	}
}

func TestPostgresUserAssignmentEvaluationRepresentability(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Assignment Timestamp Boundary Organization",
		CanonicalName:       "assignment.timestamp-boundary.organization",
		CorporateMappingKey: "corp:assignment-timestamp-boundary",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		evaluatedAt   time.Time
		sourceVersion string
	}{
		{name: "ordinary", evaluatedAt: time.Date(2026, time.September, 2, 12, 0, 0, 123456789, time.UTC), sourceVersion: "ordinary-配置-v1"},
		{name: "lower endpoint", evaluatedAt: postgresTimestamptzMinimum, sourceVersion: "lower-endpoint-v1"},
		{name: "lower sub-microsecond", evaluatedAt: postgresTimestamptzMinimum.Add(500 * time.Nanosecond), sourceVersion: "embedded-\x01-control"},
		{name: "near upper endpoint", evaluatedAt: postgresTimestamptzEnd.Add(-24 * time.Hour), sourceVersion: "near\tupper\nendpoint"},
		{name: "last representable microsecond", evaluatedAt: postgresTimestamptzEnd.Add(-time.Microsecond), sourceVersion: "last-microsecond-v1"},
		{name: "upper sub-microsecond", evaluatedAt: postgresTimestamptzEnd.Add(-time.Nanosecond), sourceVersion: "upper-sub-microsecond-v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userID := insertAssignmentTestUser(t, ctx, db, "Assignment Timestamp Boundary "+test.name)
			values := createAssignmentTestValues(normal.ID, ClassificationNormal, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, test.evaluatedAt, test.sourceVersion)
			created, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{UserID: userID, UserOrganizationAssignmentValues: values})
			if err != nil {
				t.Fatal(err)
			}
			wantTime := test.evaluatedAt.Truncate(time.Microsecond)
			if !created.Evaluation.AuthoritativeEvaluatedAt.Equal(wantTime) || created.Evaluation.SourceConfigVersion != test.sourceVersion {
				t.Fatalf("created evaluation = %#v, want time %v and source version %q", created.Evaluation, wantTime, test.sourceVersion)
			}
		})
	}
}

func TestPostgresUserAssignmentConcurrentCreate(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	db.SetMaxOpenConns(4)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Assignment Concurrency Organization",
		CanonicalName:       "assignment.concurrency.organization",
		CorporateMappingKey: "corp:assignment-concurrency",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	userID := insertAssignmentTestUser(t, ctx, db, "Assignment Create Race User")
	values := createAssignmentTestValues(normal.ID, ClassificationNormal, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC), "create-race")
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{UserID: userID, UserOrganizationAssignmentValues: values})
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	var success, conflict int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrUserAssignmentConflict):
			conflict++
		default:
			t.Fatalf("concurrent create error = %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent create success/conflict = %d/%d, want 1/1", success, conflict)
	}
}

func TestPostgresUserAssignmentDatabaseTruthTable(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Assignment Truth Organization",
		CanonicalName:       "assignment.truth.organization",
		CorporateMappingKey: "corp:assignment-truth",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	defaultID := uuid.MustParse(DefaultOrganizationID)
	userID := insertAssignmentTestUser(t, ctx, db, "Assignment Truth User")
	otherUserID := insertAssignmentTestUser(t, ctx, db, "Assignment Truth Other User")
	baseWithoutSubtypeID := uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.organizations (id, classification, display_name, canonical_name)
		VALUES ($1, 'NORMAL', 'No Subtype', 'assignment.truth.no-subtype')
	`, baseWithoutSubtypeID); err != nil {
		t.Fatal(err)
	}
	evaluatedAt := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)

	insertSQL := `
		INSERT INTO public.user_organization_assignments (
			user_id, effective_organization_id, effective_organization_classification,
			effective_normal_organization_id, organization_role, mapping_outcome,
			authoritative_evaluated_at, source_config_version, matched_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	validArgs := func() []any {
		return []any{userID, normal.ID, "NORMAL", normal.ID, "ORG_MEMBER", "EXACTLY_ONE", evaluatedAt, "truth-v1", 1}
	}
	mutate := func(index int, value any) []any {
		args := validArgs()
		args[index] = value
		return args
	}
	assertNoAssignment := func(t *testing.T) {
		t.Helper()
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.user_organization_assignments WHERE user_id = $1`, userID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("rejected mutation left %d assignment rows", count)
		}
	}
	type invariantCase struct {
		name     string
		query    string
		args     []any
		expected pgErrorExpectation
	}
	mappingTruthError := pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_mapping_truth", SchemaName: "public", TableName: "user_organization_assignments"}
	sourceVersionError := pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_source_config_version_not_blank", SchemaName: "public", TableName: "user_organization_assignments"}
	tests := []invariantCase{
		{name: "Default represented as NULL", query: insertSQL, args: mutate(1, nil), expected: pgErrorExpectation{SQLState: "23502", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "effective_organization_id"}},
		{name: "nil User identity", query: insertSQL, args: mutate(0, uuid.Nil), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_user_id_non_nil", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "nil effective Organization identity", query: insertSQL, args: mutate(1, uuid.Nil), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_effective_organization_id_non_nil", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "EXACTLY_ONE maps Default", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ORG_MEMBER", "EXACTLY_ONE", evaluatedAt, "truth-v1", 1}, expected: mappingTruthError},
		{name: "EXACTLY_ONE has NONE role", query: insertSQL, args: mutate(4, "NONE"), expected: mappingTruthError},
		{name: "EXACTLY_ONE wrong matched count", query: insertSQL, args: mutate(8, 2), expected: mappingTruthError},
		{name: "EXACTLY_ONE lacks explicit Normal subtype proof", query: insertSQL, args: []any{userID, baseWithoutSubtypeID, "NORMAL", nil, "ORG_MEMBER", "EXACTLY_ONE", evaluatedAt, "truth-v1", 1}, expected: mappingTruthError},
		{name: "EXACTLY_ONE base lacks Normal subtype", query: insertSQL, args: []any{userID, baseWithoutSubtypeID, "NORMAL", baseWithoutSubtypeID, "ORG_MEMBER", "EXACTLY_ONE", evaluatedAt, "truth-v1", 1}, expected: pgErrorExpectation{SQLState: "23503", ConstraintName: "user_org_assignments_effective_normal_organization_fkey", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "ZERO maps normal Organization", query: insertSQL, args: []any{userID, normal.ID, "NORMAL", normal.ID, "NONE", "ZERO", evaluatedAt, "truth-v1", 0}, expected: mappingTruthError},
		{name: "ZERO has member role", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ORG_MEMBER", "ZERO", evaluatedAt, "truth-v1", 0}, expected: mappingTruthError},
		{name: "ZERO wrong matched count", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "NONE", "ZERO", evaluatedAt, "truth-v1", 1}, expected: mappingTruthError},
		{name: "MULTIPLE maps normal Organization", query: insertSQL, args: []any{userID, normal.ID, "NORMAL", normal.ID, "NONE", "MULTIPLE", evaluatedAt, "truth-v1", 2}, expected: mappingTruthError},
		{name: "MULTIPLE has admin role", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ORG_ADMIN", "MULTIPLE", evaluatedAt, "truth-v1", 2}, expected: mappingTruthError},
		{name: "MULTIPLE not actually multiple", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "NONE", "MULTIPLE", evaluatedAt, "truth-v1", 1}, expected: mappingTruthError},
		{name: "unknown role", query: insertSQL, args: mutate(4, "UNKNOWN"), expected: pgErrorExpectation{SQLState: "22P02"}},
		{name: "unknown mapping outcome", query: insertSQL, args: mutate(5, "UNKNOWN"), expected: pgErrorExpectation{SQLState: "22P02"}},
		{name: "missing evaluation time", query: insertSQL, args: mutate(6, nil), expected: pgErrorExpectation{SQLState: "23502", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "authoritative_evaluated_at"}},
		{name: "infinite evaluation time", query: `
			INSERT INTO public.user_organization_assignments (
				user_id, effective_organization_id, effective_organization_classification,
				effective_normal_organization_id, organization_role, mapping_outcome,
				authoritative_evaluated_at, source_config_version, matched_count
			) VALUES ($1, $2, 'NORMAL', $2, 'ORG_MEMBER', 'EXACTLY_ONE', 'infinity', 'truth-v1', 1)
		`, args: []any{userID, normal.ID}, expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_evaluated_at_finite", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "empty source/config version", query: insertSQL, args: mutate(7, ""), expected: sourceVersionError},
		{name: "ordinary spaces only source/config version", query: insertSQL, args: mutate(7, "   "), expected: sourceVersionError},
		{name: "leading tab source/config version", query: insertSQL, args: mutate(7, "\ttruth-v1"), expected: sourceVersionError},
		{name: "trailing newline source/config version", query: insertSQL, args: mutate(7, "truth-v1\n"), expected: sourceVersionError},
	}
	for _, boundaryWhitespace := range sourceConfigVersionBoundaryWhitespace {
		for _, sourceVersion := range []string{string(boundaryWhitespace), string(boundaryWhitespace) + "truth-v1", "truth-v1" + string(boundaryWhitespace)} {
			tests = append(tests, invariantCase{name: fmt.Sprintf("source/config version boundary whitespace U+%04X", boundaryWhitespace), query: insertSQL, args: mutate(7, sourceVersion), expected: sourceVersionError})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.ExecContext(ctx, test.query, test.args...)
			assertPGError(t, err, test.expected)
			_, abortedErr := tx.ExecContext(ctx, `SELECT 1`)
			assertPGError(t, abortedErr, pgErrorExpectation{SQLState: "25P02"})
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			assertNoAssignment(t)
		})
	}

	if _, err := db.ExecContext(ctx, insertSQL, validArgs()...); err != nil {
		t.Fatalf("insert durable assignment for update invariants: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE public.user_organization_assignments
		SET organization_role = 'ORG_ADMIN', source_config_version = 'truth-v2'
		WHERE user_id = $1
	`, userID); err != nil {
		t.Fatalf("ordinary assignment update without generation/evidence gate: %v", err)
	}
	updated, err := store.FindUserOrganizationAssignment(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Role != OrganizationRoleAdmin || updated.Evaluation.SourceConfigVersion != "truth-v2" {
		t.Fatalf("ordinary assignment update was not retained: %#v", updated)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE public.user_organization_assignments SET user_id = $2 WHERE user_id = $1`, userID, otherUserID)
	assertPGError(t, err, pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_user_id_immutable", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "user_id"})
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresUserAssignmentTriggerCannotBeShadowed(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Assignment Shadow Organization",
		CanonicalName:       "assignment.shadow.organization",
		CorporateMappingKey: "corp:assignment-shadow",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	userID := insertAssignmentTestUser(t, ctx, db, "Assignment Shadow User")
	otherUserID := insertAssignmentTestUser(t, ctx, db, "Assignment Shadow Other User")
	values := createAssignmentTestValues(normal.ID, ClassificationNormal, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, time.Date(2026, 9, 1, 17, 0, 0, 0, time.UTC), "shadow-v1")
	if _, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{UserID: userID, UserOrganizationAssignmentValues: values}); err != nil {
		t.Fatal(err)
	}

	var functionSchema, functionName, functionConfig string
	var securityDefiner bool
	if err := db.QueryRowContext(ctx, `
		SELECT n.nspname, p.proname, pg_catalog.array_to_string(p.proconfig, E'\n'), p.prosecdef
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		WHERE p.oid = pg_catalog.to_regprocedure('public.ms_oncall_enforce_user_organization_assignment_invariants()')
	`).Scan(&functionSchema, &functionName, &functionConfig, &securityDefiner); err != nil {
		t.Fatal(err)
	}
	if functionSchema != "public" || functionName != "ms_oncall_enforce_user_organization_assignment_invariants" ||
		functionConfig != "search_path=pg_catalog, pg_temp" || securityDefiner {
		t.Fatalf("assignment trigger function identity/config/security = %s.%s/%q/%v", functionSchema, functionName, functionConfig, securityDefiner)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Errorf("rollback shadow-resolution transaction: %v", err)
		}
	}()
	shadowSchema := newPostgresTestIdentifier(t, "assignment_shadow")
	if _, err := tx.ExecContext(ctx, `CREATE SCHEMA `+shadowSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE `+shadowSchema+`.user_organization_assignments (marker text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL search_path = `+shadowSchema+`, public`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE public.user_organization_assignments SET user_id = $2 WHERE user_id = $1`, userID, otherUserID)
	assertPGError(t, err, pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_user_id_immutable", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "user_id"})
}

func insertAssignmentTestUser(t *testing.T, ctx context.Context, db *sql.DB, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO public.users (id, name, email) VALUES ($1, $2, '')`, id, name); err != nil {
		t.Fatal(err)
	}
	return id
}

func createAssignmentTestValues(
	organizationID uuid.UUID,
	classification Classification,
	role OrganizationRole,
	outcome MappingOutcome,
	matchedCount int,
	evaluatedAt time.Time,
	sourceVersion string,
) UserOrganizationAssignmentValues {
	return UserOrganizationAssignmentValues{
		EffectiveOrganizationID:             organizationID,
		EffectiveOrganizationClassification: classification,
		Role:                                role,
		MappingOutcome:                      outcome,
		Evaluation: AssignmentEvaluation{
			AuthoritativeEvaluatedAt: evaluatedAt,
			SourceConfigVersion:      sourceVersion,
			MatchedCount:             matchedCount,
		},
	}
}

func assertUserOrganizationAssignmentEqual(t *testing.T, got, want *UserOrganizationAssignment) {
	t.Helper()
	if got.UserID != want.UserID || got.EffectiveOrganizationID != want.EffectiveOrganizationID ||
		got.EffectiveOrganizationClassification != want.EffectiveOrganizationClassification ||
		got.Role != want.Role || got.MappingOutcome != want.MappingOutcome ||
		!got.Evaluation.AuthoritativeEvaluatedAt.Equal(want.Evaluation.AuthoritativeEvaluatedAt) ||
		got.Evaluation.SourceConfigVersion != want.Evaluation.SourceConfigVersion ||
		got.Evaluation.MatchedCount != want.Evaluation.MatchedCount {
		t.Fatalf("UserOrganizationAssignment mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}
