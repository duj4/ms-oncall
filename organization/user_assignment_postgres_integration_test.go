package organization

import (
	"context"
	"crypto/sha256"
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

	users := make([]uuid.UUID, 6)
	for i := range users {
		users[i] = insertAssignmentTestUser(t, ctx, db, fmt.Sprintf("Assignment User %d", i))
		if _, err := store.FindUserOrganizationAssignment(ctx, users[i]); !errors.Is(err, ErrUserAssignmentNotFound) {
			t.Fatalf("new User %d assignment lookup error = %v, want ErrUserAssignmentNotFound", i, err)
		}
	}

	evaluatedAt := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	member := createAssignmentTestValues(normal.ID, ClassificationNormal, AssignmentStateActive, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, evaluatedAt, "store-member-版本-v1")
	admin := createAssignmentTestValues(normal.ID, ClassificationNormal, AssignmentStateActive, OrganizationRoleAdmin, MappingOutcomeExactlyOne, 1, evaluatedAt, "store-admin-v1")
	zero := createAssignmentTestValues(defaultOrg.ID, ClassificationDefault, AssignmentStateActive, OrganizationRoleNone, MappingOutcomeZero, 0, evaluatedAt, "store-zero-v1")
	multiple := createAssignmentTestValues(defaultOrg.ID, ClassificationDefault, AssignmentStateActive, OrganizationRoleNone, MappingOutcomeMultiple, math.MaxInt32, evaluatedAt, "store-multiple-v1")
	pendingID := uuid.New()
	transitioning := createAssignmentTestValues(normal.ID, ClassificationNormal, AssignmentStateTransitioning, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, evaluatedAt, "store-transition-v1")
	transitioning.PendingTransferID = &pendingID

	inputs := []CreateUserOrganizationAssignmentInput{
		{UserID: users[0], UserOrganizationAssignmentValues: member},
		{UserID: users[1], UserOrganizationAssignmentValues: admin},
		{UserID: users[2], UserOrganizationAssignmentValues: zero},
		{UserID: users[3], UserOrganizationAssignmentValues: multiple},
		{UserID: users[4], UserOrganizationAssignmentValues: transitioning},
	}
	for i, input := range inputs {
		created, err := store.CreateUserOrganizationAssignment(ctx, input)
		if err != nil {
			t.Fatalf("create valid assignment %d: %v", i, err)
		}
		if created.UserID != input.UserID || created.AssignmentGeneration != InitialAssignmentGeneration {
			t.Fatalf("created assignment %d = %#v", i, created)
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
	if _, err := store.FindUserOrganizationAssignment(ctx, users[5]); !errors.Is(err, ErrUserAssignmentNotFound) {
		t.Fatalf("unassigned existing User lookup error = %v, want ErrUserAssignmentNotFound", err)
	}
	var unassignedRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.user_organization_assignments WHERE user_id = $1`, users[5]).Scan(&unassignedRows); err != nil {
		t.Fatal(err)
	}
	if unassignedRows != 0 {
		t.Fatalf("User creation automatically produced %d assignments", unassignedRows)
	}

	refreshedEvidence := member.Evaluation
	refreshedEvidence.AuthoritativeEvaluatedAt = evaluatedAt.Add(time.Minute)
	refreshedEvidence.SourceConfigVersion = "store-member-v2"
	refreshedEvidence.EvidenceDigest = sha256.Sum256([]byte("store-member-v2"))
	refreshed, err := store.RefreshUserOrganizationAssignmentEvidence(ctx, RefreshUserOrganizationAssignmentEvidenceInput{
		UserID:             users[0],
		ExpectedGeneration: InitialAssignmentGeneration,
		Evaluation:         refreshedEvidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AssignmentGeneration != InitialAssignmentGeneration ||
		!refreshed.Evaluation.AuthoritativeEvaluatedAt.Equal(refreshedEvidence.AuthoritativeEvaluatedAt) ||
		refreshed.Evaluation.SourceConfigVersion != refreshedEvidence.SourceConfigVersion ||
		refreshed.Evaluation.MatchedCount != refreshedEvidence.MatchedCount ||
		refreshed.Evaluation.EvidenceDigest != refreshedEvidence.EvidenceDigest ||
		refreshed.EffectiveOrganizationID != normal.ID || refreshed.MappingOutcome != MappingOutcomeExactlyOne {
		t.Fatalf("evidence refresh changed assignment state or generation: %#v", refreshed)
	}
	if _, err := store.RefreshUserOrganizationAssignmentEvidence(ctx, RefreshUserOrganizationAssignmentEvidenceInput{
		UserID:             users[0],
		ExpectedGeneration: InitialAssignmentGeneration,
		Evaluation:         refreshedEvidence,
	}); !errors.Is(err, ErrStaleAssignmentEvidence) {
		t.Fatalf("stale evidence refresh error = %v, want ErrStaleAssignmentEvidence", err)
	}

	guardedValues := member
	guardedValues.Evaluation.AuthoritativeEvaluatedAt = evaluatedAt.Add(2 * time.Minute)
	guardedValues.Evaluation.SourceConfigVersion = "store-member-v3"
	guardedValues.Evaluation.EvidenceDigest = sha256.Sum256([]byte("store-member-v3"))
	advanced, err := store.GuardedUpdateUserOrganizationAssignment(ctx, GuardedUpdateUserOrganizationAssignmentInput{
		UserID:                           users[0],
		ExpectedGeneration:               InitialAssignmentGeneration,
		UserOrganizationAssignmentValues: guardedValues,
	})
	if err != nil {
		t.Fatal(err)
	}
	if advanced.AssignmentGeneration != InitialAssignmentGeneration+1 {
		t.Fatalf("guarded assignment generation = %d, want %d", advanced.AssignmentGeneration, InitialAssignmentGeneration+1)
	}
	if _, err := store.GuardedUpdateUserOrganizationAssignment(ctx, GuardedUpdateUserOrganizationAssignmentInput{
		UserID:                           users[0],
		ExpectedGeneration:               InitialAssignmentGeneration,
		UserOrganizationAssignmentValues: guardedValues,
	}); !errors.Is(err, ErrStaleAssignmentGeneration) {
		t.Fatalf("stale guarded update error = %v, want ErrStaleAssignmentGeneration", err)
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
			values := createAssignmentTestValues(
				normal.ID,
				ClassificationNormal,
				AssignmentStateActive,
				OrganizationRoleMember,
				MappingOutcomeExactlyOne,
				1,
				test.evaluatedAt,
				test.sourceVersion,
			)
			created, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{
				UserID:                           userID,
				UserOrganizationAssignmentValues: values,
			})
			if err != nil {
				t.Fatal(err)
			}
			wantTime := test.evaluatedAt.Truncate(time.Microsecond)
			if !created.Evaluation.AuthoritativeEvaluatedAt.Equal(wantTime) ||
				created.Evaluation.SourceConfigVersion != test.sourceVersion {
				t.Fatalf("created evaluation = %#v, want time %v and source version %q", created.Evaluation, wantTime, test.sourceVersion)
			}
			found, err := store.FindUserOrganizationAssignment(ctx, userID)
			if err != nil {
				t.Fatal(err)
			}
			if !found.Evaluation.AuthoritativeEvaluatedAt.Equal(wantTime) ||
				found.Evaluation.SourceConfigVersion != test.sourceVersion {
				t.Fatalf("stored evaluation = %#v, want time %v and source version %q", found.Evaluation, wantTime, test.sourceVersion)
			}
		})
	}
}

func TestPostgresUserAssignmentGuardedConcurrency(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
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
	evaluatedAt := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)

	createRaceUser := insertAssignmentTestUser(t, ctx, db, "Assignment Create Race User")
	values := createAssignmentTestValues(normal.ID, ClassificationNormal, AssignmentStateActive, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, evaluatedAt, "create-race")
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{
				UserID:                           createRaceUser,
				UserOrganizationAssignmentValues: values,
			})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	var createSuccess, createConflict int
	for err := range errs {
		switch {
		case err == nil:
			createSuccess++
		case errors.Is(err, ErrUserAssignmentConflict):
			createConflict++
		default:
			t.Fatalf("concurrent create error = %v", err)
		}
	}
	if createSuccess != 1 || createConflict != 1 {
		t.Fatalf("concurrent create success/conflict = %d/%d, want 1/1", createSuccess, createConflict)
	}

	updateRaceUser := insertAssignmentTestUser(t, ctx, db, "Assignment Update Race User")
	if _, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{
		UserID:                           updateRaceUser,
		UserOrganizationAssignmentValues: values,
	}); err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	errs = make(chan error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			candidate := values
			candidate.Evaluation.AuthoritativeEvaluatedAt = evaluatedAt.Add(time.Duration(index+1) * time.Minute)
			candidate.Evaluation.SourceConfigVersion = fmt.Sprintf("update-race-%d", index)
			candidate.Evaluation.EvidenceDigest = sha256.Sum256([]byte(candidate.Evaluation.SourceConfigVersion))
			<-start
			_, err := store.GuardedUpdateUserOrganizationAssignment(ctx, GuardedUpdateUserOrganizationAssignmentInput{
				UserID:                           updateRaceUser,
				ExpectedGeneration:               InitialAssignmentGeneration,
				UserOrganizationAssignmentValues: candidate,
			})
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	var updateSuccess, updateStale int
	for err := range errs {
		switch {
		case err == nil:
			updateSuccess++
		case errors.Is(err, ErrStaleAssignmentGeneration):
			updateStale++
		default:
			t.Fatalf("concurrent guarded update error = %v", err)
		}
	}
	if updateSuccess != 1 || updateStale != 1 {
		t.Fatalf("concurrent guarded update success/stale = %d/%d, want 1/1", updateSuccess, updateStale)
	}
	assignment, err := store.FindUserOrganizationAssignment(ctx, updateRaceUser)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.AssignmentGeneration != InitialAssignmentGeneration+1 {
		t.Fatalf("durable generation after CAS race = %d, want %d", assignment.AssignmentGeneration, InitialAssignmentGeneration+1)
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
		INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
		VALUES ($1, 'NORMAL', 'No Subtype', 'assignment.truth.no-subtype', 'ACTIVE')
	`, baseWithoutSubtypeID); err != nil {
		t.Fatal(err)
	}
	evaluatedAt := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)
	digest := sha256.Sum256([]byte("truth-table-evidence"))
	zeroDigest := make([]byte, sha256.Size)

	insertSQL := `
		INSERT INTO public.user_organization_assignments (
			user_id, effective_organization_id, effective_organization_classification,
			effective_normal_organization_id, state, organization_role,
			assignment_generation, mapping_outcome, authoritative_evaluated_at,
			source_config_version, matched_count, evidence_digest, pending_transfer_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	validArgs := func() []any {
		return []any{userID, normal.ID, "NORMAL", normal.ID, "ACTIVE", "ORG_MEMBER", int64(1), "EXACTLY_ONE", evaluatedAt, "truth-v1", 1, digest[:], nil}
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
	sourceConfigVersionError := pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_source_config_version_not_blank", SchemaName: "public", TableName: "user_organization_assignments"}
	tests := []invariantCase{
		{name: "Default represented as NULL", query: insertSQL, args: mutate(1, nil), expected: pgErrorExpectation{SQLState: "23502", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "effective_organization_id"}},
		{name: "nil User identity", query: insertSQL, args: mutate(0, uuid.Nil), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_user_id_non_nil", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "nil effective Organization identity", query: insertSQL, args: mutate(1, uuid.Nil), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_effective_organization_id_non_nil", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "EXACTLY_ONE maps Default", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ACTIVE", "ORG_MEMBER", int64(1), "EXACTLY_ONE", evaluatedAt, "truth-v1", 1, digest[:], nil}, expected: mappingTruthError},
		{name: "EXACTLY_ONE has NONE role", query: insertSQL, args: mutate(5, "NONE"), expected: mappingTruthError},
		{name: "EXACTLY_ONE wrong matched count", query: insertSQL, args: mutate(10, 2), expected: mappingTruthError},
		{name: "EXACTLY_ONE lacks explicit Normal subtype proof", query: insertSQL, args: []any{userID, baseWithoutSubtypeID, "NORMAL", nil, "ACTIVE", "ORG_MEMBER", int64(1), "EXACTLY_ONE", evaluatedAt, "truth-v1", 1, digest[:], nil}, expected: mappingTruthError},
		{name: "EXACTLY_ONE base lacks Normal subtype", query: insertSQL, args: []any{userID, baseWithoutSubtypeID, "NORMAL", baseWithoutSubtypeID, "ACTIVE", "ORG_MEMBER", int64(1), "EXACTLY_ONE", evaluatedAt, "truth-v1", 1, digest[:], nil}, expected: pgErrorExpectation{SQLState: "23503", ConstraintName: "user_org_assignments_effective_normal_organization_fkey", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "ZERO maps normal Organization", query: insertSQL, args: []any{userID, normal.ID, "NORMAL", normal.ID, "ACTIVE", "NONE", int64(1), "ZERO", evaluatedAt, "truth-v1", 0, digest[:], nil}, expected: mappingTruthError},
		{name: "ZERO has member role", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ACTIVE", "ORG_MEMBER", int64(1), "ZERO", evaluatedAt, "truth-v1", 0, digest[:], nil}, expected: mappingTruthError},
		{name: "ZERO wrong matched count", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ACTIVE", "NONE", int64(1), "ZERO", evaluatedAt, "truth-v1", 1, digest[:], nil}, expected: mappingTruthError},
		{name: "MULTIPLE maps normal Organization", query: insertSQL, args: []any{userID, normal.ID, "NORMAL", normal.ID, "ACTIVE", "NONE", int64(1), "MULTIPLE", evaluatedAt, "truth-v1", 2, digest[:], nil}, expected: mappingTruthError},
		{name: "MULTIPLE has admin role", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ACTIVE", "ORG_ADMIN", int64(1), "MULTIPLE", evaluatedAt, "truth-v1", 2, digest[:], nil}, expected: mappingTruthError},
		{name: "MULTIPLE not actually multiple", query: insertSQL, args: []any{userID, defaultID, "DEFAULT", nil, "ACTIVE", "NONE", int64(1), "MULTIPLE", evaluatedAt, "truth-v1", 1, digest[:], nil}, expected: mappingTruthError},
		{name: "unknown state", query: insertSQL, args: mutate(4, "UNKNOWN"), expected: pgErrorExpectation{SQLState: "22P02"}},
		{name: "unknown role", query: insertSQL, args: mutate(5, "UNKNOWN"), expected: pgErrorExpectation{SQLState: "22P02"}},
		{name: "unknown mapping outcome", query: insertSQL, args: mutate(7, "UNKNOWN"), expected: pgErrorExpectation{SQLState: "22P02"}},
		{name: "zero generation", query: insertSQL, args: mutate(6, int64(0)), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_generation_positive", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "missing evaluation time", query: insertSQL, args: mutate(8, nil), expected: pgErrorExpectation{SQLState: "23502", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "authoritative_evaluated_at"}},
		{name: "infinite evaluation time", query: `
			INSERT INTO public.user_organization_assignments (
				user_id, effective_organization_id, effective_organization_classification,
				effective_normal_organization_id, state, organization_role,
				assignment_generation, mapping_outcome, authoritative_evaluated_at,
				source_config_version, matched_count, evidence_digest
			) VALUES ($1, $2, 'NORMAL', $2, 'ACTIVE', 'ORG_MEMBER', 1, 'EXACTLY_ONE', 'infinity', 'truth-v1', 1, $3)
		`, args: []any{userID, normal.ID, digest[:]}, expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_evaluated_at_finite", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "empty source/config version", query: insertSQL, args: mutate(9, ""), expected: sourceConfigVersionError},
		{name: "ordinary spaces only source/config version", query: insertSQL, args: mutate(9, "   "), expected: sourceConfigVersionError},
		{name: "tab only source/config version", query: insertSQL, args: mutate(9, "\t"), expected: sourceConfigVersionError},
		{name: "newline only source/config version", query: insertSQL, args: mutate(9, "\n"), expected: sourceConfigVersionError},
		{name: "leading tab source/config version", query: insertSQL, args: mutate(9, "\ttruth-v1"), expected: sourceConfigVersionError},
		{name: "trailing tab source/config version", query: insertSQL, args: mutate(9, "truth-v1\t"), expected: sourceConfigVersionError},
		{name: "leading newline source/config version", query: insertSQL, args: mutate(9, "\ntruth-v1"), expected: sourceConfigVersionError},
		{name: "trailing newline source/config version", query: insertSQL, args: mutate(9, "truth-v1\n"), expected: sourceConfigVersionError},
		{name: "short evidence digest", query: insertSQL, args: mutate(11, []byte("short")), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_evidence_digest_sha256", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "zero evidence digest", query: insertSQL, args: mutate(11, zeroDigest), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_evidence_digest_sha256", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "pending transfer while ACTIVE", query: insertSQL, args: mutate(12, uuid.New()), expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_pending_transfer_state", SchemaName: "public", TableName: "user_organization_assignments"}},
		{name: "nil pending transfer identity", query: insertSQL, args: []any{userID, normal.ID, "NORMAL", normal.ID, "TRANSITIONING", "ORG_MEMBER", int64(1), "EXACTLY_ONE", evaluatedAt, "truth-v1", 1, digest[:], uuid.Nil}, expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_pending_transfer_state", SchemaName: "public", TableName: "user_organization_assignments"}},
	}
	for _, boundaryWhitespace := range sourceConfigVersionBoundaryWhitespace {
		for _, sourceVersion := range []string{
			string(boundaryWhitespace),
			string(boundaryWhitespace) + "truth-v1",
			"truth-v1" + string(boundaryWhitespace),
		} {
			tests = append(tests, invariantCase{
				name:     fmt.Sprintf("source/config version boundary whitespace U+%04X", boundaryWhitespace),
				query:    insertSQL,
				args:     mutate(9, sourceVersion),
				expected: sourceConfigVersionError,
			})
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
	assertAssignmentStable := func(t *testing.T) {
		t.Helper()
		assignment, err := store.FindUserOrganizationAssignment(ctx, userID)
		if err != nil {
			t.Fatal(err)
		}
		if assignment.AssignmentGeneration != 1 || !assignment.Evaluation.AuthoritativeEvaluatedAt.Equal(evaluatedAt) || assignment.State != AssignmentStateActive {
			t.Fatalf("rejected update changed durable assignment: %#v", assignment)
		}
	}
	updateTests := []invariantCase{
		{name: "User identity immutable", query: `UPDATE public.user_organization_assignments SET user_id = $2, authoritative_evaluated_at = $3 WHERE user_id = $1`, args: []any{userID, otherUserID, evaluatedAt.Add(time.Minute)}, expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_user_id_immutable", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "user_id"}},
		{name: "generation cannot decrease", query: `UPDATE public.user_organization_assignments SET assignment_generation = 0, authoritative_evaluated_at = $2 WHERE user_id = $1`, args: []any{userID, evaluatedAt.Add(time.Minute)}, expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_generation_monotonic", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "assignment_generation"}},
		{name: "state change requires newer generation", query: `UPDATE public.user_organization_assignments SET state = 'TRANSITIONING', pending_transfer_id = $2, authoritative_evaluated_at = $3 WHERE user_id = $1`, args: []any{userID, uuid.New(), evaluatedAt.Add(time.Minute)}, expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_generation_required", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "assignment_generation"}},
		{name: "evaluation time must increase", query: `UPDATE public.user_organization_assignments SET source_config_version = 'truth-v2' WHERE user_id = $1`, args: []any{userID}, expected: pgErrorExpectation{SQLState: "23514", ConstraintName: "user_organization_assignments_evaluated_at_monotonic", SchemaName: "public", TableName: "user_organization_assignments", ColumnName: "authoritative_evaluated_at"}},
	}
	for _, test := range updateTests {
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
			assertAssignmentStable(t)
		})
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
	evaluatedAt := time.Date(2026, 9, 1, 17, 0, 0, 0, time.UTC)
	values := createAssignmentTestValues(normal.ID, ClassificationNormal, AssignmentStateActive, OrganizationRoleMember, MappingOutcomeExactlyOne, 1, evaluatedAt, "shadow-v1")
	if _, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{UserID: userID, UserOrganizationAssignmentValues: values}); err != nil {
		t.Fatal(err)
	}

	var functionSchema, functionName, functionConfig string
	var securityDefiner bool
	if err := db.QueryRowContext(ctx, `
		SELECT n.nspname, p.proname, pg_catalog.array_to_string(p.proconfig, E'\n'), p.prosecdef
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		WHERE p.oid = pg_catalog.to_regprocedure(
			'public.ms_oncall_enforce_user_organization_assignment_invariants()'
		)
	`).Scan(&functionSchema, &functionName, &functionConfig, &securityDefiner); err != nil {
		t.Fatal(err)
	}
	if functionSchema != "public" ||
		functionName != "ms_oncall_enforce_user_organization_assignment_invariants" ||
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
	_, err = tx.ExecContext(ctx, `
		UPDATE public.user_organization_assignments
		SET assignment_generation = assignment_generation - 1,
			authoritative_evaluated_at = authoritative_evaluated_at + interval '1 second'
		WHERE user_id = $1
	`, userID)
	assertPGError(t, err, pgErrorExpectation{
		SQLState:       "23514",
		ConstraintName: "user_organization_assignments_generation_monotonic",
		SchemaName:     "public",
		TableName:      "user_organization_assignments",
		ColumnName:     "assignment_generation",
	})
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
	state AssignmentState,
	role OrganizationRole,
	outcome MappingOutcome,
	matchedCount int,
	evaluatedAt time.Time,
	sourceVersion string,
) UserOrganizationAssignmentValues {
	return UserOrganizationAssignmentValues{
		EffectiveOrganizationID:             organizationID,
		EffectiveOrganizationClassification: classification,
		State:                               state,
		Role:                                role,
		MappingOutcome:                      outcome,
		Evaluation: AssignmentEvaluation{
			AuthoritativeEvaluatedAt: evaluatedAt,
			SourceConfigVersion:      sourceVersion,
			MatchedCount:             matchedCount,
			EvidenceDigest:           sha256.Sum256([]byte(sourceVersion)),
		},
	}
}

func assertUserOrganizationAssignmentEqual(t *testing.T, got, want *UserOrganizationAssignment) {
	t.Helper()
	if got.UserID != want.UserID ||
		got.EffectiveOrganizationID != want.EffectiveOrganizationID ||
		got.EffectiveOrganizationClassification != want.EffectiveOrganizationClassification ||
		got.State != want.State || got.Role != want.Role ||
		got.AssignmentGeneration != want.AssignmentGeneration ||
		got.MappingOutcome != want.MappingOutcome ||
		!got.Evaluation.AuthoritativeEvaluatedAt.Equal(want.Evaluation.AuthoritativeEvaluatedAt) ||
		got.Evaluation.SourceConfigVersion != want.Evaluation.SourceConfigVersion ||
		got.Evaluation.MatchedCount != want.Evaluation.MatchedCount ||
		got.Evaluation.EvidenceDigest != want.Evaluation.EvidenceDigest ||
		!equalOptionalUUID(got.PendingTransferID, want.PendingTransferID) {
		t.Fatalf("UserOrganizationAssignment mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
