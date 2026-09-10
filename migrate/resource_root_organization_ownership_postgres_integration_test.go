package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/service"
)

func TestPostgresResourceRootOrganizationOwnershipMigration(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	position280 := history.entries[len(history.entries)-2]
	position281 := history.latest()
	if position280.Position != 280 || position281.Position != 281 {
		t.Fatalf("unexpected ownership migration boundary: position280=%#v position281=%#v", position280, position281)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	t.Run("clean chain constraints and foreign keys", func(t *testing.T) {
		testURL := newPostgresTestDatabase(t, baseURL)
		if count, err := Up(ctx, testURL, ""); err != nil {
			t.Fatal(err)
		} else if count != len(history.entries) {
			t.Fatalf("clean chain applied %d migrations, want %d", count, len(history.entries))
		}
		assertResourceRootOwnershipSchema(t, ctx, testURL, true)
		assertResourceRootOwnershipProvenance(t, ctx, testURL, position281, true)

		conn, err := pgx.Connect(ctx, testURL)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		organizationID := uuid.New()
		insertResourceTestNormalOrganization(t, ctx, conn, organizationID, "migration-contract")
		policyID := uuid.New()
		if err := insertResourceRoot(ctx, conn, "escalation_policies", organizationID, policyID, "valid"); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"services", "schedules", "rotations"} {
			if err := insertResourceRoot(ctx, conn, table, organizationID, policyID, "valid"); err != nil {
				t.Fatalf("insert %s owned by NormalOrganization: %v", table, err)
			}
		}

		for label, invalidOrganizationID := range map[string]uuid.UUID{
			"Default":     uuid.MustParse(organization.DefaultOrganizationID),
			"nonexistent": uuid.New(),
		} {
			for _, table := range []string{"services", "schedules", "rotations", "escalation_policies"} {
				candidatePolicyID := policyID
				if table == "escalation_policies" {
					candidatePolicyID = uuid.New()
				}
				err := insertResourceRoot(ctx, conn, table, invalidOrganizationID, candidatePolicyID, strings.ToLower(label)+"-"+table)
				assertResourcePGError(t, err, "23503", table+"_organization_id_fkey")
			}
		}
	})

	t.Run("populated position 280 fails atomically", func(t *testing.T) {
		testURL := newPostgresTestDatabase(t, baseURL)
		if count, err := Up(ctx, testURL, position280.Name); err != nil {
			t.Fatal(err)
		} else if count != int(position280.Position) {
			t.Fatalf("position-280 setup applied %d migrations, want %d", count, position280.Position)
		}
		conn, err := pgx.Connect(ctx, testURL)
		if err != nil {
			t.Fatal(err)
		}
		insertLegacyResourceRoots(t, ctx, conn)
		if err := conn.Close(ctx); err != nil {
			t.Fatal(err)
		}

		count, err := Up(ctx, testURL, position281.Name)
		if count != 0 || err == nil {
			t.Fatalf("populated position-281 Up = (%d, %v), want zero applied and refusal", count, err)
		}
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "23502" {
			t.Fatalf("populated position-281 Up error = %#v / %v, want SQLSTATE 23502", databaseError, err)
		}
		assertResourceRootOwnershipSchema(t, ctx, testURL, false)
		assertResourceRootOwnershipProvenance(t, ctx, testURL, position281, false)

		conn, err = pgx.Connect(ctx, testURL)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		for _, table := range []string{"services", "schedules", "rotations", "escalation_policies"} {
			var count int
			if err := conn.QueryRow(ctx, "SELECT count(*) FROM public."+table).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("legacy %s row count after failed Up = %d, want 1", table, count)
			}
		}
	})

	t.Run("safe empty Down and populated refusal", func(t *testing.T) {
		testURL := newPostgresTestDatabase(t, baseURL)
		if count, err := Up(ctx, testURL, ""); err != nil {
			t.Fatal(err)
		} else if count != len(history.entries) {
			t.Fatalf("clean chain applied %d migrations, want %d", count, len(history.entries))
		}
		if count, err := Down(ctx, testURL, position280.Name); err != nil {
			t.Fatal(err)
		} else if count != 1 {
			t.Fatalf("empty position-281 Down applied %d migrations, want 1", count)
		}
		assertResourceRootOwnershipSchema(t, ctx, testURL, false)
		assertResourceRootOwnershipProvenance(t, ctx, testURL, position281, false)
		if count, err := Up(ctx, testURL, position281.Name); err != nil {
			t.Fatal(err)
		} else if count != 1 {
			t.Fatalf("position-281 reapply applied %d migrations, want 1", count)
		}

		conn, err := pgx.Connect(ctx, testURL)
		if err != nil {
			t.Fatal(err)
		}
		organizationID := uuid.New()
		insertResourceTestNormalOrganization(t, ctx, conn, organizationID, "down-refusal")
		policyID := uuid.New()
		if err := insertResourceRoot(ctx, conn, "escalation_policies", organizationID, policyID, "down-refusal"); err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
		for _, table := range []string{"services", "schedules", "rotations"} {
			if err := insertResourceRoot(ctx, conn, table, organizationID, policyID, "down-refusal"); err != nil {
				conn.Close(ctx)
				t.Fatal(err)
			}
		}
		if err := conn.Close(ctx); err != nil {
			t.Fatal(err)
		}

		count, err := Down(ctx, testURL, position280.Name)
		if count != 0 || err == nil {
			t.Fatalf("populated position-281 Down = (%d, %v), want zero applied and refusal", count, err)
		}
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "55000" ||
			databaseError.Message != "position-281 downgrade refused: resource rows retain Organization ownership" {
			t.Fatalf("populated position-281 Down error = %#v / %v", databaseError, err)
		}
		assertResourceRootOwnershipSchema(t, ctx, testURL, true)
		assertResourceRootOwnershipProvenance(t, ctx, testURL, position281, true)
		if err := VerifyAll(ctx, testURL); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPostgresResourceRootOrganizationOwnershipStores(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := Up(ctx, testURL, ""); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	organizationStore := organization.NewStore(db)
	organizationA := createResourceTestOrganization(t, ctx, organizationStore, "a")
	organizationB := createResourceTestOrganization(t, ctx, organizationStore, "b")
	contextA := createResourceTestHumanContext(t, ctx, db, organizationStore, organizationA.ID, "a")
	contextB := createResourceTestHumanContext(t, ctx, db, organizationStore, organizationB.ID, "b")
	defaultContext := createResourceTestDefaultHumanContext(t, ctx, db, organizationStore)
	missingContext := permission.UserContext(ctx, uuid.New().String(), permission.RoleUser)

	serviceStore, err := service.NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	scheduleStore, err := schedule.NewStore(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotationStore, err := rotation.NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	logStore, err := alertlog.NewStore(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	policyStore, err := escalation.NewStore(ctx, db, escalation.Config{LogStore: logStore})
	if err != nil {
		t.Fatal(err)
	}

	policy, err := policyStore.CreatePolicyTx(contextA, nil, &escalation.Policy{
		OrganizationID: organizationB.ID,
		Name:           "Ownership Policy",
		Description:    "ownership policy",
		Repeat:         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	serviceValue, err := serviceStore.CreateServiceTx(contextA, nil, &service.Service{
		OrganizationID:     organizationB.ID,
		Name:               "Ownership Service",
		Description:        "ownership service",
		EscalationPolicyID: policy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduleValue, err := scheduleStore.Create(contextA, &schedule.Schedule{
		OrganizationID: organizationB.ID,
		Name:           "Ownership Schedule",
		Description:    "ownership schedule",
		TimeZone:       time.UTC,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotationValue, err := rotationStore.CreateRotationTx(contextA, nil, &rotation.Rotation{
		OrganizationID: organizationB.ID,
		Name:           "Ownership Rotation",
		Description:    "ownership rotation",
		Type:           rotation.TypeDaily,
		Start:          time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC),
		ShiftLength:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]uuid.UUID{
		"policy":   policy.OrganizationID,
		"service":  serviceValue.OrganizationID,
		"schedule": scheduleValue.OrganizationID,
		"rotation": rotationValue.OrganizationID,
	} {
		if got != organizationA.ID {
			t.Fatalf("created %s OrganizationID = %s, want request-bound %s", name, got, organizationA.ID)
		}
	}

	assertResourceRootCreateDenied(t, "missing", missingContext, policy.ID, serviceStore, scheduleStore, rotationStore, policyStore)
	assertResourceRootCreateDenied(t, "default", defaultContext, policy.ID, serviceStore, scheduleStore, rotationStore, policyStore)

	for name, create := range map[string]func() error{
		"policy": func() error {
			_, err := policyStore.CreatePolicyTx(contextB, nil, &escalation.Policy{Name: policy.Name, Description: "duplicate", Repeat: 1})
			return err
		},
		"service": func() error {
			_, err := serviceStore.CreateServiceTx(contextB, nil, &service.Service{Name: serviceValue.Name, Description: "duplicate", EscalationPolicyID: policy.ID})
			return err
		},
		"schedule": func() error {
			_, err := scheduleStore.Create(contextB, &schedule.Schedule{Name: scheduleValue.Name, Description: "duplicate", TimeZone: time.UTC})
			return err
		},
		"rotation": func() error {
			_, err := rotationStore.CreateRotationTx(contextB, nil, &rotation.Rotation{Name: rotationValue.Name, Description: "duplicate", Type: rotation.TypeDaily, Start: time.Now().UTC(), ShiftLength: 1})
			return err
		},
	} {
		if err := create(); err == nil {
			t.Fatalf("%s name uniqueness unexpectedly became Organization-local", name)
		}
	}

	policy.OrganizationID = organizationB.ID
	policy.Description = "ownership policy updated"
	if err := policyStore.UpdatePolicyTx(contextB, nil, policy); err != nil {
		t.Fatal(err)
	}
	serviceValue.OrganizationID = organizationB.ID
	serviceValue.Description = "ownership service updated"
	if err := serviceStore.UpdateTx(contextB, nil, serviceValue); err != nil {
		t.Fatal(err)
	}
	scheduleValue.OrganizationID = organizationB.ID
	scheduleValue.Description = "ownership schedule updated"
	if err := scheduleStore.Update(contextB, scheduleValue); err != nil {
		t.Fatal(err)
	}
	rotationValue.OrganizationID = organizationB.ID
	rotationValue.Description = "ownership rotation updated"
	if err := rotationStore.UpdateRotationTx(contextB, nil, rotationValue); err != nil {
		t.Fatal(err)
	}

	loadedPolicy, err := policyStore.FindOnePolicyTx(contextB, nil, policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	loadedService, err := serviceStore.FindOne(contextB, serviceValue.ID)
	if err != nil {
		t.Fatal(err)
	}
	loadedSchedule, err := scheduleStore.FindOne(contextB, scheduleValue.ID)
	if err != nil {
		t.Fatal(err)
	}
	loadedRotation, err := rotationStore.FindRotation(contextB, rotationValue.ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]uuid.UUID{
		"policy":   loadedPolicy.OrganizationID,
		"service":  loadedService.OrganizationID,
		"schedule": loadedSchedule.OrganizationID,
		"rotation": loadedRotation.OrganizationID,
	} {
		if got != organizationA.ID {
			t.Fatalf("%s owner after cross-Organization update and unscoped load = %s, want %s", name, got, organizationA.ID)
		}
	}

	assertResourceRootMaterializationPaths(t, contextB, db, organizationA.ID, policy.ID, serviceValue.ID, scheduleValue.ID, rotationValue.ID, serviceStore, scheduleStore, rotationStore, policyStore)
}

func TestResourceRootOrganizationOwnershipIsInternalOnly(t *testing.T) {
	organizationID := uuid.New()
	for name, value := range map[string]any{
		"service":  service.Service{OrganizationID: organizationID},
		"schedule": schedule.Schedule{OrganizationID: organizationID},
		"rotation": rotation.Rotation{OrganizationID: organizationID},
		"policy":   escalation.Policy{OrganizationID: organizationID},
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(encoded)), "organization") || strings.Contains(string(encoded), organizationID.String()) {
			t.Fatalf("%s JSON exposed internal Organization ownership: %s", name, encoded)
		}
	}
	for name, input := range map[string]any{
		"CreateServiceInput":          graphql2.CreateServiceInput{},
		"CreateScheduleInput":         graphql2.CreateScheduleInput{},
		"CreateRotationInput":         graphql2.CreateRotationInput{},
		"CreateEscalationPolicyInput": graphql2.CreateEscalationPolicyInput{},
	} {
		typeOfInput := reflect.TypeOf(input)
		if _, present := typeOfInput.FieldByName("OrganizationID"); present {
			t.Fatalf("%s exposes client-selected OrganizationID", name)
		}
	}
}

func assertResourceRootOwnershipSchema(t *testing.T, ctx context.Context, testURL string, present bool) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, table := range []string{"services", "schedules", "rotations", "escalation_policies"} {
		var dataType, nullable string
		var columnDefault sql.NullString
		err := conn.QueryRow(ctx, `
			SELECT data_type, is_nullable, column_default
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'organization_id'
		`, table).Scan(&dataType, &nullable, &columnDefault)
		if !present {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("%s organization_id absent check = %v", table, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if dataType != "uuid" || nullable != "NO" || columnDefault.Valid {
			t.Fatalf("%s organization_id type/nullability/default = %q/%q/%q, want uuid/NO/no default", table, dataType, nullable, columnDefault.String)
		}
		var referencesNormal, referencesOnlyNormalOrganizationID, updateRestrict, deleteRestrict, ownsOnlyOrganizationID bool
		if err := conn.QueryRow(ctx, `
			SELECT
				c.confrelid = 'public.normal_organizations'::regclass,
				c.confkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = c.confrelid AND attname = 'organization_id')]::smallint[],
				c.confupdtype = 'r',
				c.confdeltype = 'r',
				c.conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = c.conrelid AND attname = 'organization_id')]::smallint[]
			FROM pg_constraint c
			WHERE c.conrelid = ('public.' || $1)::regclass
				AND c.conname = $2
		`, table, table+"_organization_id_fkey").Scan(&referencesNormal, &referencesOnlyNormalOrganizationID, &updateRestrict, &deleteRestrict, &ownsOnlyOrganizationID); err != nil {
			t.Fatal(err)
		}
		if !referencesNormal || !referencesOnlyNormalOrganizationID || !updateRestrict || !deleteRestrict || !ownsOnlyOrganizationID {
			t.Fatalf("%s ownership FK contract = normal:%t normal-organization-id:%t update-restrict:%t delete-restrict:%t local-organization-id:%t", table, referencesNormal, referencesOnlyNormalOrganizationID, updateRestrict, deleteRestrict, ownsOnlyOrganizationID)
		}
	}
	for _, table := range []string{"alerts", "integration_keys"} {
		var count int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'organization_id'
		`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("out-of-scope table %s gained organization_id", table)
		}
	}
}

func assertResourceRootOwnershipProvenance(t *testing.T, ctx context.Context, testURL string, entry canonicalMigration, present bool) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var migrationCount, provenanceCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.gorp_migrations WHERE id = $1`, entry.ID).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.ms_oncall_migration_provenance WHERE migration_id = $1`, entry.ID).Scan(&provenanceCount); err != nil {
		t.Fatal(err)
	}
	want := 0
	if present {
		want = 1
	}
	if migrationCount != want || provenanceCount != want {
		t.Fatalf("position-281 migration/provenance rows = %d/%d, want %d/%d", migrationCount, provenanceCount, want, want)
	}
}

func insertResourceTestNormalOrganization(t *testing.T, ctx context.Context, conn *pgx.Conn, id uuid.UUID, suffix string) {
	t.Helper()
	if _, err := conn.Exec(ctx, `
		INSERT INTO public.organizations (id, classification, display_name, canonical_name)
		VALUES ($1, 'NORMAL', $2, $3)
	`, id, "Resource Test Organization "+suffix, "resource-test."+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO public.normal_organizations (
			organization_id, organization_classification, corporate_mapping_key, iana_time_zone
		) VALUES ($1, 'NORMAL', $2, 'Asia/Shanghai')
	`, id, "resource-test:"+suffix); err != nil {
		t.Fatal(err)
	}
}

func insertResourceRoot(ctx context.Context, conn *pgx.Conn, table string, organizationID, policyID uuid.UUID, suffix string) error {
	switch table {
	case "services":
		_, err := conn.Exec(ctx, `INSERT INTO public.services (id, organization_id, name, description, escalation_policy_id) VALUES ($1, $2, $3, 'resource test', $4)`, uuid.New(), organizationID, "Resource Service "+suffix, policyID)
		return err
	case "schedules":
		_, err := conn.Exec(ctx, `INSERT INTO public.schedules (id, organization_id, name, description, time_zone) VALUES ($1, $2, $3, 'resource test', 'Etc/UTC')`, uuid.New(), organizationID, "Resource Schedule "+suffix)
		return err
	case "rotations":
		_, err := conn.Exec(ctx, `INSERT INTO public.rotations (id, organization_id, name, description, type, start_time, shift_length, time_zone) VALUES ($1, $2, $3, 'resource test', 'daily', now(), 1, 'Etc/UTC')`, uuid.New(), organizationID, "Resource Rotation "+suffix)
		return err
	case "escalation_policies":
		_, err := conn.Exec(ctx, `INSERT INTO public.escalation_policies (id, organization_id, name, description, repeat) VALUES ($1, $2, $3, 'resource test', 0)`, policyID, organizationID, "Resource Policy "+suffix)
		return err
	default:
		return fmt.Errorf("unknown resource root table %q", table)
	}
}

func insertLegacyResourceRoots(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	policyID := uuid.New()
	if _, err := conn.Exec(ctx, `INSERT INTO public.escalation_policies (id, name, description, repeat) VALUES ($1, 'Legacy Policy', 'legacy', 0)`, policyID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.services (id, name, description, escalation_policy_id) VALUES ($1, 'Legacy Service', 'legacy', $2)`, uuid.New(), policyID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.schedules (id, name, description, time_zone) VALUES ($1, 'Legacy Schedule', 'legacy', 'Etc/UTC')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.rotations (id, name, description, type, start_time, shift_length, time_zone) VALUES ($1, 'Legacy Rotation', 'legacy', 'daily', now(), 1, 'Etc/UTC')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
}

func assertResourcePGError(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != code || databaseError.ConstraintName != constraint {
		t.Fatalf("PostgreSQL error = %#v / %v, want SQLSTATE %s constraint %s", databaseError, err, code, constraint)
	}
}

func createResourceTestOrganization(t *testing.T, ctx context.Context, store *organization.Store, suffix string) *organization.NormalOrganization {
	t.Helper()
	value, err := store.CreateNormal(ctx, organization.CreateNormalOrganizationInput{
		DisplayName:         "Resource Store Organization " + strings.ToUpper(suffix),
		CanonicalName:       "resource-store.organization-" + suffix,
		CorporateMappingKey: "resource-store:organization-" + suffix,
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func createResourceTestHumanContext(t *testing.T, ctx context.Context, db *sql.DB, store *organization.Store, organizationID uuid.UUID, suffix string) context.Context {
	t.Helper()
	userID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO public.users (id, name, email, role) VALUES ($1, $2, '', 'user')`, userID, "Resource Store User "+strings.ToUpper(suffix)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{
		UserID: userID,
		UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
			EffectiveOrganizationID:             organizationID,
			EffectiveOrganizationClassification: organization.ClassificationNormal,
			Role:                                organization.OrganizationRoleMember,
			MappingOutcome:                      organization.MappingOutcomeExactlyOne,
			Evaluation: organization.AssignmentEvaluation{
				AuthoritativeEvaluatedAt: time.Date(2026, time.September, 10, 1, 0, 0, 0, time.UTC),
				SourceConfigVersion:      "resource-store-" + suffix,
				MatchedCount:             1,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	requestContext := permission.UserSourceContext(ctx, userID.String(), permission.RoleUser, &permission.SourceInfo{
		Type: permission.SourceTypeAuthProvider,
		ID:   sessionID.String(),
	})
	requester, err := auth.NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatal(err)
	}
	requestContext = auth.WithRequester(requestContext, requester)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(store)
	if err != nil {
		t.Fatal(err)
	}
	value, err := constructor.Construct(requestContext)
	if err != nil {
		t.Fatal(err)
	}
	return executioncontext.WithExecutionContext(requestContext, value)
}

func createResourceTestDefaultHumanContext(t *testing.T, ctx context.Context, db *sql.DB, store *organization.Store) context.Context {
	t.Helper()
	userID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO public.users (id, name, email, role) VALUES ($1, 'Resource Default User', '', 'user')`, userID); err != nil {
		t.Fatal(err)
	}
	defaultID := uuid.MustParse(organization.DefaultOrganizationID)
	if _, err := store.CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{
		UserID: userID,
		UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
			EffectiveOrganizationID:             defaultID,
			EffectiveOrganizationClassification: organization.ClassificationDefault,
			Role:                                organization.OrganizationRoleNone,
			MappingOutcome:                      organization.MappingOutcomeZero,
			Evaluation: organization.AssignmentEvaluation{
				AuthoritativeEvaluatedAt: time.Date(2026, time.September, 10, 1, 0, 0, 0, time.UTC),
				SourceConfigVersion:      "resource-store-default",
				MatchedCount:             0,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	requestContext := permission.UserSourceContext(ctx, userID.String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID.String()})
	requester, err := auth.NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatal(err)
	}
	requestContext = auth.WithRequester(requestContext, requester)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(store)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := constructor.Construct(requestContext); !errors.Is(err, executioncontext.ErrHumanExecutionContextUnavailable) || value.Valid() {
		t.Fatalf("Default Organization admission = (%#v, %v), want unavailable", value, err)
	}
	return requestContext
}

func assertResourceRootCreateDenied(t *testing.T, label string, ctx context.Context, policyID string, serviceStore *service.Store, scheduleStore *schedule.Store, rotationStore *rotation.Store, policyStore *escalation.Store) {
	t.Helper()
	checks := map[string]func() error{
		"service": func() error {
			_, err := serviceStore.CreateServiceTx(ctx, nil, &service.Service{Name: "Denied Service " + label, Description: "denied", EscalationPolicyID: policyID})
			return err
		},
		"schedule": func() error {
			_, err := scheduleStore.Create(ctx, &schedule.Schedule{Name: "Denied Schedule " + label, Description: "denied", TimeZone: time.UTC})
			return err
		},
		"rotation": func() error {
			_, err := rotationStore.CreateRotationTx(ctx, nil, &rotation.Rotation{Name: "Denied Rotation " + label, Description: "denied", Type: rotation.TypeDaily, Start: time.Now().UTC(), ShiftLength: 1})
			return err
		},
		"policy": func() error {
			_, err := policyStore.CreatePolicyTx(ctx, nil, &escalation.Policy{Name: "Denied Policy " + label, Description: "denied", Repeat: 1})
			return err
		},
	}
	for name, check := range checks {
		err := check()
		if err == nil || !strings.Contains(err.Error(), "normal Organization scoped authority is required") {
			t.Fatalf("%s %s create error = %v, want fail-closed Organization authority denial", label, name, err)
		}
	}
}

func assertResourceRootMaterializationPaths(t *testing.T, ctx context.Context, db *sql.DB, organizationID uuid.UUID, policyID, serviceID, scheduleID, rotationID string, serviceStore *service.Store, scheduleStore *schedule.Store, rotationStore *rotation.Store, policyStore *escalation.Store) {
	t.Helper()
	assertOwner := func(name string, got uuid.UUID) {
		t.Helper()
		if got != organizationID {
			t.Fatalf("%s materialized OrganizationID = %s, want %s", name, got, organizationID)
		}
	}
	services, err := serviceStore.FindMany(ctx, []string{serviceID})
	if err != nil || len(services) != 1 {
		t.Fatalf("FindMany services = %d, %v", len(services), err)
	}
	assertOwner("service FindMany", services[0].OrganizationID)
	services, err = serviceStore.FindAllByEP(ctx, policyID)
	if err != nil || len(services) != 1 {
		t.Fatalf("FindAllByEP services = %d, %v", len(services), err)
	}
	assertOwner("service FindAllByEP", services[0].OrganizationID)
	schedules, err := scheduleStore.FindMany(ctx, []string{scheduleID})
	if err != nil || len(schedules) != 1 {
		t.Fatalf("FindMany schedules = %d, %v", len(schedules), err)
	}
	assertOwner("schedule FindMany", schedules[0].OrganizationID)
	schedules, err = scheduleStore.FindAll(ctx)
	if err != nil || len(schedules) != 1 {
		t.Fatalf("FindAll schedules = %d, %v", len(schedules), err)
	}
	assertOwner("schedule FindAll", schedules[0].OrganizationID)
	rotations, err := rotationStore.FindMany(ctx, []string{rotationID})
	if err != nil || len(rotations) != 1 {
		t.Fatalf("FindMany rotations = %d, %v", len(rotations), err)
	}
	assertOwner("rotation FindMany", rotations[0].OrganizationID)
	policies, err := policyStore.FindManyPolicies(ctx, []string{policyID})
	if err != nil || len(policies) != 1 {
		t.Fatalf("FindMany policies = %d, %v", len(policies), err)
	}
	assertOwner("policy FindMany", policies[0].OrganizationID)

	userID := uuid.MustParse(permission.UserID(ctx))
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.schedule_rules (schedule_id, tgt_user_id)
		VALUES ($1, $2)
	`, scheduleID, userID); err != nil {
		t.Fatal(err)
	}
	userSchedules, err := scheduleStore.FindManyByUserID(ctx, db, uuid.NullUUID{UUID: userID, Valid: true})
	if err != nil || len(userSchedules) != 1 {
		t.Fatalf("FindManyByUserID schedules = %d, %v", len(userSchedules), err)
	}
	assertOwner("schedule FindManyByUserID", userSchedules[0].OrganizationID)

	stepID := uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.escalation_policy_steps (id, escalation_policy_id)
		VALUES ($1, $2)
	`, stepID, policyID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.escalation_policy_actions (escalation_policy_step_id, schedule_id)
		VALUES ($1, $2)
	`, stepID, scheduleID); err != nil {
		t.Fatal(err)
	}
	policies, err = policyStore.FindAllPoliciesBySchedule(ctx, scheduleID)
	if err != nil || len(policies) != 1 {
		t.Fatalf("FindAllPoliciesBySchedule policies = %d, %v", len(policies), err)
	}
	assertOwner("policy FindAllPoliciesBySchedule", policies[0].OrganizationID)

	rotationData, err := gadb.New(db).RotMgrRotationData(ctx, uuid.MustParse(rotationID))
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("rotation manager embedded row", rotationData.Rotation.OrganizationID)

	serviceSearch, err := serviceStore.Search(ctx, &service.SearchOptions{Search: "Ownership Service"})
	if err != nil || len(serviceSearch) != 1 {
		t.Fatalf("service Search = %d, %v", len(serviceSearch), err)
	}
	assertOwner("service Search", serviceSearch[0].OrganizationID)
	scheduleSearch, err := scheduleStore.Search(ctx, &schedule.SearchOptions{Search: "Ownership Schedule"})
	if err != nil || len(scheduleSearch) != 1 {
		t.Fatalf("schedule Search = %d, %v", len(scheduleSearch), err)
	}
	assertOwner("schedule Search", scheduleSearch[0].OrganizationID)
	rotationSearch, err := rotationStore.Search(ctx, &rotation.SearchOptions{Search: "Ownership Rotation"})
	if err != nil || len(rotationSearch) != 1 {
		t.Fatalf("rotation Search = %d, %v", len(rotationSearch), err)
	}
	assertOwner("rotation Search", rotationSearch[0].OrganizationID)
	policySearch, err := policyStore.Search(ctx, &escalation.SearchOptions{Search: "Ownership Policy"})
	if err != nil || len(policySearch) != 1 {
		t.Fatalf("policy Search = %d, %v", len(policySearch), err)
	}
	assertOwner("policy Search", policySearch[0].OrganizationID)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	lockedService, err := serviceStore.FindOneForUpdate(ctx, tx, serviceID)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("service FindOneForUpdate", lockedService.OrganizationID)
	lockedSchedule, err := scheduleStore.FindOneForUpdate(ctx, tx, scheduleID)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("schedule FindOneForUpdate", lockedSchedule.OrganizationID)
	lockedRotation, err := rotationStore.FindRotationForUpdateTx(ctx, tx, rotationID)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("rotation FindOneForUpdate", lockedRotation.OrganizationID)
	lockedPolicy, err := policyStore.FindOnePolicyForUpdateTx(ctx, tx, policyID)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("policy FindOneForUpdate", lockedPolicy.OrganizationID)
}
