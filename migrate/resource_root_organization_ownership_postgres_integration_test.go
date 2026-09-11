package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/service"
	"github.com/target/goalert/user/favorite"
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

	t.Run("concurrent committed create forces Down refusal", func(t *testing.T) {
		testURL := newPostgresTestDatabase(t, baseURL)
		if count, err := Up(ctx, testURL, position281.Name); err != nil {
			t.Fatal(err)
		} else if count != len(history.entries) {
			t.Fatalf("position-281 setup applied %d migrations, want %d", count, len(history.entries))
		}

		insertConn, err := pgx.Connect(ctx, testURL)
		if err != nil {
			t.Fatal(err)
		}
		defer insertConn.Close(ctx)
		organizationID := uuid.New()
		insertResourceTestNormalOrganization(t, ctx, insertConn, organizationID, "concurrent-down")

		insertTx, err := insertConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		insertCommitted := false
		defer func() {
			if !insertCommitted {
				_ = insertTx.Rollback(context.Background())
			}
		}()
		scheduleID := uuid.New()
		if _, err := insertTx.Exec(ctx, `
			INSERT INTO public.schedules (id, organization_id, name, description, time_zone)
			VALUES ($1, $2, 'Concurrent Down Schedule', 'concurrent down', 'Etc/UTC')
		`, scheduleID, organizationID); err != nil {
			t.Fatal(err)
		}

		applicationName := "resource-root-down-" + uuid.NewString()
		downURL := postgresURLWithApplicationName(t, testURL, applicationName)
		type downResult struct {
			count int
			err   error
		}
		downResultCh := make(chan downResult, 1)
		downCtx, cancelDown := context.WithTimeout(ctx, 30*time.Second)
		defer cancelDown()
		go func() {
			count, err := Down(downCtx, downURL, position280.Name)
			downResultCh <- downResult{count: count, err: err}
		}()

		observer, err := pgx.Connect(ctx, testURL)
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close(ctx)
		lockCtx, cancelLock := context.WithTimeout(ctx, 10*time.Second)
		defer cancelLock()
		lockPoll := time.NewTicker(10 * time.Millisecond)
		defer lockPoll.Stop()
		for {
			var waiting bool
			err := observer.QueryRow(lockCtx, `
				SELECT EXISTS (
					SELECT 1
					FROM pg_catalog.pg_locks AS l
					JOIN pg_catalog.pg_stat_activity AS a ON a.pid = l.pid
					WHERE a.application_name = $1
						AND l.locktype = 'relation'
						AND l.relation = 'public.schedules'::regclass
						AND l.mode = 'AccessExclusiveLock'
						AND NOT l.granted
				)
			`, applicationName).Scan(&waiting)
			if err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case result := <-downResultCh:
				t.Fatalf("position-281 Down completed before reaching the required lock boundary: (%d, %v)", result.count, result.err)
			case <-lockCtx.Done():
				t.Fatalf("observe blocked position-281 Down: %v", lockCtx.Err())
			case <-lockPoll.C:
			}
		}
		select {
		case result := <-downResultCh:
			t.Fatalf("position-281 Down did not remain blocked by the uncommitted create: (%d, %v)", result.count, result.err)
		default:
		}

		if err := insertTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		insertCommitted = true

		result := <-downResultCh
		if result.count != 0 || result.err == nil {
			t.Fatalf("concurrent populated position-281 Down = (%d, %v), want zero applied and refusal", result.count, result.err)
		}
		var databaseError *pgconn.PgError
		if !errors.As(result.err, &databaseError) || databaseError.Code != "55000" ||
			databaseError.Message != "position-281 downgrade refused: resource rows retain Organization ownership" {
			t.Fatalf("concurrent populated position-281 Down error = %#v / %v", databaseError, result.err)
		}

		var persistedOrganizationID uuid.UUID
		if err := observer.QueryRow(ctx, `SELECT organization_id FROM public.schedules WHERE id = $1`, scheduleID).Scan(&persistedOrganizationID); err != nil {
			t.Fatal(err)
		}
		if persistedOrganizationID != organizationID {
			t.Fatalf("committed concurrent schedule owner = %s, want %s", persistedOrganizationID, organizationID)
		}
		assertResourceRootOwnershipSchema(t, ctx, testURL, true)
		assertResourceRootOwnershipProvenance(t, ctx, testURL, position281, true)
		if err := VerifyAll(ctx, testURL); err != nil {
			t.Fatal(err)
		}
	})
}

func postgresURLWithApplicationName(t *testing.T, databaseURL, applicationName string) string {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("application_name", applicationName)
	parsed.RawQuery = query.Encode()
	return parsed.String()
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
	storeUserID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO public.users (id, name, email, role) VALUES ($1, 'Resource Store User', '', 'admin')`, storeUserID); err != nil {
		t.Fatal(err)
	}
	storeContext := permission.UserContext(ctx, storeUserID.String(), permission.RoleAdmin)

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

	policy, err := policyStore.CreatePolicyTx(storeContext, nil, &escalation.Policy{
		OrganizationID: organizationA.ID,
		Name:           "Ownership Policy",
		Description:    "ownership policy",
		Repeat:         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	serviceValue, err := serviceStore.CreateServiceTx(storeContext, nil, &service.Service{
		OrganizationID:     organizationA.ID,
		Name:               "Ownership Service",
		Description:        "ownership service",
		EscalationPolicyID: policy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduleValue, err := scheduleStore.Create(storeContext, &schedule.Schedule{
		OrganizationID: organizationA.ID,
		Name:           "Ownership Schedule",
		Description:    "ownership schedule",
		TimeZone:       time.UTC,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotationValue, err := rotationStore.CreateRotationTx(storeContext, nil, &rotation.Rotation{
		OrganizationID: organizationA.ID,
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
			t.Fatalf("created %s OrganizationID = %s, want explicit trusted owner %s", name, got, organizationA.ID)
		}
	}

	for name, create := range map[string]func() error{
		"policy": func() error {
			_, err := policyStore.CreatePolicyTx(storeContext, nil, &escalation.Policy{OrganizationID: organizationB.ID, Name: policy.Name, Description: "duplicate", Repeat: 1})
			return err
		},
		"service": func() error {
			_, err := serviceStore.CreateServiceTx(storeContext, nil, &service.Service{OrganizationID: organizationB.ID, Name: serviceValue.Name, Description: "duplicate", EscalationPolicyID: policy.ID})
			return err
		},
		"schedule": func() error {
			_, err := scheduleStore.Create(storeContext, &schedule.Schedule{OrganizationID: organizationB.ID, Name: scheduleValue.Name, Description: "duplicate", TimeZone: time.UTC})
			return err
		},
		"rotation": func() error {
			_, err := rotationStore.CreateRotationTx(storeContext, nil, &rotation.Rotation{OrganizationID: organizationB.ID, Name: rotationValue.Name, Description: "duplicate", Type: rotation.TypeDaily, Start: time.Now().UTC(), ShiftLength: 1})
			return err
		},
	} {
		if err := create(); err == nil {
			t.Fatalf("%s name uniqueness unexpectedly became Organization-local", name)
		}
	}

	policy.OrganizationID = organizationB.ID
	policy.Description = "ownership policy updated"
	if err := policyStore.UpdatePolicyTx(storeContext, nil, policy, nil); err != nil {
		t.Fatal(err)
	}
	serviceValue.OrganizationID = organizationB.ID
	serviceValue.Description = "ownership service updated"
	if err := serviceStore.UpdateTx(storeContext, nil, serviceValue, nil); err != nil {
		t.Fatal(err)
	}
	scheduleValue.OrganizationID = organizationB.ID
	scheduleValue.Description = "ownership schedule updated"
	if err := scheduleStore.Update(storeContext, scheduleValue); err != nil {
		t.Fatal(err)
	}
	rotationValue.OrganizationID = organizationB.ID
	rotationValue.Description = "ownership rotation updated"
	if err := rotationStore.UpdateRotationTx(storeContext, nil, rotationValue, nil); err != nil {
		t.Fatal(err)
	}

	loadedPolicy, err := policyStore.FindOnePolicyTx(storeContext, nil, policy.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	loadedService, err := serviceStore.FindOne(storeContext, serviceValue.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	loadedSchedule, err := scheduleStore.FindOne(storeContext, scheduleValue.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	loadedRotation, err := rotationStore.FindRotation(storeContext, rotationValue.ID, nil)
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

	assertResourceRootMaterializationPaths(t, storeContext, db, organizationA.ID, policy.ID, serviceValue.ID, scheduleValue.ID, rotationValue.ID, serviceStore, scheduleStore, rotationStore, policyStore)
}

type scopedRootObservation struct {
	ID             string
	OrganizationID uuid.UUID
	Name           string
}

type scopedRootSearchInput struct {
	OrganizationID uuid.UUID
	Search         string
	Omit           []string
	Only           []string
	Limit          int
	AfterName      string
	FavoritesOnly  bool
	FavoritesFirst bool
	FavoritesUser  string
}

type scopedRootStoreAdapter struct {
	name         string
	supportsOnly bool
	create       func(uuid.UUID, string) (scopedRootObservation, error)
	get          func(string, *uuid.UUID) (scopedRootObservation, error)
	batch        func([]string, *uuid.UUID) ([]scopedRootObservation, error)
	search       func(scopedRootSearchInput) ([]scopedRootObservation, error)
	lock         func(*sql.Tx, string, *uuid.UUID) (scopedRootObservation, error)
	update       func(string, string, uuid.UUID, *uuid.UUID) error
	delete       func(*sql.Tx, []string, *uuid.UUID) error
	favorite     func(string) error
}

func TestPostgresResourceRootOrganizationScopedCRUD(t *testing.T) {
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
	organizationA := createResourceTestOrganization(t, ctx, organizationStore, "scoped-a")
	organizationB := createResourceTestOrganization(t, ctx, organizationStore, "scoped-b")
	storeUserID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO public.users (id, name, email, role) VALUES ($1, 'Scoped Root Store User', '', 'admin')`, storeUserID); err != nil {
		t.Fatal(err)
	}
	storeContext := permission.UserContext(ctx, storeUserID.String(), permission.RoleAdmin)

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
	favoriteStore, err := favorite.NewStore(ctx)
	if err != nil {
		t.Fatal(err)
	}

	observeService := func(value service.Service) scopedRootObservation {
		return scopedRootObservation{ID: value.ID, OrganizationID: value.OrganizationID, Name: value.Name}
	}
	observeSchedule := func(value schedule.Schedule) scopedRootObservation {
		return scopedRootObservation{ID: value.ID, OrganizationID: value.OrganizationID, Name: value.Name}
	}
	observeRotation := func(value rotation.Rotation) scopedRootObservation {
		return scopedRootObservation{ID: value.ID, OrganizationID: value.OrganizationID, Name: value.Name}
	}
	observePolicy := func(value escalation.Policy) scopedRootObservation {
		return scopedRootObservation{ID: value.ID, OrganizationID: value.OrganizationID, Name: value.Name}
	}

	adapters := []scopedRootStoreAdapter{
		{
			name:         "service",
			supportsOnly: true,
			create: func(organizationID uuid.UUID, name string) (scopedRootObservation, error) {
				policy, err := policyStore.CreatePolicyTx(storeContext, nil, &escalation.Policy{
					OrganizationID: organizationID,
					Name:           "Support Policy " + name,
					Description:    "support",
					Repeat:         1,
				})
				if err != nil {
					return scopedRootObservation{}, err
				}
				value, err := serviceStore.CreateServiceTx(storeContext, nil, &service.Service{
					OrganizationID:     organizationID,
					Name:               name,
					Description:        "scoped service",
					EscalationPolicyID: policy.ID,
				})
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeService(*value), nil
			},
			get: func(id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := serviceStore.FindOne(storeContext, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeService(*value), nil
			},
			batch: func(ids []string, organizationID *uuid.UUID) ([]scopedRootObservation, error) {
				values, err := serviceStore.FindMany(storeContext, ids, organizationID)
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observeService(value))
				}
				return result, nil
			},
			search: func(input scopedRootSearchInput) ([]scopedRootObservation, error) {
				values, err := serviceStore.Search(storeContext, &service.SearchOptions{
					OrganizationID:  input.OrganizationID,
					Search:          input.Search,
					Omit:            input.Omit,
					Only:            input.Only,
					Limit:           input.Limit,
					After:           service.SearchCursor{Name: input.AfterName},
					FavoritesOnly:   input.FavoritesOnly,
					FavoritesFirst:  input.FavoritesFirst,
					FavoritesUserID: input.FavoritesUser,
				})
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observeService(value))
				}
				return result, nil
			},
			lock: func(tx *sql.Tx, id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := serviceStore.FindOneForUpdate(storeContext, tx, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeService(*value), nil
			},
			update: func(id, name string, modelOrganizationID uuid.UUID, organizationID *uuid.UUID) error {
				value, err := serviceStore.FindOne(storeContext, id, nil)
				if err != nil {
					return err
				}
				value.Name = name
				value.OrganizationID = modelOrganizationID
				return serviceStore.UpdateTx(storeContext, nil, value, organizationID)
			},
			delete: func(tx *sql.Tx, ids []string, organizationID *uuid.UUID) error {
				return serviceStore.DeleteManyTx(storeContext, tx, ids, organizationID)
			},
			favorite: func(id string) error {
				return favoriteStore.Set(storeContext, db, storeUserID.String(), assignment.ServiceTarget(id))
			},
		},
		{
			name: "schedule",
			create: func(organizationID uuid.UUID, name string) (scopedRootObservation, error) {
				value, err := scheduleStore.Create(storeContext, &schedule.Schedule{
					OrganizationID: organizationID,
					Name:           name,
					Description:    "scoped schedule",
					TimeZone:       time.UTC,
				})
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeSchedule(*value), nil
			},
			get: func(id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := scheduleStore.FindOne(storeContext, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeSchedule(*value), nil
			},
			batch: func(ids []string, organizationID *uuid.UUID) ([]scopedRootObservation, error) {
				values, err := scheduleStore.FindMany(storeContext, ids, organizationID)
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observeSchedule(value))
				}
				return result, nil
			},
			search: func(input scopedRootSearchInput) ([]scopedRootObservation, error) {
				values, err := scheduleStore.Search(storeContext, &schedule.SearchOptions{
					OrganizationID:  input.OrganizationID,
					Search:          input.Search,
					Omit:            input.Omit,
					Limit:           input.Limit,
					After:           schedule.SearchCursor{Name: input.AfterName},
					FavoritesOnly:   input.FavoritesOnly,
					FavoritesFirst:  input.FavoritesFirst,
					FavoritesUserID: input.FavoritesUser,
				})
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observeSchedule(value))
				}
				return result, nil
			},
			lock: func(tx *sql.Tx, id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := scheduleStore.FindOneForUpdate(storeContext, tx, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeSchedule(*value), nil
			},
			update: func(id, name string, modelOrganizationID uuid.UUID, organizationID *uuid.UUID) error {
				value, err := scheduleStore.FindOne(storeContext, id, nil)
				if err != nil {
					return err
				}
				value.Name = name
				value.OrganizationID = modelOrganizationID
				return scheduleStore.UpdateTx(storeContext, nil, value, organizationID)
			},
			delete: func(tx *sql.Tx, ids []string, organizationID *uuid.UUID) error {
				return scheduleStore.DeleteManyTx(storeContext, tx, ids, organizationID)
			},
			favorite: func(id string) error {
				return favoriteStore.Set(storeContext, db, storeUserID.String(), assignment.ScheduleTarget(id))
			},
		},
		{
			name: "rotation",
			create: func(organizationID uuid.UUID, name string) (scopedRootObservation, error) {
				value, err := rotationStore.CreateRotationTx(storeContext, nil, &rotation.Rotation{
					OrganizationID: organizationID,
					Name:           name,
					Description:    "scoped rotation",
					Type:           rotation.TypeDaily,
					Start:          time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC),
					ShiftLength:    1,
				})
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeRotation(*value), nil
			},
			get: func(id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := rotationStore.FindRotation(storeContext, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeRotation(*value), nil
			},
			batch: func(ids []string, organizationID *uuid.UUID) ([]scopedRootObservation, error) {
				values, err := rotationStore.FindMany(storeContext, ids, organizationID)
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observeRotation(value))
				}
				return result, nil
			},
			search: func(input scopedRootSearchInput) ([]scopedRootObservation, error) {
				values, err := rotationStore.Search(storeContext, &rotation.SearchOptions{
					OrganizationID:  input.OrganizationID,
					Search:          input.Search,
					Omit:            input.Omit,
					Limit:           input.Limit,
					After:           rotation.SearchCursor{Name: input.AfterName},
					FavoritesOnly:   input.FavoritesOnly,
					FavoritesFirst:  input.FavoritesFirst,
					FavoritesUserID: input.FavoritesUser,
				})
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observeRotation(value))
				}
				return result, nil
			},
			lock: func(tx *sql.Tx, id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := rotationStore.FindRotationForUpdateTx(storeContext, tx, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observeRotation(*value), nil
			},
			update: func(id, name string, modelOrganizationID uuid.UUID, organizationID *uuid.UUID) error {
				value, err := rotationStore.FindRotation(storeContext, id, nil)
				if err != nil {
					return err
				}
				value.Name = name
				value.OrganizationID = modelOrganizationID
				return rotationStore.UpdateRotationTx(storeContext, nil, value, organizationID)
			},
			delete: func(tx *sql.Tx, ids []string, organizationID *uuid.UUID) error {
				return rotationStore.DeleteManyTx(storeContext, tx, ids, organizationID)
			},
			favorite: func(id string) error {
				return favoriteStore.Set(storeContext, db, storeUserID.String(), assignment.RotationTarget(id))
			},
		},
		{
			name: "policy",
			create: func(organizationID uuid.UUID, name string) (scopedRootObservation, error) {
				value, err := policyStore.CreatePolicyTx(storeContext, nil, &escalation.Policy{
					OrganizationID: organizationID,
					Name:           name,
					Description:    "scoped policy",
					Repeat:         1,
				})
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observePolicy(*value), nil
			},
			get: func(id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := policyStore.FindOnePolicyTx(storeContext, nil, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observePolicy(*value), nil
			},
			batch: func(ids []string, organizationID *uuid.UUID) ([]scopedRootObservation, error) {
				values, err := policyStore.FindManyPolicies(storeContext, ids, organizationID)
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observePolicy(value))
				}
				return result, nil
			},
			search: func(input scopedRootSearchInput) ([]scopedRootObservation, error) {
				values, err := policyStore.Search(storeContext, &escalation.SearchOptions{
					OrganizationID:  input.OrganizationID,
					Search:          input.Search,
					Omit:            input.Omit,
					Limit:           input.Limit,
					After:           escalation.SearchCursor{Name: input.AfterName},
					FavoritesOnly:   input.FavoritesOnly,
					FavoritesFirst:  input.FavoritesFirst,
					FavoritesUserID: input.FavoritesUser,
				})
				if err != nil {
					return nil, err
				}
				result := make([]scopedRootObservation, 0, len(values))
				for _, value := range values {
					result = append(result, observePolicy(value))
				}
				return result, nil
			},
			lock: func(tx *sql.Tx, id string, organizationID *uuid.UUID) (scopedRootObservation, error) {
				value, err := policyStore.FindOnePolicyForUpdateTx(storeContext, tx, id, organizationID)
				if err != nil {
					return scopedRootObservation{}, err
				}
				return observePolicy(*value), nil
			},
			update: func(id, name string, modelOrganizationID uuid.UUID, organizationID *uuid.UUID) error {
				value, err := policyStore.FindOnePolicyTx(storeContext, nil, id, nil)
				if err != nil {
					return err
				}
				value.Name = name
				value.OrganizationID = modelOrganizationID
				return policyStore.UpdatePolicyTx(storeContext, nil, value, organizationID)
			},
			delete: func(tx *sql.Tx, ids []string, organizationID *uuid.UUID) error {
				return policyStore.DeleteManyPoliciesTx(storeContext, tx, ids, organizationID)
			},
			favorite: func(id string) error {
				return favoriteStore.Set(storeContext, db, storeUserID.String(), assignment.EscalationPolicyTarget(id))
			},
		},
	}

	for _, adapter := range adapters {
		t.Run(adapter.name, func(t *testing.T) {
			prefix := "Scoped " + strings.ToUpper(adapter.name[:1]) + adapter.name[1:] + " Root"
			ownFirst, err := adapter.create(organizationA.ID, prefix+" 01")
			if err != nil {
				t.Fatal(err)
			}
			crossMiddle, err := adapter.create(organizationB.ID, prefix+" 02")
			if err != nil {
				t.Fatal(err)
			}
			ownLast, err := adapter.create(organizationA.ID, prefix+" 03")
			if err != nil {
				t.Fatal(err)
			}

			got, err := adapter.get(ownFirst.ID, &organizationA.ID)
			if err != nil || got.ID != ownFirst.ID || got.OrganizationID != organizationA.ID {
				t.Fatalf("scoped own get = (%#v, %v)", got, err)
			}
			if _, err := adapter.get(crossMiddle.ID, &organizationA.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("scoped cross get error = %v, want sql.ErrNoRows", err)
			}
			got, err = adapter.get(crossMiddle.ID, nil)
			if err != nil || got.ID != crossMiddle.ID || got.OrganizationID != organizationB.ID {
				t.Fatalf("unscoped internal get = (%#v, %v)", got, err)
			}

			batch, err := adapter.batch([]string{ownFirst.ID, crossMiddle.ID, ownLast.ID}, &organizationA.ID)
			assertScopedRootIDs(t, batch, err, organizationA.ID, ownFirst.ID, ownLast.ID)

			searchInput := scopedRootSearchInput{OrganizationID: organizationA.ID, Search: prefix, Limit: 20}
			values, err := adapter.search(searchInput)
			assertScopedRootIDs(t, values, err, organizationA.ID, ownFirst.ID, ownLast.ID)

			searchInput.Limit = 1
			pageOne, err := adapter.search(searchInput)
			assertScopedRootIDs(t, pageOne, err, organizationA.ID, ownFirst.ID)
			searchInput.AfterName = pageOne[0].Name
			pageTwo, err := adapter.search(searchInput)
			assertScopedRootIDs(t, pageTwo, err, organizationA.ID, ownLast.ID)

			searchInput.Limit = 20
			searchInput.AfterName = ""
			searchInput.Omit = []string{ownFirst.ID, crossMiddle.ID}
			values, err = adapter.search(searchInput)
			assertScopedRootIDs(t, values, err, organizationA.ID, ownLast.ID)
			searchInput.Omit = nil
			if adapter.supportsOnly {
				searchInput.Only = []string{ownLast.ID, crossMiddle.ID}
				values, err = adapter.search(searchInput)
				assertScopedRootIDs(t, values, err, organizationA.ID, ownLast.ID)
				searchInput.Only = nil
			}

			if err := adapter.favorite(ownLast.ID); err != nil {
				t.Fatal(err)
			}
			if err := adapter.favorite(crossMiddle.ID); err != nil {
				t.Fatal(err)
			}
			searchInput.FavoritesOnly = true
			searchInput.FavoritesFirst = true
			searchInput.FavoritesUser = storeUserID.String()
			values, err = adapter.search(searchInput)
			assertScopedRootIDs(t, values, err, organizationA.ID, ownLast.ID)

			tx, err := db.BeginTx(storeContext, nil)
			if err != nil {
				t.Fatal(err)
			}
			locked, err := adapter.lock(tx, ownFirst.ID, &organizationA.ID)
			if err != nil || locked.OrganizationID != organizationA.ID {
				_ = tx.Rollback()
				t.Fatalf("scoped own lock = (%#v, %v)", locked, err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}

			tx, err = db.BeginTx(storeContext, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, lockErr := adapter.lock(tx, crossMiddle.ID, &organizationA.ID)
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(lockErr, sql.ErrNoRows) {
				t.Fatalf("scoped cross lock error = %v, want sql.ErrNoRows", lockErr)
			}

			updatedOwnName := prefix + " 04 Updated"
			if err := adapter.update(ownFirst.ID, updatedOwnName, organizationB.ID, &organizationA.ID); err != nil {
				t.Fatal(err)
			}
			got, err = adapter.get(ownFirst.ID, nil)
			if err != nil || got.Name != updatedOwnName || got.OrganizationID != organizationA.ID {
				t.Fatalf("own update/immutable OrganizationID = (%#v, %v)", got, err)
			}
			crossOriginalName := crossMiddle.Name
			if err := adapter.update(crossMiddle.ID, prefix+" 05 Cross Update", organizationA.ID, &organizationA.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("scoped cross update error = %v, want sql.ErrNoRows", err)
			}
			got, err = adapter.get(crossMiddle.ID, nil)
			if err != nil || got.Name != crossOriginalName || got.OrganizationID != organizationB.ID {
				t.Fatalf("cross update mutated resource = (%#v, %v)", got, err)
			}

			deleteOwn, err := adapter.create(organizationA.ID, prefix+" 06 Delete Own")
			if err != nil {
				t.Fatal(err)
			}
			deleteCross, err := adapter.create(organizationB.ID, prefix+" 07 Delete Cross")
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.delete(nil, []string{deleteCross.ID}, &organizationA.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("scoped cross delete error = %v, want sql.ErrNoRows", err)
			}
			if _, err := adapter.get(deleteCross.ID, nil); err != nil {
				t.Fatalf("cross delete removed resource: %v", err)
			}

			missingID := uuid.NewString()
			if err := adapter.delete(nil, []string{missingID}, &organizationA.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("scoped missing delete error = %v, want sql.ErrNoRows", err)
			}

			canonicalDuplicate, err := adapter.create(organizationA.ID, prefix+" Canonical Duplicate")
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.delete(nil, []string{canonicalDuplicate.ID, canonicalDuplicate.ID}, &organizationA.ID); err != nil {
				t.Fatalf("scoped canonical duplicate delete: %v", err)
			}
			if _, err := adapter.get(canonicalDuplicate.ID, nil); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("canonical duplicate delete lookup error = %v, want sql.ErrNoRows", err)
			}

			var caseVariantDuplicate scopedRootObservation
			var lowerCaseID, upperCaseID string
			for attempt := 0; attempt < 10 && lowerCaseID == upperCaseID; attempt++ {
				caseVariantDuplicate, err = adapter.create(organizationA.ID, fmt.Sprintf("%s Case Variant %d", prefix, attempt))
				if err != nil {
					t.Fatal(err)
				}
				lowerCaseID = strings.ToLower(caseVariantDuplicate.ID)
				upperCaseID = strings.ToUpper(caseVariantDuplicate.ID)
			}
			if lowerCaseID == upperCaseID {
				t.Fatal("generated UUIDs contained no case-variant hexadecimal characters")
			}
			if err := adapter.delete(nil, []string{lowerCaseID, upperCaseID}, &organizationA.ID); err != nil {
				t.Fatalf("scoped case-variant duplicate delete: %v", err)
			}
			if _, err := adapter.get(caseVariantDuplicate.ID, nil); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("case-variant duplicate delete lookup error = %v, want sql.ErrNoRows", err)
			}

			var internalDuplicate scopedRootObservation
			lowerCaseID, upperCaseID = "", ""
			for attempt := 0; attempt < 10 && lowerCaseID == upperCaseID; attempt++ {
				internalDuplicate, err = adapter.create(organizationB.ID, fmt.Sprintf("%s Internal Case Variant %d", prefix, attempt))
				if err != nil {
					t.Fatal(err)
				}
				lowerCaseID = strings.ToLower(internalDuplicate.ID)
				upperCaseID = strings.ToUpper(internalDuplicate.ID)
			}
			if lowerCaseID == upperCaseID {
				t.Fatal("generated UUIDs contained no case-variant hexadecimal characters")
			}
			if err := adapter.delete(nil, []string{lowerCaseID, upperCaseID}, nil); err != nil {
				t.Fatalf("unscoped internal case-variant duplicate delete: %v", err)
			}
			if _, err := adapter.get(internalDuplicate.ID, nil); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("internal case-variant duplicate delete lookup error = %v, want sql.ErrNoRows", err)
			}

			if err := adapter.delete(nil, []string{deleteOwn.ID}, &organizationA.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.get(deleteOwn.ID, nil); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("own delete lookup error = %v, want sql.ErrNoRows", err)
			}

			mixedOwn, err := adapter.create(organizationA.ID, prefix+" 08 Mixed Own")
			if err != nil {
				t.Fatal(err)
			}
			mixedCross, err := adapter.create(organizationB.ID, prefix+" 09 Mixed Cross")
			if err != nil {
				t.Fatal(err)
			}
			tx, err = db.BeginTx(storeContext, nil)
			if err != nil {
				t.Fatal(err)
			}
			deleteErr := adapter.delete(tx, []string{mixedOwn.ID, mixedCross.ID}, &organizationA.ID)
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(deleteErr, sql.ErrNoRows) {
				t.Fatalf("mixed scoped delete error = %v, want sql.ErrNoRows", deleteErr)
			}
			for _, value := range []scopedRootObservation{mixedOwn, mixedCross} {
				if _, err := adapter.get(value.ID, nil); err != nil {
					t.Fatalf("mixed delete did not roll back %s: %v", value.ID, err)
				}
			}
		})
	}

	t.Run("alternate scoped materialization", func(t *testing.T) {
		policyA, err := policyStore.CreatePolicyTx(storeContext, nil, &escalation.Policy{OrganizationID: organizationA.ID, Name: "Scoped Alternate Policy A", Repeat: 1})
		if err != nil {
			t.Fatal(err)
		}
		policyB, err := policyStore.CreatePolicyTx(storeContext, nil, &escalation.Policy{OrganizationID: organizationB.ID, Name: "Scoped Alternate Policy B", Repeat: 1})
		if err != nil {
			t.Fatal(err)
		}
		serviceA, err := serviceStore.CreateServiceTx(storeContext, nil, &service.Service{OrganizationID: organizationA.ID, Name: "Scoped Alternate Service A", EscalationPolicyID: policyA.ID})
		if err != nil {
			t.Fatal(err)
		}
		serviceB, err := serviceStore.CreateServiceTx(storeContext, nil, &service.Service{OrganizationID: organizationB.ID, Name: "Scoped Alternate Service B", EscalationPolicyID: policyB.ID})
		if err != nil {
			t.Fatal(err)
		}
		services, err := serviceStore.FindAllByEP(storeContext, policyA.ID, &organizationA.ID)
		if err != nil || len(services) != 1 || services[0].ID != serviceA.ID {
			t.Fatalf("scoped FindAllByEP = (%#v, %v)", services, err)
		}
		services, err = serviceStore.FindAllByEP(storeContext, policyB.ID, &organizationA.ID)
		if err != nil || len(services) != 0 {
			t.Fatalf("cross FindAllByEP = (%#v, %v), cross service %s", services, err, serviceB.ID)
		}

		scheduleA, err := scheduleStore.Create(storeContext, &schedule.Schedule{OrganizationID: organizationA.ID, Name: "Scoped Alternate Schedule A", TimeZone: time.UTC})
		if err != nil {
			t.Fatal(err)
		}
		scheduleB, err := scheduleStore.Create(storeContext, &schedule.Schedule{OrganizationID: organizationB.ID, Name: "Scoped Alternate Schedule B", TimeZone: time.UTC})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(storeContext, `INSERT INTO public.schedule_rules (schedule_id, tgt_user_id) VALUES ($1, $2), ($3, $2)`, scheduleA.ID, storeUserID, scheduleB.ID); err != nil {
			t.Fatal(err)
		}
		userSchedules, err := scheduleStore.FindManyByUserID(storeContext, db, uuid.NullUUID{UUID: storeUserID, Valid: true}, &organizationA.ID)
		if err != nil || len(userSchedules) != 1 || userSchedules[0].ID != scheduleA.ID {
			t.Fatalf("scoped FindManyByUserID = (%#v, %v)", userSchedules, err)
		}

		stepA, stepB := uuid.New(), uuid.New()
		if _, err := db.ExecContext(storeContext, `INSERT INTO public.escalation_policy_steps (id, escalation_policy_id) VALUES ($1, $2), ($3, $4)`, stepA, policyA.ID, stepB, policyB.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(storeContext, `INSERT INTO public.escalation_policy_actions (escalation_policy_step_id, schedule_id) VALUES ($1, $2), ($3, $4)`, stepA, scheduleA.ID, stepB, scheduleB.ID); err != nil {
			t.Fatal(err)
		}
		policies, err := policyStore.FindAllPoliciesBySchedule(storeContext, scheduleA.ID, &organizationA.ID)
		if err != nil || len(policies) != 1 || policies[0].ID != policyA.ID {
			t.Fatalf("scoped FindAllPoliciesBySchedule = (%#v, %v)", policies, err)
		}
		policies, err = policyStore.FindAllPoliciesBySchedule(storeContext, scheduleB.ID, &organizationA.ID)
		if err != nil || len(policies) != 0 {
			t.Fatalf("cross FindAllPoliciesBySchedule = (%#v, %v)", policies, err)
		}

		rotationB, err := rotationStore.CreateRotationTx(storeContext, nil, &rotation.Rotation{
			OrganizationID: organizationB.ID,
			Name:           "Scoped Alternate Rotation B",
			Type:           rotation.TypeDaily,
			Start:          time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC),
			ShiftLength:    1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := scheduleStore.ValidateField(storeContext, schedule.FieldScheduleID, scheduleB.ID); err != nil {
			t.Fatalf("shared internal schedule destination provider lost unscoped compatibility: %v", err)
		}
		if err := rotationStore.ValidateField(storeContext, rotation.FieldRotationID, rotationB.ID); err != nil {
			t.Fatalf("shared internal rotation destination provider lost unscoped compatibility: %v", err)
		}
	})

	t.Run("existing actor permission remains independent", func(t *testing.T) {
		deniedContext := permission.UserContext(ctx, uuid.NewString(), permission.RoleUnknown)
		_, err := serviceStore.Search(deniedContext, &service.SearchOptions{OrganizationID: organizationA.ID})
		if !permission.IsPermissionError(err) {
			t.Fatalf("scoped search permission error = %v, want existing AccessDenied behavior", err)
		}
	})
}

func assertScopedRootIDs(t *testing.T, values []scopedRootObservation, err error, organizationID uuid.UUID, want ...string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(values))
	for _, value := range values {
		if value.OrganizationID != organizationID {
			t.Fatalf("materialized OrganizationID = %s, want %s", value.OrganizationID, organizationID)
		}
		got = append(got, value.ID)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("materialized IDs = %v, want %v", got, want)
	}
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
	for name, options := range map[string]any{
		"service search":  service.SearchOptions{OrganizationID: organizationID},
		"schedule search": schedule.SearchOptions{OrganizationID: organizationID},
		"rotation search": rotation.SearchOptions{OrganizationID: organizationID},
		"policy search":   escalation.SearchOptions{OrganizationID: organizationID},
	} {
		encoded, err := json.Marshal(options)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), organizationID.String()) || strings.Contains(strings.ToLower(string(encoded)), "organization") {
			t.Fatalf("%s cursor payload exposed Organization filtering dimension: %s", name, encoded)
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

func assertResourceRootMaterializationPaths(t *testing.T, ctx context.Context, db *sql.DB, organizationID uuid.UUID, policyID, serviceID, scheduleID, rotationID string, serviceStore *service.Store, scheduleStore *schedule.Store, rotationStore *rotation.Store, policyStore *escalation.Store) {
	t.Helper()
	assertOwner := func(name string, got uuid.UUID) {
		t.Helper()
		if got != organizationID {
			t.Fatalf("%s materialized OrganizationID = %s, want %s", name, got, organizationID)
		}
	}
	services, err := serviceStore.FindMany(ctx, []string{serviceID}, nil)
	if err != nil || len(services) != 1 {
		t.Fatalf("FindMany services = %d, %v", len(services), err)
	}
	assertOwner("service FindMany", services[0].OrganizationID)
	services, err = serviceStore.FindAllByEP(ctx, policyID, nil)
	if err != nil || len(services) != 1 {
		t.Fatalf("FindAllByEP services = %d, %v", len(services), err)
	}
	assertOwner("service FindAllByEP", services[0].OrganizationID)
	schedules, err := scheduleStore.FindMany(ctx, []string{scheduleID}, nil)
	if err != nil || len(schedules) != 1 {
		t.Fatalf("FindMany schedules = %d, %v", len(schedules), err)
	}
	assertOwner("schedule FindMany", schedules[0].OrganizationID)
	schedules, err = scheduleStore.FindAll(ctx)
	if err != nil || len(schedules) != 1 {
		t.Fatalf("FindAll schedules = %d, %v", len(schedules), err)
	}
	assertOwner("schedule FindAll", schedules[0].OrganizationID)
	rotations, err := rotationStore.FindMany(ctx, []string{rotationID}, nil)
	if err != nil || len(rotations) != 1 {
		t.Fatalf("FindMany rotations = %d, %v", len(rotations), err)
	}
	assertOwner("rotation FindMany", rotations[0].OrganizationID)
	policies, err := policyStore.FindManyPolicies(ctx, []string{policyID}, nil)
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
	userSchedules, err := scheduleStore.FindManyByUserID(ctx, db, uuid.NullUUID{UUID: userID, Valid: true}, nil)
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
	policies, err = policyStore.FindAllPoliciesBySchedule(ctx, scheduleID, nil)
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
	lockedService, err := serviceStore.FindOneForUpdate(ctx, tx, serviceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("service FindOneForUpdate", lockedService.OrganizationID)
	lockedSchedule, err := scheduleStore.FindOneForUpdate(ctx, tx, scheduleID, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("schedule FindOneForUpdate", lockedSchedule.OrganizationID)
	lockedRotation, err := rotationStore.FindRotationForUpdateTx(ctx, tx, rotationID, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("rotation FindOneForUpdate", lockedRotation.OrganizationID)
	lockedPolicy, err := policyStore.FindOnePolicyForUpdateTx(ctx, tx, policyID, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOwner("policy FindOneForUpdate", lockedPolicy.OrganizationID)
}
