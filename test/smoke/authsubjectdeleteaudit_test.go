package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/user"
	audit "github.com/target/goalert/user/authsubjectdeleteaudit"
	"github.com/target/goalert/util/log"
)

func asInput(owner, subject string) string {
	return fmt.Sprintf(`{userID:%q,providerID:"SYNTHETIC_AUTH_PROVIDER",subjectID:%q}`, owner, subject)
}
func asSubject(t *testing.T, h *harness.Harness, owner string, cm any) (int64, string) {
	t.Helper()
	subject := uuid.NewString()
	var id int64
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO auth_subjects(user_id,provider_id,subject_id,cm_id) VALUES($1,'SYNTHETIC_AUTH_PROVIDER',$2,$3) RETURNING id`, owner, subject, cm).Scan(&id))
	return id, subject
}
func asCount(t *testing.T, h *harness.Harness, id int64, table string) int {
	t.Helper()
	var n int
	query := `SELECT count(*) FROM auth_subjects WHERE id=$1`
	if table == "audit" {
		query = `SELECT count(*) FROM auth_subject_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`
	}
	require.NoError(t, h.App().DB().QueryRow(query, id).Scan(&n))
	return n
}
func asHTTP(t *testing.T, h *harness.Harness, token, query string, variables map[string]any, trace bool, expectedStatus ...int) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	require.NoError(t, err)
	endpoint := h.URL() + "/api/graphql"
	if trace {
		endpoint += "?trace=1"
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://synthetic.invalid/SYNTHETIC_AUTH_REFERER")
	req.Header.Set("X-Request-ID", "00000000-0000-4000-8000-000000000001")
	req.Header.Set("X-Actor-ID", "00000000-0000-4000-8000-000000000002")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	status := http.StatusOK
	if len(expectedStatus) == 1 {
		status = expectedStatus[0]
	}
	require.Equal(t, status, response.StatusCode)
	var result map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
	return result
}

// Observe the actual app logger, including the enclosing access logger. Raw
// log records are forwarded to the harness, never copied into evidence.
type asLogCanary struct {
	next                       io.Writer
	private                    []string
	leaked, mutation, complete atomic.Bool
}

func (w *asLogCanary) Write(p []byte) (int, error) {
	for _, v := range w.private {
		if v != "" && bytes.Contains(p, []byte(v)) {
			w.leaked.Store(true)
		}
	}
	if bytes.Contains(p, []byte(`Mutation.`)) {
		w.mutation.Store(true)
	}
	if bytes.Contains(p, []byte(`request complete`)) {
		w.complete.Store(true)
	}
	return w.next.Write(p)
}

func TestAuthSubjectDeleteSignedHTTP(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	for _, tc := range []struct {
		actor, target string
		allowed       bool
	}{
		{"pam", "aowner", true}, {"pam", "b", true}, {"paa", "b", true}, {"pam", "pd0", true},
		{"om", "om", false}, {"om", "b", false}, {"oa", "oa", false}, {"oa", "b", false},
		{"pd0", "b", true}, {"pd0", "pd0", false}, {"pd0", "missing", false}, {"od", "b", false},
	} {
		t.Run(tc.actor+"_"+tc.target, func(t *testing.T) {
			owner := h.UUID(tc.target)
			if tc.target == "missing" {
				owner = uuid.NewString()
			}
			var id int64
			subject := uuid.NewString()
			if tc.target != "missing" {
				id, subject = asSubject(t, h, owner, nil)
			}
			r := asHTTP(t, h, f.tokens[tc.actor], `mutation{deleteAuthSubject(input:`+asInput(owner, subject)+`)}`, nil, false)
			if !tc.allowed {
				require.NotEmpty(t, r["errors"])
				if tc.target != "missing" {
					require.Equal(t, 1, asCount(t, h, id, "business"))
					require.Zero(t, asCount(t, h, id, "audit"))
				}
				return
			}
			require.Empty(t, r["errors"])
			require.JSONEq(t, `{"deleteAuthSubject":true}`, string(r["data"]))
			require.Zero(t, asCount(t, h, id, "business"))
			require.Equal(t, 1, asCount(t, h, id, "audit"))
			var actor, home, actualOwner, targetResolution string
			require.NoError(t, h.App().DB().QueryRow(`SELECT actor_id,home_organization_id,root_owner_user_id,target_org_resolution FROM auth_subject_delete_audit_events WHERE root_id=$1`, id).Scan(&actor, &home, &actualOwner, &targetResolution))
			require.Equal(t, h.UUID(tc.actor), actor)
			require.Equal(t, owner, actualOwner)
			var requestID string
			require.NoError(t, h.App().DB().QueryRow(`SELECT request_id FROM auth_subject_delete_audit_events WHERE root_id=$1`, id).Scan(&requestID))
			require.NotEqual(t, "00000000-0000-4000-8000-000000000001", requestID)
			if tc.actor == "pd0" {
				require.NotEqual(t, home, h.UUID("s2-org-a"))
				require.Equal(t, "known_normal", targetResolution)
			}
			r = asHTTP(t, h, f.tokens[tc.actor], `mutation{deleteAuthSubject(input:`+asInput(owner, subject)+`)}`, nil, false)
			require.Empty(t, r["errors"])
			require.Equal(t, 1, asCount(t, h, id, "audit"))
		})
	}
	// One signed HTTP execution, two aliases, separate field transactions.
	owner := h.UUID("b")
	id, subject := asSubject(t, h, owner, nil)
	r := asHTTP(t, h, f.tokens["pam"], `mutation{a:deleteAuthSubject(input:`+asInput(owner, subject)+`) b:deleteAuthSubject(input:`+asInput(owner, subject)+`)}`, nil, false)
	require.Empty(t, r["errors"])
	require.JSONEq(t, `{"a":true,"b":true}`, string(r["data"]))
	require.Equal(t, 1, asCount(t, h, id, "audit"))
	// Wrong owner is still a true no-op for Normal PA; the actual row survives.
	id, subject = asSubject(t, h, owner, nil)
	r = asHTTP(t, h, f.tokens["pam"], `mutation{deleteAuthSubject(input:`+asInput(h.UUID("aowner"), subject)+`)}`, nil, false)
	require.Empty(t, r["errors"])
	require.Equal(t, 1, asCount(t, h, id, "business"))
	require.Zero(t, asCount(t, h, id, "audit"))
	// Missing assignment does not acquire a new Normal-only authorization rule.
	u := sd7User(t, h)
	id, subject = asSubject(t, h, u, nil)
	r = asHTTP(t, h, f.tokens["pam"], `mutation{deleteAuthSubject(input:`+asInput(u, subject)+`)}`, nil, false)
	require.Empty(t, r["errors"])
	var resolution string
	require.NoError(t, h.App().DB().QueryRow(`SELECT target_org_resolution FROM auth_subject_delete_audit_events WHERE root_id=$1`, id).Scan(&resolution))
	require.Equal(t, "unknown", resolution)
	for _, credential := range []string{"", "SYNTHETIC_INVALID_SESSION"} {
		id, subject := asSubject(t, h, owner, nil)
		body, _ := json.Marshal(map[string]string{"query": `mutation{deleteAuthSubject(input:` + asInput(owner, subject) + `)}`})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if credential != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: credential})
		}
		response, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, response.StatusCode)
		require.NoError(t, response.Body.Close())
		require.Equal(t, 1, asCount(t, h, id, "business"))
		require.Zero(t, asCount(t, h, id, "audit"))
	}
}

func TestAuthSubjectDeleteSignedPrivacyAndAtomicFailure(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	l := log.FromContext(h.App().Context(context.Background()))
	original := l.Logrus().Out
	canary := &asLogCanary{next: original, private: []string{"SYNTHETIC_AUTH_PROVIDER", "SYNTHETIC_AUTH_SUBJECT", "SYNTHETIC_AUTH_ALIAS", "SYNTHETIC_AUTH_OPERATION", "SYNTHETIC_AUTH_REFERER", "AuthSource"}}
	for _, session := range f.sessions {
		canary.private = append(canary.private, session)
	}
	l.EnableDebug()
	l.SetOutput(canary)
	defer l.SetOutput(original)
	owner := h.UUID("b")
	subject := "SYNTHETIC_AUTH_SUBJECT"
	var id int64
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO auth_subjects(user_id,provider_id,subject_id) VALUES($1,'SYNTHETIC_AUTH_PROVIDER',$2) RETURNING id`, owner, subject).Scan(&id))
	query := `mutation SYNTHETIC_AUTH_OPERATION($input:AuthSubjectInput!){SYNTHETIC_AUTH_ALIAS:deleteAuthSubject(input:$input)}`
	variables := map[string]any{"input": map[string]any{"userID": owner, "providerID": "SYNTHETIC_AUTH_PROVIDER", "subjectID": subject}}
	r := asHTTP(t, h, f.tokens["pam"], query, variables, true)
	require.Empty(t, r["errors"])
	if bytes.Contains(r["extensions"], []byte(`tracing`)) {
		t.Fatal("private operation tracing was retained")
	}
	require.Eventually(t, func() bool { return canary.mutation.Load() && canary.complete.Load() }, time.Second, 10*time.Millisecond)
	require.False(t, canary.leaked.Load(), "private log canary leaked; sample withheld")
	mixed := asHTTP(t, h, f.tokens["pam"], `mutation{deleteAll(input:[]) SYNTHETIC_AUTH_ALIAS:deleteAuthSubject(input:`+asInput(owner, "missing")+`)}`, nil, true)
	require.Empty(t, mixed["errors"])
	require.False(t, canary.leaked.Load(), "mixed-operation diagnostic canary leaked; sample withheld")
	badInput := asHTTP(t, h, f.tokens["pam"], `mutation{SYNTHETIC_AUTH_ALIAS:deleteAuthSubject(input:{userID:"`+owner+`",providerID:"SYNTHETIC_AUTH_PROVIDER",subjectID:"SYNTHETIC_AUTH_SUBJECT",actorID:"forged"})}`, nil, true, http.StatusUnprocessableEntity)
	require.NotEmpty(t, badInput["errors"])
	require.False(t, canary.leaked.Load(), "pre-execution diagnostic canary leaked; sample withheld")
	var before string
	require.NoError(t, h.App().DB().QueryRow(`SELECT before_context::text FROM auth_subject_delete_audit_events WHERE root_id=$1`, id).Scan(&before))
	require.NotContains(t, before, "SYNTHETIC")
	for _, mode := range []string{"audit", "delete", "reinsert", "suppress"} {
		t.Run(mode, func(t *testing.T) {
			id, subject := asSubject(t, h, owner, nil)
			body := `RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SYNTHETIC_AUTH_SUBJECT';`
			table := "auth_subjects"
			event := "DELETE"
			timing := "BEFORE"
			if mode == "audit" {
				table = "auth_subject_delete_audit_events"
				event = "INSERT"
				body = `IF NEW.record_kind='success_witness' THEN ` + body + ` END IF; RETURN NEW;`
			}
			if mode == "suppress" {
				body = `RETURN NULL;`
			}
			if mode == "reinsert" {
				timing = "AFTER"
				body = `INSERT INTO auth_subjects(id,user_id,provider_id,subject_id,cm_id) VALUES(OLD.id,OLD.user_id,OLD.provider_id,OLD.subject_id,OLD.cm_id); RETURN OLD;`
			}
			sd8Exec(t, h, `CREATE FUNCTION as_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$`)
			sd8Exec(t, h, `CREATE TRIGGER as_test_fault `+timing+` `+event+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION as_test_fault()`)
			expected := func() {}
			if mode != "suppress" {
				expected = h.ExpectBackendError("auth_subject.delete transaction failed")
			}
			r := asHTTP(t, h, f.tokens["pam"], `mutation{SYNTHETIC_AUTH_ALIAS:deleteAuthSubject(input:`+asInput(owner, subject)+`)}`, nil, true)
			expected()
			if mode == "suppress" {
				require.Empty(t, r["errors"])
			} else {
				require.NotEmpty(t, r["errors"])
				reason := "delete_failed"
				if mode == "audit" {
					reason = "audit_write_failed"
				}
				if mode == "reinsert" {
					reason = "postcheck_failed"
				}
				var count int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM auth_subject_delete_audit_events WHERE record_kind='attempt_observation' AND reason_code=$1`, reason).Scan(&count))
				require.Equal(t, 1, count, "one durable failure observation after business release")
			}
			require.Equal(t, 1, asCount(t, h, id, "business"))
			require.Zero(t, asCount(t, h, id, "audit"))
			require.False(t, canary.leaked.Load(), "private log canary leaked; sample withheld")
			sd8Exec(t, h, `DROP TRIGGER as_test_fault ON `+table)
			sd8Exec(t, h, `DROP FUNCTION as_test_fault()`)
		})
	}
	// Denial selects redaction by actual schema field, even with a private alias.
	t.Run("capture", func(t *testing.T) {
		id, subject := asSubject(t, h, owner, nil)
		sd8Exec(t, h, `ALTER TABLE auth_subjects RENAME TO as_capture_fault`)
		restored := false
		defer func() {
			if !restored {
				sd8Exec(t, h, `ALTER TABLE as_capture_fault RENAME TO auth_subjects`)
			}
		}()
		expected := h.ExpectBackendError("auth_subject.delete transaction failed")
		r := asHTTP(t, h, f.tokens["pam"], `mutation{SYNTHETIC_AUTH_ALIAS:deleteAuthSubject(input:`+asInput(owner, subject)+`)}`, nil, true)
		expected()
		require.NotEmpty(t, r["errors"])
		sd8Exec(t, h, `ALTER TABLE as_capture_fault RENAME TO auth_subjects`)
		restored = true
		require.Equal(t, 1, asCount(t, h, id, "business"))
		require.Zero(t, asCount(t, h, id, "audit"))
		var count int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM auth_subject_delete_audit_events WHERE record_kind='attempt_observation' AND reason_code='capture_failed'`).Scan(&count))
		require.Equal(t, 1, count)
		require.False(t, canary.leaked.Load(), "capture-failure diagnostic canary leaked; sample withheld")
	})
	r = asHTTP(t, h, f.tokens["oa"], `mutation{SYNTHETIC_AUTH_ALIAS:deleteAuthSubject(input:`+asInput(owner, "not-present")+`)}`, nil, true)
	require.NotEmpty(t, r["errors"])
	require.False(t, canary.leaked.Load(), "private log canary leaked; sample withheld")
}

func TestAuthSubjectDeleteSystemRealBigintAndRollback(t *testing.T) {
	h := sd1Harness(t)
	a := sd7App(h)
	ctx := permission.SystemContext(t.Context(), "Engine")
	owner := sd7User(t, h)
	zero := uuid.Nil.String()
	sd8Exec(t, h, `INSERT INTO users(id,name,email) VALUES($1,'Synthetic zero identity','')`, zero)
	sd8Exec(t, h, `INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES($1,$1,'Synthetic zero CM','EMAIL','synthetic@example.invalid')`, zero)
	zeroID, zeroSubject := asSubject(t, h, zero, zero)
	zeroOK, zeroErr := a.Mutation().DeleteAuthSubject(ctx, user.AuthSubject{UserID: zero, ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: zeroSubject})
	require.NoError(t, zeroErr)
	require.True(t, zeroOK)
	require.Equal(t, 1, asCount(t, h, zeroID, "audit"))
	for _, id := range []int64{-9223372036854775808, -1, 0, 9007199254740993, 9223372036854775807} {
		subject := uuid.NewString()
		sd8Exec(t, h, `INSERT INTO auth_subjects(id,user_id,provider_id,subject_id) VALUES($1,$2,'SYNTHETIC_AUTH_PROVIDER',$3)`, id, owner, subject)
		ok, err := a.Mutation().DeleteAuthSubject(ctx, user.AuthSubject{UserID: strings.ToUpper(owner), ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: subject})
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, 1, asCount(t, h, id, "audit"))
		require.Zero(t, asCount(t, h, id, "business"))
		var beforeID string
		require.NoError(t, h.App().DB().QueryRow(`SELECT before_context->>'id' FROM auth_subject_delete_audit_events WHERE root_id=$1`, id).Scan(&beforeID))
		require.Equal(t, fmt.Sprint(id), beforeID)
	}
}

func TestAuthSubjectDeleteRealStoreStageAndRecreation(t *testing.T) {
	h := sd1Harness(t)
	ctx := permission.SystemContext(t.Context(), "Engine")
	db := h.App().DB()
	owner := sd7User(t, h)
	id, subject := asSubject(t, h, owner, nil)
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := audit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), Operation: "auth_subject.delete", RootType: "auth_subject", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", TargetOrgResolution: "unknown", OccurredAt: now, RecordedAt: now}
	input := user.AuthSubject{UserID: owner, ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: subject}
	_, err := h.App().UserStore.DeleteAuthSubjectTx(ctx, nil, &input, e)
	require.Error(t, err)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)`)
	require.NoError(t, err)
	result, err := h.App().UserStore.DeleteAuthSubjectTx(ctx, tx, &input, e)
	require.NoError(t, err)
	require.Equal(t, 1, result.DeletedCount)
	require.NoError(t, audit.AppendReceipt(ctx, tx, result.Receipt, e))
	require.Equal(t, 1, asCount(t, h, id, "business"))
	require.Zero(t, asCount(t, h, id, "audit"), "staged evidence is not yet durable")
	require.Error(t, audit.AppendReceipt(ctx, tx, result.Receipt, e), "receipt can be consumed only once")
	require.NoError(t, tx.Rollback())
	require.Equal(t, 1, asCount(t, h, id, "business"))
	require.Zero(t, asCount(t, h, id, "audit"))
	// Independently enforce both existing PK and bigint UNIQUE constraints.
	_, err = db.ExecContext(ctx, `INSERT INTO auth_subjects(user_id,provider_id,subject_id) VALUES($1,'SYNTHETIC_AUTH_PROVIDER',$2)`, owner, subject)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO auth_subjects(id,user_id,provider_id,subject_id) VALUES($1,$2,'SYNTHETIC_AUTH_PROVIDER',$3)`, id, owner, uuid.NewString())
	require.Error(t, err)
	a := sd7App(h)
	ok, err := a.Mutation().DeleteAuthSubject(ctx, input)
	require.NoError(t, err)
	require.True(t, ok)
	var newID int64
	require.NoError(t, db.QueryRow(`INSERT INTO auth_subjects(user_id,provider_id,subject_id) VALUES($1,'SYNTHETIC_AUTH_PROVIDER',$2) RETURNING id`, owner, subject).Scan(&newID))
	require.NotEqual(t, id, newID)
	ok, err = a.Mutation().DeleteAuthSubject(ctx, input)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, asCount(t, h, id, "audit"))
	require.Equal(t, 1, asCount(t, h, newID, "audit"))
	_, err = a.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: owner}})
	require.NoError(t, err)
	require.Equal(t, 1, asCount(t, h, id, "audit"), "live owner deletion must preserve historical roots")
}

func TestAuthSubjectDeleteSignedMixedFields(t *testing.T) {
	for _, mode := range []string{"a_user", "user_a", "a_cm", "cm_a"} {
		t.Run(mode, func(t *testing.T) {
			f := globalOrganizationFixture(t)
			h := f.h
			owner := h.UUID("b")
			cm := h.UUID("cm-b")
			id, subject := asSubject(t, h, owner, cm)
			typ, parentID := "user", owner
			if strings.Contains(mode, "cm") {
				typ, parentID = "contactMethod", cm
			}
			a := `a:deleteAuthSubject(input:` + asInput(owner, subject) + `)`
			parent := fmt.Sprintf(`p:deleteAll(input:[{type:%s,id:%q}])`, typ, parentID)
			query := `mutation{` + a + ` ` + parent + `}`
			if strings.HasSuffix(mode, "_a") {
				query = `mutation{` + parent + ` ` + a + `}`
			}
			r := asHTTP(t, h, f.tokens["pam"], query, nil, false)
			require.Empty(t, r["errors"])
			require.JSONEq(t, `{"a":true,"p":true}`, string(r["data"]))
			explicit := 1
			if strings.HasSuffix(mode, "_a") {
				explicit = 0
			}
			require.Equal(t, explicit, asCount(t, h, id, "audit"))
			require.Zero(t, asCount(t, h, id, "business"))
		})
	}
}
