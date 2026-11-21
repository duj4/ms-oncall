package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/util/timeutil"
)

// A deliberately bounded database/sql model of the real resolver and Stores.
// It exercises statement order, receipts and transaction ownership, not native
// PostgreSQL locks, FKs, trigger execution or SQL semantic correctness.
type u03ModelRule struct {
	id, schedule, user, rotation string
	start, end, days             string
	created                      int
}
type u03Model struct {
	schedule, org                       string
	rules                               []u03ModelRule
	events                              [][]driver.NamedValue
	queries                             []string
	begins, commits, rollbacks, deletes int
	failAudit, failInsert, zeroReceipt  bool
	failRead                            bool
	beforeChildLock                     func(*u03ModelTx)
}
type u03ModelConnector struct{ model *u03Model }

func (c u03ModelConnector) Connect(context.Context) (driver.Conn, error) {
	return &u03ModelConn{m: c.model}, nil
}
func (u03ModelConnector) Driver() driver.Driver { return sd2Driver{} }

type u03ModelConn struct {
	m  *u03Model
	tx *u03ModelTx
}

func (c *u03ModelConn) Prepare(q string) (driver.Stmt, error) { return &u03ModelStmt{c, q}, nil }
func (*u03ModelConn) Close() error                            { return nil }
func (c *u03ModelConn) Begin() (driver.Tx, error) {
	c.m.begins++
	c.tx = &u03ModelTx{m: c.m, rules: slices.Clone(c.m.rules)}
	return c.tx, nil
}

type u03ModelTx struct {
	m        *u03Model
	rules    []u03ModelRule
	events   [][]driver.NamedValue
	readOnly bool
}

func (tx *u03ModelTx) Commit() error {
	tx.m.commits++
	tx.m.rules = slices.Clone(tx.rules)
	tx.m.events = append(tx.m.events, tx.events...)
	return nil
}
func (tx *u03ModelTx) Rollback() error { tx.m.rollbacks++; return nil }

type u03ModelStmt struct {
	c *u03ModelConn
	q string
}

func (*u03ModelStmt) Close() error  { return nil }
func (*u03ModelStmt) NumInput() int { return -1 }
func modelArgs(values []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(values))
	for i, v := range values {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}
func (s *u03ModelStmt) Exec(v []driver.Value) (driver.Result, error) {
	return s.c.ExecContext(context.Background(), s.q, modelArgs(v))
}
func (s *u03ModelStmt) Query(v []driver.Value) (driver.Rows, error) {
	return s.c.QueryContext(context.Background(), s.q, modelArgs(v))
}

type u03ModelRows struct {
	cols    int
	values  [][]driver.Value
	lateErr error
}

func (r *u03ModelRows) Columns() []string { return make([]string, r.cols) }
func (*u03ModelRows) Close() error        { return nil }
func (r *u03ModelRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		if r.lateErr != nil {
			return r.lateErr
		}
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}
func modelRows(cols int, values ...[]driver.Value) driver.Rows {
	return &u03ModelRows{cols: cols, values: values}
}
func compactSQL(q string) string { return strings.ToLower(strings.Join(strings.Fields(q), " ")) }
func (c *u03ModelConn) QueryContext(_ context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	q = compactSQL(q)
	c.m.queries = append(c.m.queries, q)
	if rows, handled, err := c.updateSafetyQuery(q, a); handled {
		return rows, err
	}
	switch {
	case strings.Contains(q, "from schedules"):
		return modelRows(5, []driver.Value{c.m.schedule, c.m.org, "Synthetic Schedule", "", "Etc/UTC"}), nil
	case strings.HasPrefix(q, "select id from schedule_rules"):
		if !strings.Contains(q, "order by id for update") {
			return nil, errors.New("missing ordered child lock")
		}
		if c.m.beforeChildLock != nil {
			c.m.beforeChildLock(c.tx)
		}
		var out [][]driver.Value
		for _, r := range c.tx.rules {
			if r.schedule == a[0].Value {
				out = append(out, []driver.Value{r.id})
			}
		}
		return modelRows(1, out...), nil
	case strings.HasPrefix(q, "select") && strings.Contains(q, "from schedule_rules"):
		if !strings.HasSuffix(q, "order by created_at, id") {
			return nil, errors.New("changed positional order")
		}
		var selected []u03ModelRule
		for _, r := range c.tx.rules {
			if r.schedule == a[0].Value && (r.user != "" && r.user == a[1].Value || r.rotation != "" && r.rotation == a[2].Value) {
				selected = append(selected, r)
			}
		}
		slices.SortFunc(selected, func(a, b u03ModelRule) int {
			if a.created < b.created {
				return -1
			}
			if a.created > b.created {
				return 1
			}
			return strings.Compare(a.id, b.id)
		})
		var out [][]driver.Value
		for _, r := range selected {
			var u, rot driver.Value
			if r.user != "" {
				u = r.user
			}
			if r.rotation != "" {
				rot = r.rotation
			}
			out = append(out, []driver.Value{r.id, r.schedule, r.days, r.start, r.end, u, rot})
		}
		if c.m.failRead {
			return &u03ModelRows{cols: 7, values: out, lateErr: errors.New("synthetic interrupted read")}, nil
		}
		return modelRows(7, out...), nil
	case strings.HasPrefix(q, "delete from schedule_rules"):
		if !strings.Contains(q, "returning id,schedule_id,tgt_user_id,tgt_rotation_id") || !strings.Contains(q, "and schedule_id=$2 and (tgt_user_id=$3 or tgt_rotation_id=$4)") {
			return nil, errors.New("missing scoped RETURNING")
		}
		c.m.deletes++
		var ids pq.StringArray
		if err := ids.Scan(a[0].Value); err != nil {
			return nil, err
		}
		var out [][]driver.Value
		retained := make([]u03ModelRule, 0, len(c.tx.rules))
		for _, r := range c.tx.rules {
			if !c.m.zeroReceipt && slices.Contains(ids, r.id) && r.schedule == a[1].Value && (r.user != "" && r.user == a[2].Value || r.rotation != "" && r.rotation == a[3].Value) {
				var u, rot driver.Value
				if r.user != "" {
					u = r.user
				}
				if r.rotation != "" {
					rot = r.rotation
				}
				out = append(out, []driver.Value{r.id, r.schedule, u, rot})
			} else {
				retained = append(retained, r)
			}
		}
		c.tx.rules = retained
		return modelRows(4, out...), nil
	}
	return nil, errors.New("unexpected model query")
}
func (c *u03ModelConn) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	q = compactSQL(q)
	c.m.queries = append(c.m.queries, q)
	switch {
	case strings.HasPrefix(q, "update schedule_rules"):
		for i := range c.tx.rules {
			if c.tx.rules[i].id == a[0].Value {
				c.tx.rules[i].start = a[3].Value.(string)
				c.tx.rules[i].end = a[4].Value.(string)
			}
		}
	case strings.HasPrefix(q, "insert into schedule_rules"):
		if c.m.failInsert {
			return nil, errors.New("SYNTHETIC_INSERT_FAILURE")
		}
		r := u03ModelRule{id: a[0].Value.(string), schedule: a[1].Value.(string), days: "{t,t,t,t,t,t,t}", start: a[3].Value.(string), end: a[4].Value.(string), created: 100}
		if a[5].Value != nil {
			r.user = a[5].Value.(string)
		}
		if a[6].Value != nil {
			r.rotation = a[6].Value.(string)
		}
		c.tx.rules = append(c.tx.rules, r)
	case strings.HasPrefix(q, "insert into schedule_rotation_delete_audit_events"):
		if c.m.failAudit && a[5].Value == "success_witness" {
			return nil, errors.New("SYNTHETIC_AUDIT_FAILURE")
		}
		if a[5].Value == "attempt_observation" && a[22].Value != "[]" {
			return nil, errors.New("failure has effects")
		}
		c.tx.events = append(c.tx.events, slices.Clone(a))
	default:
		return nil, errors.New("unexpected model exec")
	}
	return driver.RowsAffected(1), nil
}

func newU03Model(t *testing.T, kind string, n int) (*u03Model, *Mutation, context.Context, assignment.RawTarget) {
	t.Helper()
	s := &u03Model{schedule: uuid.NewString(), org: uuid.NewString()}
	target := assignment.RawTarget{ID: uuid.NewString(), Type: assignment.TargetTypeUser}
	if kind == "rotation" {
		target.Type = assignment.TargetTypeRotation
	}
	for i := range n {
		r := u03ModelRule{id: uuid.NewString(), schedule: s.schedule, days: "{t,t,t,t,t,t,t}", start: "00:00:00", end: "00:00:00", created: i}
		if kind == "user" {
			r.user = target.ID
		} else {
			r.rotation = target.ID
		}
		s.rules = append(s.rules, r)
	}
	db := sql.OpenDB(u03ModelConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	ctx := sd3InternalSystemContext()
	rs, err := rule.NewStore(ctx, db)
	require.NoError(t, err)
	ss, err := schedule.NewStore(ctx, db, nil)
	require.NoError(t, err)
	return s, (*Mutation)(&App{DB: db, RuleStore: rs, ScheduleStore: ss, PreviewSigner: previewTestSigner{}}), ctx, target
}

func TestScheduleTargetUpdateRealResolverRuleMatrix(t *testing.T) {
	for _, kind := range []string{"user", "rotation"} {
		for _, tc := range []struct {
			name                string
			existing, requested int
			changed             bool
		}{
			{"identical", 3, 3, false}, {"same_count_changed", 3, 3, true}, {"remove_one", 3, 2, false}, {"remove_multiple", 4, 1, false}, {"clear", 3, 0, false}, {"empty_noop", 0, 0, false}, {"insert", 1, 3, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				s, m, ctx, target := newU03Model(t, kind, tc.existing)
				before := slices.Clone(s.rules)
				// Reverse physical enumeration. Positional semantics use created_at,id.
				slices.Reverse(s.rules)
				inputs := make([]graphql2.ScheduleRuleInput, tc.requested)
				for i := range inputs {
					fakeID := uuid.NewString()
					inputs[i].ID = &fakeID
					if tc.changed {
						start := timeutil.Clock(8 * time.Hour)
						inputs[i].Start = &start
					}
				}
				ok, err := runU03ModelUpdate(t, s, m, ctx, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target, Rules: inputs})
				require.NoError(t, err)
				require.True(t, ok)
				require.Len(t, s.rules, tc.requested)
				for i := 0; i < min(tc.existing, tc.requested); i++ {
					require.True(t, slices.ContainsFunc(s.rules, func(r u03ModelRule) bool { return r.id == before[i].id }))
				}
				for _, r := range s.rules {
					if !slices.ContainsFunc(before, func(b u03ModelRule) bool { return r.id == b.id }) {
						require.NotEqual(t, uuid.Nil, uuid.MustParse(r.id))
					}
					if tc.changed {
						require.Equal(t, "08:00", r.start)
					}
				}
				if tc.requested >= tc.existing {
					require.Empty(t, s.events)
					require.Zero(t, s.deletes)
				} else {
					require.Len(t, s.events, 1)
					e := s.events[0]
					require.Equal(t, "schedule", e[23].Value)
					require.Equal(t, "updateScheduleTarget", e[24].Value)
					require.Equal(t, s.schedule, e[6].Value)
					require.Equal(t, s.org, e[7].Value)
					var effects []sraudit.Effect
					require.NoError(t, json.Unmarshal([]byte(e[22].Value.(string)), &effects))
					require.Len(t, effects, tc.existing-tc.requested)
					for _, f := range effects {
						require.True(t, slices.ContainsFunc(before[tc.requested:], func(r u03ModelRule) bool { return r.id == f.ResourceUUID.String() }))
						require.Equal(t, target.ID, f.RuleDeletion.TargetID.String())
						require.Equal(t, kind, f.RuleDeletion.TargetKind)
						require.Equal(t, s.schedule, f.RuleDeletion.ScheduleID.String())
						require.Equal(t, "update_induced", f.Cause)
					}
				}
				require.Equal(t, 1, s.begins)
				require.Equal(t, 1, s.commits)
				lock, read := -1, -1
				for i, q := range s.queries {
					if strings.HasPrefix(q, "select id from schedule_rules") {
						lock = i
					}
					if strings.Contains(q, "order by created_at, id") {
						read = i
					}
				}
				require.Greater(t, read, lock)
				require.Greater(t, lock, 0)
			})
		}
	}
}

func TestScheduleTargetUpdateActualReceiptAndAuditRollback(t *testing.T) {
	for _, mode := range []string{"zero_actual_rows", "audit_failed"} {
		t.Run(mode, func(t *testing.T) {
			s, m, ctx, target := newU03Model(t, "user", 3)
			before := slices.Clone(s.rules)
			s.zeroReceipt = mode == "zero_actual_rows"
			s.failAudit = mode == "audit_failed"
			ok, err := runU03ModelUpdate(t, s, m, ctx, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target})
			require.Equal(t, before, s.rules)
			if s.failAudit {
				require.Error(t, err)
				require.False(t, ok)
				require.Equal(t, 1, s.rollbacks)
				require.Len(t, s.events, 1)
				require.Equal(t, "attempt_observation", s.events[0][5].Value)
				require.Equal(t, "[]", s.events[0][22].Value)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Len(t, s.events, 1)
				require.Equal(t, "attempt_observation", s.events[0][5].Value)
			}
		})
	}
}

func TestScheduleTargetUpdateInheritedDestructiveFailsClosed(t *testing.T) {
	s, m, ctx, target := newU03Model(t, "user", 3)
	before := slices.Clone(s.rules)
	err := withContextTx(ctx, m.DB, func(inner context.Context, tx *sql.Tx) error {
		ok, err := m.UpdateScheduleTarget(inner, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target})
		require.Error(t, err)
		require.False(t, ok)
		return err
	})
	require.Error(t, err)
	require.Equal(t, before, s.rules)
	require.Zero(t, s.deletes)
	require.Empty(t, s.events)
}

func TestScheduleTargetUpdateCreationConfigurationBoundary(t *testing.T) {
	s, m, ctx, target := newU03Model(t, "user", 0)
	err := withContextTx(ctx, m.DB, func(inner context.Context, tx *sql.Tx) error {
		ok, err := m.configureScheduleTarget(inner, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target, Rules: []graphql2.ScheduleRuleInput{{}}}, nil)
		require.True(t, ok)
		return err
	})
	require.NoError(t, err)
	require.Len(t, s.rules, 1)
	require.Empty(t, s.events)
	require.Equal(t, 1, s.begins)
	require.Equal(t, 1, s.commits)
}

func TestScheduleTargetUpdatePostWaitRuleWriters(t *testing.T) {
	// Controlled model schedules represent the actual independent Store UPDATE,
	// DeleteManyTx and FK-cascade writer shapes. No PG lock evidence is claimed.
	for _, writer := range []string{"retarget_out", "retarget_in", "reparent_out", "delete", "user_or_rotation_cascade"} {
		t.Run(writer, func(t *testing.T) {
			s, m, ctx, target := newU03Model(t, "user", 2)

			if writer == "retarget_in" {
				s.rules[1].user = uuid.NewString()
			}
			before := slices.Clone(s.rules)
			s.beforeChildLock = func(tx *u03ModelTx) {
				switch writer {
				case "retarget_out":
					tx.rules[1].user = uuid.NewString()
				case "retarget_in":
					tx.rules[1].user = target.ID
				case "reparent_out":
					tx.rules[1].schedule = uuid.NewString()
				default:
					tx.rules = tx.rules[:1]
				}
			}
			ok, err := runU03ModelUpdate(t, s, m, ctx, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target})
			require.Error(t, err)
			require.False(t, ok)
			var typed *ds.DeletionSafetyError
			require.ErrorAs(t, err, &typed)
			require.Equal(t, ds.DeletionDependencyChanged, typed.Code)
			require.Equal(t, before, s.rules)
			require.Zero(t, s.deletes)
			require.Len(t, s.events, 1)
			require.Equal(t, "attempt_observation", s.events[0][5].Value)

		})
	}
}

func TestScheduleTargetUpdateInheritedDenialNoIndependentWriter(t *testing.T) {
	s, m, ctx, target := newU03Model(t, "user", 2)
	err := withContextTx(ctx, m.DB, func(inner context.Context, tx *sql.Tx) error {
		denied := permission.ServiceContext(inner, uuid.NewString())
		ok, err := m.UpdateScheduleTarget(denied, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target})
		require.False(t, ok)
		require.Error(t, err)
		return err
	})
	require.Error(t, err)
	require.Equal(t, 1, s.begins)
	require.Zero(t, s.commits)
	require.Equal(t, 1, s.rollbacks)
	require.Empty(t, s.events)
	require.Empty(t, s.queries)
}

func TestScheduleTargetUpdateTieOrderAndOtherCollections(t *testing.T) {
	s, m, ctx, target := newU03Model(t, "user", 3)
	for i := range s.rules {
		s.rules[i].created = 0
	}
	ids := []string{s.rules[0].id, s.rules[1].id, s.rules[2].id}
	slices.Sort(ids)
	otherTarget := s.rules[0]
	otherTarget.id = uuid.NewString()
	otherTarget.user = uuid.NewString()
	otherSchedule := s.rules[0]
	otherSchedule.id = uuid.NewString()
	otherSchedule.schedule = uuid.NewString()
	s.rules = append(s.rules, otherTarget, otherSchedule)
	ok, err := runU03ModelUpdate(t, s, m, ctx, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target, Rules: []graphql2.ScheduleRuleInput{{}}})
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, s.rules, 3)
	require.Contains(t, s.rules, otherTarget)
	require.Contains(t, s.rules, otherSchedule)
	require.True(t, slices.ContainsFunc(s.rules, func(r u03ModelRule) bool { return r.id == ids[0] }))
	var effects []sraudit.Effect
	require.NoError(t, json.Unmarshal([]byte(s.events[0][22].Value.(string)), &effects))
	require.Len(t, effects, 2)
	for _, f := range effects {
		require.Contains(t, ids[1:], f.ResourceUUID.String())
	}
}

func TestScheduleTargetUpdatePartialReadCannotChooseDeletionTail(t *testing.T) {
	s, m, ctx, target := newU03Model(t, "user", 3)
	before := slices.Clone(s.rules)
	s.failRead = true
	ok, err := runU03ModelUpdate(t, s, m, ctx, graphql2.ScheduleTargetInput{ScheduleID: &s.schedule, Target: &target})
	require.Error(t, err)
	require.False(t, ok)
	require.Equal(t, before, s.rules)
	require.Zero(t, s.deletes)
	require.Len(t, s.events, 1)
	require.Equal(t, "attempt_observation", s.events[0][5].Value)
	require.Equal(t, "[]", s.events[0][22].Value)
}
