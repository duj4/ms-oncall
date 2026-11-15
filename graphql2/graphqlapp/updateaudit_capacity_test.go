package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/gadb"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

// This uses the existing deterministic database/sql transaction model. No
// PostgreSQL access or claim of new native rollback evidence is involved.
func TestUpdateAuditExactCapacityRollsBack(t *testing.T) {
	for _, operation := range []string{epaudit.PolicyUpdate, epaudit.StepUpdate, sraudit.ScheduleTargetUpdate} {
		t.Run(operation, func(t *testing.T) {
			s := &sd2State{}
			var connector driver.Connector = sd2Connector{s}
			if operation == sraudit.ScheduleTargetUpdate {
				connector = scheduleTargetLifecycleConnector{s}
			}
			db := sql.OpenDB(connector)
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			ctx := sd3InternalSystemContext()
			var err error
			if operation == sraudit.ScheduleTargetUpdate {
				e := scheduleTargetUpdateTestEvent(ctx)
				f := scheduleTargetUpdateTestEffect(t, e)
				for range 14900 {
					id := uuid.New()
					f.ResourceUUID, f.EffectID = &id, uuid.New()
					e.Effects = append(e.Effects, f)
				}
				require.Less(t, e.JSONBytes(), sraudit.MaxJSONBytes)
				success := e
				success.RecordKind, success.Outcome, success.Reason, success.Provenance, success.DeletionMechanism, success.Cause = "success_witness", "committed", "children_deleted", "EXPLICIT", "explicit_sql", "update_induced"
				require.ErrorIs(t, success.Validate(), sraudit.ErrCapacity)
				err = withScheduleTargetUpdateAuditTx(ctx, db, &e, func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "SD2 synthetic delete")
					return err
				})
			} else {
				e := epUpdateTestEvent(ctx)
				e.Operation = operation
				parent, count, cascade := e.RootID, 14848, false
				if operation == epaudit.PolicyUpdate {
					e.ParentPolicyID = uuid.Nil
					parent, count, cascade = uuid.New(), 14600, true
					n := 0
					e.Effects = []epaudit.Effect{{EffectID: uuid.New(), ResourceType: epaudit.Step, ResourceUUID: &parent, StepNumber: &n,
						RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: "escalation_policy.step", Change: "deleted",
						Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced"}}
				}
				for range count {
					r := gadb.EPStepActionsDeleteReceiptRow{ID: uuid.New(), EscalationPolicyStepID: parent, UserID: uuid.NullUUID{UUID: uuid.New(), Valid: true}}
					if cascade {
						r.ChannelID, r.UserID = r.UserID, uuid.NullUUID{}
					}
					f, err := epUpdateActionEffect(e, r, cascade)
					require.NoError(t, err)
					e.Effects = append(e.Effects, f)
				}
				raw, marshalErr := json.Marshal(e.Canonical().Effects)
				require.NoError(t, marshalErr)
				require.Less(t, len(raw), epaudit.MaxJSONBytes)
				success := e
				success.RecordKind, success.Outcome, success.Reason, success.Provenance, success.DeletionMechanism, success.Cause = "success_witness", "committed", "children_deleted", "EXPLICIT", "explicit_sql", "update_induced"
				require.ErrorIs(t, success.Validate(), epaudit.ErrCapacity)
				err = withEPUpdateAuditTx(ctx, db, &e, func(ctx context.Context, tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "SD2 synthetic delete")
					return err
				})
			}
			require.Error(t, err)
			require.Equal(t, 1, s.deletes, "business operation ran once")
			require.Zero(t, s.commits, "capacity rejection cannot commit the business transaction")
			require.Zero(t, s.witnesses)
			require.Equal(t, 1, s.observations, "empty failure observation still persists after release")
			require.Zero(t, db.Stats().InUse)
		})
	}
}

// This small driver models only ON CONFLICT/ROW equality for the real Writers.
// It compares every actual bound value, including canonical Effects bytes.
type capacityReplayConn struct {
	stored  []driver.NamedValue
	queries int
}
type capacityReplayConnector struct{ conn *capacityReplayConn }

func (c capacityReplayConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (capacityReplayConnector) Driver() driver.Driver                          { return sd2Driver{} }
func (*capacityReplayConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*capacityReplayConn) Close() error              { return nil }
func (*capacityReplayConn) Begin() (driver.Tx, error) { return &sd2Tx{s: &sd2State{}}, nil }
func (c *capacityReplayConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(query, "ON CONFLICT(event_id) DO NOTHING") {
		return nil, errors.New("unexpected write")
	}
	if c.stored != nil {
		return driver.RowsAffected(0), nil
	}
	c.stored = slices.Clone(args)
	return driver.RowsAffected(1), nil
}
func (c *capacityReplayConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "IS NOT DISTINCT FROM ROW(") {
		return nil, errors.New("unexpected query")
	}
	c.queries++
	return &capacityReplayRows{same: reflect.DeepEqual(c.stored, args)}, nil
}

type capacityReplayRows struct{ same, done bool }

func (*capacityReplayRows) Columns() []string { return []string{"same"} }
func (*capacityReplayRows) Close() error      { return nil }
func (r *capacityReplayRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done, values[0] = true, r.same
	return nil
}

func TestUpdateAuditExactCapacityWriterReplay(t *testing.T) {
	for _, operation := range []string{epaudit.PolicyUpdate, epaudit.StepUpdate, sraudit.ScheduleTargetUpdate} {
		t.Run(operation, func(t *testing.T) {
			c := &capacityReplayConn{}
			db := sql.OpenDB(capacityReplayConnector{c})
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			ctx := sd3InternalSystemContext()
			if operation == sraudit.ScheduleTargetUpdate {
				e := scheduleTargetUpdateTestEvent(ctx)
				e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "success_witness", "committed", "children_deleted", "EXPLICIT", "explicit_sql", "update_induced"
				e.Effects = []sraudit.Effect{scheduleTargetUpdateTestEffect(t, e)}
				f := e.Effects[0]
				id := uuid.New()
				f.EffectID, f.ResourceUUID = uuid.New(), &id
				e.Effects = append(e.Effects, f)
				require.NoError(t, sraudit.Append(ctx, tx, e))
				slices.Reverse(e.Effects)
				require.NoError(t, sraudit.Append(ctx, tx, e))
				e.Effects[0].EffectID = uuid.New()
				require.ErrorIs(t, sraudit.Append(ctx, tx, e), sraudit.ErrConflict)
			} else {
				e := epUpdateTestEvent(ctx)
				e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "success_witness", "committed", "children_deleted", "EXPLICIT", "explicit_sql", "update_induced"
				f := epUpdateTestEffect(t, e)
				if operation == epaudit.PolicyUpdate {
					e.Operation, e.ParentPolicyID = operation, uuid.Nil
					n := 0
					step := epaudit.Effect{EffectID: uuid.New(), ResourceType: epaudit.Step, ResourceUUID: f.ParentStepID, StepNumber: &n,
						RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: "escalation_policy.step", Change: "deleted",
						Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced"}
					e.Effects = append(e.Effects, step)
					f.Provenance, f.DeletionMechanism, f.Cause = "CASCADE", "fk_cascade", "step_delete"
				} else {
					e.Effects = append(e.Effects, epUpdateTestEffect(t, e))
				}
				e.Effects = append(e.Effects, f)
				require.NoError(t, epaudit.Append(ctx, tx, e))
				slices.Reverse(e.Effects)
				require.NoError(t, epaudit.Append(ctx, tx, e))
				e.Effects[0].EffectID = uuid.New()
				require.ErrorIs(t, epaudit.Append(ctx, tx, e), epaudit.ErrConflict)
			}
			require.Equal(t, 2, c.queries)
		})
	}
}
