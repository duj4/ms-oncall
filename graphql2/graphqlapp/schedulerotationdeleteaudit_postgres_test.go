package graphqlapp_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2/graphqlapp"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestPostgresSRFailureBatch350(t *testing.T) {
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("explicit PostgreSQL opt-in required")
	}
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "all_350", true: "last_adapter_failure"}[fail], func(t *testing.T) {
			h := harness.NewHarness(t, "", "")
			t.Cleanup(h.Close)
			db := h.App().DB()
			if fail {
				_, err := db.Exec(`CREATE FUNCTION sd6_batch_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd6_batch_fail BEFORE INSERT ON schedule_rotation_delete_audit_events FOR EACH ROW EXECUTE FUNCTION sd6_batch_fail()`)
				require.NoError(t, err)
			}
			persisted, released := graphqlapp.SD6FailureBatchForTest(db, 50, 50)
			require.Equal(t, !fail, persisted)
			require.True(t, released)
			total := 0
			for _, table := range []string{"service_delete_audit_events", "user_cmnr_delete_audit_events", "integration_key_delete_audit_events", "escalation_policy_delete_audit_events", "schedule_rotation_delete_audit_events"} {
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
				total += n
			}
			if fail {
				require.Zero(t, total)
			} else {
				require.Equal(t, 350, total)
			}
			persisted, released = graphqlapp.SD6FailureBatchForTest(db, 51, 50)
			require.False(t, persisted)
			require.True(t, released)
			var sr int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM schedule_rotation_delete_audit_events`).Scan(&sr))
			if fail {
				require.Zero(t, sr)
			} else {
				require.Equal(t, 100, sr)
			}
		})
	}
}

func TestPostgresSRSharedJSONBBudgetRollback(t *testing.T) {
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("explicit PostgreSQL opt-in required")
	}
	h := harness.NewHarness(t, "", "")
	t.Cleanup(h.Close)
	err := graphqlapp.SD6AggregateBudgetForTest(t.Context(), h.App().DB())
	require.ErrorIs(t, err, sraudit.ErrCapacity)
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_rotation_delete_audit_events`).Scan(&n))
	require.Zero(t, n)
}
