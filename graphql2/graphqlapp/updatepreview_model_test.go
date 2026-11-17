package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rule"
)

func (c *u03ModelConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Begin()
	if err == nil {
		c.tx.readOnly = options.ReadOnly
	}
	return tx, err
}

// Extend the pre-existing bounded SQL model with the new read-only statements.
// Native tests, rather than this model, prove SQL, locks, FKs and concurrency.
func (c *u03ModelConn) updateSafetyQuery(q string, a []driver.NamedValue) (driver.Rows, bool, error) {
	rows := func(n int, v ...[]driver.Value) (driver.Rows, bool, error) { return modelRows(n, v...), true, nil }
	if strings.HasPrefix(q, "select exists(select from public.organizations") {
		return rows(1, []driver.Value{true})
	}
	if strings.Contains(q, "jsonb_agg(jsonb_build_array(user_id,organization_id,user_role,organization_role)") || strings.Contains(q, "jsonb_agg(jsonb_build_array(id,organization_id,time_zone") {
		return rows(1, []driver.Value{"synthetic-target-state"})
	}
	if strings.HasPrefix(q, "select id::text from public.organizations") || strings.HasPrefix(q, "select organization_id::text from public.normal_organizations") {
		return rows(1, []driver.Value{c.m.org})
	}
	if strings.Contains(q, "current_setting('transaction_read_only')") {
		ro, iso := "off", "read committed"
		if c.tx.readOnly {
			ro, iso = "on", "repeatable read"
		}
		return rows(3, []driver.Value{ro, iso, time.Now()})
	}
	if strings.HasPrefix(q, "select organization_id,jsonb_build_array") {
		return rows(2, []driver.Value{c.m.org, "synthetic-root-state"})
	}
	if strings.HasPrefix(q, "select organization_id") {
		return rows(1, []driver.Value{c.m.org})
	}
	if strings.HasPrefix(q, "select id,schedule_id,tgt_user_id,tgt_rotation_id") {
		for _, r := range c.tx.rules {
			if r.id == a[0].Value {
				var u, rot driver.Value
				if r.user != "" {
					u = r.user
				}
				if r.rotation != "" {
					rot = r.rotation
				}
				return rows(4, []driver.Value{r.id, r.schedule, u, rot})
			}
		}
		return rows(4)
	}
	if strings.HasPrefix(q, "select coalesce(jsonb_agg") {
		var state []u03ModelRule
		for _, r := range c.tx.rules {
			if r.schedule == a[0].Value {
				state = append(state, r)
			}
		}
		slices.SortFunc(state, func(a, b u03ModelRule) int { return strings.Compare(a.id, b.id) })
		// Fields are explicit because the original model's fields are private.
		safe := [][]any{}
		for _, r := range state {
			safe = append(safe, []any{r.id, r.schedule, r.user, r.rotation, r.start, r.end, r.days, r.created})
		}
		raw, _ := json.Marshal(safe)
		return rows(1, []driver.Value{string(raw)})
	}
	if strings.HasPrefix(q, "select id::text from schedule_rules") {
		out := [][]driver.Value{}
		for _, r := range c.tx.rules {
			if r.schedule == a[0].Value {
				out = append(out, []driver.Value{r.id})
			}
		}
		return rows(1, out...)
	}
	if strings.HasPrefix(q, "select u.id::text") || strings.HasPrefix(q, "select u.user_id::text") || strings.HasPrefix(q, "select s.id::text from schedules") || strings.HasPrefix(q, "select r.id::text from rotations") {
		return rows(1)
	}
	if !strings.HasPrefix(q, "with user_org as") {
		return nil, false, nil
	}
	var ids pq.StringArray
	if len(a) > 0 {
		requireScan := ids.Scan(a[0].Value)
		if requireScan != nil {
			return nil, true, requireScan
		}
	}
	if strings.Contains(q, "select * from (") {
		out := [][]driver.Value{}
		for _, r := range c.tx.rules {
			if !slices.Contains(ids, r.id) {
				continue
			}
			// Collector pages use strict lexical ordering of the selected IDs.
			if len(a) > 2 && (r.id <= a[1].Value.(string)) {
				continue
			}
			if strings.Contains(q, "s.id::text as rid") {
				out = append(out, []driver.Value{r.id, r.schedule, "", "", c.m.org, nil, nil, "", false, nil, int64(0), "", int64(0), []byte("[]"), nil, nil})
				continue
			}
			uid := r.user
			kind := ds.ResourceUser
			if strings.Contains(q, "r.tgt_rotation_id::text as tid") {
				uid = r.rotation
				kind = ds.ResourceRotation
			}
			if uid == "" {
				continue
			}
			out = append(out, []driver.Value{uid, r.id, r.schedule, r.schedule, c.m.org, nil, nil, "", false, nil, int64(kind), uid, int64(0), []byte("[]"), nil, nil})
		}
		return rows(16, out...)
	}
	out := [][]driver.Value{}
	for _, id := range ids {
		out = append(out, []driver.Value{id, c.m.org})
	}
	return rows(2, out...)
}

func u03ModelConfirmation(t *testing.T, s *u03Model, ctx context.Context, input graphql2.ScheduleTargetInput) *graphql2.DeletionSafetyConfirmationInput {
	t.Helper()
	clone := *s
	clone.rules = slices.Clone(s.rules)
	clone.queries = nil
	clone.events = nil
	clone.beforeChildLock = nil
	clone.failAudit = false
	clone.zeroReceipt = false
	db := sql.OpenDB(u03ModelConnector{&clone})
	defer func() { require.NoError(t, db.Close()) }()
	rs, err := rule.NewStore(ctx, db)
	require.NoError(t, err)
	ss, err := schedule.NewStore(ctx, db, nil)
	require.NoError(t, err)
	app := &App{DB: db, RuleStore: rs, ScheduleStore: ss, PreviewSigner: previewTestSigner{}}
	p, err := app.Query().PreviewUpdateScheduleTarget(ctx, input)
	if err != nil {
		return nil
	}
	return &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}
}
func runU03ModelUpdate(t *testing.T, s *u03Model, m *Mutation, ctx context.Context, input graphql2.ScheduleTargetInput) (bool, error) {
	t.Helper()
	input.Confirmation = u03ModelConfirmation(t, s, ctx, input)
	return m.UpdateScheduleTarget(ctx, input)
}
