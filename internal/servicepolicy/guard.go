// Package servicepolicy protects routing replacement, never Policy deletion.
// Facts are shared by the read-only preview and the actual Store recheck.
package servicepolicy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

type Alert struct {
	ID     int64
	Status string
}

type State struct {
	ID, AlertID       int64
	Policy            uuid.UUID
	Step              sql.NullString
	StepNumber, Loops int
	Last, Next        sql.NullTime
	Force             bool
}

type Facts struct {
	Service, Organization, Before, After uuid.UUID
	Root                                 string
	Policies, Steps, Actions             []string
	Alerts                               []Alert
	States                               []State
}

const policiesQuery = `SELECT jsonb_build_array(id,organization_id,name,description,repeat,step_count)::text FROM escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id`
const stepsQuery = `SELECT jsonb_build_array(id,escalation_policy_id,step_number,delay,multi_ack)::text FROM escalation_policy_steps WHERE escalation_policy_id=ANY($1::uuid[]) ORDER BY id`
const actionsQuery = `SELECT jsonb_build_array(a.id,a.escalation_policy_step_id,a.user_id,a.schedule_id,a.rotation_id,a.channel_id)::text FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id WHERE s.escalation_policy_id=ANY($1::uuid[]) ORDER BY a.id`

func unavailable() error { return &ds.DeletionSafetyError{Code: ds.DeletionUnavailable} }

func (f Facts) Changed() bool { return f.Before != f.After }
func (f Facts) RequiresConfirmation() bool {
	if !f.Changed() {
		return false
	}
	for _, a := range f.Alerts {
		if a.Status != "closed" {
			return true
		}
	}
	return false
}
func (f Facts) Digest() (string, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return "", unavailable()
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

// Caller owns admission and the transaction. A Service FOR UPDATE fences new
// Alert/State FK references. NOWAIT on existing dependencies avoids reversing
// the EP/Delete and runtime writer lock order; refusal is safe to retry anew.
func Load(ctx context.Context, tx *sql.Tx, id string, next *string, org *uuid.UUID, locked bool) (Facts, error) {
	var f Facts
	if tx == nil {
		return f, unavailable()
	}
	query := `SELECT id,organization_id,escalation_policy_id,jsonb_build_array(id,organization_id,name,description,maintenance_expires_at,escalation_policy_id)::text FROM services WHERE id=$1 AND ($2::uuid IS NULL OR organization_id=$2)`
	if locked {
		query += ` FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, query, id, org).Scan(&f.Service, &f.Organization, &f.Before, &f.Root); err != nil {
		return f, err
	}
	var err error
	f.After = f.Before
	if next != nil {
		f.After, err = uuid.Parse(*next)
		if err != nil {
			return f, unavailable()
		}
	}
	if !f.Changed() {
		return f, nil
	}
	ids := pq.Array([]string{f.Before.String(), f.After.String()})
	// Do not lock an unvalidated foreign target. Repeat this check after the
	// locks, since a policy organization can itself be concurrently changed.
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM escalation_policies WHERE id=ANY($1::uuid[]) AND organization_id=$2`, ids, f.Organization).Scan(&count); err != nil {
		return f, err
	}
	if count != 2 {
		return f, unavailable()
	}
	if locked {
		for _, q := range []string{
			`SELECT id::text FROM escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE NOWAIT`,
			`SELECT id::text FROM escalation_policy_steps WHERE escalation_policy_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE NOWAIT`,
			`SELECT a.id::text FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id WHERE s.escalation_policy_id=ANY($1::uuid[]) ORDER BY a.id FOR SHARE OF a NOWAIT`,
		} {
			if _, err := stringsQuery(ctx, tx, q, ids); err != nil {
				return f, err
			}
		}
		for _, q := range []string{
			`SELECT id::text FROM alerts WHERE service_id=$1 ORDER BY id FOR SHARE NOWAIT`,
			`SELECT id::text FROM escalation_policy_state WHERE service_id=$1 ORDER BY id FOR SHARE NOWAIT`,
		} {
			if _, err := stringsQuery(ctx, tx, q, id); err != nil {
				return f, err
			}
		}
	}
	// Separate reads after locks are required under READ COMMITTED.
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM escalation_policies WHERE id=ANY($1::uuid[]) AND organization_id=$2`, ids, f.Organization).Scan(&count); err != nil {
		return f, err
	}
	if count != 2 {
		return f, unavailable()
	}
	f.Policies, err = stringsQuery(ctx, tx, policiesQuery, ids)
	if err != nil {
		return f, err
	}
	f.Steps, err = stringsQuery(ctx, tx, stepsQuery, ids)
	if err != nil {
		return f, err
	}
	f.Actions, err = stringsQuery(ctx, tx, actionsQuery, ids)
	if err != nil {
		return f, err
	}
	f.Alerts, f.States, err = runtime(ctx, tx, f.Service)
	if err != nil {
		return f, err
	}
	var foreignStep bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM escalation_policy_state es JOIN escalation_policy_steps st ON st.id=es.escalation_policy_step_id WHERE es.service_id=$1 AND st.escalation_policy_id<>$2)`, f.Service, f.Before).Scan(&foreignStep); err != nil {
		return f, err
	}
	if foreignStep {
		return f, unavailable()
	}
	open := make(map[int64]bool, len(f.Alerts))
	for _, a := range f.Alerts {
		open[a.ID] = a.Status != "closed"
	}
	for _, s := range f.States {
		if s.Policy != f.Before {
			return f, unavailable()
		}
		if !open[s.AlertID] {
			return f, unavailable()
		}
	}
	return f, nil
}

func stringsQuery(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
		if len(result) > ds.DefaultBudget().MaxDependencies {
			return nil, unavailable()
		}
	}
	return result, rows.Err()
}

func runtime(ctx context.Context, tx *sql.Tx, id uuid.UUID) ([]Alert, []State, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,status::text FROM alerts WHERE service_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, nil, err
	}
	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.Status); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		if a.Status != "triggered" && a.Status != "active" && a.Status != "closed" {
			_ = rows.Close()
			return nil, nil, unavailable()
		}
		alerts = append(alerts, a)
		if len(alerts) > ds.DefaultBudget().MaxDependencies {
			_ = rows.Close()
			return nil, nil, unavailable()
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,alert_id,escalation_policy_id,escalation_policy_step_id,escalation_policy_step_number,loop_count,last_escalation,next_escalation,force_escalation FROM escalation_policy_state WHERE service_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var states []State
	for rows.Next() {
		var s State
		if err := rows.Scan(&s.ID, &s.AlertID, &s.Policy, &s.Step, &s.StepNumber, &s.Loops, &s.Last, &s.Next, &s.Force); err != nil {
			return nil, nil, err
		}
		states = append(states, s)
		if len(states) > ds.DefaultBudget().MaxDependencies {
			return nil, nil, unavailable()
		}
	}
	return alerts, states, rows.Err()
}

type key struct{}
type capability struct {
	mu     sync.Mutex
	tx     *sql.Tx
	digest string
	used   bool
}

// Bind stays inside the admitted owner, after signed consent and locked facts.
func Bind(ctx context.Context, tx *sql.Tx, f Facts) (context.Context, error) {
	digest, err := f.Digest()
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, key{}, &capability{tx: tx, digest: digest}), nil
}

// Consume is called before UPDATE, so catching a refusal cannot commit a write.
func Consume(ctx context.Context, tx *sql.Tx, f Facts) error {
	if ctx == nil {
		return unavailable()
	}
	c, _ := ctx.Value(key{}).(*capability)
	if c == nil || tx == nil || c.tx != tx {
		return unavailable()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	digest, err := f.Digest()
	if err != nil {
		return err
	}
	if c.used || c.digest != digest {
		return unavailable()
	}
	c.used = true
	return nil
}

// VerifyResult corroborates the existing trigger's precise runtime reset.
// State identities, Alerts, Service and both Policies must survive.
func VerifyResult(ctx context.Context, tx *sql.Tx, f Facts) error {
	var policy uuid.UUID
	if err := tx.QueryRowContext(ctx, `SELECT escalation_policy_id FROM services WHERE id=$1 AND organization_id=$2`, f.Service, f.Organization).Scan(&policy); err != nil {
		return err
	}
	if policy != f.After {
		return unavailable()
	}
	alerts, states, err := runtime(ctx, tx, f.Service)
	if err != nil {
		return err
	}
	want := append([]State(nil), f.States...)
	for i := range want {
		want[i].Policy = f.After
		want[i].Step = sql.NullString{}
		want[i].StepNumber = 0
		want[i].Loops = 0
		want[i].Last = sql.NullTime{}
		want[i].Next = sql.NullTime{}
		want[i].Force = false
	}
	if !reflect.DeepEqual(alerts, f.Alerts) || !reflect.DeepEqual(states, want) {
		return unavailable()
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM escalation_policies WHERE id=ANY($1::uuid[]) AND organization_id=$2`, pq.Array([]string{f.Before.String(), f.After.String()}), f.Organization).Scan(&count); err != nil {
		return err
	}
	if count != 2 {
		return unavailable()
	}
	for _, projection := range []struct {
		query string
		want  []string
	}{{policiesQuery, f.Policies}, {stepsQuery, f.Steps}, {actionsQuery, f.Actions}} {
		actual, err := stringsQuery(ctx, tx, projection.query, pq.Array([]string{f.Before.String(), f.After.String()}))
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, projection.want) {
			return unavailable()
		}
	}
	return nil
}
