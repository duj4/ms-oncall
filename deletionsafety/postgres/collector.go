package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/executioncontext"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/sqlutil"
)

// Purpose distinguishes a disposable preview from facts read again inside a
// future mutation's owning transaction. Recheck grants no mutation capability.
type Purpose uint8

const (
	Preview Purpose = iota + 1
	Recheck
)

// Limits bound raw observations before deduplication, queries (including empty
// final pages), JSON envelopes/fragments/bytes, and total elapsed query time.
type Limits struct {
	PageSize, MaxRows, MaxQueries, MaxJSONBytes, MaxFragments int
	Timeout                                                   time.Duration
}

func DefaultLimits() Limits {
	return Limits{PageSize: 256, MaxRows: 10000, MaxQueries: 512, MaxJSONBytes: 1 << 20, MaxFragments: 10000, Timeout: 15 * time.Second}
}

// Result is published only on success. Failure discards observations, coverage,
// counts and scope fingerprints so foreign or partially scanned rows cannot be
// inferred from diagnostics. Collection.Completeness is never Complete on error.
type Result struct {
	Collection       ds.Collection
	ScopeFingerprint string
	ObservedAt       time.Time
	Limits           Limits
}

// Target is resolved only from the owning transaction. Accessors return copies.
// It contains no client-selected Organization or presumed parent identity.
type Target struct {
	resource     ds.Resource
	organization uuid.UUID
	owner        ds.Resource
}

func (t Target) Resource() ds.Resource     { return t.resource }
func (t Target) OrganizationID() uuid.UUID { return t.organization }
func (t Target) Owner() ds.Resource        { return t.owner }

// AuthorizeFacts must be a trusted server-selected, read-only operation/target
// authorizer. It runs in the supplied transaction after actual identity
// resolution. Matching a Home or knowing an ID alone grants no capability.
// Do not pass a mutation helper, a locking helper, or a client-selected callback.
type AuthorizeFacts func(context.Context, *sql.Tx, Target) error

type collector struct {
	tx                                  *sql.Tx
	ctx                                 context.Context
	limits                              Limits
	result                              Result
	organization                        string
	global                              bool
	removed, checked                    map[ds.Resource]bool
	queue                               map[ds.ResourceKind][]string
	rows, queries, fragments, jsonBytes int
}

func unavailable() error   { return &ds.DeletionSafetyError{Code: ds.DeletionUnavailable} }
func limitExceeded() error { return &ds.DeletionSafetyError{Code: ds.DeletionPreviewLimitExceeded} }
func safeError(err error) error {
	var typed *ds.DeletionSafetyError
	if errors.As(err, &typed) {
		return &ds.DeletionSafetyError{Code: typed.Code}
	}
	return unavailable()
}

// Collect resolves the actual target and scope in tx. root is a selector, never
// proof of authority. No Organization ID is accepted from a wire request.
// Canonical admitted Human authority or a compiled internal System context is
// required. The caller still owns operation-specific authorization and commit.
func Collect(ctx context.Context, tx *sql.Tx, root ds.Resource, purpose Purpose, limits Limits, authorize AuthorizeFacts) (Result, error) {
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	bad := Result{Collection: ds.Collection{Completeness: ds.DependenciesIncomplete}}
	if ctx == nil || tx == nil || authorize == nil || purpose < Preview || purpose > Recheck ||
		limits.PageSize < 1 || limits.PageSize > 1000 || limits.MaxRows < 1 || limits.MaxRows > 100000 ||
		limits.MaxQueries < 1 || limits.MaxQueries > 10000 || limits.MaxJSONBytes < 1 || limits.MaxJSONBytes > 8<<20 ||
		limits.MaxFragments < 1 || limits.MaxFragments > 100000 || limits.Timeout <= 0 || limits.Timeout > time.Minute {
		return bad, unavailable()
	}
	id, err := uuid.Parse(root.ID)
	if err != nil || id == uuid.Nil || id.String() != root.ID {
		return bad, unavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	c := collector{tx: tx, ctx: ctx, limits: limits, removed: map[ds.Resource]bool{}, checked: map[ds.Resource]bool{}, queue: map[ds.ResourceKind][]string{}}
	var fingerprint string
	var admittedOrganizationRole string
	if permission.System(ctx) {
		c.global = true
		fingerprint = "internal-system:" + permission.SystemComponentName(ctx)
	} else {
		authority, e := executioncontext.CheckHumanAuthority(ctx)
		if e != nil {
			return bad, unavailable()
		}
		org, ok := authority.EffectiveOrganizationID()
		if !ok || !executioncontext.EligibleForOrganizationBusinessScope(authority, org) {
			return bad, unavailable()
		}
		c.organization = org.String()
		admittedOrganizationRole = string(authority.Privileges().OrganizationRole())
		fingerprint = fmt.Sprint(authority.PrincipalKind(), ":", authority.ActualActorID(), ":", authority.AuthorityMode(), ":", org, ":", admittedOrganizationRole, ":", authority.Privileges().PlatformAdmin())
	}
	var readOnly, isolation string
	if err := c.queryRow(`SELECT current_setting('transaction_read_only'), current_setting('transaction_isolation'), statement_timestamp()`).Scan(&readOnly, &isolation, &c.result.ObservedAt); err != nil {
		return bad, safeError(err)
	}
	fenced := purpose == Recheck && guard.Fenced(ctx, tx)
	if purpose == Preview && readOnly != "on" || !fenced && isolation != "repeatable read" && isolation != "serializable" {
		return bad, unavailable()
	}
	if !c.global {
		// Re-observe the actor's persisted Home inside this snapshot. Admission
		// outside the owning transaction is not silently treated as fresh state.
		var org, role, organizationRole string
		if err := c.queryRow(userOrganizations+` SELECT organization_id::text,user_role::text,organization_role::text FROM user_org WHERE user_id=$1::uuid`, permission.UserID(ctx)).Scan(&org, &role, &organizationRole); err != nil {
			return bad, safeError(err)
		}
		expectedRole := "user"
		if permission.Admin(ctx) {
			expectedRole = "admin"
		}
		if org != c.organization || role != expectedRole || organizationRole != admittedOrganizationRole {
			return bad, unavailable()
		}
	}
	query, ok := identityQueries[root.Kind]
	if !ok {
		bad.Collection.Completeness = ds.DependenciesUnsupported
		return bad, unavailable()
	}
	var org string
	if err := c.queryRow(userOrganizations+query, root.ID).Scan(&org); err != nil {
		return bad, safeError(err)
	}
	if !c.allowed(org) {
		return bad, unavailable()
	}
	target := Target{resource: root, organization: uuid.MustParse(org)}
	if ownership, ok := ownershipQueries[root.Kind]; ok {
		var id string
		if err := c.queryRow(ownership.query, root.ID).Scan(&id); err != nil {
			return bad, safeError(err)
		}
		target.owner = ds.Resource{Kind: ownership.kind, ID: id}
	}
	if err := authorize(ctx, tx, target); err != nil {
		return bad, unavailable()
	}
	// Even a global System read must resolve a real Organization, rather than
	// defaulting an orphaned owner into an invented scope.
	c.enqueue(root)
	for len(c.queue) != 0 {
		kinds := make([]ds.ResourceKind, 0, len(c.queue))
		for kind := range c.queue {
			kinds = append(kinds, kind)
		}
		slices.Sort(kinds)
		kind := kinds[0]
		ids := c.queue[kind]
		delete(c.queue, kind)
		slices.Sort(ids)
		if err := c.collectKind(kind, ids); err != nil {
			if err == errUnsupported {
				bad.Collection.Completeness = ds.DependenciesUnsupported
				return bad, unavailable()
			}
			return bad, safeError(err)
		}
		for _, id := range ids {
			c.checked[ds.Resource{Kind: kind, ID: id}] = true
		}
	}
	if err := c.validateReferences(); err != nil {
		return bad, safeError(err)
	}
	for object := range c.checked {
		c.result.Collection.Checked = append(c.result.Collection.Checked, object)
	}
	slices.SortFunc(c.result.Collection.Checked, func(a, b ds.Resource) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return compareID(a.ID, b.ID)
	})
	c.result.Collection.Completeness = ds.DependenciesComplete
	c.result.Limits = limits
	c.result.ScopeFingerprint = fmt.Sprintf("%x", sha256.Sum256([]byte(fingerprint)))
	return c.result, nil
}

func compareID(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func (c *collector) allowed(org string) bool {
	id, err := uuid.Parse(org)
	return err == nil && id != uuid.Nil && (c.global || org == c.organization)
}

type scanner interface{ Scan(...any) error }
type failedScan struct{ err error }

func (s failedScan) Scan(...any) error { return s.err }

func (c *collector) queryRow(query string, args ...any) scanner {
	if c.queries >= c.limits.MaxQueries {
		return failedScan{limitExceeded()}
	}
	c.queries++
	return c.tx.QueryRowContext(c.ctx, query, args...)
}

func (c *collector) enqueue(r ds.Resource) {
	if c.removed[r] {
		return
	}
	c.removed[r] = true
	c.queue[r.Kind] = append(c.queue[r.Kind], r.ID)
}

func (c *collector) add(d ds.Dependency) error {
	c.rows += 1 + len(d.Before.References) + len(d.After.References)
	if c.rows > c.limits.MaxRows {
		return limitExceeded()
	}
	decision, err := ds.Evaluate(ds.EvaluationInput{Dependency: d})
	if err != nil {
		return unavailable()
	}
	c.result.Collection.Dependencies = append(c.result.Collection.Dependencies, d)
	if c.removed[d.Target] && decision.CanProceed && decision.Change == ds.ChangeDeleted && decision.Affected != d.Target {
		c.enqueue(decision.Affected)
	}
	return nil
}

type projection struct {
	relation                                                             ds.RelationshipKind
	target, referencing, parent, owner                                   ds.ResourceKind
	from, filter, targetID, referenceID, parentID, ownerID, organization string
	start, end, alert, sameOwner, position, referenceKind, reference     string
	risk, references                                                     string
}

func expression(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func (c *collector) read(p projection, ids []string, numeric bool) error {
	if p.references == "" {
		p.references = projectionReferences(p)
	}
	cast := "uuid[]"
	if numeric {
		cast = "bigint[]"
	}
	base := fmt.Sprintf(`SELECT %s::text AS tid, %s::text AS rid, %s::text AS pid, %s::text AS oid,
	 %s::text AS org, %s AS start_time, %s AS end_time, %s::text AS alert,
	 %s AS same_owner, %s AS position, %s::int AS reference_kind, %s::text AS reference_id, %s::int AS risk, %s AS refs
	 FROM %s WHERE %s = ANY($1::%s)`, p.targetID, p.referenceID, expression(p.parentID, "''"), expression(p.ownerID, "''"), p.organization,
		expression(p.start, "NULL::timestamptz"), expression(p.end, "NULL::timestamptz"), expression(p.alert, "''"), expression(p.sameOwner, "false"), expression(p.position, "NULL::int"), expression(p.referenceKind, "0"), expression(p.reference, "''"), expression(p.risk, "0"), expression(p.references, "'[]'::jsonb"), p.from, p.filter, cast)
	var previousTarget, previousReference string
	for {
		if c.queries >= c.limits.MaxQueries {
			return limitExceeded()
		}
		c.queries++
		query := userOrganizations + ` SELECT * FROM (` + base + `) AS facts WHERE (tid,rid)>($2,$3) ORDER BY tid,rid LIMIT $4`
		rows, err := c.tx.QueryContext(c.ctx, query, sqlutil.StringArray(ids), previousTarget, previousReference, c.limits.PageSize)
		if err != nil {
			return unavailable()
		}
		count := 0
		for rows.Next() {
			count++
			d := ds.Dependency{Relationship: p.relation, Target: ds.Resource{Kind: p.target}, Referencing: ds.Resource{Kind: p.referencing}}
			var parent, owner, org, alert, reference string
			var start, end sql.NullTime
			var position sql.NullInt64
			var referenceKind ds.ResourceKind
			var rawReferences []byte
			if err := rows.Scan(&d.Target.ID, &d.Referencing.ID, &parent, &owner, &org, &start, &end, &alert, &d.State.SameOwner, &position, &referenceKind, &reference, &d.State.NotificationRisk, &rawReferences); err != nil {
				rows.Close()
				return unavailable()
			}
			if !c.allowed(org) {
				rows.Close()
				return unavailable()
			}
			if p.parent != ds.ResourceUnknown {
				d.Parent = ds.Resource{Kind: p.parent, ID: parent}
			}
			if p.owner != ds.ResourceUnknown {
				d.Owner = ds.Resource{Kind: p.owner, ID: owner}
			}
			switch alert {
			case "":
			case "triggered":
				d.State.Alert = ds.AlertTriggered
			case "active":
				d.State.Alert = ds.AlertActive
			case "closed":
				d.State.Alert = ds.AlertClosed
			default:
				rows.Close()
				return unavailable()
			}
			if start.Valid || end.Valid {
				if !start.Valid || !end.Valid {
					rows.Close()
					return unavailable()
				}
				d.Before.WindowStart, d.Before.WindowEnd = start.Time, end.Time
				d.State.Period, err = ds.ClassifyPeriod(start.Time, end.Time, c.result.ObservedAt)
				if err != nil {
					rows.Close()
					return unavailable()
				}
			}
			if position.Valid {
				n := int(position.Int64)
				d.Before.Position = &n
			}
			if referenceKind != ds.ResourceUnknown {
				d.Before.References = []ds.Resource{{Kind: referenceKind, ID: reference}}
			}
			var references []struct {
				Kind ds.ResourceKind
				ID   *string
			}
			if json.Unmarshal(rawReferences, &references) != nil {
				rows.Close()
				return unavailable()
			}
			for _, ref := range references {
				if ref.ID == nil {
					continue
				}
				r := ds.Resource{Kind: ref.Kind, ID: *ref.ID}
				if !slices.Contains(d.Before.References, r) {
					d.Before.References = append(d.Before.References, r)
				}
			}
			if d.Referencing.Kind == ds.ResourceScheduleRule && referenceKind != ds.ResourceUnknown {
				d.Before.References = append(d.Before.References, ds.Resource{Kind: ds.ResourceScheduleTarget, ID: d.Owner.ID + ":" + number(referenceKind) + ":" + reference})
			}
			if err := c.add(d); err != nil {
				rows.Close()
				return err
			}
			previousTarget, previousReference = d.Target.ID, d.Referencing.ID
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil || closeErr != nil {
			return unavailable()
		}
		if count < c.limits.PageSize {
			return nil
		}
	}
}

func number(k ds.ResourceKind) string { return strconv.Itoa(int(k)) }

func (c *collector) validateReferences() error {
	byKind := map[ds.ResourceKind]map[string]bool{}
	for _, d := range c.result.Collection.Dependencies {
		references := append([]ds.Resource{d.Target, d.Referencing, d.Parent, d.Owner}, d.Before.References...)
		for _, r := range references {
			if r.Kind == ds.ResourceNotificationChannel && !c.global {
				return unavailable()
			}
			if _, ok := referenceQueries[r.Kind]; !ok {
				continue
			}
			if byKind[r.Kind] == nil {
				byKind[r.Kind] = map[string]bool{}
			}
			byKind[r.Kind][r.ID] = true
		}
	}
	kinds := make([]ds.ResourceKind, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	for _, kind := range kinds {
		ids := byKind[kind]
		query := referenceQueries[kind]
		values := make([]string, 0, len(ids))
		for id := range ids {
			values = append(values, id)
		}
		slices.Sort(values)
		if c.queries >= c.limits.MaxQueries {
			return limitExceeded()
		}
		c.queries++
		rows, err := c.tx.QueryContext(c.ctx, userOrganizations+query, sqlutil.StringArray(values))
		if err != nil {
			return unavailable()
		}
		for rows.Next() {
			var id, org string
			scanErr := rows.Scan(&id, &org)
			allowed := kind == ds.ResourceNotificationChannel && c.global || c.allowed(org)
			if scanErr != nil || !allowed {
				rows.Close()
				return unavailable()
			}
			delete(ids, id)
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil || closeErr != nil || len(ids) != 0 {
			return unavailable()
		}
	}
	return nil
}
