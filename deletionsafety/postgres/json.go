package postgres

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/util/sqlutil"
)

type temporary struct {
	Start, End time.Time
}

type shift struct {
	Start, End time.Time
	UserID     string
}

// projectV1 deliberately does not use the Schedule getter, normalization, user
// existence filtering, merging or trimming. Array order is stored order.
func projectV1(envelope int64, schedule string, raw []byte, asOf time.Time, maxFragments int) ([]ds.Dependency, int, error) {
	if envelope <= 0 {
		return nil, 0, unavailable()
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || members == nil {
		return nil, 0, unavailable()
	}
	for key := range members {
		if key != "TemporarySchedules" && key != "OnCallNotificationRules" {
			return nil, 0, errUnsupported
		}
	}
	if !array(members["TemporarySchedules"]) {
		return nil, 0, unavailable()
	}
	data, err := boundedArray(members["TemporarySchedules"], maxFragments)
	if err != nil {
		return nil, 0, err
	}
	var result []ds.Dependency
	units := 0
	sched := ds.Resource{Kind: ds.ResourceSchedule, ID: schedule}
	for i, rawTemporary := range data {
		var fields map[string]json.RawMessage
		if json.Unmarshal(rawTemporary, &fields) != nil || fields == nil || !array(fields["Shifts"]) {
			return nil, 0, unavailable()
		}
		for key := range fields {
			if key != "Start" && key != "End" && key != "Shifts" {
				return nil, 0, errUnsupported
			}
		}
		var t temporary
		if json.Unmarshal(rawTemporary, &t) != nil {
			return nil, 0, unavailable()
		}
		period, err := ds.ClassifyPeriod(t.Start, t.End, asOf)
		if err != nil {
			return nil, 0, unavailable()
		}
		rawShifts, err := boundedArray(fields["Shifts"], maxFragments-units-1)
		if err != nil {
			return nil, 0, err
		}
		units += 1 + len(rawShifts)
		temp := ds.Resource{Kind: ds.ResourceTemporarySchedule, ID: fmt.Sprintf("schedule-data:%d:temporary:%d", envelope, i)}
		result = append(result, ds.Dependency{Target: sched, Referencing: temp, Parent: sched, Owner: sched, Relationship: ds.RelationshipScheduleTemporary,
			State: ds.BusinessState{Period: period}, Before: ds.Configuration{WindowStart: t.Start, WindowEnd: t.End}})
		for j, rawShift := range rawShifts {
			var s shift
			if json.Unmarshal(rawShift, &s) != nil {
				return nil, 0, unavailable()
			}
			var shiftFields map[string]json.RawMessage
			if json.Unmarshal(rawShifts[j], &shiftFields) != nil || shiftFields == nil {
				return nil, 0, unavailable()
			}
			for key := range shiftFields {
				if key != "Start" && key != "End" && key != "UserID" {
					return nil, 0, errUnsupported
				}
			}
			id, err := uuid.Parse(s.UserID)
			if err != nil || id == uuid.Nil || !strings.EqualFold(id.String(), s.UserID) {
				return nil, 0, unavailable()
			}
			if _, err := ds.ClassifyPeriod(s.Start, s.End, asOf); err != nil {
				return nil, 0, unavailable()
			}
			start, end := s.Start, s.End
			if start.Before(t.Start) {
				start = t.Start
			}
			if end.After(t.End) {
				end = t.End
			}
			// V1 has no representation of a raw reference whose effective
			// interval is empty. Preserve the boundary as unsupported instead of
			// inventing a state, dropping the fragment, or changing the contract.
			if !start.Before(end) {
				return nil, 0, errUnsupported
			}
			period, err := ds.ClassifyPeriod(start, end, asOf)
			if err != nil {
				return nil, 0, unavailable()
			}
			fixed := ds.Resource{Kind: ds.ResourceFixedShift, ID: temp.ID + ":shift:" + strconv.Itoa(j)}
			position := j
			base := ds.Dependency{Referencing: fixed, Parent: temp, Owner: sched, State: ds.BusinessState{Period: period}, Before: ds.Configuration{References: []ds.Resource{{Kind: ds.ResourceUser, ID: id.String()}}, WindowStart: start, WindowEnd: end, Position: &position}}
			base.Target, base.Relationship = sched, ds.RelationshipScheduleShift
			result = append(result, base)
			base.Target, base.Relationship = temp, ds.RelationshipTemporaryShift
			result = append(result, base)
			base.Target, base.Relationship = ds.Resource{Kind: ds.ResourceUser, ID: id.String()}, ds.RelationshipShiftUser
			result = append(result, base)
		}
	}
	if value, ok := members["OnCallNotificationRules"]; ok {
		if !array(value) {
			return nil, 0, unavailable()
		}
		rules, err := boundedArray(value, maxFragments-units)
		if err != nil {
			return nil, 0, err
		}
		units += len(rules)
		if units > maxFragments {
			return nil, 0, limitExceeded()
		}
		seen := map[string]bool{}
		for ordinal, rawRule := range rules {
			var r struct{ ID, ChannelID string }
			if json.Unmarshal(rawRule, &r) != nil {
				return nil, 0, unavailable()
			}
			prefix := schedule + ":"
			local, err := strconv.ParseInt(strings.TrimPrefix(r.ID, prefix), 10, 32)
			channel, e := uuid.Parse(r.ChannelID)
			if err != nil || e != nil || channel == uuid.Nil || local < 0 || r.ID != prefix+strconv.FormatInt(local, 10) || seen[r.ID] {
				return nil, 0, unavailable()
			}
			seen[r.ID] = true
			rule := ds.Resource{Kind: ds.ResourceOnCallNotificationRule, ID: fmt.Sprintf("schedule-data:%d:oncall:%d:%d", envelope, ordinal, local)}
			position := ordinal
			result = append(result, ds.Dependency{Target: sched, Referencing: rule, Parent: sched, Owner: sched, Relationship: ds.RelationshipScheduleOnCallRule, Before: ds.Configuration{Position: &position}},
				ds.Dependency{Target: rule, Referencing: ds.Resource{Kind: ds.ResourceNotificationChannel, ID: channel.String()}, Relationship: ds.RelationshipRetainedChannel})
		}
	}
	return result, units, nil
}

func array(raw json.RawMessage) bool {
	return len(raw) > 0 && strings.HasPrefix(strings.TrimSpace(string(raw)), "[")
}

// Stop before decoding an over-budget element or allocating a typed roster.
// SQL separately caps the raw and projected byte streams.
func boundedArray(raw []byte, limit int) ([]json.RawMessage, error) {
	if limit < 0 {
		return nil, limitExceeded()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, unavailable()
	}
	var result []json.RawMessage
	for decoder.More() {
		if len(result) >= limit {
			return nil, limitExceeded()
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, unavailable()
		}
		result = append(result, value)
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
		return nil, unavailable()
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, unavailable()
	}
	return result, nil
}

// Known members only; unknown member presence is returned as a Boolean. SQL
// ordinality is one-based and is used only to retain stored order here. Go's
// zero-based positions form the accepted audit-compatible fragment identity.
const scheduleDataProjection = `jsonb_build_object('TemporarySchedules',
 CASE WHEN jsonb_typeof(d.data->'V1'->'TemporarySchedules')='array' THEN
 COALESCE((SELECT jsonb_agg(CASE WHEN jsonb_typeof(t.value)='object' THEN jsonb_build_object(
 'Start',t.value->'Start','End',t.value->'End','Shifts',
 CASE WHEN jsonb_typeof(t.value->'Shifts')='array' THEN COALESCE((SELECT jsonb_agg(
 CASE WHEN jsonb_typeof(sh.value)='object' THEN jsonb_build_object('Start',sh.value->'Start','End',sh.value->'End','UserID',sh.value->'UserID') ELSE NULL END ORDER BY sh.ordinality)
 FROM jsonb_array_elements(t.value->'Shifts') WITH ORDINALITY sh), '[]'::jsonb) ELSE NULL END)
 ELSE NULL END ORDER BY t.ordinality)
 FROM jsonb_array_elements(d.data->'V1'->'TemporarySchedules') WITH ORDINALITY t),'[]'::jsonb)
 ELSE NULL END,
 'OnCallNotificationRules',CASE WHEN jsonb_typeof(d.data->'V1'->'OnCallNotificationRules')='array' THEN
 COALESCE((SELECT jsonb_agg(jsonb_build_object('ID',r.value->'ID','ChannelID',r.value->'ChannelID') ORDER BY r.ordinality)
 FROM jsonb_array_elements(d.data->'V1'->'OnCallNotificationRules') WITH ORDINALITY r),'[]'::jsonb)
 ELSE NULL END)`

const unknownScheduleData = `CASE WHEN jsonb_typeof(d.data)='object' AND jsonb_typeof(d.data->'V1')='object' THEN
 (d.data-'V1')<>'{}'::jsonb OR ((d.data->'V1')-'TemporarySchedules'-'OnCallNotificationRules')<>'{}'::jsonb OR
 EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.data->'V1'->'TemporarySchedules')='array' THEN d.data->'V1'->'TemporarySchedules' ELSE '[]'::jsonb END) t
 WHERE CASE WHEN jsonb_typeof(t)='object' THEN (t-'Start'-'End'-'Shifts')<>'{}'::jsonb ELSE false END) OR
 EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.data->'V1'->'TemporarySchedules')='array' THEN d.data->'V1'->'TemporarySchedules' ELSE '[]'::jsonb END) t,
 LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t->'Shifts')='array' THEN t->'Shifts' ELSE '[]'::jsonb END) sh
 WHERE CASE WHEN jsonb_typeof(sh)='object' THEN (sh-'Start'-'End'-'UserID')<>'{}'::jsonb ELSE false END) OR
 EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.data->'V1'->'OnCallNotificationRules')='array' THEN d.data->'V1'->'OnCallNotificationRules' ELSE '[]'::jsonb END) r
 WHERE CASE WHEN jsonb_typeof(r)='object' THEN (r-'ID'-'ChannelID'-'Time'-'WeekdayFilter'-'NextNotification')<>'{}'::jsonb ELSE false END)
 ELSE false END`

func (c *collector) readScheduleData(kind ds.ResourceKind, ids []string) error {
	var filter string
	if kind == ds.ResourceSchedule {
		filter = "d.schedule_id=ANY($1::uuid[])"
	} else {
		filter = "$1::uuid[] IS NOT NULL"
	}
	var cursor int64
	for {
		if c.queries >= c.limits.MaxQueries {
			return limitExceeded()
		}
		c.queries++
		// The byte guard bounds the JSON returned to Go. Stored JSON detoasting
		// and projection remain server work covered by the overall deadline.
		query := `WITH page AS MATERIALIZED (
		 SELECT d.id,d.schedule_id,d.data,octet_length(d.data::text) AS raw_bytes
		 FROM public.schedule_data d WHERE ` + filter + ` AND d.id>$2 ORDER BY d.id LIMIT $4
		), raw_sized AS (
		 SELECT page.*,sum(raw_bytes) OVER(ORDER BY id) AS raw_total FROM page
		), projected AS MATERIALIZED (
		 SELECT d.*,CASE WHEN raw_total<=$3 THEN ` + scheduleDataProjection + ` ELSE NULL END AS projection FROM raw_sized d
		), bounded AS (
		 SELECT projected.*,greatest(raw_bytes,COALESCE(octet_length(projection::text),0)) AS budget_bytes,
		 sum(greatest(raw_bytes,COALESCE(octet_length(projection::text),0))) OVER(ORDER BY id) AS budget_total FROM projected
		)
		 SELECT d.id,d.schedule_id::text,s.organization_id::text,
		 jsonb_typeof(d.data)='object' AND jsonb_typeof(d.data->'V1')='object',
		 CASE WHEN budget_total<=$3 THEN ` + unknownScheduleData + ` ELSE false END,
		 CASE WHEN budget_total<=$3 THEN projection ELSE NULL END,budget_bytes
		 FROM bounded d LEFT JOIN public.schedules s ON s.id=d.schedule_id ORDER BY d.id`
		rows, err := c.tx.QueryContext(c.ctx, query, sqlutil.StringArray(ids), cursor, c.limits.MaxJSONBytes-c.jsonBytes, c.limits.PageSize)
		if err != nil {
			return unavailable()
		}
		var projected []struct {
			org  string
			deps []ds.Dependency
		}
		count := 0
		for rows.Next() {
			count++
			var id int64
			var schedule, org string
			var valid, unknown sql.NullBool
			var raw []byte
			var size int
			if rows.Scan(&id, &schedule, &org, &valid, &unknown, &raw, &size) != nil {
				rows.Close()
				return unavailable()
			}
			cursor = id
			c.jsonBytes += size
			if c.jsonBytes > c.limits.MaxJSONBytes {
				rows.Close()
				return limitExceeded()
			}
			if !valid.Valid || !valid.Bool {
				rows.Close()
				return unavailable()
			}
			if unknown.Bool {
				rows.Close()
				return errUnsupported
			}
			deps, units, err := projectV1(id, schedule, raw, c.result.ObservedAt, c.limits.MaxFragments-c.fragments)
			if err != nil {
				rows.Close()
				return err
			}
			c.fragments += units
			if kind == ds.ResourceUser {
				filtered := deps[:0]
				for _, d := range deps {
					if d.Relationship == ds.RelationshipShiftUser && slicesContains(ids, d.Target.ID) {
						filtered = append(filtered, d)
					}
				}
				deps = filtered
			}
			if len(deps) > 0 && !c.allowed(org) {
				rows.Close()
				return unavailable()
			}
			projected = append(projected, struct {
				org  string
				deps []ds.Dependency
			}{org, deps})
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil || closeErr != nil {
			return unavailable()
		}
		// Resolve raw users in a single batched lookup after releasing Rows on
		// the same transaction/connection. A missing UUID is never filtered out.
		users := map[string]bool{}
		for _, p := range projected {
			for _, d := range p.deps {
				if d.Relationship == ds.RelationshipShiftUser {
					users[d.Target.ID] = true
				}
			}
		}
		if len(users) > 0 {
			userIDs := make([]string, 0, len(users))
			for id := range users {
				userIDs = append(userIDs, id)
			}
			if c.queries >= c.limits.MaxQueries {
				return limitExceeded()
			}
			c.queries++
			rows, err := c.tx.QueryContext(c.ctx, userOrganizations+` SELECT user_id::text,organization_id::text FROM user_org WHERE user_id=ANY($1::uuid[]) ORDER BY user_id`, sqlutil.StringArray(userIDs))
			if err != nil {
				return unavailable()
			}
			for rows.Next() {
				var id, org string
				if rows.Scan(&id, &org) != nil || !c.allowed(org) {
					rows.Close()
					return unavailable()
				}
				delete(users, id)
			}
			err = rows.Err()
			closeErr := rows.Close()
			if err != nil || closeErr != nil || len(users) != 0 {
				return unavailable()
			}
		}
		for _, p := range projected {
			for _, d := range p.deps {
				if err := c.add(d); err != nil {
					return err
				}
			}
		}
		if count < c.limits.PageSize {
			return nil
		}
	}
}

func slicesContains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
