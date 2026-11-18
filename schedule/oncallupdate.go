package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"

	"github.com/google/uuid"
	"github.com/target/goalert/internal/scheduledataref"
	audit "github.com/target/goalert/schedule/oncallupdateaudit"
)

// OnCallSnapshot is a complete minimal business projection. Derived runtime
// timestamps are deliberately excluded from consent and audit differences.
func OnCallSnapshot(id uuid.UUID, rules []OnCallNotificationRule) ([]audit.Rule, error) {
	out := make([]audit.Rule, 0, len(rules))
	for _, r := range rules {
		v := audit.Rule{ID: r.ID.String(), Channel: r.ChannelID.String()}
		if (r.Time == nil) != (r.WeekdayFilter == nil) {
			return nil, audit.ErrInvalid
		}
		if r.Time != nil {
			v.Time = r.Time.String()
			b, err := r.WeekdayFilter.MarshalText()
			if err != nil {
				return nil, err
			}
			v.Weekdays = string(b)
		}
		out = append(out, v)
	}
	return audit.Canonical(id, out)
}

func (store *Store) ReadOnCallUpdate(ctx context.Context, tx *sql.Tx, id uuid.UUID, locked bool) (int64, []OnCallNotificationRule, error) {
	if tx == nil {
		return 0, nil, audit.ErrInvalid
	}
	query := `SELECT id,data FROM schedule_data WHERE schedule_id=$1`
	if locked {
		query += ` FOR UPDATE`
	}
	var envelope int64
	var raw []byte
	err := tx.QueryRowContext(ctx, query, id).Scan(&envelope, &raw)
	if err == sql.ErrNoRows {
		return 0, []OnCallNotificationRule{}, nil
	}
	if err != nil {
		return 0, nil, err
	}
	if string(raw) != "{}" {
		if _, err := scheduledataref.Users(raw, id); err != nil {
			return 0, nil, err
		}
	}
	var data Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return 0, nil, err
	}
	if _, err := OnCallSnapshot(id, data.V1.OnCallNotificationRules); err != nil {
		return 0, nil, err
	}
	return envelope, data.V1.OnCallNotificationRules, nil
}

// RetainNextNotifications merges current system state only when configuration
// is equivalent. It never restores old configuration from a preview snapshot.
func RetainNextNotifications(current, desired []OnCallNotificationRule) {
	for i := range desired {
		for _, old := range current {
			if old.ID == desired[i].ID && old.ChannelID == desired[i].ChannelID && reflect.DeepEqual(old.Time, desired[i].Time) && reflect.DeepEqual(old.WeekdayFilter, desired[i].WeekdayFilter) {
				desired[i].NextNotification = old.NextNotification
				break
			}
		}
	}
}

func lockOnCallChannels(ctx context.Context, tx *sql.Tx, b, a []audit.Rule) error {
	ids := map[string]bool{}
	for _, r := range append(append([]audit.Rule{}, b...), a...) {
		ids[r.Channel] = true
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		var actual string
		if err := tx.QueryRowContext(ctx, `SELECT id::text FROM notification_channels WHERE id=$1 AND dest IS NOT NULL FOR SHARE NOWAIT`, id).Scan(&actual); err != nil {
			return err
		}
	}
	return nil
}
