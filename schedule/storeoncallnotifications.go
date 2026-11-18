package schedule

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/target/goalert/internal/oncalljsonguard"
	"github.com/target/goalert/permission"
	audit "github.com/target/goalert/schedule/oncallupdateaudit"
	"github.com/target/goalert/util/timeutil"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

const onCallNotificationRuleLimit = 50

// SetOnCallNotificationRules will set/replace all notification rules for the given schedule ID.
func (store *Store) SetOnCallNotificationRules(ctx context.Context, tx *sql.Tx, scheduleID uuid.UUID, rules []OnCallNotificationRule) error {
	return store.SetOnCallNotificationRulesScoped(ctx, tx, scheduleID, rules, nil)
}

// SetOnCallNotificationRulesScoped replaces rules after authorizing the parent Schedule's Organization.
// A nil organizationID retains the unscoped compatibility behavior.
func (store *Store) SetOnCallNotificationRulesScoped(ctx context.Context, tx *sql.Tx, scheduleID uuid.UUID, rules []OnCallNotificationRule, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return err
	}

	err = PrepareOnCallNotificationRules(scheduleID, rules)
	if err != nil {
		return err
	}

	var before []audit.Rule
	var envelope int64
	var actualOrg uuid.UUID
	return store.updateScheduleData(ctx, tx, scheduleID, organizationID, func(tx *sql.Tx, data *Data) error {
		var err error
		before, err = OnCallSnapshot(scheduleID, data.V1.OnCallNotificationRules)
		if err != nil {
			return err
		}
		after, err := OnCallSnapshot(scheduleID, rules)
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT d.id,s.organization_id FROM schedule_data d JOIN schedules s ON s.id=d.schedule_id WHERE s.id=$1`, scheduleID).Scan(&envelope, &actualOrg); err != nil {
			return err
		}
		if err := lockOnCallChannels(ctx, tx, before, after); err != nil {
			return err
		}
		if err := oncalljsonguard.Authorize(ctx, tx, scheduleID, actualOrg, envelope, before, after); err != nil {
			return err
		}
		RetainNextNotifications(data.V1.OnCallNotificationRules, rules)
		data.V1.OnCallNotificationRules = rules
		return nil
	}, func(tx *sql.Tx, _ *Data) error {
		_, actual, err := store.ReadOnCallUpdate(ctx, tx, scheduleID, false)
		if err != nil {
			return err
		}
		after, err := OnCallSnapshot(scheduleID, actual)
		if err != nil {
			return err
		}
		return oncalljsonguard.Finish(ctx, tx, scheduleID, actualOrg, envelope, before, after)
	})
}

// PrepareOnCallNotificationRules validates rules and assigns omitted IDs in place.
// It does not access Schedule state, authorize a parent, or perform persistence.
func PrepareOnCallNotificationRules(scheduleID uuid.UUID, rules []OnCallNotificationRule) error {
	err := validate.Range("Rules", len(rules), 0, onCallNotificationRuleLimit)
	if err != nil {
		return err
	}

	type dupkey struct {
		HasTime bool
		Time    timeutil.Clock
		Channel uuid.UUID
	}
	m := make(map[dupkey]struct{})
	for i, r := range rules {
		if r.WeekdayFilter != nil && r.WeekdayFilter.IsNever() {
			return validation.NewFieldError("Rules[%d].WeekdayFilter", "At least one day must be enabled when specifying a weekday filter.")
		}
		if r.WeekdayFilter != nil && r.Time == nil {
			return validation.NewFieldError("Rules[%d].WeekdayFilter", "Weekday filter may only be used with Time.")
		}
		if r.WeekdayFilter == nil && r.Time != nil {
			return validation.NewFieldError("Rules[%d].WeekdayFilter", "Weekday filter is required with Time.")
		}
		key := dupkey{
			HasTime: r.Time != nil,
			Channel: r.ChannelID,
		}
		if key.HasTime {
			key.Time = *r.Time
		}

		if _, ok := m[key]; ok {
			if key.HasTime {
				return validation.NewFieldError(fmt.Sprintf("Rules[%d]", i), "Rule already exists for that channel and time-of-day.")
			}

			return validation.NewFieldError(fmt.Sprintf("Rules[%d]", i), "On-change rule already exists for that channel.")
		}
		m[key] = struct{}{}
	}

	ids := make([]bool, onCallNotificationRuleLimit)
	for i, r := range rules {
		if !r.ID.valid {
			continue
		}
		fieldName := fmt.Sprintf("Rules[%d].ID", i)
		err = validate.Range(fieldName, r.ID.id, 0, onCallNotificationRuleLimit-1)
		if err != nil {
			return err
		}
		if r.ID.scheduleID != scheduleID {
			return validation.NewFieldError(fieldName, "wrong schedule ID")
		}
		if ids[r.ID.id] {
			return validation.NewFieldError(fieldName, "duplicate ID value not allowed")
		}
		ids[r.ID.id] = true
	}
	nextID := func() int {
		for i, used := range ids {
			if used {
				continue
			}
			ids[i] = true
			return i
		}

		// should be impossible
		panic("could not find unused ID")
	}

	for i, r := range rules {
		if r.ID.valid {
			continue
		}

		rules[i].ID.scheduleID = scheduleID
		rules[i].ID.valid = true
		rules[i].ID.id = nextID()
	}

	return nil
}

// OnCallNotificationRules returns the current set of OnCallNotificationRules for the provided scheduleID.
func (store *Store) OnCallNotificationRules(ctx context.Context, tx *sql.Tx, scheduleID uuid.UUID) ([]OnCallNotificationRule, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return nil, err
	}

	data, err := store.scheduleData(ctx, tx, scheduleID)
	if err != nil {
		return nil, err
	}

	return data.V1.OnCallNotificationRules, nil
}
