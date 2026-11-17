package postgres

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

// scheduleAuditShape adds no product rule. The unchanged raw Collector has
// already validated the envelope; this checks that its real, untrimmed effects
// are expressible by frozen B2 too. In particular a shift crossing its envelope
// has an effective Collector interval, but B2 requires raw containment. Never
// issue even a legacy Store capability for an unauditable shape.
func scheduleAuditShape(ctx context.Context, tx *sql.Tx, root ds.Resource) error {
	rows, err := tx.QueryContext(ctx, `SELECT d.id,s.organization_id,
 jsonb_build_object('TemporarySchedules',d.data#>'{V1,TemporarySchedules}',
 'OnCallNotificationRules',COALESCE((SELECT jsonb_agg(jsonb_build_object('ID',r->'ID','ChannelID',r->'ChannelID','Time',r->'Time','WeekdayFilter',r->'WeekdayFilter') ORDER BY n)
 FROM jsonb_array_elements(COALESCE(NULLIF(d.data#>'{V1,OnCallNotificationRules}','null'::jsonb),'[]'::jsonb)) WITH ORDINALITY nr(r,n)),'[]'::jsonb))
 FROM public.schedule_data d JOIN public.schedules s ON s.id=d.schedule_id WHERE d.schedule_id=$1`, root.ID)
	if err != nil {
		return unavailable()
	}
	defer rows.Close()
	for rows.Next() {
		var envelope int64
		var org uuid.UUID
		var raw []byte
		if rows.Scan(&envelope, &org, &raw) != nil {
			return unavailable()
		}
		if _, err := sraudit.ProjectData(sraudit.Event{RootType: sraudit.Schedule, RootID: uuid.MustParse(root.ID), TargetOrganizationID: org}, envelope, raw, sraudit.MaxEffects); err != nil {
			return unavailable()
		}
	}
	if rows.Err() != nil {
		return unavailable()
	}
	return nil
}
