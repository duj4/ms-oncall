package postgres

import "github.com/target/goalert/util/sqlutil"

// Root deletion retains the Schedule and both optional User endpoints. Validate
// each endpoint against the actual parent's scope, also for global collectors.
// NULL on one side is a legal add-only/remove-only Override; both absent,
// equal endpoints, broken joins and unknown user assignments remain unavailable.
func (c *collector) validateUserOverrides(ids []string) error {
	var invalid bool
	err := c.queryRow(userOrganizations+` SELECT EXISTS(
 SELECT FROM public.user_overrides o
 LEFT JOIN public.schedules s ON s.id=o.tgt_schedule_id
 LEFT JOIN user_org a ON a.user_id=o.add_user_id AND a.organization_id=s.organization_id
 LEFT JOIN user_org r ON r.user_id=o.remove_user_id AND r.organization_id=s.organization_id
 WHERE o.id=ANY($1::uuid[]) AND (s.id IS NULL
 OR (o.add_user_id IS NULL AND o.remove_user_id IS NULL)
 OR o.add_user_id=o.remove_user_id
 OR (o.add_user_id IS NOT NULL AND a.user_id IS NULL)
 OR (o.remove_user_id IS NOT NULL AND r.user_id IS NULL)
 OR NOT isfinite(o.start_time) OR NOT isfinite(o.end_time)
 OR o.start_time<'0001-01-01'::timestamptz OR o.end_time>='10000-01-01'::timestamptz
 OR o.end_time<=o.start_time))`, sqlutil.StringArray(ids)).Scan(&invalid)
	if err != nil {
		return err
	}
	if invalid {
		return unavailable()
	}
	return nil
}
