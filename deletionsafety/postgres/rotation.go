package postgres

import "github.com/target/goalert/util/sqlutil"

// validateRotation corroborates the entire current roster, including reverse
// State references. A LEFT JOIN or a foreign State must never hide a corrupt row.
// Version 1 is a historical engine runtime and has no deletion mapping here.
// Only a Rotation root admits this closure; other root profiles retain their
// existing unsupported runtime boundary. The caller owns snapshot/lock safety.
func (c *collector) validateRotation(ids []string) error {
	var invalid bool
	err := c.queryRow(userOrganizations+` SELECT
 EXISTS(SELECT FROM public.rotations r WHERE r.id=ANY($1::uuid[]) AND (
   r.participant_count<>(SELECT count(*) FROM public.rotation_participants p WHERE p.rotation_id=r.id)
   OR (r.participant_count>0 AND NOT EXISTS(SELECT FROM public.rotation_state s WHERE s.rotation_id=r.id))
   OR (r.participant_count=0 AND EXISTS(SELECT FROM public.rotation_state s WHERE s.rotation_id=r.id))))
 OR EXISTS(SELECT FROM public.rotation_participants p
   LEFT JOIN public.rotations r ON r.id=p.rotation_id
   LEFT JOIN user_org u ON u.user_id=p.user_id AND u.organization_id=r.organization_id
   WHERE p.rotation_id=ANY($1::uuid[]) AND (u.user_id IS NULL
     OR p.id='00000000-0000-0000-0000-000000000000' OR p.user_id='00000000-0000-0000-0000-000000000000' OR p.position<0
     OR p.position>=r.participant_count
     OR (SELECT count(*) FROM public.rotation_participants other WHERE other.rotation_id=p.rotation_id AND other.position=p.position)<>1))
 OR EXISTS(SELECT FROM public.rotation_state s
   LEFT JOIN public.rotation_participants p ON p.id=s.rotation_participant_id
   WHERE (s.rotation_id=ANY($1::uuid[]) OR p.rotation_id=ANY($1::uuid[]))
   AND (s.id<=0 OR p.id IS NULL OR p.rotation_id<>s.rotation_id OR p.position<>s.position
     OR s.version<>2 OR NOT isfinite(s.shift_start)
     OR s.shift_start<'0001-01-01'::timestamptz OR s.shift_start>='10000-01-01'::timestamptz))`, sqlutil.StringArray(ids)).Scan(&invalid)
	if err != nil {
		return err
	}
	if invalid {
		return unavailable()
	}
	return nil
}
