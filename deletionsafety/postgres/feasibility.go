package postgres

import (
	"context"
	"database/sql"

	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

// CheckDeleteFeasibility checks the native profiles' static execution boundary
// against a complete, authorized plan. Domain policy describes the intended
// effects; it does not imply that a frozen B2 adapter supports those effects.
// This read-only check issues no guard, locks, writes or audit. Enforcement
// must still stabilize, recollect, authorize, check confirmation and bind its
// own transaction. A BLOCK remains inspectable and cannot be confirmed away.
func CheckDeleteFeasibility(ctx context.Context, tx *sql.Tx, plan ds.DeletionPlan) error {
	if ctx == nil || tx == nil {
		return unavailable()
	}
	if err := checkDeletePlan(plan); err != nil {
		return err
	}
	if !plan.CanProceed() {
		return nil
	}
	if plan.Targets()[0].Kind == ds.ResourceContactMethod {
		var ids []string
		for _, root := range plan.Targets() {
			ids = append(ids, root.ID)
		}
		// Match the existing CM guard's unsupported bundle/non-FK boundary.
		// Private status_details is used only as an internal predicate.
		var unsupported bool
		err := tx.QueryRowContext(ctx, `WITH selected_messages AS (
 SELECT m.id,m.contact_method_id,m.message_type,m.last_status FROM public.outgoing_messages m
 WHERE m.contact_method_id=ANY($1::uuid[]) OR m.user_verification_code_id IN (
 SELECT id FROM public.user_verification_codes WHERE contact_method_id=ANY($1::uuid[])))
 SELECT EXISTS(SELECT FROM selected_messages WHERE contact_method_id IS NULL
 OR NOT(contact_method_id=ANY($1::uuid[])) OR message_type IN ('alert_notification_bundle','alert_status_update_bundle') OR last_status='bundled')
 OR EXISTS(SELECT FROM public.outgoing_messages b JOIN selected_messages m ON b.status_details=m.id::text WHERE b.last_status='bundled')`, pq.Array(ids)).Scan(&unsupported)
		if err != nil || unsupported {
			return unavailable()
		}
	}
	for _, root := range plan.Targets() {
		if root.Kind == ds.ResourceSchedule {
			if err := scheduleAuditShape(ctx, tx, root); err != nil {
				return safeError(err)
			}
		}
	}
	return nil
}

func checkDeletePlan(plan ds.DeletionPlan) error {
	targets := plan.Targets()
	if len(targets) == 0 || plan.ImpactVersion() == "" {
		return unavailable()
	}
	if len(targets) > 50 {
		return limitExceeded()
	}
	kind := targets[0].Kind
	switch kind {
	case ds.ResourceNotificationRule, ds.ResourceContactMethod, ds.ResourceService,
		ds.ResourceEscalationPolicy, ds.ResourceSchedule, ds.ResourceRotation,
		ds.ResourceUserOverride, ds.ResourceIntegrationKey, ds.ResourceUser:
	default:
		return unavailable()
	}
	for _, root := range targets {
		if root.Kind != kind {
			return unavailable()
		}
	}
	if !plan.CanProceed() {
		return nil
	}
	if kind == ds.ResourceEscalationPolicy {
		for _, impact := range plan.Impacts() {
			if impact.Referencing.Kind == ds.ResourceNotificationChannel {
				return unavailable() // native EP profile has no approved Channel scope
			}
		}
	}
	for _, change := range plan.Changes() {
		unsupported := false
		switch kind {
		case ds.ResourceService:
			// SD3 permits Alert/Key/Favorite business effects and approved
			// Alert-owned cleanup, but has no Message/Signal B2 projection.
			unsupported = change.Resource.Kind == ds.ResourceOutgoingMessage || change.Resource.Kind == ds.ResourcePendingSignal
		case ds.ResourceEscalationPolicy:
			unsupported = change.Resource.Kind == ds.ResourceOutgoingMessage || change.Resource.Kind == ds.ResourceEscalationHistory
		case ds.ResourceSchedule:
			// Preserve the accepted native profile's history boundary, even
			// though the older audit envelope has a History representation.
			unsupported = change.Resource.Kind == ds.ResourceOutgoingMessage || change.Resource.Kind == ds.ResourceScheduleHistory
		case ds.ResourceUser:
			// These effects are not admitted by the User-only SD8 profile.
			// In particular a closed cycle is INFO/DELETED, not retained.
			switch change.Resource.Kind {
			case ds.ResourceNotificationPolicyCycle, ds.ResourceOutgoingMessage,
				ds.ResourceVerificationState, ds.ResourceAlertStatusSubscription,
				ds.ResourceLegacyKeyAttribution:
				unsupported = true
			case ds.ResourceUser:
				unsupported = change.Cause != ds.CauseExplicit // external status-CM setting
			}
		}
		if unsupported {
			return unavailable()
		}
	}
	return nil
}
