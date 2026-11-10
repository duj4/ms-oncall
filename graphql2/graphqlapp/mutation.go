package graphqlapp

import (
	context "context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/target/goalert/assignment"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/keyring"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/user"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Mutation App

func (a *App) Mutation() graphql2.MutationResolver { return (*Mutation)(a) }

func (a *Mutation) ReEncryptKeyringsAndConfig(ctx context.Context) (bool, error) {
	err := permission.LimitCheckAny(ctx, permission.Admin)
	if err != nil {
		return false, err
	}

	err = keyring.ReEncryptAll(ctx, a.DB, a.EncryptionKeys)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (a *Mutation) SendSignal(ctx context.Context, input graphql2.SendSignalInput) (bool, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return false, err
	}

	if !expflag.ContextHas(ctx, expflag.UnivKeys) {
		return false, errors.New("feature not enabled")
	}

	svcID, err := validate.ParseUUID("ServiceID", input.ServiceID)
	if err != nil {
		return false, err
	}

	organizationID, err := rootStoreOrganizationID(ctx)
	if err != nil {
		return false, err
	}
	if organizationID != nil {
		// A Service ID is only a locator. Authorize before MapDestToID,
		// which already writes notification-channel destination state.
		if _, err := a.ServiceStore.FindOne(ctx, input.ServiceID, organizationID); err != nil {
			return false, err
		}
	}

	destID, err := a.NCStore.MapDestToID(ctx, a.DB, *input.Dest)
	if err != nil {
		return false, err
	}

	data, err := json.Marshal(input.Params)
	if err != nil {
		return false, err
	}

	err = gadb.New(a.DB).IntKeyInsertSignalMessage(ctx, gadb.IntKeyInsertSignalMessageParams{
		DestID:    destID,
		ServiceID: svcID,
		Params:    data,
	})
	if err != nil {
		return false, err
	}

	return true, nil
}

func (a *Mutation) SetFavorite(ctx context.Context, input graphql2.SetFavoriteInput) (bool, error) {
	var err error
	if input.Favorite {
		err = a.FavoriteStore.Set(ctx, a.DB, permission.UserID(ctx), input.Target)
	} else {
		err = a.FavoriteStore.Unset(ctx, a.DB, permission.UserID(ctx), input.Target)
	}

	if err != nil {
		return false, err
	}
	return true, nil
}

func (a *Mutation) LinkAccount(ctx context.Context, token string) (bool, error) {
	err := a.AuthLinkStore.LinkAccount(ctx, token)
	return err == nil, err
}

func (a *Mutation) SetScheduleOnCallNotificationRules(ctx context.Context, input graphql2.SetScheduleOnCallNotificationRulesInput) (bool, error) {
	schedID, err := parseUUID("ScheduleID", input.ScheduleID)
	if err != nil {
		return false, err
	}
	organizationID, authorityErr := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	if authorityErr != nil && a.DestReg == nil {
		// Without a registry, safe destination validation is unavailable.
		return false, authorityErr
	}
	home := organizationID
	if authorityErr == nil && home != nil && len(input.Rules) > 0 {
		target, err := (*App)(a).rootReadScope(ctx, assignment.TargetTypeSchedule, input.ScheduleID)
		if err != nil {
			return false, err
		}
		if target != nil && *target != *home {
			return false, validation.NewFieldError("Rules", "Foreign Schedule destination/channel ownership policy is not defined")
		}
	}

	rules := make([]schedule.OnCallNotificationRule, 0, len(input.Rules))
	validationChannels := make(map[gadb.DestHashV1]uuid.UUID)
	for _, r := range input.Rules {
		info, err := a.DestReg.TypeInfo(ctx, r.Dest.Type)
		if err != nil {
			return false, err
		}
		if !info.IsSchedOnCallNotify() {
			return false, validation.NewFieldError("Rules[%d].Dest.Type", "unsupported destination type")
		}
		if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
			return false, err
		}
		if err := a.DestReg.ValidateDest(ctx, r.Dest); err != nil {
			return false, err
		}
		if _, err := a.DestReg.DisplayInfo(ctx, r.Dest); err != nil {
			return false, err
		}
		// Preserve duplicate-rule validation without mapping or writing channels.
		hash := r.Dest.DestHash()
		if _, ok := validationChannels[hash]; !ok {
			validationChannels[hash] = uuid.New()
		}
		r.ChannelID = validationChannels[hash]
		rules = append(rules, r.OnCallNotificationRule)
	}
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return false, err
	}
	if err := schedule.PrepareOnCallNotificationRules(schedID, rules); err != nil {
		return false, err
	}
	if authorityErr != nil {
		return false, authorityErr
	}
	err = withContextTx(ctx, a.DB, func(ctx context.Context, tx *sql.Tx) error {
		organizationID, err = existingRootTargetOrganizationTx(ctx, tx, assignment.TargetTypeSchedule, input.ScheduleID, false)
		if err != nil {
			return err
		}
		if home != nil && organizationID != nil && *home != *organizationID && len(input.Rules) > 0 {
			return validation.NewFieldError("Rules", "Foreign Schedule destination/channel ownership policy is not defined")
		}
		if organizationID != nil {
			// Use the existing nonlocking parent check before channel mapping.
			_, err := gadb.New(tx).SchedCheckOrganization(ctx, gadb.SchedCheckOrganizationParams{ScheduleID: schedID, OrganizationID: *organizationID})
			if errors.Is(err, sql.ErrNoRows) {
				return validation.NewFieldError("ScheduleID", "schedule does not exist")
			}
			if err != nil {
				return err
			}
		}
		for i, r := range input.Rules {
			chID, err := a.NCStore.MapDestToID(ctx, tx, r.Dest)
			if err != nil {
				return err
			}
			rules[i].ChannelID = chID
		}
		return a.ScheduleStore.SetOnCallNotificationRulesScoped(ctx, tx, schedID, rules, organizationID)
	})

	return err == nil, err
}

func (a *Mutation) SetTemporarySchedule(ctx context.Context, input graphql2.SetTemporaryScheduleInput) (bool, error) {
	schedID, err := parseUUID("ScheduleID", input.ScheduleID)
	if err != nil {
		return false, err
	}

	tmp := schedule.TemporarySchedule{
		Start:  input.Start,
		End:    input.End,
		Shifts: input.Shifts,
	}

	var clearSet bool
	if input.ClearStart != nil || input.ClearEnd != nil {
		if input.ClearStart == nil {
			return false, validation.NewFieldError("ClearStart", "must be set if ClearEnd is set")
		}
		if input.ClearEnd == nil {
			return false, validation.NewFieldError("ClearEnd", "must be set if ClearStart is set")
		}
		clearSet = true
	}
	organizationID, authorityErr := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	if authorityErr != nil {
		if a.UserStore == nil {
			// Missing validation dependencies must not permit unscoped access.
			return false, authorityErr
		}
		if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
			return false, err
		}
		// User existence is global exact-base validation, independent of the
		// Schedule parent. Keep it in Normalize's existing per-shift order.
		check, err := a.UserStore.UserExists(ctx)
		if err != nil {
			return false, err
		}
		if _, validationErr := tmp.Normalize(check); validationErr != nil {
			return false, validationErr
		}
		if clearSet && !input.ClearEnd.After(*input.ClearStart) {
			return false, validation.NewFieldError("ClearEnd", "must be after ClearStart")
		}
		return false, authorityErr
	}

	err = withContextTx(ctx, a.DB, func(ctx context.Context, tx *sql.Tx) error {
		organizationID, err = existingRootTargetOrganization(ctx, tx, assignment.TargetTypeSchedule, input.ScheduleID)
		if err != nil {
			return err
		}
		if clearSet {
			return a.ScheduleStore.SetClearTemporaryScheduleScoped(ctx, tx, schedID, tmp, *input.ClearStart, *input.ClearEnd, organizationID)
		}

		return a.ScheduleStore.SetTemporaryScheduleScoped(ctx, tx, schedID, tmp, organizationID)
	})

	return err == nil, err
}

func (a *Mutation) ClearTemporarySchedules(ctx context.Context, input graphql2.ClearTemporarySchedulesInput) (bool, error) {
	schedID, err := parseUUID("ScheduleID", input.ScheduleID)
	if err != nil {
		return false, err
	}
	organizationID, err := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	if err != nil {
		// Match the Store's safe range checks without accessing Schedule data.
		var futureErr, rangeErr error
		if time.Until(input.End) <= 5*time.Minute {
			futureErr = validation.NewFieldError("End", "must be at least 5 min the future")
		}
		if !input.End.After(input.Start) {
			rangeErr = validation.NewFieldError("End", "must be after Start")
		}
		if validationErr := validate.Many(futureErr, rangeErr); validationErr != nil {
			return false, validationErr
		}
		return false, err
	}

	err = withContextTx(ctx, a.DB, func(ctx context.Context, tx *sql.Tx) error {
		organizationID, err = existingRootTargetOrganization(ctx, tx, assignment.TargetTypeSchedule, input.ScheduleID)
		if err != nil {
			return err
		}
		return a.ScheduleStore.ClearTemporarySchedulesScoped(ctx, tx, schedID, input.Start, input.End, organizationID)
	})

	return err == nil, err
}

func (a *Mutation) TestContactMethod(ctx context.Context, id string) (bool, error) {
	cmID, err := validate.ParseUUID("ContactMethodID", id)
	if err != nil {
		return false, err
	}
	cm, err := (*App)(a).FindOneCM(ctx, cmID)
	if err != nil {
		return false, err
	}
	if cm == nil {
		return false, validation.NewGenericError("contact method not found")
	}
	err = a.NotificationStore.SendContactMethodTest(ctx, id)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (a *Mutation) AddAuthSubject(ctx context.Context, input user.AuthSubject) (bool, error) {
	isDefault, err := isDefaultHuman(ctx)
	if err != nil {
		return false, err
	}
	if isDefault {
		err := withContextTx(ctx, a.DB, func(ctx context.Context, tx *sql.Tx) error {
			if err := authorizeDefaultUserTarget(ctx, tx, input.UserID); err != nil {
				return err
			}
			return a.UserStore.AddAuthSubjectTx(ctx, tx, &input)
		})
		return err == nil, err
	}
	err = a.UserStore.AddAuthSubjectTx(ctx, nil, &input)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (a *Mutation) DeleteAuthSubject(ctx context.Context, input user.AuthSubject) (bool, error) {
	isDefault, err := isDefaultHuman(ctx)
	if err != nil {
		return false, err
	}
	if isDefault {
		err := withContextTx(ctx, a.DB, func(ctx context.Context, tx *sql.Tx) error {
			if err := authorizeDefaultUserTarget(ctx, tx, input.UserID); err != nil {
				return err
			}
			return a.UserStore.DeleteAuthSubjectTx(ctx, tx, &input)
		})
		return err == nil, err
	}
	err = a.UserStore.DeleteAuthSubjectTx(ctx, nil, &input)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (a *Mutation) EndAllAuthSessionsByCurrentUser(ctx context.Context) (bool, error) {
	err := a.AuthHandler.EndAllUserSessionsTx(ctx, nil)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (a *Mutation) DeleteAll(ctx context.Context, input []assignment.RawTarget) (ok bool, err error) {
	audit := newDeleteAllAudit(ctx, a.DB, input)
	defer func() {
		// Admission failures have no business transaction or trusted target.
		if audit != nil && !audit.started && err != nil {
			err = audit.nextAttempt().finish(err)
		}
	}()
	isDefault, err := isDefaultHuman(ctx)
	if err != nil {
		return false, err
	}
	var hasRootTarget, hasIntegrationKey, hasService, hasEPManagement bool
	for _, tgt := range input {
		if isDefault {
			switch tgt.TargetType() {
			case assignment.TargetTypeService, assignment.TargetTypeEscalationPolicy, assignment.TargetTypeSchedule, assignment.TargetTypeRotation, assignment.TargetTypeIntegrationKey, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule, assignment.TargetTypeUser, assignment.TargetTypeUserSession:
			default:
				return false, permission.NewAccessDenied("delete operation is outside approved Default management")
			}
		}
		if tgt.TargetType() == assignment.TargetTypeService {
			hasService = true
		}
		if tgt.TargetType() == assignment.TargetTypeIntegrationKey {
			hasIntegrationKey = true
		}
		switch tgt.TargetType() {
		case assignment.TargetTypeEscalationPolicy, assignment.TargetTypeSchedule, assignment.TargetTypeRotation:
			hasEPManagement = true
		}

		switch tgt.TargetType() {
		case assignment.TargetTypeService,
			assignment.TargetTypeSchedule,
			assignment.TargetTypeRotation,
			assignment.TargetTypeEscalationPolicy,
			assignment.TargetTypeIntegrationKey,
			assignment.TargetTypeUserOverride:
			hasRootTarget = true
		}
	}
	if hasIntegrationKey {
		// Deny incapable callers before any unrelated target-group writes.
		// Actual targets are still authorized inside each retry's transaction.
		if _, err := integrationKeyManagementAuthority(ctx); err != nil {
			return false, err
		}
	}

	if hasEPManagement {
		// EP and indirect Schedule/Rotation deletion require management eligibility
		// before the shared transaction can write any target group. Scope and
		// complete-set matching still apply independently inside each Store.
		if _, err := epManagementAuthority(ctx, epManagementDelete); err != nil {
			return false, err
		}
	}

	var homeOrganizationID *uuid.UUID
	if hasService {
		// Role-ineligible Service deletion must precede every target-group write.
		// Complete-set validation remains in the existing scoped Store operation.
		var err error
		homeOrganizationID, err = serviceManagementAuthority(ctx, serviceManagementDelete)
		if err != nil {
			return false, err
		}
	} else if hasRootTarget {
		var err error
		if hasEPManagement || hasIntegrationKey {
			homeOrganizationID, err = rootManagementHome(ctx)
		} else {
			homeOrganizationID, err = rootStoreOrganizationID(ctx)
		}
		if err != nil {
			return false, err
		}
	}

	// Retry because deleting frequently can cause a deadlock
	// under heavy load.
	retryLogger := retry.Log(ctx)
	if audit != nil {
		retryLogger = retry.Log(audit.retryContext())
	}
	err = retry.DoTemporaryError(func(int) error {
		var attempt *deleteAllAttempt
		if audit != nil {
			attempt = audit.nextAttempt()
		}
		return a.tryDeleteAll(ctx, input, homeOrganizationID, attempt)
	},
		retryLogger,
		retry.Limit(5),
		retry.FibBackoff(time.Second),
	)

	return err == nil, err
}

func (a *Mutation) tryDeleteAll(ctx context.Context, input []assignment.RawTarget, homeOrganizationID *uuid.UUID, audit *deleteAllAttempt) (err error) {
	if audit != nil {
		defer func() { err = audit.finish(err) }()
	}
	isDefault, err := isDefaultHuman(ctx)
	if err != nil {
		return err
	}
	var tx *sql.Tx
	if audit == nil {
		tx, err = a.DB.BeginTx(ctx, nil)
	} else {
		tx, err = audit.begin(ctx)
	}
	if err != nil {
		return err
	}
	if audit == nil {
		defer sqlutil.Rollback(ctx, "graphql: delete all", tx)
	}

	m := make(map[assignment.TargetType][]string)
	for _, tgt := range input {
		m[tgt.TargetType()] = append(m[tgt.TargetType()], tgt.TargetID())
	}
	if isDefault {
		for _, id := range m[assignment.TargetTypeUser] {
			if err := authorizeDefaultUserTarget(ctx, tx, id); err != nil {
				return err
			}
		}
		for _, id := range m[assignment.TargetTypeUserSession] {
			var owner string
			err := tx.QueryRowContext(ctx, `SELECT user_id FROM auth_user_sessions WHERE id=$1 FOR UPDATE`, id).Scan(&owner)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			if err := authorizeDefaultUserTarget(ctx, tx, owner); err != nil {
				return err
			}
		}
	}

	// Resolve Rotation before Schedule to retain the existing table/root lock
	// order. These are independent group scopes, never a shared global scope.
	rootScopes := make(map[assignment.TargetType]*uuid.UUID)
	for _, typ := range []assignment.TargetType{assignment.TargetTypeRotation, assignment.TargetTypeSchedule} {
		if len(m[typ]) == 0 {
			continue
		}
		rootScopes[typ], err = existingRootDeleteTargetOrganization(ctx, tx, typ, m[typ])
		if err != nil {
			return err
		}
	}
	if err := validateScheduleRotationDeleteTx(ctx, tx, m, rootScopes[assignment.TargetTypeRotation], rootScopes[assignment.TargetTypeSchedule]); err != nil {
		return err
	}

	order := []assignment.TargetType{
		assignment.TargetTypeRotation,
		assignment.TargetTypeUserOverride,
		assignment.TargetTypeSchedule,
		assignment.TargetTypeCalendarSubscription,
		assignment.TargetTypeUser,
		assignment.TargetTypeIntegrationKey,
		assignment.TargetTypeHeartbeatMonitor,
		assignment.TargetTypeService,
		assignment.TargetTypeEscalationPolicy,
		assignment.TargetTypeNotificationRule,
		assignment.TargetTypeContactMethod,
		assignment.TargetTypeUserSession,
	}

	if audit != nil {
		audit.groupsStarted = true
	}
	for _, typ := range order {
		ids := m[typ]
		if len(ids) == 0 {
			continue
		}
		switch typ {
		case assignment.TargetTypeUserOverride:
			err = errors.Wrap(a.OverrideStore.DeleteUserOverrideTxScoped(ctx, tx, ids, homeOrganizationID), "delete user overrides")
		case assignment.TargetTypeUser:
			err = errors.Wrap(a.UserStore.DeleteManyTx(ctx, tx, ids), "delete users")
		case assignment.TargetTypeService:
			// Resolve only this group's scope. In particular, a Foreign Service
			// must not grant its Organization to Schedule/Rotation/EP deletion.
			var serviceOrg *uuid.UUID
			serviceOrg, err = serviceDeleteTargetOrganization(ctx, tx, ids)
			if err == nil && audit != nil {
				err = audit.capture(ctx, ids, serviceOrg)
			}
			if err == nil {
				if audit != nil {
					audit.service.deletedRoots, err = a.ServiceStore.DeleteManyForAuditTx(ctx, tx, ids, serviceOrg)
				} else {
					err = a.ServiceStore.DeleteManyTx(ctx, tx, ids, serviceOrg)
				}
			}
			if err == nil && audit != nil {
				err = audit.witness(ctx)
			}
			err = errors.Wrap(err, "delete services")
		case assignment.TargetTypeEscalationPolicy:
			var policyOrg *uuid.UUID
			policyOrg, err = existingRootDeleteTargetOrganization(ctx, tx, typ, ids)
			if err == nil {
				err = a.PolicyStore.DeleteManyPoliciesTx(ctx, tx, ids, policyOrg)
			}
			err = errors.Wrap(err, "delete escalation policies")
		case assignment.TargetTypeIntegrationKey:
			var serviceAudit *serviceDeleteAttempt
			if audit != nil {
				serviceAudit = audit.service
			}
			if serviceAudit == nil {
				err = a.deleteIntegrationKeys(ctx, tx, ids)
			} else {
				err = a.deleteIntegrationKeysWithAudit(ctx, tx, ids, serviceAudit)
			}
			err = errors.Wrap(err, "delete integration keys")
		case assignment.TargetTypeSchedule:
			err = errors.Wrap(a.ScheduleStore.DeleteManyTx(ctx, tx, ids, rootScopes[typ]), "delete schedules")
		case assignment.TargetTypeCalendarSubscription:
			err = errors.Wrap(a.CalSubStore.DeleteTx(ctx, tx, permission.UserID(ctx), ids...), "delete calendar subscriptions")
		case assignment.TargetTypeRotation:
			err = errors.Wrap(a.RotationStore.DeleteManyTx(ctx, tx, ids, rootScopes[typ]), "delete rotations")
		case assignment.TargetTypeContactMethod:
			if audit == nil {
				err = a.CMStore.Delete(ctx, tx, ids...)
			} else {
				result, deleteErr := a.CMStore.DeleteForAuditTx(ctx, tx, ids...)
				audit.collect(result, "contact_method")
				err = deleteErr
			}
			err = errors.Wrap(err, "delete contact methods")
		case assignment.TargetTypeNotificationRule:
			if audit == nil {
				err = a.NRStore.DeleteTx(ctx, tx, ids...)
			} else {
				result, deleteErr := a.NRStore.DeleteForAuditTx(ctx, tx, ids...)
				audit.collect(result, "notification_rule")
				err = deleteErr
			}
			err = errors.Wrap(err, "delete notification rules")
		case assignment.TargetTypeHeartbeatMonitor:
			err = errors.Wrap(a.HeartbeatStore.DeleteTx(ctx, tx, ids...), "delete heartbeat monitors")
		case assignment.TargetTypeUserSession:
			err = errors.Wrap(a.AuthHandler.EndUserSessionTx(ctx, tx, ids...), "end user sessions")
		default:
			return validation.NewFieldError("type", "unsupported type "+typ.String())
		}
		if err != nil {
			return err
		}
	}

	if audit != nil {
		return audit.commit(ctx)
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}
