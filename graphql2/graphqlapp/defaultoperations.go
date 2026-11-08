package graphqlapp

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type humanAdmission uint8

const (
	invalidHumanAuthority humanAdmission = iota
	nonHumanAdmission
	validNormalHuman
	validDefaultHuman
)

// Missing authority never changes an authenticated Human into a legacy caller.
// Non-Human compatibility is selected only by server-owned authentication
// metadata; admission itself grants no resolver or Store permissions.
func humanOperationAdmission(ctx context.Context) (humanAdmission, error) {
	deny := permission.NewAccessDenied("current Human authority is required")
	if ctx == nil {
		return invalidHumanAuthority, deny
	}
	source := permission.Source(ctx)
	if auth.RequesterFromContext(ctx) != nil || executioncontext.ExecutionContextFromContext(ctx) != nil ||
		(source != nil && source.Type == permission.SourceTypeAuthProvider) {
		ec, err := executioncontext.CheckHumanAuthority(ctx)
		if err != nil {
			return invalidHumanAuthority, err
		}
		home, ok := ec.HomeOrganizationID()
		if !ok {
			return invalidHumanAuthority, deny
		}
		if home.String() == organization.DefaultOrganizationID {
			return validDefaultHuman, nil
		}
		return validNormalHuman, nil
	}
	if permission.System(ctx) {
		return nonHumanAdmission, nil
	}
	if source != nil {
		switch source.Type {
		case permission.SourceTypeNotificationCallback, permission.SourceTypeIntegrationKey,
			permission.SourceTypeContactMethod, permission.SourceTypeHeartbeat,
			permission.SourceTypeNotificationChannel, permission.SourceTypeCalendarSubscription,
			permission.SourceTypeGQLAPIKey, permission.SourceTypeUIK:
			if source.ID != "" && permission.All(ctx) {
				return nonHumanAdmission, nil
			}
		}
		return invalidHumanAuthority, deny
	}
	if !permission.All(ctx) && permission.UserID(ctx) == "" && !permission.Service(ctx) && !permission.Team(ctx) {
		return nonHumanAdmission, nil // anonymous/public fields retain their own checks
	}
	return invalidHumanAuthority, deny
}

// Default admission is identity evidence, not a grant to legacy resolvers
// which only check permission.User/Admin. Keep its new API surface bounded;
// each allowed operation still performs its own target and relationship checks.
func defaultHumanOperation(ctx context.Context, object, field string, args map[string]interface{}) error {
	if object != "Query" && object != "Mutation" && object != "Subscription" {
		return nil
	}
	state, err := humanOperationAdmission(ctx)
	if err != nil {
		return err
	}
	if state != validDefaultHuman {
		return nil
	}
	current, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return err
	}
	if object == "Query" && field == "currentOrganizationContext" {
		return nil
	}
	deny := permission.NewAccessDenied("operation is outside approved Default management")
	if !current.Privileges().PlatformAdmin() {
		return deny
	}
	switch object {
	case "Query":
		switch field {
		case "manageableOrganizations", "service", "services", "escalationPolicy", "escalationPolicies", "schedule", "schedules", "rotation", "rotations", "user", "users", "userOverrides", "integrationKey", "integrationKeyTypes", "destinationTypes", "destinationFieldSearch", "destinationFieldValidate", "destinationFieldValueName", "destinationDisplayInfo", "timeZones", "calcRotationHandoffTimes", "experimentalFlags", "systemLimits":
			return nil
		case "config":
			all := false
			switch v := args["all"].(type) {
			case nil:
			case bool:
				all = v
			case *bool:
				all = v != nil && *v
			default:
				return deny
			}
			if !all {
				return nil // existing public UI configuration only
			}
		}
	case "Mutation":
		switch field {
		case "createService", "createEscalationPolicy", "createSchedule", "createRotation", "updateService", "updateEscalationPolicy", "updateSchedule", "updateRotation", "createEscalationPolicyStep", "updateEscalationPolicyStep", "updateScheduleTarget", "deleteAll", "setTemporarySchedule", "clearTemporarySchedules", "setScheduleOnCallNotificationRules", "createIntegrationKey", "createUserContactMethod", "updateUserContactMethod", "createUserNotificationRule", "sendContactMethodVerification", "verifyContactMethod", "updateUser", "createBasicAuth", "updateBasicAuth", "addAuthSubject", "deleteAuthSubject":
			return nil
		}
	}
	return deny
}

func isDefaultHuman(ctx context.Context) (bool, error) {
	state, err := humanOperationAdmission(ctx)
	return state == validDefaultHuman, err
}

// The new Default PA compatibility path may manage already approved Normal
// target Users. It does not create Default recovery/self-service privileges.
func authorizeDefaultUserTarget(ctx context.Context, tx *sql.Tx, id string) error {
	isDefault, err := isDefaultHuman(ctx)
	if err != nil {
		return err
	}
	if !isDefault {
		return nil
	}
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return err
	}
	if !ec.Privileges().PlatformAdmin() || tx == nil {
		return permission.NewAccessDenied("Normal User management authority is required")
	}
	home := uuid.MustParse(organization.DefaultOrganizationID)
	_, err = contactMethodTargetOrganization(ctx, tx, id, &home, true)
	return err
}
