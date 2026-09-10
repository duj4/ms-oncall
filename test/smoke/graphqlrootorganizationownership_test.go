package smoke

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/test/smoke/harness"
)

func TestGraphQLRootOrganizationOwnership(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, "", "")
	defer h.Close()

	serviceResponse := h.GraphQLQuery2(`
		mutation {
			createService(input: {
				name: "Organization Ownership Service"
				newEscalationPolicy: {name: "Organization Ownership Policy"}
			}) {
				id
				escalationPolicy {id}
			}
		}
	`)
	require.Empty(t, serviceResponse.Errors)
	var serviceResult struct {
		CreateService struct {
			ID               string
			EscalationPolicy struct{ ID string }
		}
	}
	require.NoError(t, json.Unmarshal(serviceResponse.Data, &serviceResult))
	require.NotEmpty(t, serviceResult.CreateService.ID)
	require.NotEmpty(t, serviceResult.CreateService.EscalationPolicy.ID)

	scheduleResponse := h.GraphQLQuery2(`
		mutation {
			createSchedule(input: {
				name: "Organization Ownership Schedule"
				timeZone: "Etc/UTC"
				targets: [{
					newRotation: {
						name: "Organization Ownership Rotation"
						timeZone: "Etc/UTC"
						start: "2026-09-10T00:00:00Z"
						type: daily
					}
					rules: [{
						start: "00:00"
						end: "23:59"
						weekdayFilter: [true, true, true, true, true, true, true]
					}]
				}]
			}) {
				id
				targets {target {id}}
			}
		}
	`)
	require.Empty(t, scheduleResponse.Errors)
	var scheduleResult struct {
		CreateSchedule struct {
			ID      string
			Targets []struct{ Target struct{ ID string } }
		}
	}
	require.NoError(t, json.Unmarshal(scheduleResponse.Data, &scheduleResult))
	require.NotEmpty(t, scheduleResult.CreateSchedule.ID)
	require.Len(t, scheduleResult.CreateSchedule.Targets, 1)
	require.NotEmpty(t, scheduleResult.CreateSchedule.Targets[0].Target.ID)

	wantOrganizationID := uuid.MustParse(harness.SmokeOrganizationID)
	for _, root := range []struct {
		table string
		id    string
	}{
		{table: "services", id: serviceResult.CreateService.ID},
		{table: "escalation_policies", id: serviceResult.CreateService.EscalationPolicy.ID},
		{table: "schedules", id: scheduleResult.CreateSchedule.ID},
		{table: "rotations", id: scheduleResult.CreateSchedule.Targets[0].Target.ID},
	} {
		var gotOrganizationID uuid.UUID
		err := h.App().DB().QueryRow(
			"SELECT organization_id FROM "+root.table+" WHERE id = $1",
			root.id,
		).Scan(&gotOrganizationID)
		require.NoError(t, err)
		require.Equal(t, wantOrganizationID, gotOrganizationID, root.table)
	}
}

func TestGraphQLRootOrganizationOwnershipFailsClosed(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, "", "")
	defer h.Close()

	missingOrganizationUserID := h.UUID("missing-org-user")
	defaultOrganizationUserID := h.UUID("default-org-user")
	_, err := h.App().DB().Exec(`
		INSERT INTO users (id, name, email, role)
		VALUES
			($1, 'Missing Organization User', '', 'user'),
			($2, 'Default Organization User', '', 'user')
	`, missingOrganizationUserID, defaultOrganizationUserID)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`
		INSERT INTO user_organization_assignments (
			user_id,
			effective_organization_id,
			effective_organization_classification,
			effective_normal_organization_id,
			organization_role,
			mapping_outcome,
			authoritative_evaluated_at,
			source_config_version,
			matched_count
		) VALUES (
			$1,
			$2,
			'DEFAULT',
			NULL,
			'NONE',
			'ZERO',
			now(),
			'smoke-default-restricted-v1',
			0
		);
	`, defaultOrganizationUserID, organization.DefaultOrganizationID)
	require.NoError(t, err)

	mutations := []struct {
		name  string
		query string
	}{
		{
			name: "service",
			query: `mutation {
				createService(input: {
					name: "Denied Root Ownership Service"
					newEscalationPolicy: {name: "Denied Nested Policy"}
				}) {id}
			}`,
		},
		{
			name: "schedule",
			query: `mutation {
				createSchedule(input: {
					name: "Denied Root Ownership Schedule"
					timeZone: "Etc/UTC"
				}) {id}
			}`,
		},
		{
			name: "rotation",
			query: `mutation {
				createRotation(input: {
					name: "Denied Root Ownership Rotation"
					timeZone: "Etc/UTC"
					start: "2026-09-10T00:00:00Z"
					type: daily
				}) {id}
			}`,
		},
		{
			name:  "escalation policy",
			query: `mutation {createEscalationPolicy(input: {name: "Denied Root Ownership Policy"}) {id}}`,
		},
	}
	for _, authority := range []struct {
		name   string
		userID string
	}{
		{name: "missing canonical ExecutionContext", userID: missingOrganizationUserID},
		{name: "Default-restricted authority", userID: defaultOrganizationUserID},
	} {
		t.Run(authority.name, func(t *testing.T) {
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					response := h.GraphQLQueryUserT(t, authority.userID, mutation.query)
					require.NotEmpty(t, response.Errors)
					require.True(t, strings.Contains(response.Errors[0].Message, "normal Organization scoped authority is required"), response.Errors[0].Message)
				})
			}
		})
	}

	for _, table := range []string{"services", "schedules", "rotations", "escalation_policies"} {
		var rootCount int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM `+table).Scan(&rootCount))
		require.Zero(t, rootCount, table)
	}

	var defaultAssignmentCount int
	require.NoError(t, h.App().DB().QueryRow(`
		SELECT count(*)
		FROM user_organization_assignments
		WHERE user_id = $1
			AND effective_organization_id = $2
			AND effective_organization_classification = 'DEFAULT'
			AND effective_normal_organization_id IS NULL
			AND organization_role = 'NONE'
			AND mapping_outcome = 'ZERO'
			AND matched_count = 0
	`, defaultOrganizationUserID, organization.DefaultOrganizationID).Scan(&defaultAssignmentCount))
	require.Equal(t, 1, defaultAssignmentCount)
}
