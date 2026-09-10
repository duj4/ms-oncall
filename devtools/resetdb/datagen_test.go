package main

import (
	"testing"

	"github.com/google/uuid"
)

func TestGenerateAssignsExplicitLocalOrganizationOwnership(t *testing.T) {
	config := datagenConfig{
		Seed:                 1,
		UserCount:            1,
		CMMax:                1,
		NRMax:                1,
		EPCount:              1,
		EPMaxStep:            1,
		EPMaxAssigned:        1,
		SvcCount:             1,
		RotationMaxPart:      1,
		ScheduleCount:        1,
		AlertClosedCount:     1,
		AlertActiveCount:     1,
		RotationCount:        1,
		IntegrationKeyMax:    1,
		ScheduleMaxRules:     1,
		ScheduleMaxOverrides: 1,
		HeartbeatMonitorMax:  1,
		UserFavMax:           1,
		SvcLabelMax:          1,
		UniqueLabelKeys:      1,
		LabelValueMax:        1,
		MsgPerAlertMax:       1,
	}
	data := config.Generate()
	if data.OrganizationID == uuid.Nil {
		t.Fatal("generated local Organization identity is nil")
	}
	for name, owners := range map[string][]uuid.UUID{
		"services":            {data.Services[0].OrganizationID},
		"schedules":           {data.Schedules[0].OrganizationID},
		"rotations":           {data.Rotations[0].OrganizationID},
		"escalation policies": {data.EscalationPolicies[0].OrganizationID},
	} {
		for _, owner := range owners {
			if owner != data.OrganizationID {
				t.Fatalf("%s owner = %s, want explicit generated owner %s", name, owner, data.OrganizationID)
			}
		}
	}
}
