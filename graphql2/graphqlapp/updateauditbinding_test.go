package graphqlapp

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/internal/updateguard"
)

func TestUpdateReceiptMustMatchConfirmedIdentityScopeAndSource(t *testing.T) {
	e := epUpdateTestEvent(sd3InternalSystemContext())
	original := epUpdateTestEffect(t, e)
	expected, err := updateEPConsent([]epaudit.Effect{original})
	require.NoError(t, err)
	for _, mode := range []string{"match", "root", "organization", "parent", "target", "source", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			tx := new(sql.Tx)
			resource := ds.Resource{Kind: ds.ResourceEscalationPolicyAction, ID: original.ResourceUUID.String()}
			ctx, err := updateguard.Bind(context.Background(), tx, []ds.Resource{resource})
			require.NoError(t, err)
			require.NoError(t, updateguard.Consume(ctx, tx, resource))
			actual := original
			switch mode {
			case "root":
				actual.RootID = uuid.New()
			case "organization":
				actual.TargetOrganizationID = uuid.New()
			case "parent":
				id := uuid.New()
				actual.ParentStepID = &id
			case "target":
				id := uuid.New()
				actual.TargetID = &id
			case "source":
				actual.Provenance = "CASCADE"
			}
			receipts := []epaudit.Effect{actual}
			if mode == "duplicate" {
				receipts = append(receipts, actual)
			}
			err = (updateAssessment{expected: expected}).finish(ctx, tx, receipts)
			if mode == "match" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
