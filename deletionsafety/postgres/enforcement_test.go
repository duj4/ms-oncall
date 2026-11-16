package postgres

import (
	"regexp"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	guard "github.com/target/goalert/internal/deletionguard"
)

// Every actual relational projection, including empty/unsupported probes and
// reference identity checks, must be fenced. A newly added projection cannot
// silently widen the Collector read set behind the enforcement protocol.
func TestEnforcementFenceCoversCollectorReadSet(t *testing.T) {
	queries := []string{userOrganizations, `SELECT FROM public.schedule_data JOIN public.users`}
	for _, q := range identityQueries {
		queries = append(queries, q)
	}
	for _, q := range ownershipQueries {
		queries = append(queries, q.query)
	}
	for _, q := range referenceQueries {
		queries = append(queries, q)
	}
	for _, q := range unsupportedQueries {
		queries = append(queries, q)
	}
	for kind := ds.ResourceService; kind <= ds.ResourceScheduleTarget; kind++ {
		for _, p := range projections(kind) {
			queries = append(queries, p.from)
		}
	}
	table := regexp.MustCompile(`public\.([a-z_]+)`)
	for _, q := range queries {
		for _, match := range table.FindAllStringSubmatch(q, -1) {
			require.True(t, slices.Contains(guard.Tables(), match[1]), "unfenced collector table: %s", match[1])
		}
	}
}
