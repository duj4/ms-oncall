package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	ds "github.com/target/goalert/deletionsafety"
)

// BatchScopeFingerprint preserves the existing authority fingerprint for other
// profiles. User roots additionally bind their persisted organization/role
// facts, so even System confirmation becomes stale after an assignment change.
// Homogeneous batches combine those facts as a set without changing BuildPlan's
// canonical version algorithm or any relationship policy.
func BatchScopeFingerprint(targets []ds.Resource, fingerprints []string) (string, error) {
	if len(targets) == 0 || len(targets) != len(fingerprints) {
		return "", unavailable()
	}
	for _, fp := range fingerprints {
		b, err := hex.DecodeString(fp)
		if err != nil || len(b) != sha256.Size || strings.ToLower(fp) != fp {
			return "", unavailable()
		}
	}
	if slices.ContainsFunc(targets, func(r ds.Resource) bool { return r.Kind != ds.ResourceUser }) {
		for _, fp := range fingerprints {
			if fp != fingerprints[0] {
				return "", unavailable()
			}
		}
		return fingerprints[0], nil
	}
	values := slices.Clone(fingerprints)
	slices.Sort(values)
	values = slices.Compact(values)
	if len(values) == 1 {
		return values[0], nil
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(values, ":")))), nil
}
