package organization

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	// ErrInvalidOrganizationAssignmentResolverConfiguration indicates that a
	// resolver configuration snapshot is malformed or contradictory.
	ErrInvalidOrganizationAssignmentResolverConfiguration = errors.New("invalid Organization assignment resolver configuration")
	// ErrInvalidOrganizationAssignmentResolverInput indicates that at least one
	// explicitly supplied verified mapping identifier is malformed.
	ErrInvalidOrganizationAssignmentResolverInput = errors.New("invalid Organization assignment resolver input")
	// ErrStaleOrganizationAssignmentResolverConfiguration indicates that a
	// configured durable mapping target no longer exists.
	ErrStaleOrganizationAssignmentResolverConfiguration = errors.New("stale Organization assignment resolver configuration")
)

// OrganizationAssignmentMappingRule maps one already-verified enterprise
// identifier to one exact durable NormalOrganization corporate mapping key.
type OrganizationAssignmentMappingRule struct {
	EnterpriseMappingIdentifier string
	CorporateMappingKey         string
}

// OrganizationAssignmentResolverConfig is an explicit immutable configuration
// snapshot once accepted by NewOrganizationAssignmentResolver.
type OrganizationAssignmentResolverConfig struct {
	SourceConfigVersion string
	Rules               []OrganizationAssignmentMappingRule
}

// OrganizationAssignmentDecision is a bounded cardinality and effective-target
// decision. It deliberately contains no User, role, capability, persistence
// evidence, or assignment-mutation fields.
type OrganizationAssignmentDecision struct {
	MappingOutcome                      MappingOutcome
	MatchedCount                        int
	EffectiveOrganizationID             uuid.UUID
	EffectiveOrganizationClassification Classification
	SourceConfigVersion                 string
}

type organizationAssignmentReader interface {
	FindNormalByCorporateMappingKey(context.Context, string) (*NormalOrganization, error)
	FindDefault(context.Context) (*Organization, error)
}

// OrganizationAssignmentResolver deterministically resolves explicitly
// supplied already-verified enterprise mapping identifiers through a minimal
// read-only Organization seam.
type OrganizationAssignmentResolver struct {
	reader                organizationAssignmentReader
	sourceConfigVersion   string
	corporateKeyByMapping map[string]string
}

// NewOrganizationAssignmentResolver validates and copies a complete
// configuration snapshot. No Organization lookup occurs during construction.
func NewOrganizationAssignmentResolver(reader organizationAssignmentReader, config OrganizationAssignmentResolverConfig) (*OrganizationAssignmentResolver, error) {
	if nilOrganizationAssignmentReader(reader) {
		return nil, fmt.Errorf("%w: Organization reader is required", ErrInvalidOrganizationAssignmentResolverConfiguration)
	}
	if err := validateSourceConfigVersion(config.SourceConfigVersion); err != nil {
		return nil, fmt.Errorf("%w: source/config version is invalid", ErrInvalidOrganizationAssignmentResolverConfiguration)
	}
	if len(config.Rules) > math.MaxInt32 {
		return nil, fmt.Errorf("%w: too many mapping rules", ErrInvalidOrganizationAssignmentResolverConfiguration)
	}

	corporateKeyByMapping := make(map[string]string, len(config.Rules))
	for _, rule := range config.Rules {
		mappingIdentifier, err := normalizeEnterpriseMappingIdentifier(rule.EnterpriseMappingIdentifier)
		if err != nil {
			return nil, fmt.Errorf("%w: mapping rule identifier is invalid", ErrInvalidOrganizationAssignmentResolverConfiguration)
		}
		if err := validateResolverCorporateMappingKey(rule.CorporateMappingKey); err != nil {
			return nil, fmt.Errorf("%w: corporate mapping target is invalid", ErrInvalidOrganizationAssignmentResolverConfiguration)
		}
		configuredKey, exists := corporateKeyByMapping[mappingIdentifier]
		if exists && configuredKey != rule.CorporateMappingKey {
			return nil, fmt.Errorf("%w: normalized mapping rule is contradictory", ErrInvalidOrganizationAssignmentResolverConfiguration)
		}
		corporateKeyByMapping[mappingIdentifier] = rule.CorporateMappingKey
	}

	return &OrganizationAssignmentResolver{
		reader:                reader,
		sourceConfigVersion:   config.SourceConfigVersion,
		corporateKeyByMapping: corporateKeyByMapping,
	}, nil
}

// Resolve returns a deterministic Organization cardinality and effective-target
// decision. Identifiers are assumed to have already been verified by a caller;
// this method does not authenticate or interpret identity-provider claims.
func (r *OrganizationAssignmentResolver) Resolve(ctx context.Context, enterpriseMappingIdentifiers []string) (OrganizationAssignmentDecision, error) {
	var zero OrganizationAssignmentDecision
	if r == nil || nilOrganizationAssignmentReader(r.reader) {
		return zero, fmt.Errorf("%w: resolver is not initialized", ErrInvalidOrganizationAssignmentResolverConfiguration)
	}

	normalizedInputs := make(map[string]struct{}, len(enterpriseMappingIdentifiers))
	for _, value := range enterpriseMappingIdentifiers {
		normalized, err := normalizeEnterpriseMappingIdentifier(value)
		if err != nil {
			return zero, fmt.Errorf("%w: mapping identifier is invalid", ErrInvalidOrganizationAssignmentResolverInput)
		}
		normalizedInputs[normalized] = struct{}{}
	}

	corporateKeys := make(map[string]struct{}, len(normalizedInputs))
	for identifier := range normalizedInputs {
		if key, ok := r.corporateKeyByMapping[identifier]; ok {
			corporateKeys[key] = struct{}{}
		}
	}
	sortedCorporateKeys := make([]string, 0, len(corporateKeys))
	for key := range corporateKeys {
		sortedCorporateKeys = append(sortedCorporateKeys, key)
	}
	sort.Strings(sortedCorporateKeys)

	type observedState struct {
		lifecycle Lifecycle
	}
	observedByID := make(map[uuid.UUID]observedState, len(sortedCorporateKeys))
	activeByID := make(map[uuid.UUID]struct{}, len(sortedCorporateKeys))
	for _, key := range sortedCorporateKeys {
		normal, err := r.reader.FindNormalByCorporateMappingKey(ctx, key)
		if errors.Is(err, ErrNotFound) {
			return zero, fmt.Errorf("%w: configured target is unavailable", ErrStaleOrganizationAssignmentResolverConfiguration)
		}
		if err != nil {
			return zero, fmt.Errorf("resolve configured Organization target: %w", err)
		}
		if err := validateResolvedNormalOrganization(key, normal); err != nil {
			return zero, err
		}
		state := observedState{lifecycle: normal.Lifecycle}
		if previous, ok := observedByID[normal.ID]; ok && previous != state {
			return zero, fmt.Errorf("%w: inconsistent repeated Normal Organization identity", ErrInvariantViolation)
		}
		observedByID[normal.ID] = state
		if normal.Lifecycle == LifecycleActive {
			activeByID[normal.ID] = struct{}{}
		}
	}

	matchedCount := len(activeByID)
	decision := OrganizationAssignmentDecision{
		MatchedCount:        matchedCount,
		SourceConfigVersion: r.sourceConfigVersion,
	}
	if matchedCount == 1 {
		for id := range activeByID {
			decision.MappingOutcome = MappingOutcomeExactlyOne
			decision.EffectiveOrganizationID = id
			decision.EffectiveOrganizationClassification = ClassificationNormal
		}
		return decision, nil
	}

	defaultOrg, err := r.reader.FindDefault(ctx)
	if err != nil {
		return zero, fmt.Errorf("resolve distinguished Default Organization: %w", err)
	}
	if err := validateResolvedDefaultOrganization(defaultOrg); err != nil {
		return zero, err
	}
	decision.EffectiveOrganizationID = defaultOrg.ID
	decision.EffectiveOrganizationClassification = ClassificationDefault
	if matchedCount == 0 {
		decision.MappingOutcome = MappingOutcomeZero
	} else {
		decision.MappingOutcome = MappingOutcomeMultiple
	}
	return decision, nil
}

func nilOrganizationAssignmentReader(reader organizationAssignmentReader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}

func normalizeEnterpriseMappingIdentifier(value string) (string, error) {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("invalid enterprise mapping identifier")
	}
	normalized := strings.Trim(value, sourceConfigVersionBoundaryWhitespace)
	if normalized == "" {
		return "", fmt.Errorf("invalid enterprise mapping identifier")
	}
	return normalized, nil
}

func validateResolverCorporateMappingKey(value string) error {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || value == "" ||
		strings.Trim(value, sourceConfigVersionBoundaryWhitespace) != value {
		return fmt.Errorf("invalid corporate mapping key")
	}
	return nil
}

func validateResolvedNormalOrganization(expectedCorporateKey string, normal *NormalOrganization) error {
	if normal == nil || normal.ID == uuid.Nil || normal.ID.String() == DefaultOrganizationID ||
		normal.Classification != ClassificationNormal || normal.CorporateMappingKey != expectedCorporateKey {
		return fmt.Errorf("%w: contradictory Normal Organization lookup result", ErrInvariantViolation)
	}
	if err := validateLifecycle(normal.Lifecycle); err != nil {
		return err
	}
	return nil
}

func validateResolvedDefaultOrganization(org *Organization) error {
	if org == nil || org.ID.String() != DefaultOrganizationID ||
		org.Classification != ClassificationDefault ||
		org.CanonicalName != DefaultOrganizationCanonicalName ||
		org.Lifecycle != LifecycleActive {
		return fmt.Errorf("%w: contradictory distinguished Default Organization", ErrInvariantViolation)
	}
	return nil
}

var _ organizationAssignmentReader = (*Store)(nil)
