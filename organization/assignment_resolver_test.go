package organization

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type fakeOrganizationAssignmentReader struct {
	normalByKey      map[string]*NormalOrganization
	normalErrorByKey map[string]error
	defaultOrg       *Organization
	defaultErr       error
	normalLookups    []string
	defaultLookups   int
}

func (r *fakeOrganizationAssignmentReader) FindNormalByCorporateMappingKey(_ context.Context, key string) (*NormalOrganization, error) {
	r.normalLookups = append(r.normalLookups, key)
	if err := r.normalErrorByKey[key]; err != nil {
		return nil, err
	}
	org, ok := r.normalByKey[key]
	if !ok {
		return nil, ErrNotFound
	}
	return org, nil
}

func (r *fakeOrganizationAssignmentReader) FindDefault(context.Context) (*Organization, error) {
	r.defaultLookups++
	if r.defaultErr != nil {
		return nil, r.defaultErr
	}
	return r.defaultOrg, nil
}

func testNormalOrganization(id uuid.UUID, key string, lifecycle Lifecycle) *NormalOrganization {
	return &NormalOrganization{
		Organization: Organization{
			ID:             id,
			Classification: ClassificationNormal,
			Lifecycle:      lifecycle,
		},
		CorporateMappingKey: key,
	}
}

func testDefaultOrganization() *Organization {
	return &Organization{
		ID:             uuid.MustParse(DefaultOrganizationID),
		Classification: ClassificationDefault,
		CanonicalName:  DefaultOrganizationCanonicalName,
		Lifecycle:      LifecycleActive,
	}
}

func newFakeOrganizationAssignmentReader() *fakeOrganizationAssignmentReader {
	return &fakeOrganizationAssignmentReader{
		normalByKey:      make(map[string]*NormalOrganization),
		normalErrorByKey: make(map[string]error),
		defaultOrg:       testDefaultOrganization(),
	}
}

func newTestOrganizationAssignmentResolver(t *testing.T, reader organizationAssignmentReader, rules []OrganizationAssignmentMappingRule) *OrganizationAssignmentResolver {
	t.Helper()
	resolver, err := NewOrganizationAssignmentResolver(reader, OrganizationAssignmentResolverConfig{
		SourceConfigVersion: "mapping-config-配置-v1",
		Rules:               rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func assertOrganizationAssignmentDecision(t *testing.T, got OrganizationAssignmentDecision, outcome MappingOutcome, count int, id uuid.UUID, classification Classification) {
	t.Helper()
	if got.MappingOutcome != outcome || got.MatchedCount != count ||
		got.EffectiveOrganizationID != id ||
		got.EffectiveOrganizationClassification != classification ||
		got.SourceConfigVersion != "mapping-config-配置-v1" {
		t.Fatalf("decision = %#v, want outcome=%s count=%d id=%s classification=%s source=mapping-config-配置-v1",
			got, outcome, count, id, classification)
	}
}

func assertOrganizationAssignmentResolverCallDoesNotPanic(t *testing.T, call func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Organization assignment resolver call panicked: %v", recovered)
		}
	}()
	call()
}

func TestNewOrganizationAssignmentResolverRejectsNilReader(t *testing.T) {
	var store *Store
	var fake *fakeOrganizationAssignmentReader
	tests := []struct {
		name   string
		reader organizationAssignmentReader
	}{
		{name: "plain nil interface"},
		{name: "typed nil Store", reader: store},
		{name: "typed nil fake", reader: fake},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var resolver *OrganizationAssignmentResolver
			var err error
			assertOrganizationAssignmentResolverCallDoesNotPanic(t, func() {
				resolver, err = NewOrganizationAssignmentResolver(test.reader, OrganizationAssignmentResolverConfig{
					SourceConfigVersion: "config-v1",
				})
			})
			if resolver != nil {
				t.Fatalf("resolver = %#v, want nil", resolver)
			}
			if !errors.Is(err, ErrInvalidOrganizationAssignmentResolverConfiguration) {
				t.Fatalf("constructor error = %v, want invalid resolver configuration", err)
			}
		})
	}
}

func TestOrganizationAssignmentResolverResolveRejectsInvalidReader(t *testing.T) {
	var fake *fakeOrganizationAssignmentReader
	tests := []struct {
		name     string
		resolver *OrganizationAssignmentResolver
	}{
		{name: "nil resolver"},
		{name: "zero value resolver", resolver: &OrganizationAssignmentResolver{}},
		{name: "typed nil reader", resolver: &OrganizationAssignmentResolver{reader: fake}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decision OrganizationAssignmentDecision
			var err error
			assertOrganizationAssignmentResolverCallDoesNotPanic(t, func() {
				decision, err = test.resolver.Resolve(context.Background(), nil)
			})
			if decision != (OrganizationAssignmentDecision{}) {
				t.Fatalf("decision = %#v, want zero value", decision)
			}
			if !errors.Is(err, ErrInvalidOrganizationAssignmentResolverConfiguration) {
				t.Fatalf("Resolve error = %v, want invalid resolver configuration", err)
			}
		})
	}
}

func TestNormalizeEnterpriseMappingIdentifier(t *testing.T) {
	boundary := sourceConfigVersionBoundaryWhitespace
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "ordinary ASCII", input: "enterprise:team-a", want: "enterprise:team-a"},
		{name: "valid non-ASCII Unicode", input: "企业:值班组", want: "企业:值班组"},
		{name: "fixed boundary whitespace", input: boundary + "enterprise:team-a" + boundary, want: "enterprise:team-a"},
		{name: "case preserved", input: "Enterprise:Team-A", want: "Enterprise:Team-A"},
		{name: "internal whitespace preserved", input: "enterprise:\tteam  a\nmember", want: "enterprise:\tteam  a\nmember"},
		{name: "malformed UTF-8", input: string([]byte{'a', 0xff, 'b'}), wantErr: true},
		{name: "U+0000", input: "enterprise:\x00team", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace only", input: boundary, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeEnterpriseMappingIdentifier(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeEnterpriseMappingIdentifier(%q) unexpectedly succeeded", test.input)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("normalizeEnterpriseMappingIdentifier(%q) = %q, %v; want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestOrganizationAssignmentResolverConfigurationValidation(t *testing.T) {
	t.Run("valid source config version", func(t *testing.T) {
		reader := newFakeOrganizationAssignmentReader()
		_, err := NewOrganizationAssignmentResolver(reader, OrganizationAssignmentResolverConfig{
			SourceConfigVersion: "版本\tinternal\nvalue",
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	invalidVersions := []string{
		"",
		" version",
		"version\u3000",
		"version\x00value",
		string([]byte{'v', 0xff}),
	}
	for index, sourceVersion := range invalidVersions {
		t.Run("invalid source config version "+string(rune('a'+index)), func(t *testing.T) {
			reader := newFakeOrganizationAssignmentReader()
			_, err := NewOrganizationAssignmentResolver(reader, OrganizationAssignmentResolverConfig{SourceConfigVersion: sourceVersion})
			if !errors.Is(err, ErrInvalidOrganizationAssignmentResolverConfiguration) {
				t.Fatalf("constructor error = %v, want invalid resolver configuration", err)
			}
			if len(reader.normalLookups) != 0 || reader.defaultLookups != 0 {
				t.Fatalf("invalid source version caused reads: normal=%v default=%d", reader.normalLookups, reader.defaultLookups)
			}
		})
	}

	t.Run("duplicate equivalent same target accepted and deduplicated", func(t *testing.T) {
		reader := newFakeOrganizationAssignmentReader()
		id := uuid.New()
		reader.normalByKey["corp:key-a"] = testNormalOrganization(id, "corp:key-a", LifecycleActive)
		resolver := newTestOrganizationAssignmentResolver(t, reader, []OrganizationAssignmentMappingRule{
			{EnterpriseMappingIdentifier: "\u3000enterprise:a", CorporateMappingKey: "corp:key-a"},
			{EnterpriseMappingIdentifier: "enterprise:a\u00a0", CorporateMappingKey: "corp:key-a"},
		})
		decision, err := resolver.Resolve(context.Background(), []string{" enterprise:a "})
		if err != nil {
			t.Fatal(err)
		}
		assertOrganizationAssignmentDecision(t, decision, MappingOutcomeExactlyOne, 1, id, ClassificationNormal)
		if !reflect.DeepEqual(reader.normalLookups, []string{"corp:key-a"}) {
			t.Fatalf("normal lookups = %v, want one lookup", reader.normalLookups)
		}
	})

	t.Run("duplicate equivalent different targets rejected pre-read", func(t *testing.T) {
		reader := newFakeOrganizationAssignmentReader()
		_, err := NewOrganizationAssignmentResolver(reader, OrganizationAssignmentResolverConfig{
			SourceConfigVersion: "config-v1",
			Rules: []OrganizationAssignmentMappingRule{
				{EnterpriseMappingIdentifier: "enterprise:a", CorporateMappingKey: "corp:key-a"},
				{EnterpriseMappingIdentifier: "\u3000enterprise:a ", CorporateMappingKey: "corp:key-b"},
			},
		})
		if !errors.Is(err, ErrInvalidOrganizationAssignmentResolverConfiguration) {
			t.Fatalf("constructor error = %v, want invalid resolver configuration", err)
		}
		if len(reader.normalLookups) != 0 || reader.defaultLookups != 0 {
			t.Fatalf("conflicting configuration caused reads: normal=%v default=%d", reader.normalLookups, reader.defaultLookups)
		}
	})

	invalidTargets := []string{
		"",
		" corp:key",
		"corp:key\u3000",
		"corp:\x00key",
		string([]byte{'c', 0xff}),
	}
	for index, target := range invalidTargets {
		t.Run("invalid corporate target "+string(rune('a'+index)), func(t *testing.T) {
			reader := newFakeOrganizationAssignmentReader()
			_, err := NewOrganizationAssignmentResolver(reader, OrganizationAssignmentResolverConfig{
				SourceConfigVersion: "config-v1",
				Rules: []OrganizationAssignmentMappingRule{{
					EnterpriseMappingIdentifier: "enterprise:a",
					CorporateMappingKey:         target,
				}},
			})
			if !errors.Is(err, ErrInvalidOrganizationAssignmentResolverConfiguration) {
				t.Fatalf("constructor error = %v, want invalid resolver configuration", err)
			}
			if len(reader.normalLookups) != 0 || reader.defaultLookups != 0 {
				t.Fatalf("invalid target caused reads: normal=%v default=%d", reader.normalLookups, reader.defaultLookups)
			}
		})
	}

	t.Run("invalid raw identifier is not echoed", func(t *testing.T) {
		const raw = "sensitive-enterprise-identifier"
		_, err := NewOrganizationAssignmentResolver(newFakeOrganizationAssignmentReader(), OrganizationAssignmentResolverConfig{
			SourceConfigVersion: "config-v1",
			Rules: []OrganizationAssignmentMappingRule{{
				EnterpriseMappingIdentifier: raw + "\x00",
				CorporateMappingKey:         "corp:key",
			}},
		})
		if err == nil || strings.Contains(err.Error(), raw) {
			t.Fatalf("configuration error leaked raw identifier: %v", err)
		}
	})

	t.Run("accepted snapshot is immutable", func(t *testing.T) {
		reader := newFakeOrganizationAssignmentReader()
		id := uuid.New()
		reader.normalByKey["corp:key-a"] = testNormalOrganization(id, "corp:key-a", LifecycleActive)
		config := OrganizationAssignmentResolverConfig{
			SourceConfigVersion: "config-v1",
			Rules: []OrganizationAssignmentMappingRule{{
				EnterpriseMappingIdentifier: "enterprise:a",
				CorporateMappingKey:         "corp:key-a",
			}},
		}
		resolver, err := NewOrganizationAssignmentResolver(reader, config)
		if err != nil {
			t.Fatal(err)
		}
		config.SourceConfigVersion = "mutated"
		config.Rules[0] = OrganizationAssignmentMappingRule{EnterpriseMappingIdentifier: "enterprise:b", CorporateMappingKey: "corp:key-b"}
		decision, err := resolver.Resolve(context.Background(), []string{"enterprise:a"})
		if err != nil {
			t.Fatal(err)
		}
		if decision.SourceConfigVersion != "config-v1" || decision.EffectiveOrganizationID != id {
			t.Fatalf("configuration mutation changed accepted snapshot: %#v", decision)
		}
	})
}

func TestOrganizationAssignmentResolverCardinalityAndLifecycle(t *testing.T) {
	defaultID := uuid.MustParse(DefaultOrganizationID)
	activeA := uuid.New()
	activeB := uuid.New()
	activeC := uuid.New()
	suspended := uuid.New()
	retired := uuid.New()
	sameIdentity := uuid.New()

	rules := []OrganizationAssignmentMappingRule{
		{EnterpriseMappingIdentifier: "enterprise:active-a", CorporateMappingKey: "corp:active-a"},
		{EnterpriseMappingIdentifier: "enterprise:alias-a", CorporateMappingKey: "corp:active-a"},
		{EnterpriseMappingIdentifier: "enterprise:active-b", CorporateMappingKey: "corp:active-b"},
		{EnterpriseMappingIdentifier: "enterprise:active-c", CorporateMappingKey: "corp:active-c"},
		{EnterpriseMappingIdentifier: "enterprise:suspended", CorporateMappingKey: "corp:suspended"},
		{EnterpriseMappingIdentifier: "enterprise:retired", CorporateMappingKey: "corp:retired"},
		{EnterpriseMappingIdentifier: "enterprise:same-one", CorporateMappingKey: "corp:same-one"},
		{EnterpriseMappingIdentifier: "enterprise:same-two", CorporateMappingKey: "corp:same-two"},
		{EnterpriseMappingIdentifier: "Enterprise:Case", CorporateMappingKey: "corp:case"},
		{EnterpriseMappingIdentifier: "enterprise:internal  space", CorporateMappingKey: "corp:internal"},
	}

	tests := []struct {
		name           string
		inputs         []string
		wantOutcome    MappingOutcome
		wantCount      int
		wantID         uuid.UUID
		wantClass      Classification
		wantNormalKeys []string
	}{
		{name: "no identifiers", wantOutcome: MappingOutcomeZero, wantID: defaultID, wantClass: ClassificationDefault},
		{name: "unknown identifiers only", inputs: []string{"enterprise:unknown"}, wantOutcome: MappingOutcomeZero, wantID: defaultID, wantClass: ClassificationDefault},
		{name: "suspended only", inputs: []string{"enterprise:suspended"}, wantOutcome: MappingOutcomeZero, wantID: defaultID, wantClass: ClassificationDefault, wantNormalKeys: []string{"corp:suspended"}},
		{name: "retired only", inputs: []string{"enterprise:retired"}, wantOutcome: MappingOutcomeZero, wantID: defaultID, wantClass: ClassificationDefault, wantNormalKeys: []string{"corp:retired"}},
		{name: "one active", inputs: []string{"enterprise:active-a"}, wantOutcome: MappingOutcomeExactlyOne, wantCount: 1, wantID: activeA, wantClass: ClassificationNormal, wantNormalKeys: []string{"corp:active-a"}},
		{name: "repeated same input", inputs: []string{"enterprise:active-a", " enterprise:active-a ", "enterprise:active-a"}, wantOutcome: MappingOutcomeExactlyOne, wantCount: 1, wantID: activeA, wantClass: ClassificationNormal, wantNormalKeys: []string{"corp:active-a"}},
		{name: "two aliases same target", inputs: []string{"enterprise:alias-a", "enterprise:active-a"}, wantOutcome: MappingOutcomeExactlyOne, wantCount: 1, wantID: activeA, wantClass: ClassificationNormal, wantNormalKeys: []string{"corp:active-a"}},
		{name: "active plus suspended", inputs: []string{"enterprise:suspended", "enterprise:active-a"}, wantOutcome: MappingOutcomeExactlyOne, wantCount: 1, wantID: activeA, wantClass: ClassificationNormal, wantNormalKeys: []string{"corp:active-a", "corp:suspended"}},
		{name: "different keys same Organization identity", inputs: []string{"enterprise:same-two", "enterprise:same-one"}, wantOutcome: MappingOutcomeExactlyOne, wantCount: 1, wantID: sameIdentity, wantClass: ClassificationNormal, wantNormalKeys: []string{"corp:same-one", "corp:same-two"}},
		{name: "two distinct active", inputs: []string{"enterprise:active-b", "enterprise:active-a"}, wantOutcome: MappingOutcomeMultiple, wantCount: 2, wantID: defaultID, wantClass: ClassificationDefault, wantNormalKeys: []string{"corp:active-a", "corp:active-b"}},
		{name: "three distinct active", inputs: []string{"enterprise:active-c", "enterprise:active-a", "enterprise:active-b"}, wantOutcome: MappingOutcomeMultiple, wantCount: 3, wantID: defaultID, wantClass: ClassificationDefault, wantNormalKeys: []string{"corp:active-a", "corp:active-b", "corp:active-c"}},
		{name: "case remains distinct", inputs: []string{"enterprise:case"}, wantOutcome: MappingOutcomeZero, wantID: defaultID, wantClass: ClassificationDefault},
		{name: "internal whitespace remains distinct", inputs: []string{"enterprise:internal space"}, wantOutcome: MappingOutcomeZero, wantID: defaultID, wantClass: ClassificationDefault},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newFakeOrganizationAssignmentReader()
			reader.normalByKey = map[string]*NormalOrganization{
				"corp:active-a":  testNormalOrganization(activeA, "corp:active-a", LifecycleActive),
				"corp:active-b":  testNormalOrganization(activeB, "corp:active-b", LifecycleActive),
				"corp:active-c":  testNormalOrganization(activeC, "corp:active-c", LifecycleActive),
				"corp:suspended": testNormalOrganization(suspended, "corp:suspended", LifecycleSuspended),
				"corp:retired":   testNormalOrganization(retired, "corp:retired", LifecycleRetired),
				"corp:same-one":  testNormalOrganization(sameIdentity, "corp:same-one", LifecycleActive),
				"corp:same-two":  testNormalOrganization(sameIdentity, "corp:same-two", LifecycleActive),
				"corp:case":      testNormalOrganization(uuid.New(), "corp:case", LifecycleActive),
				"corp:internal":  testNormalOrganization(uuid.New(), "corp:internal", LifecycleActive),
			}
			resolver := newTestOrganizationAssignmentResolver(t, reader, rules)
			decision, err := resolver.Resolve(context.Background(), test.inputs)
			if err != nil {
				t.Fatal(err)
			}
			assertOrganizationAssignmentDecision(t, decision, test.wantOutcome, test.wantCount, test.wantID, test.wantClass)
			if !reflect.DeepEqual(reader.normalLookups, test.wantNormalKeys) {
				t.Fatalf("normal lookup order = %v, want %v", reader.normalLookups, test.wantNormalKeys)
			}
			wantDefaultLookups := 0
			if test.wantOutcome != MappingOutcomeExactlyOne {
				wantDefaultLookups = 1
			}
			if reader.defaultLookups != wantDefaultLookups {
				t.Fatalf("Default lookup count = %d, want %d", reader.defaultLookups, wantDefaultLookups)
			}
		})
	}
}

func TestOrganizationAssignmentResolverRuleAndInputPermutations(t *testing.T) {
	idA, idB := uuid.New(), uuid.New()
	rules := []OrganizationAssignmentMappingRule{
		{EnterpriseMappingIdentifier: "enterprise:b", CorporateMappingKey: "corp:b"},
		{EnterpriseMappingIdentifier: "enterprise:alias-a", CorporateMappingKey: "corp:a"},
		{EnterpriseMappingIdentifier: "enterprise:a", CorporateMappingKey: "corp:a"},
	}
	inputs := []string{"enterprise:b", " enterprise:a ", "enterprise:alias-a"}

	for ruleIndex, rulePermutation := range resolverRulePermutations(rules) {
		for inputIndex, inputPermutation := range resolverStringPermutations(inputs) {
			reader := newFakeOrganizationAssignmentReader()
			reader.normalByKey["corp:a"] = testNormalOrganization(idA, "corp:a", LifecycleActive)
			reader.normalByKey["corp:b"] = testNormalOrganization(idB, "corp:b", LifecycleActive)
			resolver := newTestOrganizationAssignmentResolver(t, reader, rulePermutation)
			decision, err := resolver.Resolve(context.Background(), inputPermutation)
			if err != nil {
				t.Fatalf("rule permutation %d input permutation %d: %v", ruleIndex, inputIndex, err)
			}
			assertOrganizationAssignmentDecision(t, decision, MappingOutcomeMultiple, 2, uuid.MustParse(DefaultOrganizationID), ClassificationDefault)
			if !reflect.DeepEqual(reader.normalLookups, []string{"corp:a", "corp:b"}) {
				t.Fatalf("rule permutation %d input permutation %d lookup order = %v", ruleIndex, inputIndex, reader.normalLookups)
			}
		}
	}
}

func resolverRulePermutations(values []OrganizationAssignmentMappingRule) [][]OrganizationAssignmentMappingRule {
	result := make([][]OrganizationAssignmentMappingRule, 0)
	resolverPermute(len(values), func(indexes []int) {
		permutation := make([]OrganizationAssignmentMappingRule, len(values))
		for index, source := range indexes {
			permutation[index] = values[source]
		}
		result = append(result, permutation)
	})
	return result
}

func resolverStringPermutations(values []string) [][]string {
	result := make([][]string, 0)
	resolverPermute(len(values), func(indexes []int) {
		permutation := make([]string, len(values))
		for index, source := range indexes {
			permutation[index] = values[source]
		}
		result = append(result, permutation)
	})
	return result
}

func resolverPermute(size int, collect func([]int)) {
	indexes := make([]int, size)
	for index := range indexes {
		indexes[index] = index
	}
	var visit func(int)
	visit = func(position int) {
		if position == size {
			collect(append([]int(nil), indexes...))
			return
		}
		for index := position; index < size; index++ {
			indexes[position], indexes[index] = indexes[index], indexes[position]
			visit(position + 1)
			indexes[position], indexes[index] = indexes[index], indexes[position]
		}
	}
	visit(0)
}

func TestOrganizationAssignmentResolverFailurePaths(t *testing.T) {
	const rawIdentifier = "sensitive-enterprise-identifier"
	rule := OrganizationAssignmentMappingRule{EnterpriseMappingIdentifier: rawIdentifier, CorporateMappingKey: "corp:target"}

	t.Run("malformed input fails before reads without echo", func(t *testing.T) {
		reader := newFakeOrganizationAssignmentReader()
		resolver := newTestOrganizationAssignmentResolver(t, reader, []OrganizationAssignmentMappingRule{rule})
		_, err := resolver.Resolve(context.Background(), []string{rawIdentifier, "invalid\x00"})
		if !errors.Is(err, ErrInvalidOrganizationAssignmentResolverInput) || strings.Contains(err.Error(), rawIdentifier) {
			t.Fatalf("Resolve error = %v, want bounded invalid input without raw identifier", err)
		}
		if len(reader.normalLookups) != 0 || reader.defaultLookups != 0 {
			t.Fatalf("malformed input caused reads: normal=%v default=%d", reader.normalLookups, reader.defaultLookups)
		}
	})

	t.Run("matched configured target missing fails closed without echo", func(t *testing.T) {
		reader := newFakeOrganizationAssignmentReader()
		resolver := newTestOrganizationAssignmentResolver(t, reader, []OrganizationAssignmentMappingRule{rule})
		_, err := resolver.Resolve(context.Background(), []string{rawIdentifier})
		if !errors.Is(err, ErrStaleOrganizationAssignmentResolverConfiguration) || strings.Contains(err.Error(), rawIdentifier) {
			t.Fatalf("Resolve error = %v, want bounded stale configuration without raw identifier", err)
		}
		if reader.defaultLookups != 0 {
			t.Fatalf("missing configured target fell back to Default %d times", reader.defaultLookups)
		}
	})

	t.Run("reader failure fails closed", func(t *testing.T) {
		readerErr := errors.New("database unavailable")
		reader := newFakeOrganizationAssignmentReader()
		reader.normalErrorByKey["corp:target"] = readerErr
		resolver := newTestOrganizationAssignmentResolver(t, reader, []OrganizationAssignmentMappingRule{rule})
		_, err := resolver.Resolve(context.Background(), []string{rawIdentifier})
		if !errors.Is(err, readerErr) {
			t.Fatalf("Resolve error = %v, want reader failure", err)
		}
		if reader.defaultLookups != 0 {
			t.Fatalf("reader failure fell back to Default %d times", reader.defaultLookups)
		}
	})

	for _, test := range []struct {
		name   string
		inputs []string
		rules  []OrganizationAssignmentMappingRule
	}{
		{name: "ZERO", inputs: nil, rules: nil},
		{name: "MULTIPLE", inputs: []string{"enterprise:a", "enterprise:b"}, rules: []OrganizationAssignmentMappingRule{
			{EnterpriseMappingIdentifier: "enterprise:a", CorporateMappingKey: "corp:a"},
			{EnterpriseMappingIdentifier: "enterprise:b", CorporateMappingKey: "corp:b"},
		}},
	} {
		t.Run("Default lookup error for "+test.name, func(t *testing.T) {
			defaultErr := errors.New("Default read failed")
			reader := newFakeOrganizationAssignmentReader()
			reader.defaultErr = defaultErr
			reader.normalByKey["corp:a"] = testNormalOrganization(uuid.New(), "corp:a", LifecycleActive)
			reader.normalByKey["corp:b"] = testNormalOrganization(uuid.New(), "corp:b", LifecycleActive)
			resolver := newTestOrganizationAssignmentResolver(t, reader, test.rules)
			_, err := resolver.Resolve(context.Background(), test.inputs)
			if !errors.Is(err, defaultErr) {
				t.Fatalf("Resolve error = %v, want Default lookup failure", err)
			}
		})
	}

	t.Run("contradictory Normal lookup results fail closed", func(t *testing.T) {
		invalidResults := map[string]*NormalOrganization{
			"nil":              nil,
			"missing identity": testNormalOrganization(uuid.Nil, "corp:target", LifecycleActive),
			"Default identity": testNormalOrganization(uuid.MustParse(DefaultOrganizationID), "corp:target", LifecycleActive),
			"wrong classification": func() *NormalOrganization {
				org := testNormalOrganization(uuid.New(), "corp:target", LifecycleActive)
				org.Classification = ClassificationDefault
				return org
			}(),
			"wrong key":         testNormalOrganization(uuid.New(), "corp:other", LifecycleActive),
			"unknown lifecycle": testNormalOrganization(uuid.New(), "corp:target", "UNKNOWN"),
		}
		names := make([]string, 0, len(invalidResults))
		for name := range invalidResults {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			t.Run(name, func(t *testing.T) {
				reader := newFakeOrganizationAssignmentReader()
				reader.normalByKey["corp:target"] = invalidResults[name]
				resolver := newTestOrganizationAssignmentResolver(t, reader, []OrganizationAssignmentMappingRule{rule})
				_, err := resolver.Resolve(context.Background(), []string{rawIdentifier})
				if !errors.Is(err, ErrInvariantViolation) {
					t.Fatalf("Resolve error = %v, want invariant violation", err)
				}
			})
		}
	})

	t.Run("same identity with inconsistent lifecycle fails closed", func(t *testing.T) {
		id := uuid.New()
		reader := newFakeOrganizationAssignmentReader()
		reader.normalByKey["corp:a"] = testNormalOrganization(id, "corp:a", LifecycleActive)
		reader.normalByKey["corp:b"] = testNormalOrganization(id, "corp:b", LifecycleSuspended)
		resolver := newTestOrganizationAssignmentResolver(t, reader, []OrganizationAssignmentMappingRule{
			{EnterpriseMappingIdentifier: "enterprise:a", CorporateMappingKey: "corp:a"},
			{EnterpriseMappingIdentifier: "enterprise:b", CorporateMappingKey: "corp:b"},
		})
		_, err := resolver.Resolve(context.Background(), []string{"enterprise:a", "enterprise:b"})
		if !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("Resolve error = %v, want invariant violation", err)
		}
	})

	t.Run("contradictory Default lookup result fails closed", func(t *testing.T) {
		invalidDefaults := map[string]*Organization{
			"nil": nil,
			"wrong identity": {
				ID:             uuid.New(),
				Classification: ClassificationDefault,
				CanonicalName:  DefaultOrganizationCanonicalName,
				Lifecycle:      LifecycleActive,
			},
			"wrong classification": {
				ID:             uuid.MustParse(DefaultOrganizationID),
				Classification: ClassificationNormal,
				CanonicalName:  DefaultOrganizationCanonicalName,
				Lifecycle:      LifecycleActive,
			},
			"wrong canonical identity": {
				ID:             uuid.MustParse(DefaultOrganizationID),
				Classification: ClassificationDefault,
				CanonicalName:  "wrong.default",
				Lifecycle:      LifecycleActive,
			},
			"inactive": {
				ID:             uuid.MustParse(DefaultOrganizationID),
				Classification: ClassificationDefault,
				CanonicalName:  DefaultOrganizationCanonicalName,
				Lifecycle:      LifecycleSuspended,
			},
		}
		names := make([]string, 0, len(invalidDefaults))
		for name := range invalidDefaults {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			t.Run(name, func(t *testing.T) {
				reader := newFakeOrganizationAssignmentReader()
				reader.defaultOrg = invalidDefaults[name]
				resolver := newTestOrganizationAssignmentResolver(t, reader, nil)
				_, err := resolver.Resolve(context.Background(), nil)
				if !errors.Is(err, ErrInvariantViolation) {
					t.Fatalf("Resolve error = %v, want invariant violation", err)
				}
			})
		}
	})
}

func TestOrganizationAssignmentReaderSurfaceIsReadOnlyAndNarrow(t *testing.T) {
	typeOfReader := reflect.TypeOf((*organizationAssignmentReader)(nil)).Elem()
	if typeOfReader.NumMethod() != 2 {
		t.Fatalf("organizationAssignmentReader has %d methods, want exactly 2", typeOfReader.NumMethod())
	}
	want := []string{"FindDefault", "FindNormalByCorporateMappingKey"}
	got := make([]string, 0, typeOfReader.NumMethod())
	for index := 0; index < typeOfReader.NumMethod(); index++ {
		got = append(got, typeOfReader.Method(index).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("organizationAssignmentReader methods = %v, want %v", got, want)
	}
}
