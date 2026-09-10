package executioncontextvalue

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

type testValue struct {
	valid   bool
	id      uuid.UUID
	present bool
}

func (v testValue) Valid() bool { return v.valid }

func (v testValue) EffectiveOrganizationID() (uuid.UUID, bool) {
	return v.id, v.present
}

func TestEffectiveOrganizationIDFailsClosed(t *testing.T) {
	normalID := uuid.New()
	defaultID := uuid.MustParse(organization.DefaultOrganizationID)
	tests := []struct {
		name  string
		value *testValue
		want  uuid.UUID
		ok    bool
	}{
		{name: "missing"},
		{name: "invalid", value: &testValue{id: normalID, present: true}},
		{name: "scope absent", value: &testValue{valid: true}},
		{name: "nil identity", value: &testValue{valid: true, present: true}},
		{name: "Default", value: &testValue{valid: true, id: defaultID, present: true}},
		{name: "Normal", value: &testValue{valid: true, id: normalID, present: true}, want: normalID, ok: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.value != nil {
				ctx = With(ctx, test.value)
			}
			got, ok := EffectiveOrganizationID(ctx)
			if got != test.want || ok != test.ok {
				t.Fatalf("EffectiveOrganizationID = (%s, %t), want (%s, %t)", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestWithoutShadowsInheritedValue(t *testing.T) {
	value := &testValue{valid: true, id: uuid.New(), present: true}
	ctx := Without(With(context.Background(), value))
	if got, ok := EffectiveOrganizationID(ctx); got != uuid.Nil || ok {
		t.Fatalf("EffectiveOrganizationID after Without = (%s, %t), want absent", got, ok)
	}
}
