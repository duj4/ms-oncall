package auth_test

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/target/goalert/auth"
)

func TestRequesterExposesIdentityOnly(t *testing.T) {
	typ := reflect.TypeOf(auth.Requester{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Fatalf("Requester field %s is exported", typ.Field(i).Name)
		}
	}

	ptrType := reflect.TypeOf((*auth.Requester)(nil))
	methods := make([]string, 0, ptrType.NumMethod())
	for i := 0; i < ptrType.NumMethod(); i++ {
		methods = append(methods, ptrType.Method(i).Name)
	}
	sort.Strings(methods)
	want := []string{"SessionID", "UserID", "Valid"}
	if !reflect.DeepEqual(methods, want) {
		t.Fatalf("Requester method surface = %v, want identity-only %v", methods, want)
	}
	if typ.NumMethod() != 0 {
		t.Fatalf("Requester value exposes %d methods, want pointer-only read accessors", typ.NumMethod())
	}
}

func TestRequesterPublicCompositionSignatures(t *testing.T) {
	type constructor func(string, string) (auth.Requester, error)
	type setter func(context.Context, auth.Requester) context.Context
	type getter func(context.Context) *auth.Requester

	var newRequester constructor = auth.NewRequester
	var withRequester setter = auth.WithRequester
	var fromContext getter = auth.RequesterFromContext
	if newRequester == nil || withRequester == nil || fromContext == nil {
		t.Fatal("Requester composition seam is incomplete")
	}
}
