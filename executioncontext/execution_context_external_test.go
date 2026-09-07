package executioncontext_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/user"
)

func TestExternalZeroAndNilValuesExposeNoAuthority(t *testing.T) {
	for _, context := range []*executioncontext.ExecutionContext{nil, {}} {
		if context.Valid() || context.PrincipalKind() != "" || context.PrincipalID() != "" || context.ActualActorID() != "" ||
			context.AuthenticationSource() != nil || context.Privileges() != nil || context.AuthorityMode() != "" {
			t.Fatalf("invalid ExecutionContext exposed authority: %#v", context)
		}
		if value, present := context.EffectiveOrganizationID(); present || value != uuid.Nil {
			t.Fatalf("invalid effective Organization = (%s, %t)", value, present)
		}
	}
	var source *executioncontext.AuthenticationSource
	var privileges *executioncontext.PrivilegeMetadata
	if source.Type() != "" || source.ID() != "" || privileges.OrganizationRole() != "" || privileges.PlatformAdmin() {
		t.Fatal("nil metadata exposed evidence")
	}
}

func TestExecutionContextRepresentationUsesUnexportedFields(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(executioncontext.ExecutionContext{}),
		reflect.TypeOf(executioncontext.AuthenticationSource{}),
		reflect.TypeOf(executioncontext.PrivilegeMetadata{}),
	} {
		for index := 0; index < typ.NumField(); index++ {
			if typ.Field(index).IsExported() {
				t.Fatalf("%s.%s is exported", typ.Name(), typ.Field(index).Name)
			}
		}
	}
}

func TestExecutionContextReadOnlyMethodSurface(t *testing.T) {
	assertMethodSurface(t, reflect.TypeOf((*executioncontext.ExecutionContext)(nil)), []string{
		"ActualActorID",
		"AuthenticationSource",
		"AuthorityMode",
		"EffectiveOrganizationID",
		"PrincipalID",
		"PrincipalKind",
		"Privileges",
		"Valid",
	})
	assertMethodSurface(t, reflect.TypeOf((*executioncontext.AuthenticationSource)(nil)), []string{"ID", "Type"})
	assertMethodSurface(t, reflect.TypeOf((*executioncontext.PrivilegeMetadata)(nil)), []string{"OrganizationRole", "PlatformAdmin"})
	assertMethodSurface(t, reflect.TypeOf(executioncontext.ExecutionContext{}), []string{})
}

func assertMethodSurface(t *testing.T, typ reflect.Type, want []string) {
	t.Helper()
	got := make([]string, 0, typ.NumMethod())
	for index := 0; index < typ.NumMethod(); index++ {
		got = append(got, typ.Method(index).Name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s exported methods = %v, want %v", typ, got, want)
	}
}

func TestHumanExecutionContextConstructorRequiresCanonicalStores(t *testing.T) {
	type constructorSignature func(*user.Store, *organization.Store) (*executioncontext.HumanExecutionContextConstructor, error)
	var constructor constructorSignature = executioncontext.NewHumanExecutionContextConstructor
	if constructor == nil {
		t.Fatal("human ExecutionContext constructor is nil")
	}
}

func TestHumanExecutionContextPackageHasNoImmediateSessionLookup(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate test source")
	}
	directory := filepath.Dir(filename)
	packages, err := parser.ParseDir(token.NewFileSet(), directory, func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse executioncontext package: %v", err)
	}
	for _, file := range packages["executioncontext"].Files {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "FindCurrentUserSession" {
				t.Fatalf("executioncontext retains immediate Session lookup dependency in %s", file.Name.Name)
			}
			return true
		})
	}
}
