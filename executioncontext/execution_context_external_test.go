package executioncontext_test

import (
	"go/ast"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"golang.org/x/tools/go/packages"
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
	type constructorSignature func(*organization.Store) (*executioncontext.HumanExecutionContextConstructor, error)
	var constructor constructorSignature = executioncontext.NewHumanExecutionContextConstructor
	if constructor == nil {
		t.Fatal("human ExecutionContext constructor is nil")
	}
}

func TestCurrentUserOrganizationProjectionIsBounded(t *testing.T) {
	typ := reflect.TypeOf(organization.CurrentUserOrganization{})
	got := make([]string, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		got[index] = typ.Field(index).Name
	}
	want := []string{"UserID", "UserRole", "OrganizationID", "Role"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CurrentUserOrganization fields = %v, want bounded admission projection %v", got, want)
	}
}

func TestHumanExecutionContextPackageHasNoImmediateSessionLookup(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate test source")
	}
	directory := filepath.Dir(filename)
	// Load only the production package's syntax using the current build tags.
	loaded, err := packages.Load(&packages.Config{
		Dir:  directory,
		Mode: packages.NeedName | packages.NeedCompiledGoFiles | packages.NeedSyntax,
	}, ".")
	if err != nil {
		t.Fatalf("load executioncontext package: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Name != "executioncontext" {
		t.Fatalf("expected one executioncontext package, got %v", loaded)
	}
	pkg := loaded[0]
	if len(pkg.Errors) != 0 || len(pkg.Syntax) == 0 {
		t.Fatalf("executioncontext syntax unavailable: %v", pkg.Errors)
	}
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "FindCurrentUserSession" {
				t.Fatalf("executioncontext retains immediate Session lookup dependency at %s", pkg.Fset.Position(selector.Pos()))
			}
			return true
		})
	}
}
