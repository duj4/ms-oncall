package executioncontext_test

import (
	"encoding"
	"encoding/gob"
	"encoding/json"
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
)

func TestExternalZeroValueHasNoAuthority(t *testing.T) {
	original := executioncontext.ExecutionContext{}
	copyOfContext := original
	if original.Valid() || copyOfContext.Valid() {
		t.Fatal("an externally initialized or copied zero value is valid")
	}
	if original.PrincipalKind() != "" || original.PrincipalID() != "" || original.ActualActorID() != "" || original.AuthorityMode() != "" {
		t.Fatal("external zero value exposed identity or authority")
	}
	if _, present := original.EffectiveOrganizationID(); present {
		t.Fatal("external zero value exposed an effective Organization")
	}
	if _, present := original.AssignmentGeneration(); present {
		t.Fatal("external zero value exposed assignment generation")
	}
	if _, present := original.PlatformAdminAssumptionID(); present {
		t.Fatal("external zero value exposed assumption evidence")
	}
	if original.AuthenticationSource() != nil || original.Privileges() != nil {
		t.Fatal("external zero value exposed nested trust evidence")
	}
}

func TestExternalNilPointerAccessorsFailClosed(t *testing.T) {
	var context *executioncontext.ExecutionContext
	var source *executioncontext.AuthenticationSource
	var privileges *executioncontext.PrivilegeMetadata
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("nil-pointer accessor panicked: %v", recovered)
		}
	}()

	if context.Valid() || context.PrincipalKind() != "" || context.PrincipalID() != "" || context.ActualActorID() != "" ||
		context.AuthenticationSource() != nil || context.Privileges() != nil || context.AuthorityMode() != "" {
		t.Fatal("nil ExecutionContext exposed identity or authority")
	}
	if value, present := context.EffectiveOrganizationID(); present || value != uuid.Nil {
		t.Fatalf("nil EffectiveOrganizationID = (%s, %t), want absent", value, present)
	}
	if value, present := context.AssignmentGeneration(); present || value != 0 {
		t.Fatalf("nil AssignmentGeneration = (%d, %t), want absent", value, present)
	}
	if value, present := context.PlatformAdminAssumptionID(); present || value != "" {
		t.Fatalf("nil PlatformAdminAssumptionID = (%q, %t), want absent", value, present)
	}
	if source.Type() != "" || source.ID() != "" {
		t.Fatal("nil AuthenticationSource exposed evidence")
	}
	if privileges.OrganizationRole() != "" || privileges.PlatformAdmin() {
		t.Fatal("nil PrivilegeMetadata exposed evidence")
	}
}

func TestTrustBearingRepresentationsHaveNoExportedFields(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(executioncontext.ExecutionContext{}),
		reflect.TypeOf(executioncontext.AuthenticationSource{}),
		reflect.TypeOf(executioncontext.PrivilegeMetadata{}),
	}
	for _, typ := range types {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.IsExported() {
					t.Fatalf("trust-bearing field %s.%s is exported", typ.Name(), field.Name)
				}
			}
			value := reflect.New(typ).Elem()
			for i := 0; i < value.NumField(); i++ {
				if value.Field(i).CanSet() {
					t.Fatalf("external reflection can set private trust-bearing field %s.%s", typ.Name(), typ.Field(i).Name)
				}
			}
		})
	}
}

func TestExecutionContextReadOnlyMethodSurface(t *testing.T) {
	assertMethodSurface(t, reflect.TypeOf((*executioncontext.ExecutionContext)(nil)), []string{
		"ActualActorID",
		"AssignmentGeneration",
		"AuthenticationSource",
		"AuthorityMode",
		"EffectiveOrganizationID",
		"PlatformAdminAssumptionID",
		"PrincipalID",
		"PrincipalKind",
		"Privileges",
		"Valid",
	})
	assertMethodSurface(t, reflect.TypeOf((*executioncontext.AuthenticationSource)(nil)), []string{"ID", "Type"})
	assertMethodSurface(t, reflect.TypeOf((*executioncontext.PrivilegeMetadata)(nil)), []string{"OrganizationRole", "PlatformAdmin"})
	assertMethodSurface(t, reflect.TypeOf(executioncontext.ExecutionContext{}), []string{})
	assertMethodSurface(t, reflect.TypeOf(executioncontext.AuthenticationSource{}), []string{})
	assertMethodSurface(t, reflect.TypeOf(executioncontext.PrivilegeMetadata{}), []string{})
}

func assertMethodSurface(t *testing.T, typ reflect.Type, want []string) {
	t.Helper()
	got := make([]string, 0, typ.NumMethod())
	for i := 0; i < typ.NumMethod(); i++ {
		got = append(got, typ.Method(i).Name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s exported methods = %v, want read-only surface %v", typ, got, want)
	}
}

func TestTrustBearingTypesImplementNoUnmarshaler(t *testing.T) {
	values := map[string]any{
		"ExecutionContext":     (*executioncontext.ExecutionContext)(nil),
		"AuthenticationSource": (*executioncontext.AuthenticationSource)(nil),
		"PrivilegeMetadata":    (*executioncontext.PrivilegeMetadata)(nil),
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			if _, ok := value.(json.Unmarshaler); ok {
				t.Fatal("implements json.Unmarshaler")
			}
			if _, ok := value.(gob.GobDecoder); ok {
				t.Fatal("implements gob.GobDecoder")
			}
			if _, ok := value.(encoding.TextUnmarshaler); ok {
				t.Fatal("implements encoding.TextUnmarshaler")
			}
		})
	}
}

func TestPackageExportsNoExecutionContextConstructor(t *testing.T) {
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
	pkg := packages["executioncontext"]
	if pkg == nil {
		t.Fatal("parsed executioncontext package not found")
	}
	for _, file := range pkg.Files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !function.Name.IsExported() || function.Type.Results == nil {
				continue
			}
			for _, result := range function.Type.Results.List {
				if returnsExecutionContext(result.Type) {
					t.Fatalf("exported package function %s can construct an ExecutionContext", function.Name.Name)
				}
			}
		}
	}
}

func returnsExecutionContext(expression ast.Expr) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name == "ExecutionContext"
	case *ast.StarExpr:
		return returnsExecutionContext(value.X)
	case *ast.ArrayType:
		return returnsExecutionContext(value.Elt)
	default:
		return false
	}
}
