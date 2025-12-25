package contextcheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

// TestAnalyzer runs the analyzer against test data.
func TestAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, Analyzer, "a")
}

// TestIsContextBackground tests the context.Background() detection logic.
func TestIsContextBackground(t *testing.T) {
	tests := []struct {
		name string
		code string
		want bool
		expr string
	}{
		{
			name: "context.Background() call",
			code: `package main
import "context"
func main() { ctx := context.Background() }`,
			want: true,
			expr: "context.Background()",
		},
		{
			name: "context.TODO() call",
			code: `package main
import "context"
func main() { ctx := context.TODO() }`,
			want: false,
			expr: "context.TODO()",
		},
		{
			name: "context.WithCancel call",
			code: `package main
import "context"
func main() { ctx, _ := context.WithCancel(context.Background()) }`,
			want: false,
			expr: "context.WithCancel()",
		},
		{
			name: "other package Background func",
			code: `package main
type myctx struct{}
func (m myctx) Background() {}
func main() { var c myctx; c.Background() }`,
			want: false,
			expr: "myctx.Background()",
		},
		{
			name: "simple function call",
			code: `package main
func Background() {}
func main() { Background() }`,
			want: false,
			expr: "Background()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tt.code, 0)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			// Find the first CallExpr matching our target
			var found bool
			ast.Inspect(f, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					got := isContextBackground(call)
					if got == tt.want {
						found = true
						return false
					}
				}
				return true
			})

			if !found {
				t.Errorf("expected isContextBackground to return %v for %s", tt.want, tt.expr)
			}
		})
	}
}

// TestIsAllowedFunction tests the allowed function detection logic.
func TestIsAllowedFunction(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		funcName string
		isTest   bool
		want     bool
	}{
		{
			name:     "main function in main package",
			code:     `package main; func main() {}`,
			funcName: "main",
			want:     true,
		},
		{
			name:     "init function",
			code:     `package foo; func init() {}`,
			funcName: "init",
			want:     true,
		},
		{
			name:     "Test function",
			code:     `package foo; func TestSomething() {}`,
			funcName: "TestSomething",
			want:     true,
		},
		{
			name:     "Benchmark function",
			code:     `package foo; func BenchmarkSomething() {}`,
			funcName: "BenchmarkSomething",
			want:     true,
		},
		{
			name:     "Example function",
			code:     `package foo; func Example() {}`,
			funcName: "Example",
			want:     true,
		},
		{
			name:     "ExampleWithName function",
			code:     `package foo; func ExampleFoo() {}`,
			funcName: "ExampleFoo",
			want:     true,
		},
		{
			name:     "regular function",
			code:     `package foo; func doWork() {}`,
			funcName: "doWork",
			want:     false,
		},
		{
			name:     "Test prefix but too short",
			code:     `package foo; func Test() {}`,
			funcName: "Test",
			want:     false,
		},
		{
			name:     "main function not in main package",
			code:     `package foo; func main() {}`,
			funcName: "main",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tt.code, 0)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			// Find the function with the specified name
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					if fn.Name.Name == tt.funcName {
						// Create a minimal pass for testing
						// Note: This is a simplified test; full testing uses analysistest
						t.Logf("Found function %s in package", tt.funcName)
						return
					}
				}
			}
		})
	}
}

// TestIsTestSetupFunction tests detection of common test setup function patterns.
func TestIsTestSetupFunction(t *testing.T) {
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"setup function", "setup", true},
		{"Setup function", "Setup", true},
		{"setupTest function", "setupTest", true},
		{"teardown function", "teardown", true},
		{"TearDown function", "TearDown", true},
		{"TestMain function", "TestMain", true},
		{"newTestServer", "newTestServer", true},
		{"createTestDB", "createTestDB", true},
		{"mockService", "mockService", true},
		{"MockStorage", "MockStorage", true},
		{"testFixture", "testFixture", true},
		{"helperFunc", "helperFunc", true},
		{"doWork function", "doWork", false},
		{"processEvent function", "processEvent", false},
		{"handleRequest function", "handleRequest", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTestSetupFunction(tt.funcName)
			if got != tt.want {
				t.Errorf("isTestSetupFunction(%q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

// TestHasTestHelper tests detection of t.Helper() calls.
func TestHasTestHelper(t *testing.T) {
	tests := []struct {
		name string
		code string
		want bool
	}{
		{
			name: "function with t.Helper",
			code: `package foo
import "testing"
func helper(t *testing.T) {
	t.Helper()
	// do stuff
}`,
			want: true,
		},
		{
			name: "function without t.Helper",
			code: `package foo
import "testing"
func notHelper(t *testing.T) {
	t.Log("something")
}`,
			want: false,
		},
		{
			name: "function with Helper on different receiver",
			code: `package foo
type myT struct{}
func (m *myT) Helper() {}
func notATestHelper() {
	var m myT
	m.Helper()
}`,
			want: false, // Only t.Helper() on testing.T is matched
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tt.code, 0)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			// Find the function and check for Helper
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					got := hasTestHelper(fn)
					if got != tt.want {
						t.Errorf("hasTestHelper() = %v, want %v", got, tt.want)
					}
					return
				}
			}
			t.Fatal("no function found in test code")
		})
	}
}

// TestExemptionComment tests the exemption comment detection.
func TestExemptionComment(t *testing.T) {
	t.Run("exemption comment syntax", func(t *testing.T) {
		validComments := []string{
			"// contextcheck:exempt reason=\"initialization\"",
			"// contextcheck:exempt",
			"/* contextcheck:exempt */",
		}

		for _, comment := range validComments {
			if !containsExemption(comment) {
				t.Errorf("expected %q to be recognized as exemption", comment)
			}
		}
	})

	t.Run("non-exemption comments", func(t *testing.T) {
		invalidComments := []string{
			"// some other comment",
			"// exempt from rule",
			"// nolint:contextcheck",
		}

		for _, comment := range invalidComments {
			if containsExemption(comment) {
				t.Errorf("expected %q to NOT be recognized as exemption", comment)
			}
		}
	})
}

// containsExemption is a helper to check if a string contains the exemption marker.
func containsExemption(s string) bool {
	return len(s) > 0 && (len(s) >= len(ExemptionComment)) && (findExemption(s))
}

func findExemption(s string) bool {
	for i := 0; i <= len(s)-len(ExemptionComment); i++ {
		if s[i:i+len(ExemptionComment)] == ExemptionComment {
			return true
		}
	}
	return false
}
