// Package contextcheck provides a static analysis tool that detects inappropriate
// usage of context.Background() in Go code.
//
// The analyzer flags context.Background() calls outside of approved locations:
//   - main() function in main packages
//   - init() functions
//   - Test functions (TestXxx, BenchmarkXxx, ExampleXxx)
//   - Test helper functions (t.Helper())
//   - Functions/files with explicit exemption comments
//
// Usage:
//
//	go vet -vettool=$(which contextcheck) ./...
//
// Or integrate with golangci-lint as a custom analyzer.
package contextcheck

import (
	"go/ast"
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// ExemptionComment is the magic comment that exempts a context.Background() call.
// Example: // contextcheck:exempt reason="initialization in background worker"
const ExemptionComment = "contextcheck:exempt"

// Analyzer is the context.Background() checker analyzer.
var Analyzer = &analysis.Analyzer{
	Name:     "contextcheck",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

const doc = `check for inappropriate context.Background() usage

context.Background() creates an empty context that cannot be canceled and has
no deadline. Using it in request handling paths prevents graceful shutdown,
timeout enforcement, and distributed tracing.

Allowed locations:
- main() function (application initialization)
- init() functions (package initialization)
- Test functions (TestXxx, BenchmarkXxx, ExampleXxx)
- Test helper functions (t.Helper())
- Lines with contextcheck:exempt comment

All other usages should propagate a parent context.`

// run executes the analyzer.
func run(pass *analysis.Pass) (interface{}, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Track allowed function contexts
	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
		(*ast.CallExpr)(nil),
	}

	var currentFunc *ast.FuncDecl
	var inAllowedFunc bool

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.FuncDecl:
			currentFunc = node
			inAllowedFunc = isAllowedFunction(pass, node)

		case *ast.CallExpr:
			if isContextBackground(node) {
				if !inAllowedFunc && !hasExemptionComment(pass, node.Pos()) {
					funcName := "unknown"
					if currentFunc != nil && currentFunc.Name != nil {
						funcName = currentFunc.Name.Name
					}
					pass.Reportf(node.Pos(),
						"context.Background() used in %s; propagate parent context instead or add contextcheck:exempt comment",
						funcName)
				}
			}
		}
	})

	return nil, nil
}

// isContextBackground checks if the call expression is context.Background().
func isContextBackground(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check for context.Background()
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == "context" && sel.Sel.Name == "Background"
}

// isAllowedFunction determines if the function is an approved location for context.Background().
func isAllowedFunction(pass *analysis.Pass, fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}

	name := fn.Name.Name

	// main() in main package
	if name == "main" && pass.Pkg.Name() == "main" {
		return true
	}

	// init() functions
	if name == "init" {
		return true
	}

	// Test functions: TestXxx, BenchmarkXxx, ExampleXxx
	if strings.HasPrefix(name, "Test") && len(name) > 4 {
		return true
	}
	if strings.HasPrefix(name, "Benchmark") && len(name) > 9 {
		return true
	}
	if strings.HasPrefix(name, "Example") {
		return true
	}

	// Test setup/helper functions in test files
	if strings.HasSuffix(pass.Fset.File(fn.Pos()).Name(), "_test.go") {
		// Check if function calls t.Helper()
		if hasTestHelper(fn) {
			return true
		}
		// Common test setup function patterns
		if isTestSetupFunction(name) {
			return true
		}
	}

	return false
}

// hasTestHelper checks if function body contains t.Helper() call.
func hasTestHelper(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}

	for _, stmt := range fn.Body.List {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if sel.Sel.Name == "Helper" {
			return true
		}
	}
	return false
}

// isTestSetupFunction checks if function name matches common test setup patterns.
func isTestSetupFunction(name string) bool {
	lowerName := strings.ToLower(name)
	setupPatterns := []string{
		"setup",
		"teardown",
		"testmain",
		"newtest",
		"createtest",
		"mock",
		"fixture",
		"helper",
	}

	for _, pattern := range setupPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}
	return false
}

// hasExemptionComment checks if the line has an exemption comment.
func hasExemptionComment(pass *analysis.Pass, pos token.Pos) bool {
	file := pass.Fset.File(pos)
	if file == nil {
		return false
	}

	line := file.Line(pos)
	filename := file.Name()

	// Find the correct AST file for this position
	for _, f := range pass.Files {
		astFilename := pass.Fset.File(f.Pos()).Name()
		if astFilename != filename {
			continue
		}

		// Check all comments in the file
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				commentLine := file.Line(c.Pos())
				// Check same line or line above
				if commentLine == line || commentLine == line-1 {
					if strings.Contains(c.Text, ExemptionComment) {
						return true
					}
				}
			}
		}
		break
	}

	return false
}
