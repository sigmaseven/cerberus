// Command contextcheck runs the context.Background() static analysis checker.
//
// Usage:
//
//	go install github.com/yourusername/cerberus/tools/contextcheck/cmd/contextcheck@latest
//	contextcheck ./...
//
// Or with go vet:
//
//	go vet -vettool=$(which contextcheck) ./...
//
// The tool flags context.Background() calls outside of approved locations:
//   - main() function in main packages
//   - init() functions
//   - Test functions (TestXxx, BenchmarkXxx, ExampleXxx)
//   - Test helper functions
//   - Lines with contextcheck:exempt comment
package main

import (
	"cerberus/tools/contextcheck"

	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(contextcheck.Analyzer)
}
