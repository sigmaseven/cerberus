// Package a contains test cases for the contextcheck analyzer.
package a

import "context"

// Regular function - context.Background() should be flagged
func regularFunction() {
	_ = context.Background() // want "context.Background\\(\\) used in regularFunction"
}

// Handler simulates a request handler - context.Background() should be flagged
func handleRequest() {
	ctx := context.Background() // want "context.Background\\(\\) used in handleRequest"
	_ = ctx
}

// processData is an internal function - context.Background() should be flagged
func processData() context.Context {
	return context.Background() // want "context.Background\\(\\) used in processData"
}

// Multiple violations in one function
func multipleViolations() {
	ctx1 := context.Background() // want "context.Background\\(\\) used in multipleViolations"
	ctx2 := context.Background() // want "context.Background\\(\\) used in multipleViolations"
	_, _ = ctx1, ctx2
}

// Nested call - inner context.Background() should be flagged
func nestedCall() {
	ctx, cancel := context.WithCancel(context.Background()) // want "context.Background\\(\\) used in nestedCall"
	defer cancel()
	_ = ctx
}
