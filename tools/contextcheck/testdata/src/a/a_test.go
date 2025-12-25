// Test file - context.Background() in test functions is allowed
package a

import (
	"context"
	"testing"
)

// TestFunction - context.Background() is allowed in Test functions
func TestFunction(t *testing.T) {
	ctx := context.Background() // OK - Test function
	_ = ctx
}

// BenchmarkFunction - context.Background() is allowed in Benchmark functions
func BenchmarkFunction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ctx := context.Background() // OK - Benchmark function
		_ = ctx
	}
}

// ExampleFunction - context.Background() is allowed in Example functions
func Example() {
	ctx := context.Background() // OK - Example function
	_ = ctx
}

// setupTest - context.Background() is allowed in test setup functions
func setupTest(t *testing.T) context.Context {
	t.Helper()
	return context.Background() // OK - test helper function
}

// createTestContext - context.Background() is allowed in test helper functions
func createTestContext() context.Context {
	return context.Background() // OK - test setup function (name contains "test")
}

// mockContextProvider - context.Background() is allowed in mock functions
func mockContextProvider() context.Context {
	return context.Background() // OK - mock function
}
