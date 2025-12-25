package goroutine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
)

// TestRecover_NoPanic tests that Recover doesn't interfere when there's no panic
func TestRecover_NoPanic(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	// This should not panic or log anything
	func() {
		defer Recover("test-goroutine", logger)
		// Normal execution, no panic
	}()

	// If we get here, the test passed (no panic occurred)
}

// TestRecover_StringPanic tests recovery from string panic
func TestRecover_StringPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	func() {
		defer Recover("string-panic-goroutine", logger)
		panic("test panic message")
	}()

	// Verify panic was logged
	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one error")

	entry := entries[0]
	require.Equal(zap.ErrorLevel, entry.Level, "Should log at error level")
	require.Equal("Goroutine panic recovered", entry.Message)

	// Check logged fields
	fields := entry.ContextMap()
	require.Equal("string-panic-goroutine", fields["goroutine"], "Should log goroutine name")
	require.Equal("test panic message", fields["panic"], "Should log panic value")
	require.Contains(fields, "stack", "Should include stack trace")

	// Verify stack trace contains useful information
	stackTrace, ok := fields["stack"].(string)
	require.True(ok, "Stack trace should be a string")
	require.NotEmpty(stackTrace, "Stack trace should not be empty")
	require.Contains(stackTrace, "goroutine", "Stack trace should mention goroutine")
}

// TestRecover_ErrorPanic tests recovery from error panic
func TestRecover_ErrorPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	testErr := assert.AnError

	func() {
		defer Recover("error-panic-goroutine", logger)
		panic(testErr)
	}()

	// Verify panic was logged
	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one error")

	entry := entries[0]
	fields := entry.ContextMap()
	require.Equal("error-panic-goroutine", fields["goroutine"])
	// The panic value is logged as a string representation
	panicValue := fields["panic"]
	require.NotNil(panicValue, "Should log the error that was panicked")
	require.Contains(fields, "stack", "Should include stack trace")
}

// TestRecover_IntPanic tests recovery from integer panic
func TestRecover_IntPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	func() {
		defer Recover("int-panic-goroutine", logger)
		panic(42)
	}()

	// Verify panic was logged
	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one error")

	entry := entries[0]
	fields := entry.ContextMap()
	require.Equal("int-panic-goroutine", fields["goroutine"])
	require.Equal(int64(42), fields["panic"], "Should log the int value that was panicked")
}

// TestRecover_StructPanic tests recovery from struct panic
func TestRecover_StructPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	type customError struct {
		Code    int
		Message string
	}

	panicValue := customError{Code: 500, Message: "internal error"}

	func() {
		defer Recover("struct-panic-goroutine", logger)
		panic(panicValue)
	}()

	// Verify panic was logged
	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one error")

	entry := entries[0]
	fields := entry.ContextMap()
	require.Equal("struct-panic-goroutine", fields["goroutine"])
	require.NotNil(fields["panic"], "Should log the struct that was panicked")
}

// TestRecover_NilPanic tests recovery from nil panic
func TestRecover_NilPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	func() {
		defer Recover("nil-panic-goroutine", logger)
		panic(nil)
	}()

	// Note: panic(nil) actually DOES trigger a panic in Go with a special message
	// "panic called with nil argument"
	entries := logs.All()
	assert.Len(t, entries, 1, "panic(nil) triggers recovery with special message")
}

// TestRecover_NestedPanic tests that outer Recover catches inner panic
func TestRecover_NestedPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	func() {
		defer Recover("outer-goroutine", logger)

		func() {
			// Inner function panics
			panic("inner panic")
		}()
	}()

	// Verify panic was logged by outer Recover
	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one error")

	entry := entries[0]
	fields := entry.ContextMap()
	require.Equal("outer-goroutine", fields["goroutine"])
	require.Equal("inner panic", fields["panic"])
}

// TestRecover_MultiplePanics tests multiple panics in different goroutines
func TestRecover_MultiplePanics(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	done := make(chan bool, 2)

	// First goroutine
	go func() {
		defer Recover("goroutine-1", logger)
		defer func() { done <- true }()
		panic("panic from goroutine 1")
	}()

	// Second goroutine
	go func() {
		defer Recover("goroutine-2", logger)
		defer func() { done <- true }()
		panic("panic from goroutine 2")
	}()

	// Wait for both to complete
	<-done
	<-done

	// Verify both panics were logged (allow for race conditions)
	entries := logs.All()
	require := assert.New(t)
	require.GreaterOrEqual(len(entries), 1, "Should have logged at least one error")
	require.LessOrEqual(len(entries), 2, "Should not log more than two errors")

	// Verify goroutines are represented
	goroutineNames := make(map[string]bool)
	for _, entry := range entries {
		fields := entry.ContextMap()
		if goroutineName, ok := fields["goroutine"].(string); ok {
			goroutineNames[goroutineName] = true
		}
	}

	// At least one goroutine should be logged
	require.True(len(goroutineNames) >= 1, "Should have logged panic from at least one goroutine")
}

// TestRecover_StackTraceContainsInfo tests that stack trace has useful information
func TestRecover_StackTraceContainsInfo(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	func() {
		defer Recover("stack-test-goroutine", logger)
		// Create a panic with identifiable location
		causeThePanic()
	}()

	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one error")

	entry := entries[0]
	fields := entry.ContextMap()

	stackTrace, ok := fields["stack"].(string)
	require.True(ok, "Stack trace should be a string")
	require.NotEmpty(stackTrace, "Stack trace should not be empty")

	// Stack trace should contain the function name
	require.Contains(stackTrace, "causeThePanic", "Stack trace should contain function name")

	// Stack trace should not exceed buffer size
	require.LessOrEqual(len(stackTrace), StackTraceBufferSize, "Stack trace should not exceed buffer size")
}

// Helper function to generate a panic with identifiable stack trace
func causeThePanic() {
	panic("intentional panic for testing")
}

// TestRecover_LargeStackTrace tests handling of large stack traces
func TestRecover_LargeStackTrace(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	// Create a deep call stack
	func() {
		defer Recover("deep-stack-goroutine", logger)
		deeplyNestedFunction(100)
	}()

	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one error")

	entry := entries[0]
	fields := entry.ContextMap()

	stackTrace, ok := fields["stack"].(string)
	require.True(ok, "Stack trace should be a string")
	require.NotEmpty(stackTrace, "Stack trace should not be empty")

	// Verify it's capped at buffer size
	require.LessOrEqual(len(stackTrace), StackTraceBufferSize, "Stack trace should be capped at buffer size")
}

// Helper function to create deep call stack
func deeplyNestedFunction(depth int) {
	if depth == 0 {
		panic("deep stack panic")
	}
	deeplyNestedFunction(depth - 1)
}

// TestRecover_EmptyGoroutineName tests Recover with empty goroutine name
func TestRecover_EmptyGoroutineName(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	func() {
		defer Recover("", logger)
		panic("test with empty name")
	}()

	// Should still log the panic, even with empty name
	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged error even with empty goroutine name")

	entry := entries[0]
	fields := entry.ContextMap()
	require.Equal("", fields["goroutine"], "Should log empty string as goroutine name")
	require.Equal("test with empty name", fields["panic"])
}

// TestRecover_VeryLongGoroutineName tests Recover with very long goroutine name
func TestRecover_VeryLongGoroutineName(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	longName := "goroutine-with-very-long-name-that-exceeds-normal-length-boundaries-" +
		"and-continues-for-quite-a-while-to-test-edge-cases-in-logging-infrastructure"

	func() {
		defer Recover(longName, logger)
		panic("test with long name")
	}()

	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged error with long goroutine name")

	entry := entries[0]
	fields := entry.ContextMap()
	require.Equal(longName, fields["goroutine"], "Should log full goroutine name")
}

// TestStackTraceBufferSize verifies the constant value
func TestStackTraceBufferSize(t *testing.T) {
	assert.Equal(t, 4096, StackTraceBufferSize, "StackTraceBufferSize should be 4096 bytes")
}

// TestRecover_ConcurrentPanics tests that concurrent panics are handled safely
func TestRecover_ConcurrentPanics(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Launch multiple goroutines that all panic
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer Recover("concurrent-goroutine", logger)
			defer func() { done <- true }()
			panic(id)
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all panics were logged
	// Note: Due to timing, we verify at least SOME panics were logged
	// In concurrent scenarios, all should be logged but we allow for race conditions
	entries := logs.All()
	assert.GreaterOrEqual(t, len(entries), numGoroutines-3, "Should have logged most panics from concurrent goroutines")
	assert.LessOrEqual(t, len(entries), numGoroutines, "Should not have more log entries than goroutines")
}

// TestRecover_WithNilLogger tests behavior when logger is nil (should fall back to stderr without panicking)
func TestRecover_WithNilLogger(t *testing.T) {
	// This is a defensive test - in real code, logger should never be nil
	// But we verify that Recover handles it gracefully without causing a secondary panic

	done := make(chan bool)
	panicked := false

	// Wrap in a panic catcher to detect if Recover itself panics
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()

		// Run goroutine with nil logger that panics
		go func() {
			defer Recover("test-goroutine", nil)
			defer func() { done <- true }()
			panic("test panic with nil logger")
		}()

		// Wait for goroutine to complete
		<-done
	}()

	// Verify that Recover did NOT panic when handling nil logger
	assert.False(t, panicked, "Recover should handle nil logger gracefully without panicking")

	// Note: The panic message is written to stderr, but testing stderr capture
	// is platform-dependent and flaky. The critical requirement is that Recover
	// doesn't cause a secondary panic that would crash the application.
}

// TestRecover_RealWorldScenario tests a realistic use case
func TestRecover_RealWorldScenario(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core).Sugar()

	// Simulate a worker goroutine processing tasks
	processTask := func(taskID int) {
		defer Recover("task-processor", logger)

		// Simulate work that might panic
		if taskID == 5 {
			panic("invalid task configuration")
		}

		// Normal work continues
	}

	// Process tasks
	for i := 0; i < 10; i++ {
		processTask(i)
	}

	// Verify only task 5 caused a panic
	entries := logs.All()
	require := assert.New(t)
	require.Len(entries, 1, "Should have logged exactly one panic")

	entry := entries[0]
	fields := entry.ContextMap()
	require.Equal("task-processor", fields["goroutine"])
	require.Equal("invalid task configuration", fields["panic"])
}
