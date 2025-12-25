package goroutine

import (
	"runtime"
	"testing"
	"time"
)

// LeakDetector provides goroutine leak detection utilities for tests
// TASK 147.5: Test helper for detecting goroutine leaks

// AssertNoLeaks registers a cleanup function that verifies goroutine count
// returns to baseline after test completion. This should be called at the
// beginning of tests that launch goroutines.
//
// Usage:
//
//	func TestSomething(t *testing.T) {
//	    goroutine.AssertNoLeaks(t)
//	    // ... test code that launches goroutines ...
//	}
func AssertNoLeaks(t *testing.T) {
	t.Helper()
	AssertNoLeaksWithTimeout(t, 5*time.Second, 100*time.Millisecond)
}

// AssertNoLeaksWithTimeout is like AssertNoLeaks but with custom timeout and polling interval
func AssertNoLeaksWithTimeout(t *testing.T, timeout, pollInterval time.Duration) {
	t.Helper()
	before := runtime.NumGoroutine()

	t.Cleanup(func() {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			current := runtime.NumGoroutine()
			if current <= before {
				return // Success - goroutine count returned to baseline
			}
			time.Sleep(pollInterval)
		}

		// Log final state for debugging
		current := runtime.NumGoroutine()
		if current > before {
			t.Errorf("goroutine leak detected: started with %d goroutines, ended with %d (leaked %d)",
				before, current, current-before)

			// Capture stack traces for debugging
			buf := make([]byte, 1024*1024) // 1MB buffer
			n := runtime.Stack(buf, true)
			t.Logf("Active goroutines:\n%s", string(buf[:n]))
		}
	})
}

// WaitForGoroutineCount waits until the goroutine count reaches the target or timeout expires
// Returns true if target was reached, false if timeout expired
func WaitForGoroutineCount(target int, timeout, pollInterval time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= target {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}

// GetGoroutineCount returns the current number of goroutines
func GetGoroutineCount() int {
	return runtime.NumGoroutine()
}

// GoroutineSnapshot captures goroutine state for comparison
type GoroutineSnapshot struct {
	Count int
	Time  time.Time
}

// TakeSnapshot captures the current goroutine count
func TakeSnapshot() GoroutineSnapshot {
	return GoroutineSnapshot{
		Count: runtime.NumGoroutine(),
		Time:  time.Now(),
	}
}

// Compare checks if the current goroutine count exceeds the snapshot
// Returns the difference (positive means leak, negative means fewer goroutines)
func (s GoroutineSnapshot) Compare() int {
	return runtime.NumGoroutine() - s.Count
}

// AssertNoLeak checks if there are no leaked goroutines since the snapshot was taken
// Waits up to timeout for goroutines to clean up before asserting
func (s GoroutineSnapshot) AssertNoLeak(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= s.Count {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	current := runtime.NumGoroutine()
	if current > s.Count {
		t.Errorf("goroutine leak: snapshot had %d goroutines, now have %d (leaked %d) over %v",
			s.Count, current, current-s.Count, time.Since(s.Time))
	}
}
