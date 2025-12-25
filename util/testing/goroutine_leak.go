package testing

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// CheckGoroutineCleanup verifies no goroutine leaks after test completion
// Usage: defer CheckGoroutineCleanup(t)() at the start of any test that launches goroutines
//
// Example:
//
//	func TestWorkerPool(t *testing.T) {
//	    defer CheckGoroutineCleanup(t)()
//	    // Test code that launches goroutines
//	    pool.Start()
//	    pool.Stop()
//	}
//
// Security: Goroutine leaks are a form of resource exhaustion that can lead to DoS
func CheckGoroutineCleanup(t *testing.T) func() {
	before := runtime.NumGoroutine()

	return func() {
		// Allow time for goroutines to exit gracefully
		assert.Eventually(t, func() bool {
			after := runtime.NumGoroutine()
			if after > before {
				// Log which goroutines are still running (debugging aid)
				t.Logf("Goroutine leak detected: before=%d, after=%d, leaked=%d",
					before, after, after-before)

				// Dump stack traces if leaks detected (helps debugging)
				buf := make([]byte, 1<<20) // 1MB buffer for stack traces
				n := runtime.Stack(buf, true)
				t.Logf("Stack traces:\n%s", buf[:n])

				return false
			}
			return true
		}, 5*time.Second, 100*time.Millisecond,
			"Goroutine leak detected: %d goroutines still running", runtime.NumGoroutine()-before)
	}
}

// WaitForGoroutines waits for a WaitGroup with timeout
// Returns error if WaitGroup doesn't complete within timeout
//
// Usage:
//
//	err := WaitForGoroutines(&worker.wg, 5*time.Second)
//	assert.NoError(t, err, "Workers should exit within timeout")
//
// This prevents tests from hanging indefinitely on WaitGroup.Wait()
func WaitForGoroutines(wg *sync.WaitGroup, timeout time.Duration) error {
	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return errors.New("goroutines did not exit within timeout")
	}
}

// AssertGoroutineCleanup is a non-deferred version for explicit checks
// Use this when you need to verify goroutine cleanup at specific points in a test
//
// Example:
//
//	func TestMultipleStartStop(t *testing.T) {
//	    before := runtime.NumGoroutine()
//
//	    pool.Start()
//	    pool.Stop()
//	    AssertGoroutineCleanup(t, before)
//
//	    pool.Start()  // Restart
//	    pool.Stop()
//	    AssertGoroutineCleanup(t, before)
//	}
func AssertGoroutineCleanup(t *testing.T, before int) {
	assert.Eventually(t, func() bool {
		after := runtime.NumGoroutine()
		if after > before {
			t.Logf("Goroutine leak: before=%d, after=%d, leaked=%d",
				before, after, after-before)
			return false
		}
		return true
	}, 5*time.Second, 100*time.Millisecond,
		"Goroutine leak detected")
}

// CountGoroutines returns the current number of goroutines
// Useful for baseline measurements before test actions
func CountGoroutines() int {
	return runtime.NumGoroutine()
}

// DumpGoroutines dumps all goroutine stack traces to the test log
// Use this for debugging goroutine leaks
func DumpGoroutines(t *testing.T) {
	buf := make([]byte, 1<<20) // 1MB buffer
	n := runtime.Stack(buf, true)
	t.Logf("Goroutine stack traces (%d goroutines):\n%s",
		runtime.NumGoroutine(), buf[:n])
}
