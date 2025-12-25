package goroutine

import (
	"fmt"
	"os"
	"runtime"

	"go.uber.org/zap"
)

const (
	// StackTraceBufferSize is the buffer size for stack trace collection
	StackTraceBufferSize = 4096
)

// Recover recovers from panics in goroutines and logs them
// If logger is nil, falls back to stderr to ensure panic is recorded
func Recover(name string, logger *zap.SugaredLogger) {
	if r := recover(); r != nil {
		buf := make([]byte, StackTraceBufferSize)
		n := runtime.Stack(buf, false)

		if logger != nil {
			logger.Errorw("Goroutine panic recovered",
				"goroutine", name,
				"panic", r,
				"stack", string(buf[:n]))
		} else {
			// Fallback to stderr when logger is nil
			fmt.Fprintf(os.Stderr, "PANIC in goroutine %s (no logger): %v\n%s\n",
				name, r, string(buf[:n]))
		}
	}
}
