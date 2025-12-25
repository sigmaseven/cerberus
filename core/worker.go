package core

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"time"

	"cerberus/metrics"
	"cerberus/util/goroutine"
	"go.uber.org/zap"
)

// WorkerPool provides a generic worker pool for parallel task processing
type WorkerPool struct {
	workers   int
	queueSize int
	taskCh    chan func()
	wg        sync.WaitGroup
	logger    *zap.SugaredLogger
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
	mu        sync.RWMutex
	poolType  string // For metrics identification
}

// NewWorkerPool creates a new worker pool with default context
// BACKWARD COMPATIBILITY: Maintains original signature using background context
// TASK 144.4: Delegates to context-aware constructor
func NewWorkerPool(workers int, queueSize int, logger *zap.SugaredLogger) *WorkerPool {
	return NewWorkerPoolWithContext(context.Background(), workers, queueSize, "default", logger)
}

// NewWorkerPoolWithType creates a new worker pool with a specific type for metrics
// BACKWARD COMPATIBILITY: Maintains type signature using background context
// TASK 144.4: Delegates to context-aware constructor
func NewWorkerPoolWithType(workers int, queueSize int, poolType string, logger *zap.SugaredLogger) *WorkerPool {
	return NewWorkerPoolWithContext(context.Background(), workers, queueSize, poolType, logger)
}

// NewWorkerPoolWithContext creates a new worker pool with parent context for lifecycle management
// TASK 144.4: New constructor that accepts parent context for graceful shutdown
//
// Parameters:
//   - parentCtx: Parent context for lifecycle coordination (cancellation propagates to workers)
//   - workers: Number of worker goroutines to spawn
//   - queueSize: Size of task queue buffer
//   - poolType: Type identifier for metrics (must match ^[a-zA-Z0-9_-]+$)
//   - logger: Structured logger for observability
//
// Returns:
//   - Configured WorkerPool instance (workers NOT started yet - call Start())
//
// Lifecycle:
//   - Workers start when Start() is called
//   - Call Stop() OR cancel parentCtx to stop workers
//   - Stop() is safe to call multiple times
//   - Workers exit gracefully when context is cancelled
//
// Thread-Safety:
//   - Safe to call from multiple goroutines
//   - Submit() is thread-safe after Start()
//
// Example:
//
//	appCtx, appCancel := context.WithCancel(context.Background())
//	defer appCancel()
//
//	wp := NewWorkerPoolWithContext(appCtx, 4, 100, "event-processor", logger)
//	if err := wp.Start(); err != nil {
//	    return err
//	}
//	defer wp.Stop()
//
// Graceful Shutdown:
//   - Cancelling appCtx will stop all workers
//   - Stop() provides same functionality plus waits for completion
func NewWorkerPoolWithContext(parentCtx context.Context, workers int, queueSize int, poolType string, logger *zap.SugaredLogger) *WorkerPool {
	if poolType == "" {
		poolType = "default"
	}
	// Basic validation for poolType (alphanumeric, underscore, dash)
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, poolType); !matched {
		logger.Warnw("Invalid poolType, using default", "poolType", poolType)
		poolType = "default"
	}

	// TASK 144.4: Derive cancellable context from parent for lifecycle management
	// This allows parent context cancellation to propagate to worker goroutines
	ctx, cancel := context.WithCancel(parentCtx)
	return &WorkerPool{
		workers:   workers,
		queueSize: queueSize,
		taskCh:    make(chan func(), queueSize),
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		running:   false,
		poolType:  poolType,
	}
}

// Start begins processing tasks with the worker pool
func (wp *WorkerPool) Start() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.running {
		return nil // Already running
	}

	wp.running = true
	wp.logger.Infof("Starting worker pool with %d workers and queue size %d", wp.workers, wp.queueSize)

	// Initialize metrics
	metrics.WorkerPoolActiveWorkers.WithLabelValues(wp.poolType).Set(float64(wp.workers))

	// Start workers
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}

	return nil
}

// Stop gracefully shuts down the worker pool
// BLOCKING-2 FIX: Enhanced timeout handling with explicit goroutine leak warning
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.running {
		return
	}

	wp.running = false
	wp.logger.Infow("Stopping worker pool", "pool_type", wp.poolType, "workers", wp.workers)

	// Cancel context to signal workers to stop
	wp.cancel()

	// Close task channel to prevent new tasks
	close(wp.taskCh)

	// Wait for all workers to finish with timeout
	// BLOCKING-2 FIX: If timeout occurs, goroutines are leaked but we proceed to prevent deadlock
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		wp.logger.Infow("Worker pool stopped successfully", "pool_type", wp.poolType)
	case <-time.After(30 * time.Second):
		// BLOCKING-2 FIX: Explicit warning about goroutine leak
		wp.logger.Errorw("Worker pool shutdown timed out - goroutines leaked",
			"pool_type", wp.poolType,
			"workers", wp.workers,
			"timeout_seconds", 30,
			"remediation", "leaked worker goroutines will continue running until process exits")
		// Update metrics to indicate unhealthy state
		metrics.WorkerPoolActiveWorkers.WithLabelValues(wp.poolType).Set(-1)
	}
}

// Submit adds a task to the worker pool queue
func (wp *WorkerPool) Submit(task func()) error {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	if !wp.running {
		return ErrWorkerPoolNotRunning
	}

	select {
	case wp.taskCh <- task:
		// Update queue size metric
		metrics.WorkerPoolQueueSize.WithLabelValues(wp.poolType).Set(float64(len(wp.taskCh)))
		return nil
	default:
		return ErrWorkerPoolQueueFull
	}
}

// SubmitWithTimeout adds a task with a timeout
func (wp *WorkerPool) SubmitWithTimeout(task func(), timeout time.Duration) error {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	if !wp.running {
		return ErrWorkerPoolNotRunning
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case wp.taskCh <- task:
		return nil
	case <-ctx.Done():
		return ErrWorkerPoolTimeout
	}
}

// GetStats returns current worker pool statistics
func (wp *WorkerPool) GetStats() WorkerPoolStats {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	return WorkerPoolStats{
		Workers:     wp.workers,
		QueueSize:   wp.queueSize,
		Running:     wp.running,
		QueuedTasks: len(wp.taskCh),
		Capacity:    cap(wp.taskCh),
	}
}

// worker is the main worker goroutine
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	defer goroutine.Recover("worker-pool", wp.logger)

	wp.logger.Debugw("Worker started", "worker_id", id)

	for {
		select {
		case <-wp.ctx.Done():
			wp.logger.Debugw("Worker stopping due to context cancellation", "worker_id", id)
			return
		case task, ok := <-wp.taskCh:
			if !ok {
				// Channel closed, exit
				wp.logger.Debugw("Worker stopping due to closed channel", "worker_id", id)
				return
			}

			// Execute task with panic recovery
			func() {
				defer func() {
					if r := recover(); r != nil {
						wp.logger.Errorw("Task panicked in worker",
							"worker_id", id,
							"panic", r)
					}
				}()
				task()
				// Track task completion
				metrics.WorkerPoolTasksProcessed.WithLabelValues(wp.poolType).Inc()
			}()
		}
	}
}

// WorkerPoolStats contains statistics about the worker pool
type WorkerPoolStats struct {
	Workers     int  `json:"workers"`
	QueueSize   int  `json:"queue_size"`
	Running     bool `json:"running"`
	QueuedTasks int  `json:"queued_tasks"`
	Capacity    int  `json:"capacity"`
}

// Errors
var (
	ErrWorkerPoolNotRunning = errors.New("worker pool is not running")
	ErrWorkerPoolQueueFull  = errors.New("worker pool task queue is full")
	ErrWorkerPoolTimeout    = errors.New("worker pool task submission timed out")
)
