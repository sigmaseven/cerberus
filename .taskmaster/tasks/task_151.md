# Task ID: 151

**Title:** Refactor main.go Initialization - Extract to Dedicated Package

**Status:** done

**Dependencies:** 144 ✓

**Priority:** medium

**Description:** Reduce main.go from 1,415 lines to <200 lines by extracting initialization logic to init/ package with testable, composable component initializers.

**Details:**

main.go is 1,415 lines of initialization code:
- 89 error checks
- 47 logging statements
- 23 goroutine launches
- 12 defer statements
- Impossible to test

Current structure:
```go
func main() {
  // 1400 lines of copy-paste initialization
  // Mix of config, storage, API, ML, SOAR, detect, ingest setup
  // No abstraction, no composition
}
```

Refactoring strategy:
1. Create init/ package with component initializers:
   ```go
   // init/storage.go
   func InitializeStorage(ctx context.Context, cfg *config.Config, logger *zap.SugaredLogger) (*storage.Manager, error)
   
   // init/api.go
   func InitializeAPI(ctx context.Context, cfg *config.Config, storage *storage.Manager, logger *zap.SugaredLogger) (*api.Server, error)
   
   // init/detection.go
   func InitializeDetection(ctx context.Context, cfg *config.Config, storage *storage.Manager, logger *zap.SugaredLogger) (*detect.Engine, error)
   
   // init/ml.go
   func InitializeML(ctx context.Context, cfg *config.Config, storage *storage.Manager, logger *zap.SugaredLogger) (*ml.System, error)
   ```
2. Create initialization orchestrator:
   ```go
   // init/app.go
   type App struct {
     Config   *config.Config
     Storage  *storage.Manager
     API      *api.Server
     Detection *detect.Engine
     ML       *ml.System
     logger   *zap.SugaredLogger
   }
   
   func NewApp(ctx context.Context) (*App, error) {
     // Initialize components in dependency order
     // Handle errors gracefully
     // Return composed application
   }
   
   func (a *App) Start(ctx context.Context) error
   func (a *App) Stop() error
   ```
3. Simplify main.go:
   ```go
   func main() {
     ctx, cancel := context.WithCancel(context.Background())
     defer cancel()
     
     app, err := init.NewApp(ctx)
     if err != nil {
       log.Fatalf("Failed to initialize: %v", err)
     }
     defer app.Stop()
     
     if err := app.Start(ctx); err != nil {
       log.Fatalf("Failed to start: %v", err)
     }
     
     // Wait for shutdown signal
     waitForShutdown(cancel)
   }
   ```
4. Add initialization tests:
   - Test each component initializer in isolation
   - Test initialization failure handling
   - Test startup order dependencies
5. Optimize startup time:
   - Parallelize independent initializations
   - Lazy load non-critical components
   - Add startup progress logging

Success criteria:
- main.go under 200 lines (5x reduction)
- Each component initializer <100 lines
- Integration tests covering initialization failures
- Startup time under 5 seconds (currently 15s)
- All components testable in isolation

**Test Strategy:**

1. Unit tests - test each component initializer in isolation
2. Integration tests - test initialization failure scenarios
3. Startup time benchmark - measure time to ready state (<5s)
4. Dependency order test - verify correct initialization sequence
5. Graceful degradation test - verify partial initialization handling
6. Mock tests - test main.go with mocked init package
7. E2E test - full application lifecycle (init/start/stop)

## Subtasks

### 151.1. Create init/ package structure with component initializers

**Status:** pending  
**Dependencies:** None  

Create the init/ package directory and implement individual component initializers (storage.go, api.go, detection.go, ml.go, soar.go, ingest.go) that extract initialization logic from main.go. Each initializer should be a standalone function returning the initialized component and error.

**Details:**

Analyze current main.go to identify initialization blocks for each subsystem. Create init/ directory and files:
- init/storage.go: InitializeStorage(ctx, cfg, logger) -> (*storage.Manager, error)
- init/api.go: InitializeAPI(ctx, cfg, storage, logger) -> (*api.Server, error)
- init/detection.go: InitializeDetection(ctx, cfg, storage, logger) -> (*detect.Engine, error)
- init/ml.go: InitializeML(ctx, cfg, storage, logger) -> (*ml.System, error)
- init/soar.go: InitializeSOAR(ctx, cfg, storage, logger) -> (*soar.System, error)
- init/ingest.go: InitializeIngest(ctx, cfg, storage, logger) -> (*ingest.Manager, error)

Each function should:
- Accept context for cancellation
- Handle configuration specific to that component
- Include proper error wrapping with context
- Keep to <100 lines per function
- Extract the 89 error checks from main.go into appropriate initializers

### 151.2. Design and implement App orchestrator with dependency management

**Status:** pending  
**Dependencies:** 151.1  

Create init/app.go containing the App struct and NewApp() orchestrator that initializes all components in correct dependency order with comprehensive error handling and cleanup on partial failures.

**Details:**

Create init/app.go with:

type App struct {
  Config    *config.Config
  Logger    *zap.SugaredLogger
  Storage   *storage.Manager
  API       *api.Server
  Detection *detect.Engine
  ML        *ml.System
  SOAR      *soar.System
  Ingest    *ingest.Manager
}

func NewApp(ctx context.Context) (*App, error) - orchestrates initialization in dependency order:
1. Config loading
2. Logger setup
3. Storage initialization (foundational dependency)
4. Parallel initialization of independent components (API, Detection, ML, SOAR, Ingest)
5. Cleanup on any failure using defer recovery

func (a *App) Start(ctx context.Context) error - starts all services, launches goroutines
func (a *App) Stop() error - graceful shutdown with timeout, stops all 23 goroutines

Implement proper error aggregation for cleanup failures and startup progress logging.

### 151.3. Add comprehensive tests for component initializers with failure scenarios

**Status:** pending  
**Dependencies:** 151.1  

Implement thorough unit and integration tests for all component initializers, covering failure scenarios, partial initialization cleanup, and dependency validation to ensure robust error handling.

**Details:**

Create comprehensive test suites:

1. Unit tests for each init/*.go file:
- Valid configuration scenarios
- Invalid configuration (missing required fields)
- Dependency failures (e.g., storage connection fails)
- Context cancellation during initialization
- Resource cleanup on errors
- Nil parameter handling

2. Integration tests:
- Test initialization order dependencies
- Verify proper error propagation
- Test partial failure cleanup (ensure no resource leaks)
- Verify all 89 error checks are covered
- Test logging output (verify 47 logging statements are preserved)

3. Failure injection tests:
- Simulate storage connection failures
- Simulate API port binding failures
- Simulate ML model loading failures
- Verify graceful degradation where applicable

Use table-driven tests where possible. Aim for 90%+ coverage on init/ package.

### 151.4. Refactor main.go to use App orchestrator and implement shutdown handling

**Status:** pending  
**Dependencies:** 151.2  

Simplify main.go from 1,415 lines to <200 lines by replacing all initialization code with init.NewApp() call, implementing clean signal-based shutdown handling, and removing duplicated initialization logic.

**Details:**

Refactor main.go to:

```go
func main() {
  // Setup context with cancellation (5 lines)
  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()
  
  // Initialize application (10 lines)
  app, err := init.NewApp(ctx)
  if err != nil {
    log.Fatalf("Failed to initialize application: %v", err)
  }
  defer func() {
    if err := app.Stop(); err != nil {
      log.Printf("Shutdown error: %v", err)
    }
  }()
  
  // Start services (10 lines)
  if err := app.Start(ctx); err != nil {
    log.Fatalf("Failed to start application: %v", err)
  }
  
  // Wait for shutdown signal (20 lines)
  waitForShutdown(cancel)
}

func waitForShutdown(cancel context.CancelFunc) {
  sigChan := make(chan os.Signal, 1)
  signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
  <-sigChan
  log.Println("Shutdown signal received")
  cancel()
}
```

Delete all extracted initialization code. Target: <200 lines total including imports and comments.

### 151.5. Optimize startup time with parallel initialization and progress logging

**Status:** pending  
**Dependencies:** 151.2, 151.3, 151.4  

Reduce startup time from 15s to <5s by parallelizing independent component initializations, implementing lazy loading for non-critical components, and adding structured progress logging for observability.

**Details:**

Optimization strategy:

1. Identify parallelization opportunities in init/app.go:
- Storage must initialize first (foundational)
- API, Detection, ML, SOAR, Ingest can initialize in parallel (goroutines with errgroup)
- Use sync.WaitGroup or errgroup for parallel initialization

2. Implement lazy loading:
- Defer ML model loading until first prediction request
- Defer SOAR playbook compilation until first execution
- Load Sigma rules asynchronously after startup

3. Add startup progress logging:
```go
logger.Info("Initializing storage...")
start := time.Now()
// ... init storage ...
logger.Infof("Storage initialized in %v", time.Since(start))
```

4. Profile startup:
- Add pprof instrumentation during startup
- Identify slowest initializers
- Measure before/after timings

5. Benchmark:
- Create benchmark test measuring full startup time
- Target: <5s from process start to ready state
- Document startup time in README
