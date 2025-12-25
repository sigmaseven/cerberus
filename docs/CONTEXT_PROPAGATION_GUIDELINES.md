# Context Propagation Guidelines

This document establishes coding standards for proper context handling in the Cerberus SIEM codebase. Following these guidelines ensures graceful shutdown, proper timeout handling, and distributed tracing support.

## Table of Contents

1. [When to Use context.Background() vs Parent Context](#when-to-use-contextbackground-vs-parent-context)
2. [Function Signature Patterns](#function-signature-patterns)
3. [Timeout and Cancellation Best Practices](#timeout-and-cancellation-best-practices)
4. [HTTP Client Context Handling](#http-client-context-handling)
5. [Database Operations](#database-operations)
6. [Goroutine Spawning](#goroutine-spawning)
7. [Code Review Checklist](#code-review-checklist)

## When to Use context.Background() vs Parent Context

### Use `context.Background()` ONLY for:

1. **Application Entry Point**
   ```go
   func main() {
       ctx := context.Background()
       app.Run(ctx)
   }
   ```

2. **CLI Commands** (short-lived, no shutdown coordination)
   ```go
   func runCommand() {
       ctx := context.Background()
       // CLI operations...
   }
   ```

3. **Test Setup**
   ```go
   func TestSomething(t *testing.T) {
       ctx := context.Background()
       // Test code...
   }
   ```

### Use Parent Context for:

1. **HTTP Handlers** - Always propagate `r.Context()`
   ```go
   func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
       ctx := r.Context()
       result, err := h.service.Process(ctx, data)
   }
   ```

2. **Service Layer** - Accept and propagate context
   ```go
   func (s *Service) Process(ctx context.Context, data Data) error {
       return s.storage.Save(ctx, data)
   }
   ```

3. **Background Workers** - Use app shutdown context
   ```go
   func (w *Worker) Start(ctx context.Context) {
       for {
           select {
           case <-ctx.Done():
               return
           case item := <-w.queue:
               w.process(ctx, item)
           }
       }
   }
   ```

## Function Signature Patterns

### Standard Pattern: Context as First Parameter

```go
// GOOD: Context is first parameter
func ProcessEvent(ctx context.Context, event *Event) error

// GOOD: Method with context
func (s *Service) Save(ctx context.Context, data *Data) error

// BAD: Context not first
func ProcessEvent(event *Event, ctx context.Context) error

// BAD: No context parameter
func ProcessEvent(event *Event) error
```

### Optional Operations with Context

```go
// For operations that can run detached or with context
type Option func(*options)

func WithContext(ctx context.Context) Option {
    return func(o *options) {
        o.ctx = ctx
    }
}
```

## Timeout and Cancellation Best Practices

### Always Set Timeouts for External Calls

```go
// GOOD: HTTP call with timeout
func callExternalAPI(ctx context.Context, url string) error {
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return err
    }

    resp, err := http.DefaultClient.Do(req)
    // ...
}

// BAD: No timeout
func callExternalAPI(url string) error {
    resp, err := http.Get(url)  // Can hang forever!
    // ...
}
```

### Check Context Before Long Operations

```go
func processItems(ctx context.Context, items []Item) error {
    for _, item := range items {
        // Check if context is cancelled before each item
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        if err := processItem(ctx, item); err != nil {
            return err
        }
    }
    return nil
}
```

### Timeout Recommendations by Operation Type

| Operation Type | Recommended Timeout |
|---------------|---------------------|
| Database query | 5-30 seconds |
| HTTP API call | 10-60 seconds |
| DNS resolution | 5 seconds |
| File I/O | 30 seconds |
| Bulk operations | 5 minutes |

## HTTP Client Context Handling

### Creating HTTP Requests

```go
// GOOD: Use NewRequestWithContext
req, err := http.NewRequestWithContext(ctx, method, url, body)

// BAD: Creates request without context
req, err := http.NewRequest(method, url, body)
req = req.WithContext(ctx)  // Less efficient
```

### HTTP Client Configuration

```go
// GOOD: Configure client with appropriate timeouts
client := &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        DialContext: (&net.Dialer{
            Timeout:   5 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
        TLSHandshakeTimeout:   10 * time.Second,
        ResponseHeaderTimeout: 10 * time.Second,
        IdleConnTimeout:       90 * time.Second,
    },
}
```

### Webhook/Notification Functions

```go
// GOOD: Accept context, use WithContext request
func sendWebhook(ctx context.Context, url string, payload interface{}) error {
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    body, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("marshal payload: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("create request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("send request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        return fmt.Errorf("webhook failed: status %d", resp.StatusCode)
    }

    return nil
}
```

## Database Operations

### Always Accept Context

```go
// GOOD: Database operations accept context
func (s *Storage) GetByID(ctx context.Context, id string) (*Entity, error) {
    row := s.db.QueryRowContext(ctx, "SELECT * FROM entities WHERE id = ?", id)
    // ...
}

// GOOD: Transaction with context
func (s *Storage) UpdateWithTransaction(ctx context.Context, updates []Update) error {
    tx, err := s.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    for _, u := range updates {
        if _, err := tx.ExecContext(ctx, u.Query, u.Args...); err != nil {
            return err
        }
    }

    return tx.Commit()
}
```

## Goroutine Spawning

### Detached Goroutines Must Support Cancellation

```go
// GOOD: Goroutine respects cancellation
func (s *Service) StartBackgroundWorker(ctx context.Context) {
    go func() {
        ticker := time.NewTicker(time.Minute)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                log.Info("worker shutting down")
                return
            case <-ticker.C:
                s.doWork(ctx)
            }
        }
    }()
}

// BAD: Goroutine cannot be stopped
func (s *Service) StartBackgroundWorker() {
    go func() {
        for {
            time.Sleep(time.Minute)
            s.doWork()  // Runs forever, blocks shutdown
        }
    }()
}
```

### Deriving Contexts for Goroutines

```go
// When spawning work that should outlive the request but respect shutdown
func (h *Handler) HandleAsync(w http.ResponseWriter, r *http.Request) {
    // Use application shutdown context, not request context
    workCtx, cancel := context.WithTimeout(h.shutdownCtx, 5*time.Minute)

    go func() {
        defer cancel()
        h.processAsync(workCtx, data)
    }()

    w.WriteHeader(http.StatusAccepted)
}
```

## Code Review Checklist

### Before Approving Code, Verify:

- [ ] No `context.Background()` in handler/service code (except allowed exceptions)
- [ ] All HTTP client calls use `http.NewRequestWithContext()`
- [ ] All database operations use `*Context()` variants
- [ ] External API calls have appropriate timeouts
- [ ] Goroutines check `ctx.Done()` in their loops
- [ ] Context is the first parameter in function signatures
- [ ] No `context.TODO()` in production code
- [ ] Long-running loops check for cancellation

### Allowed Exceptions for `context.Background()`:

1. `main()` function
2. CLI command entry points
3. Test setup functions
4. Initialization code that runs before app context exists

### Red Flags to Watch For:

```go
// RED FLAG: HTTP call without context
http.Get(url)
http.Post(url, contentType, body)
http.NewRequest(method, url, body)

// RED FLAG: Database call without context
db.Query(query, args...)
db.Exec(query, args...)

// RED FLAG: Infinite loop without context check
for {
    doWork()
}

// RED FLAG: context.Background() in handler
func Handler(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()  // Should use r.Context()
}
```

## Migration Pattern

When updating legacy code:

1. Add `ctx context.Context` as first parameter
2. Update all internal calls to pass context
3. Replace `http.NewRequest` with `http.NewRequestWithContext`
4. Add timeout wrapper if calling external services
5. Update callers to pass their context
6. Run tests to ensure context propagation works

```go
// Before
func sendNotification(url string, msg Message) error {
    body, _ := json.Marshal(msg)
    resp, err := http.Post(url, "application/json", bytes.NewReader(body))
    // ...
}

// After
func sendNotification(ctx context.Context, url string, msg Message) error {
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    body, _ := json.Marshal(msg)
    req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := httpClient.Do(req)
    // ...
}
```
