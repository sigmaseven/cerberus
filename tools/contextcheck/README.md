# contextcheck - Static Analysis for context.Background()

A Go static analysis tool that detects inappropriate usage of `context.Background()` in production code.

## Purpose

`context.Background()` creates an empty context that cannot be canceled and has no deadline. Using it in request handling paths prevents:

- **Graceful shutdown** - Operations can't be interrupted during shutdown
- **Timeout enforcement** - Requests have no deadline to respect
- **Distributed tracing** - Request correlation is lost
- **Resource cleanup** - Context cancellation can't trigger cleanup

This tool enforces proper context propagation by flagging `context.Background()` usage outside of approved locations.

## Installation

```bash
go install cerberus/tools/contextcheck/cmd/contextcheck@latest
```

## Usage

### As a standalone tool

```bash
contextcheck ./...
```

### With go vet

```bash
go vet -vettool=$(which contextcheck) ./...
```

### In CI/CD pipeline

Add to your CI configuration:

```yaml
- name: Check context.Background() usage
  run: |
    go install cerberus/tools/contextcheck/cmd/contextcheck@latest
    contextcheck ./...
```

## Allowed Locations

The analyzer allows `context.Background()` in these locations:

| Location | Reason |
|----------|--------|
| `main()` function | Application initialization |
| `init()` functions | Package initialization |
| `TestXxx` functions | Test setup |
| `BenchmarkXxx` functions | Benchmark setup |
| `ExampleXxx` functions | Example code |
| Test helper functions | Functions calling `t.Helper()` |
| Test setup functions | Functions with names containing setup, mock, fixture, helper |
| Exempted lines | Lines with `contextcheck:exempt` comment |

## Exemption Comments

To exempt a specific usage, add a comment on the same line or line above:

```go
// contextcheck:exempt reason="background worker initialization"
ctx := context.Background()
```

Or inline:

```go
ctx := context.Background() // contextcheck:exempt
```

## Examples

### Flagged (Incorrect)

```go
// Handler should use request context
func handleRequest(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background() // FLAGGED: use r.Context() instead
    db.QueryContext(ctx, "SELECT ...")
}

// Service layer should accept context parameter
func fetchUser(id string) (*User, error) {
    ctx := context.Background() // FLAGGED: add ctx parameter
    return db.QueryContext(ctx, "SELECT ...")
}
```

### Correct

```go
// Handler uses request context
func handleRequest(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context() // OK: propagates request context
    db.QueryContext(ctx, "SELECT ...")
}

// Service layer accepts context parameter
func fetchUser(ctx context.Context, id string) (*User, error) {
    return db.QueryContext(ctx, "SELECT ...") // OK: uses provided context
}

// Main function initialization
func main() {
    ctx := context.Background() // OK: application startup
    server.Run(ctx)
}

// Test function
func TestFetchUser(t *testing.T) {
    ctx := context.Background() // OK: test setup
    // ...
}
```

## Integration with golangci-lint

To use with golangci-lint, add to `.golangci.yml`:

```yaml
linters-settings:
  custom:
    contextcheck:
      path: ./tools/contextcheck/contextcheck.so
      description: Check for inappropriate context.Background() usage

linters:
  enable:
    - contextcheck
```

Build the plugin:

```bash
go build -buildmode=plugin -o tools/contextcheck/contextcheck.so ./tools/contextcheck
```

## Fixing Violations

When the tool flags a `context.Background()` usage:

1. **Add context parameter to function**:
   ```go
   // Before
   func processData() { ctx := context.Background(); ... }

   // After
   func processData(ctx context.Context) { ... }
   ```

2. **Propagate request context in handlers**:
   ```go
   // Before
   func handler(w http.ResponseWriter, r *http.Request) {
       ctx := context.Background()
   }

   // After
   func handler(w http.ResponseWriter, r *http.Request) {
       ctx := r.Context()
   }
   ```

3. **Use parent context in goroutines**:
   ```go
   // Before
   go func() {
       ctx := context.Background()
       doWork(ctx)
   }()

   // After
   go func(parentCtx context.Context) {
       doWork(parentCtx)
   }(ctx)
   ```

## Contributing

When adding new allowed patterns:

1. Add test cases to `testdata/src/a/`
2. Update the allowlist in `analyzer.go`
3. Document the new pattern in this README
4. Run tests: `go test ./...`

## License

Same license as the Cerberus SIEM project.
