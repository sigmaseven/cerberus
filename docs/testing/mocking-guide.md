# Mocking Guide

**Purpose:** Guide for mocking external dependencies in tests.

---

## Interface-Based Mocking

### Creating Mocks

```go
type MockStorage struct {
    events map[string]*core.Event
    mu     sync.RWMutex
}

func NewMockStorage() *MockStorage {
    return &MockStorage{
        events: make(map[string]*core.Event),
    }
}

func (m *MockStorage) GetEvent(id string) (*core.Event, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    event, ok := m.events[id]
    if !ok {
        return nil, errors.New("not found")
    }
    return event, nil
}
```

---

## HTTP Mocking (httptest)

```go
import (
    "net/http"
    "net/http/httptest"
)

mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status": "ok"}`))
}))
defer mockServer.Close()
```

---

## Database Mocking (sqlmock)

```go
import "github.com/DATA-DOG/go-sqlmock"

db, mock, _ := sqlmock.New()
mock.ExpectQuery("SELECT (.+) FROM users").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1"))
```

---

## Time Mocking

```go
type Clock interface {
    Now() time.Time
}

type MockClock struct {
    currentTime time.Time
}

func (m *MockClock) Now() time.Time {
    return m.currentTime
}
```

---

**Last Updated:** 2025-11-20

