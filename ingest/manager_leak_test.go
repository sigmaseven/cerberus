package ingest

import (
	"runtime"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"

	"go.uber.org/zap"
)

// mockDynamicListenerStorage is a minimal mock for testing
type mockDynamicListenerStorage struct{}

func (m *mockDynamicListenerStorage) CreateListener(listener *storage.DynamicListener) error {
	return nil
}
func (m *mockDynamicListenerStorage) UpdateListener(id string, listener *storage.DynamicListener) error {
	return nil
}
func (m *mockDynamicListenerStorage) DeleteListener(id string) error { return nil }
func (m *mockDynamicListenerStorage) GetListener(id string) (*storage.DynamicListener, error) {
	return nil, nil
}
func (m *mockDynamicListenerStorage) GetAllListeners() ([]*storage.DynamicListener, error) {
	return []*storage.DynamicListener{}, nil
}
func (m *mockDynamicListenerStorage) UpdateStatistics(id string, stats *storage.ListenerStats) error {
	return nil
}
func (m *mockDynamicListenerStorage) UpdateListenerStatus(id, status string) error { return nil }
func (m *mockDynamicListenerStorage) SetStartedAt(id string, t time.Time) error    { return nil }
func (m *mockDynamicListenerStorage) SetStoppedAt(id string, t time.Time) error    { return nil }
func (m *mockDynamicListenerStorage) CheckPortConflict(host string, port int, protocol, excludeID string) (bool, error) {
	return false, nil
}
func (m *mockDynamicListenerStorage) GetListenersByStatus(status string) ([]*storage.DynamicListener, error) {
	return []*storage.DynamicListener{}, nil
}

// mockFieldMappingStorage is a minimal mock for testing
type mockFieldMappingStorage struct{}

func (m *mockFieldMappingStorage) Get(name string) (*storage.FieldMapping, error) {
	return nil, nil
}
func (m *mockFieldMappingStorage) List() ([]*storage.FieldMapping, error) {
	return []*storage.FieldMapping{}, nil
}
func (m *mockFieldMappingStorage) Create(mapping *storage.FieldMapping) error { return nil }
func (m *mockFieldMappingStorage) Update(mapping *storage.FieldMapping) error { return nil }
func (m *mockFieldMappingStorage) Delete(name string) error                    { return nil }
func (m *mockFieldMappingStorage) SeedDefaults(yamlPath string) error          { return nil }

// TestListenerManagerGoroutineLeak verifies that ListenerManager.Shutdown() doesn't leak goroutines
// BLOCKING-6: Goroutine leak detection test for ListenerManager
func TestListenerManagerGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create test components
	mockStorage := &mockDynamicListenerStorage{}
	mockFieldStorage := &mockFieldMappingStorage{}
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{
		Engine: config.EngineConfig{
			RateLimit: 1000,
		},
	}

	// Create listener manager (this starts the stats collector goroutine)
	manager := NewListenerManager(mockStorage, mockFieldStorage, eventCh, cfg, sugar, nil)

	// Allow goroutine to start
	time.Sleep(200 * time.Millisecond)

	// Shutdown manager
	manager.Shutdown()

	// Close event channel
	close(eventCh)

	// Force GC and wait for goroutines to terminate
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()

	// BLOCKING-3 FIX: ListenerManager stats collector now has proper defer for ticker.Stop()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak detected: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// TestListenerManagerMultipleShutdown tests multiple shutdown calls
// BLOCKING-6: Ensure Shutdown() is idempotent and doesn't leak
func TestListenerManagerMultipleShutdown(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	defer logger.Sync()

	mockStorage := &mockDynamicListenerStorage{}
	mockFieldStorage := &mockFieldMappingStorage{}
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{
		Engine: config.EngineConfig{
			RateLimit: 1000,
		},
	}

	manager := NewListenerManager(mockStorage, mockFieldStorage, eventCh, cfg, sugar, nil)
	time.Sleep(200 * time.Millisecond)

	// Call shutdown multiple times
	manager.Shutdown()
	manager.Shutdown() // Second call should be safe
	manager.Shutdown() // Third call should be safe

	close(eventCh)

	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak after multiple shutdowns: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak after multiple shutdowns: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}
