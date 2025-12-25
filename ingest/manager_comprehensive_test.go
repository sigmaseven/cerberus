package ingest

import (
	"fmt"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// mockListenerStorage implements DynamicListenerStorageInterface for testing
type mockListenerStorage struct {
	listeners map[string]*storage.DynamicListener
	portMap   map[string]bool // host:port:protocol -> inUse
}

func newMockListenerStorage() *mockListenerStorage {
	return &mockListenerStorage{
		listeners: make(map[string]*storage.DynamicListener),
		portMap:   make(map[string]bool),
	}
}

func (m *mockListenerStorage) CreateListener(listener *storage.DynamicListener) error {
	m.listeners[listener.ID] = listener
	key := fmt.Sprintf("%s:%d:%s", listener.Host, listener.Port, listener.Protocol)
	m.portMap[key] = true
	return nil
}

func (m *mockListenerStorage) GetListener(id string) (*storage.DynamicListener, error) {
	listener, ok := m.listeners[id]
	if !ok {
		return nil, fmt.Errorf("listener not found")
	}
	return listener, nil
}

func (m *mockListenerStorage) GetAllListeners() ([]*storage.DynamicListener, error) {
	listeners := make([]*storage.DynamicListener, 0, len(m.listeners))
	for _, l := range m.listeners {
		listeners = append(listeners, l)
	}
	return listeners, nil
}

func (m *mockListenerStorage) UpdateListener(id string, listener *storage.DynamicListener) error {
	if _, ok := m.listeners[id]; !ok {
		return fmt.Errorf("listener not found")
	}
	m.listeners[id] = listener
	return nil
}

func (m *mockListenerStorage) DeleteListener(id string) error {
	if _, ok := m.listeners[id]; !ok {
		return fmt.Errorf("listener not found")
	}
	delete(m.listeners, id)
	return nil
}

func (m *mockListenerStorage) CheckPortConflict(host string, port int, protocol, excludeID string) (bool, error) {
	key := fmt.Sprintf("%s:%d:%s", host, port, protocol)
	if excludeID != "" {
		// Check if the excluded listener uses this port
		if l, ok := m.listeners[excludeID]; ok {
			excludeKey := fmt.Sprintf("%s:%d:%s", l.Host, l.Port, l.Protocol)
			if excludeKey == key {
				return false, nil // Same listener, no conflict
			}
		}
	}
	return m.portMap[key], nil
}

func (m *mockListenerStorage) UpdateListenerStatus(id, status string) error {
	if l, ok := m.listeners[id]; ok {
		l.Status = status
	}
	return nil
}

func (m *mockListenerStorage) GetListenersByStatus(status string) ([]*storage.DynamicListener, error) {
	listeners := make([]*storage.DynamicListener, 0)
	for _, l := range m.listeners {
		if l.Status == status {
			listeners = append(listeners, l)
		}
	}
	return listeners, nil
}

func (m *mockListenerStorage) SetStartedAt(id string, t time.Time) error {
	if l, ok := m.listeners[id]; ok {
		l.StartedAt = t
	}
	return nil
}

func (m *mockListenerStorage) SetStoppedAt(id string, t time.Time) error {
	if l, ok := m.listeners[id]; ok {
		l.StoppedAt = t
	}
	return nil
}

func (m *mockListenerStorage) IncrementEventCount(id string) error {
	return nil
}

func (m *mockListenerStorage) IncrementErrorCount(id string) error {
	return nil
}

func (m *mockListenerStorage) UpdateStatistics(id string, stats *storage.ListenerStats) error {
	if l, ok := m.listeners[id]; ok {
		l.EventsReceived = stats.EventsReceived
		l.ErrorCount = stats.ErrorCount
		l.LastEvent = stats.LastEvent
	}
	return nil
}

// mockFieldMappingStorage implements FieldMappingStorage for testing
type mockFieldMappingStorage struct {
	mappings map[string]*storage.FieldMapping
}

func newMockFieldMappingStorage() *mockFieldMappingStorage {
	return &mockFieldMappingStorage{
		mappings: map[string]*storage.FieldMapping{
			"sigma": {
				ID:       "sigma",
				Name:     "Sigma Fields",
				Mappings: make(map[string]string),
			},
		},
	}
}

func (m *mockFieldMappingStorage) Get(id string) (*storage.FieldMapping, error) {
	mapping, ok := m.mappings[id]
	if !ok {
		return nil, fmt.Errorf("mapping not found")
	}
	return mapping, nil
}

func (m *mockFieldMappingStorage) GetByName(name string) (*storage.FieldMapping, error) {
	for _, mapping := range m.mappings {
		if mapping.Name == name {
			return mapping, nil
		}
	}
	return nil, fmt.Errorf("mapping not found")
}

func (m *mockFieldMappingStorage) List() ([]*storage.FieldMapping, error) {
	mappings := make([]*storage.FieldMapping, 0, len(m.mappings))
	for _, mapping := range m.mappings {
		mappings = append(mappings, mapping)
	}
	return mappings, nil
}

func (m *mockFieldMappingStorage) Create(mapping *storage.FieldMapping) error {
	m.mappings[mapping.ID] = mapping
	return nil
}

func (m *mockFieldMappingStorage) Update(mapping *storage.FieldMapping) error {
	if _, ok := m.mappings[mapping.ID]; !ok {
		return fmt.Errorf("mapping not found")
	}
	m.mappings[mapping.ID] = mapping
	return nil
}

func (m *mockFieldMappingStorage) Delete(id string) error {
	delete(m.mappings, id)
	return nil
}

func (m *mockFieldMappingStorage) SeedDefaults(yamlPath string) error {
	return nil
}

// TestNewListenerManager tests listener manager creation
func TestNewListenerManager(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)

	require.NotNil(t, lm)
	assert.NotNil(t, lm.listeners)
	assert.NotNil(t, lm.storage)
	assert.NotNil(t, lm.rawEventCh)
	assert.NotNil(t, lm.logger)
	assert.Equal(t, 100, lm.maxListeners)
	assert.True(t, lm.restoreEnabled)

	// Cleanup
	lm.Shutdown()
}

// TestListenerManager_CreateListener tests listener creation
func TestListenerManager_CreateListener(t *testing.T) {
	tests := []struct {
		name        string
		listener    *storage.DynamicListener
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid syslog listener",
			listener: &storage.DynamicListener{
				Name:         "test-syslog",
				Type:         "syslog",
				Protocol:     "udp",
				Host:         "127.0.0.1",
				Port:         5140,
				Source:       "test-source",
				FieldMapping: "sigma",
			},
			expectError: false,
		},
		{
			name: "Valid CEF listener",
			listener: &storage.DynamicListener{
				Name:         "test-cef",
				Type:         "cef",
				Protocol:     "tcp",
				Host:         "0.0.0.0",
				Port:         5141,
				Source:       "cef-source",
				FieldMapping: "sigma",
			},
			expectError: false,
		},
		{
			name: "Valid JSON listener",
			listener: &storage.DynamicListener{
				Name:         "test-json",
				Type:         "json",
				Protocol:     "http",
				Host:         "127.0.0.1",
				Port:         5142,
				Source:       "json-source",
				FieldMapping: "sigma",
			},
			expectError: false,
		},
		{
			name: "Missing name",
			listener: &storage.DynamicListener{
				Type:     "syslog",
				Protocol: "udp",
				Host:     "127.0.0.1",
				Port:     5143,
				Source:   "test-source",
			},
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name: "Invalid type",
			listener: &storage.DynamicListener{
				Name:     "test-invalid",
				Type:     "invalid",
				Protocol: "udp",
				Host:     "127.0.0.1",
				Port:     5144,
				Source:   "test-source",
			},
			expectError: true,
			errorMsg:    "invalid type",
		},
		{
			name: "Invalid protocol",
			listener: &storage.DynamicListener{
				Name:     "test-invalid-proto",
				Type:     "syslog",
				Protocol: "invalid",
				Host:     "127.0.0.1",
				Port:     5145,
				Source:   "test-source",
			},
			expectError: true,
			errorMsg:    "invalid protocol",
		},
		{
			name: "Invalid port (negative)",
			listener: &storage.DynamicListener{
				Name:     "test-invalid-port",
				Type:     "syslog",
				Protocol: "udp",
				Host:     "127.0.0.1",
				Port:     -1,
				Source:   "test-source",
			},
			expectError: true,
			errorMsg:    "port must be between 0 and 65535",
		},
		{
			name: "Invalid port (too high)",
			listener: &storage.DynamicListener{
				Name:     "test-invalid-port2",
				Type:     "syslog",
				Protocol: "udp",
				Host:     "127.0.0.1",
				Port:     70000,
				Source:   "test-source",
			},
			expectError: true,
			errorMsg:    "port must be between 0 and 65535",
		},
		{
			name: "Missing source",
			listener: &storage.DynamicListener{
				Name:     "test-no-source",
				Type:     "syslog",
				Protocol: "udp",
				Host:     "127.0.0.1",
				Port:     5146,
			},
			expectError: true,
			errorMsg:    "source identifier is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := newMockListenerStorage()
			mockFieldMapping := newMockFieldMappingStorage()
			eventCh := make(chan *core.Event, 100)
			cfg := &config.Config{}
			logger := zap.NewNop().Sugar()

			// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
			lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
			defer lm.Shutdown()

			created, err := lm.CreateListener(tt.listener)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, created)
				assert.NotEmpty(t, created.ID)
				assert.Equal(t, "stopped", created.Status)
				assert.Equal(t, tt.listener.Name, created.Name)
			}
		})
	}
}

// TestListenerManager_PortConflict tests port conflict detection
func TestListenerManager_PortConflict(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create first listener
	listener1 := &storage.DynamicListener{
		Name:     "listener1",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5150,
		Source:   "source1",
	}

	_, err := lm.CreateListener(listener1)
	assert.NoError(t, err)

	// Try to create second listener on same port - should fail
	listener2 := &storage.DynamicListener{
		Name:     "listener2",
		Type:     "cef",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5150,
		Source:   "source2",
	}

	_, err = lm.CreateListener(listener2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

// TestListenerManager_ListListeners tests listing all listeners
func TestListenerManager_ListListeners(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create multiple listeners
	for i := 0; i < 5; i++ {
		listener := &storage.DynamicListener{
			Name:     fmt.Sprintf("listener%d", i),
			Type:     "syslog",
			Protocol: "udp",
			Host:     "127.0.0.1",
			Port:     5200 + i,
			Source:   fmt.Sprintf("source%d", i),
		}
		_, err := lm.CreateListener(listener)
		assert.NoError(t, err)
	}

	// List all listeners
	listeners, err := lm.ListListeners()
	assert.NoError(t, err)
	assert.Equal(t, 5, len(listeners))
}

// TestListenerManager_GetListener tests getting a specific listener
func TestListenerManager_GetListener(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create listener
	listener := &storage.DynamicListener{
		Name:     "test-listener",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5250,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	assert.NoError(t, err)

	// Get listener
	retrieved, err := lm.GetListener(created.ID)
	assert.NoError(t, err)
	assert.Equal(t, created.ID, retrieved.ID)
	assert.Equal(t, created.Name, retrieved.Name)

	// Try to get non-existent listener
	_, err = lm.GetListener("non-existent-id")
	assert.Error(t, err)
}

// TestListenerManager_DeleteListener tests listener deletion
func TestListenerManager_DeleteListener(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create listener
	listener := &storage.DynamicListener{
		Name:     "test-listener",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5260,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	assert.NoError(t, err)

	// Delete listener
	err = lm.DeleteListener(created.ID)
	assert.NoError(t, err)

	// Try to get deleted listener
	_, err = lm.GetListener(created.ID)
	assert.Error(t, err)
}

// TestListenerManager_UpdateListener tests listener updates
func TestListenerManager_UpdateListener(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create listener
	listener := &storage.DynamicListener{
		Name:     "test-listener",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5270,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	assert.NoError(t, err)

	// Update listener
	updates := &storage.DynamicListener{
		Name:     "updated-listener",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5271,
		Source:   "updated-source",
	}

	err = lm.UpdateListener(created.ID, updates)
	assert.NoError(t, err)

	// Verify update
	retrieved, err := lm.GetListener(created.ID)
	assert.NoError(t, err)
	assert.Equal(t, "updated-listener", retrieved.Name)
	assert.Equal(t, 5271, retrieved.Port)
}

// TestListenerManager_MaxListeners tests max listener limit
// Note: The max listener limit applies to RUNNING listeners (lm.listeners map),
// not created/stopped listeners in storage. This test simulates the limit.
func TestListenerManager_MaxListeners(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	lm.maxListeners = 3 // Set low limit for testing

	// Create and add running listeners to simulate the limit
	// Must provide StopCh since Shutdown will try to close them
	for i := 0; i < 3; i++ {
		listenerID := uuid.New().String()
		ml := &ManagedListener{
			Config: &storage.DynamicListener{
				ID:   listenerID,
				Name: fmt.Sprintf("listener%d", i),
			},
			Status:    "running",
			StartTime: time.Now(),
			StopCh:    make(chan struct{}),
		}
		lm.listeners[listenerID] = ml
	}

	// Try to create one more - should fail due to running listener limit
	listener := &storage.DynamicListener{
		Name:     "listener-overflow",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5303,
		Source:   "overflow-source",
	}
	_, err := lm.CreateListener(listener)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum listener limit")

	// Proper shutdown
	lm.Shutdown()
}

// TestListenerManager_ValidateConfig tests configuration validation
func TestListenerManager_ValidateConfig(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	tests := []struct {
		name        string
		listener    *storage.DynamicListener
		expectError bool
	}{
		{
			name: "Valid configuration",
			listener: &storage.DynamicListener{
				Name:     "valid",
				Type:     "syslog",
				Protocol: "udp",
				Host:     "127.0.0.1",
				Port:     5350,
				Source:   "source",
			},
			expectError: false,
		},
		{
			name: "TLS without cert files",
			listener: &storage.DynamicListener{
				Name:     "tls-no-certs",
				Type:     "json",
				Protocol: "http",
				Host:     "127.0.0.1",
				Port:     5351,
				Source:   "source",
				TLS:      true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lm.validateConfig(tt.listener)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestListenerManager_IncrementCounters tests event and error counter increments
func TestListenerManager_IncrementCounters(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)

	// Create a managed listener entry directly (simulating a running listener)
	listenerID := uuid.New().String()
	ml := &ManagedListener{
		Config: &storage.DynamicListener{
			ID:   listenerID,
			Name: "test",
		},
		EventCounter: 0,
		ErrorCounter: 0,
		StartTime:    time.Now(),
		Status:       "running",
		StopCh:       make(chan struct{}),
	}
	lm.listeners[listenerID] = ml

	// Increment event counter
	lm.IncrementEventCount(listenerID)
	assert.Equal(t, int64(1), ml.EventCounter)

	// Increment error counter
	lm.IncrementErrorCount(listenerID)
	assert.Equal(t, int64(1), ml.ErrorCounter)

	// Increment non-existent listener (should not panic)
	lm.IncrementEventCount("non-existent")
	lm.IncrementErrorCount("non-existent")

	// Cleanup
	lm.Shutdown()
}

// BenchmarkListenerManager_CreateListener benchmarks listener creation
func BenchmarkListenerManager_CreateListener(b *testing.B) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 1000)
	cfg := &config.Config{}
	logger := zap.NewNop().Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		listener := &storage.DynamicListener{
			Name:     fmt.Sprintf("bench-listener-%d", i),
			Type:     "syslog",
			Protocol: "udp",
			Host:     "127.0.0.1",
			Port:     10000 + (i % 50000), // Avoid port conflicts
			Source:   "bench-source",
		}
		lm.CreateListener(listener)
	}
}
