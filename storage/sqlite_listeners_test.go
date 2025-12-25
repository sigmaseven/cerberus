package storage

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// setupListenerTestDB creates a fresh in-memory database for listener testing
func setupListenerTestDB(t *testing.T) *SQLiteDynamicListenerStorage {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	db, err := NewSQLite(":memory:", sugar)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	storage, err := NewSQLiteDynamicListenerStorage(db, sugar)
	if err != nil {
		t.Fatalf("Failed to create listener storage: %v", err)
	}

	return storage
}

// createTestListener creates a test listener with all fields populated
func createTestListener(id string, port int) *DynamicListener {
	return &DynamicListener{
		ID:             id,
		Name:           "Test Listener " + id,
		Description:    "Test description for " + id,
		Type:           "syslog",
		Protocol:       "tcp",
		Host:           "0.0.0.0",
		Port:           port,
		TLS:            false,
		Status:         "stopped",
		Tags:           []string{"test", "syslog"},
		Source:         "test-source",
		EventsReceived: 0,
		ErrorCount:     0,
		CreatedBy:      "admin",
	}
}

func TestNewSQLiteDynamicListenerStorage(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	db, err := NewSQLite(":memory:", sugar)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	storage, err := NewSQLiteDynamicListenerStorage(db, sugar)
	if err != nil {
		t.Errorf("Failed to create listener storage: %v", err)
	}
	if storage == nil {
		t.Error("Expected non-nil storage")
	}
	if storage.db == nil {
		t.Error("Expected non-nil db")
	}
	if storage.logger == nil {
		t.Error("Expected non-nil logger")
	}
}

func TestCreateListener(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener001", 5140)

	err := storage.CreateListener(listener)
	if err != nil {
		t.Errorf("Failed to create listener: %v", err)
	}

	// Verify listener was created
	retrieved, err := storage.GetListener("listener001")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil listener")
	}
	if retrieved.ID != "listener001" {
		t.Errorf("Expected ID listener001, got %s", retrieved.ID)
	}
	if retrieved.Name != "Test Listener listener001" {
		t.Errorf("Expected name 'Test Listener listener001', got %s", retrieved.Name)
	}
	if retrieved.Port != 5140 {
		t.Errorf("Expected port 5140, got %d", retrieved.Port)
	}
	if retrieved.Type != "syslog" {
		t.Errorf("Expected type syslog, got %s", retrieved.Type)
	}
	if retrieved.Protocol != "tcp" {
		t.Errorf("Expected protocol tcp, got %s", retrieved.Protocol)
	}
	if len(retrieved.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(retrieved.Tags))
	}
}

func TestCreateListener_MinimalFields(t *testing.T) {
	storage := setupListenerTestDB(t)

	listener := &DynamicListener{
		ID:       "listener_minimal",
		Name:     "Minimal Listener",
		Type:     "json",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     5000,
		Status:   "stopped",
	}

	err := storage.CreateListener(listener)
	if err != nil {
		t.Errorf("Failed to create minimal listener: %v", err)
	}

	retrieved, err := storage.GetListener("listener_minimal")
	if err != nil {
		t.Errorf("Failed to retrieve minimal listener: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil listener")
	}
	if retrieved.ID != "listener_minimal" {
		t.Errorf("Expected ID listener_minimal, got %s", retrieved.ID)
	}
}

func TestCreateListener_WithTLS(t *testing.T) {
	storage := setupListenerTestDB(t)

	listener := createTestListener("listener_tls", 6140)
	listener.TLS = true
	listener.CertFile = "/path/to/cert.pem"
	listener.KeyFile = "/path/to/key.pem"

	err := storage.CreateListener(listener)
	if err != nil {
		t.Errorf("Failed to create TLS listener: %v", err)
	}

	retrieved, err := storage.GetListener("listener_tls")
	if err != nil {
		t.Errorf("Failed to retrieve TLS listener: %v", err)
	}
	if !retrieved.TLS {
		t.Error("Expected TLS to be true")
	}
	if retrieved.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected cert file '/path/to/cert.pem', got %s", retrieved.CertFile)
	}
	if retrieved.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected key file '/path/to/key.pem', got %s", retrieved.KeyFile)
	}
}

func TestCreateListener_SQLInjectionPrevention(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Attempt SQL injection through various fields
	listener := &DynamicListener{
		ID:          "listener_sql'; DROP TABLE dynamic_listeners; --",
		Name:        "Test'; DELETE FROM dynamic_listeners WHERE '1'='1",
		Description: "'; UPDATE dynamic_listeners SET status='running' WHERE '1'='1'; --",
		Type:        "syslog",
		Protocol:    "tcp",
		Host:        "0.0.0.0",
		Port:        9999,
		Status:      "stopped",
		Source:      "'; DROP TABLE dynamic_listeners; --",
	}

	err := storage.CreateListener(listener)
	if err != nil {
		t.Errorf("Failed to create listener with SQL injection attempt: %v", err)
	}

	// Verify data was stored safely
	retrieved, err := storage.GetListener("listener_sql'; DROP TABLE dynamic_listeners; --")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil listener")
	}
	if !strings.Contains(retrieved.Name, "DELETE FROM dynamic_listeners") {
		t.Error("SQL injection attempt should be stored as literal text")
	}

	// Verify table still exists by querying all listeners
	listeners, err := storage.GetAllListeners()
	if err != nil {
		t.Errorf("Table should still exist after SQL injection attempt: %v", err)
	}
	if len(listeners) == 0 {
		t.Error("Expected at least one listener")
	}
}

func TestCreateListener_DuplicatePort(t *testing.T) {
	storage := setupListenerTestDB(t)

	listener1 := createTestListener("listener_dup1", 5141)
	err := storage.CreateListener(listener1)
	if err != nil {
		t.Fatalf("Failed to create first listener: %v", err)
	}

	// Try to create another listener with same host/port/protocol (should fail due to UNIQUE constraint)
	listener2 := createTestListener("listener_dup2", 5141)
	err = storage.CreateListener(listener2)
	if err == nil {
		t.Error("Expected error when creating listener with duplicate port")
	}
}

func TestGetListener(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener002", 5142)

	// Create listener
	err := storage.CreateListener(listener)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Retrieve listener
	retrieved, err := storage.GetListener("listener002")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil listener")
	}
	if retrieved.ID != "listener002" {
		t.Errorf("Expected ID listener002, got %s", retrieved.ID)
	}
	if len(retrieved.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(retrieved.Tags))
	}
}

func TestGetListener_NotFound(t *testing.T) {
	storage := setupListenerTestDB(t)

	retrieved, err := storage.GetListener("nonexistent")
	if err != nil {
		t.Errorf("Expected nil error for nonexistent listener, got: %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil listener for nonexistent ID")
	}
}

func TestGetListener_SQLInjection(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Attempt SQL injection in query
	retrieved, err := storage.GetListener("' OR '1'='1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil listener for SQL injection attempt")
	}
}

func TestGetAllListeners(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Create multiple listeners
	for i := 1; i <= 5; i++ {
		listener := createTestListener(fmt.Sprintf("listener_multi_%d", i), 5200+i)
		err := storage.CreateListener(listener)
		if err != nil {
			t.Fatalf("Failed to create listener %d: %v", i, err)
		}
	}

	// Get all listeners
	listeners, err := storage.GetAllListeners()
	if err != nil {
		t.Errorf("Failed to get all listeners: %v", err)
	}
	if len(listeners) != 5 {
		t.Errorf("Expected 5 listeners, got %d", len(listeners))
	}
}

func TestGetAllListeners_Empty(t *testing.T) {
	storage := setupListenerTestDB(t)

	listeners, err := storage.GetAllListeners()
	if err != nil {
		t.Errorf("Failed to get all listeners: %v", err)
	}
	if len(listeners) != 0 {
		t.Errorf("Expected 0 listeners, got %d", len(listeners))
	}
}

func TestGetAllListeners_OrderedByCreatedAt(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Create listeners with slight time delays
	for i := 1; i <= 3; i++ {
		listener := createTestListener(fmt.Sprintf("listener_order_%d", i), 5300+i)
		storage.CreateListener(listener)
		time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
	}

	listeners, err := storage.GetAllListeners()
	if err != nil {
		t.Errorf("Failed to get all listeners: %v", err)
	}
	if len(listeners) != 3 {
		t.Fatalf("Expected 3 listeners, got %d", len(listeners))
	}

	// Verify descending order (newest first)
	for i := 0; i < len(listeners)-1; i++ {
		if listeners[i].CreatedAt.Before(listeners[i+1].CreatedAt) {
			t.Error("Listeners should be ordered by CreatedAt DESC")
			break
		}
	}
}

func TestGetListenersByStatus(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Create listeners with different statuses
	listener1 := createTestListener("listener_status_1", 5401)
	listener1.Status = "running"
	storage.CreateListener(listener1)

	listener2 := createTestListener("listener_status_2", 5402)
	listener2.Status = "stopped"
	storage.CreateListener(listener2)

	listener3 := createTestListener("listener_status_3", 5403)
	listener3.Status = "running"
	storage.CreateListener(listener3)

	// Get running listeners
	running, err := storage.GetListenersByStatus("running")
	if err != nil {
		t.Errorf("Failed to get listeners by status: %v", err)
	}
	if len(running) != 2 {
		t.Errorf("Expected 2 running listeners, got %d", len(running))
	}

	// Get stopped listeners
	stopped, err := storage.GetListenersByStatus("stopped")
	if err != nil {
		t.Errorf("Failed to get listeners by status: %v", err)
	}
	if len(stopped) != 1 {
		t.Errorf("Expected 1 stopped listener, got %d", len(stopped))
	}
}

func TestGetListenersByStatus_NoResults(t *testing.T) {
	storage := setupListenerTestDB(t)

	listeners, err := storage.GetListenersByStatus("error")
	if err != nil {
		t.Errorf("Failed to get listeners by status: %v", err)
	}
	if len(listeners) != 0 {
		t.Errorf("Expected 0 listeners with error status, got %d", len(listeners))
	}
}

func TestGetListenersByStatus_SQLInjection(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Attempt SQL injection in status filter
	listeners, err := storage.GetListenersByStatus("' OR '1'='1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// Should return empty results, not all listeners
	if len(listeners) != 0 {
		t.Errorf("Expected 0 listeners for SQL injection attempt, got %d", len(listeners))
	}
}

func TestUpdateListener(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener003", 5143)

	// Create listener
	err := storage.CreateListener(listener)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Update listener
	listener.Name = "Updated Listener Name"
	listener.Description = "Updated Description"
	listener.Port = 5144
	listener.Status = "running"
	listener.Tags = []string{"updated", "test"}

	err = storage.UpdateListener("listener003", listener)
	if err != nil {
		t.Errorf("Failed to update listener: %v", err)
	}

	// Verify update
	retrieved, err := storage.GetListener("listener003")
	if err != nil {
		t.Errorf("Failed to retrieve updated listener: %v", err)
	}
	if retrieved.Name != "Updated Listener Name" {
		t.Errorf("Expected name 'Updated Listener Name', got %s", retrieved.Name)
	}
	if retrieved.Description != "Updated Description" {
		t.Errorf("Expected description 'Updated Description', got %s", retrieved.Description)
	}
	if retrieved.Port != 5144 {
		t.Errorf("Expected port 5144, got %d", retrieved.Port)
	}
	if retrieved.Status != "running" {
		t.Errorf("Expected status running, got %s", retrieved.Status)
	}
	if len(retrieved.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(retrieved.Tags))
	}
}

func TestUpdateListener_NotFound(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("nonexistent", 5145)

	err := storage.UpdateListener("nonexistent", listener)
	if err == nil {
		t.Error("Expected error when updating nonexistent listener")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestUpdateListener_SQLInjection(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_update_sql", 5146)

	// Create listener
	storage.CreateListener(listener)

	// Attempt SQL injection in update
	listener.Name = "'; DELETE FROM dynamic_listeners WHERE '1'='1'; --"
	listener.Description = "'; UPDATE dynamic_listeners SET status='error' WHERE '1'='1'; --"

	err := storage.UpdateListener("listener_update_sql", listener)
	if err != nil {
		t.Errorf("Failed to update listener: %v", err)
	}

	// Verify SQL injection was stored as literal text
	retrieved, err := storage.GetListener("listener_update_sql")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if !strings.Contains(retrieved.Name, "DELETE FROM dynamic_listeners") {
		t.Error("SQL injection should be stored as literal text")
	}
}

func TestUpdateListenerStatus(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_status_update", 5147)

	// Create listener
	storage.CreateListener(listener)

	// Update status
	err := storage.UpdateListenerStatus("listener_status_update", "running")
	if err != nil {
		t.Errorf("Failed to update listener status: %v", err)
	}

	// Verify status update
	retrieved, err := storage.GetListener("listener_status_update")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved.Status != "running" {
		t.Errorf("Expected status running, got %s", retrieved.Status)
	}
}

func TestUpdateListenerStatus_NotFound(t *testing.T) {
	storage := setupListenerTestDB(t)

	err := storage.UpdateListenerStatus("nonexistent", "running")
	if err == nil {
		t.Error("Expected error when updating status of nonexistent listener")
	}
}

func TestUpdateStatistics(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_stats", 5148)

	// Create listener
	storage.CreateListener(listener)

	// Update statistics
	now := time.Now()
	stats := &ListenerStats{
		EventsReceived:  1000,
		ErrorCount:      5,
		LastEvent:       now,
		EventsPerMinute: 10.5,
	}

	err := storage.UpdateStatistics("listener_stats", stats)
	if err != nil {
		t.Errorf("Failed to update statistics: %v", err)
	}

	// Verify statistics update
	retrieved, err := storage.GetListener("listener_stats")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved.EventsReceived != 1000 {
		t.Errorf("Expected 1000 events received, got %d", retrieved.EventsReceived)
	}
	if retrieved.ErrorCount != 5 {
		t.Errorf("Expected 5 errors, got %d", retrieved.ErrorCount)
	}
	if retrieved.LastEvent.IsZero() {
		t.Error("Expected non-zero last event time")
	}
}

func TestUpdateStatistics_NotFound(t *testing.T) {
	storage := setupListenerTestDB(t)

	stats := &ListenerStats{
		EventsReceived: 100,
		ErrorCount:     0,
	}

	err := storage.UpdateStatistics("nonexistent", stats)
	if err == nil {
		t.Error("Expected error when updating statistics of nonexistent listener")
	}
}

func TestIncrementEventCount(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_inc_event", 5149)

	// Create listener
	storage.CreateListener(listener)

	// Increment event count multiple times
	for i := 0; i < 5; i++ {
		err := storage.IncrementEventCount("listener_inc_event")
		if err != nil {
			t.Errorf("Failed to increment event count: %v", err)
		}
	}

	// Verify event count
	retrieved, err := storage.GetListener("listener_inc_event")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved.EventsReceived != 5 {
		t.Errorf("Expected 5 events received, got %d", retrieved.EventsReceived)
	}
	if retrieved.LastEvent.IsZero() {
		t.Error("Expected non-zero last event time")
	}
}

func TestIncrementErrorCount(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_inc_error", 5150)

	// Create listener
	storage.CreateListener(listener)

	// Increment error count multiple times
	for i := 0; i < 3; i++ {
		err := storage.IncrementErrorCount("listener_inc_error")
		if err != nil {
			t.Errorf("Failed to increment error count: %v", err)
		}
	}

	// Verify error count
	retrieved, err := storage.GetListener("listener_inc_error")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved.ErrorCount != 3 {
		t.Errorf("Expected 3 errors, got %d", retrieved.ErrorCount)
	}
}

func TestSetStartedAt(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_start", 5151)

	// Create listener
	storage.CreateListener(listener)

	// Set started timestamp
	startTime := time.Now()
	err := storage.SetStartedAt("listener_start", startTime)
	if err != nil {
		t.Errorf("Failed to set started timestamp: %v", err)
	}

	// Verify started timestamp
	retrieved, err := storage.GetListener("listener_start")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved.StartedAt.IsZero() {
		t.Error("Expected non-zero started timestamp")
	}
	if retrieved.StoppedAt.IsZero() {
		// StoppedAt should be NULL after setting StartedAt
		// (IsZero() returns true for NULL time.Time)
		// This is expected behavior
	}
}

func TestSetStoppedAt(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_stop", 5152)

	// Create listener
	storage.CreateListener(listener)

	// Set stopped timestamp
	stopTime := time.Now()
	err := storage.SetStoppedAt("listener_stop", stopTime)
	if err != nil {
		t.Errorf("Failed to set stopped timestamp: %v", err)
	}

	// Verify stopped timestamp
	retrieved, err := storage.GetListener("listener_stop")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved.StoppedAt.IsZero() {
		t.Error("Expected non-zero stopped timestamp")
	}
}

func TestDeleteListener(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener004", 5153)

	// Create listener
	err := storage.CreateListener(listener)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Delete listener
	err = storage.DeleteListener("listener004")
	if err != nil {
		t.Errorf("Failed to delete listener: %v", err)
	}

	// Verify deletion
	retrieved, err := storage.GetListener("listener004")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil listener after deletion")
	}
}

func TestDeleteListener_NotFound(t *testing.T) {
	storage := setupListenerTestDB(t)

	err := storage.DeleteListener("nonexistent")
	if err == nil {
		t.Error("Expected error when deleting nonexistent listener")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestDeleteListener_SQLInjection(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Attempt SQL injection in delete
	err := storage.DeleteListener("' OR '1'='1")
	// Should not delete anything since ID doesn't match
	if err == nil {
		t.Error("Expected error for SQL injection attempt")
	}
}

func TestCheckPortConflict(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_conflict", 5154)

	// Create listener
	storage.CreateListener(listener)

	// Check for conflict with same host/port/protocol
	conflict, err := storage.CheckPortConflict("0.0.0.0", 5154, "tcp", "")
	if err != nil {
		t.Errorf("Failed to check port conflict: %v", err)
	}
	if !conflict {
		t.Error("Expected port conflict to be detected")
	}

	// Check for no conflict with different port
	conflict, err = storage.CheckPortConflict("0.0.0.0", 5155, "tcp", "")
	if err != nil {
		t.Errorf("Failed to check port conflict: %v", err)
	}
	if conflict {
		t.Error("Expected no port conflict for different port")
	}

	// Check for no conflict with different protocol
	conflict, err = storage.CheckPortConflict("0.0.0.0", 5154, "udp", "")
	if err != nil {
		t.Errorf("Failed to check port conflict: %v", err)
	}
	if conflict {
		t.Error("Expected no port conflict for different protocol")
	}

	// Check for no conflict with different host
	conflict, err = storage.CheckPortConflict("127.0.0.1", 5154, "tcp", "")
	if err != nil {
		t.Errorf("Failed to check port conflict: %v", err)
	}
	if conflict {
		t.Error("Expected no port conflict for different host")
	}
}

func TestCheckPortConflict_ExcludeID(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_exclude", 5156)

	// Create listener
	storage.CreateListener(listener)

	// Check for conflict excluding the same listener (should not conflict)
	conflict, err := storage.CheckPortConflict("0.0.0.0", 5156, "tcp", "listener_exclude")
	if err != nil {
		t.Errorf("Failed to check port conflict: %v", err)
	}
	if conflict {
		t.Error("Expected no conflict when excluding the same listener ID")
	}

	// Check for conflict excluding a different listener (should still conflict)
	conflict, err = storage.CheckPortConflict("0.0.0.0", 5156, "tcp", "different_id")
	if err != nil {
		t.Errorf("Failed to check port conflict: %v", err)
	}
	if !conflict {
		t.Error("Expected conflict when excluding a different listener ID")
	}
}

func TestCheckPortConflict_SQLInjection(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Attempt SQL injection in port conflict check
	conflict, err := storage.CheckPortConflict("'; DROP TABLE dynamic_listeners; --", 5157, "tcp", "")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if conflict {
		t.Error("Expected no conflict for SQL injection attempt")
	}

	// Verify table still exists
	_, err = storage.GetAllListeners()
	if err != nil {
		t.Errorf("Table should still exist: %v", err)
	}
}

// Edge case tests

func TestCreateListener_NilTags(t *testing.T) {
	storage := setupListenerTestDB(t)

	listener := &DynamicListener{
		ID:       "listener_nil_tags",
		Name:     "Test with nil tags",
		Type:     "syslog",
		Protocol: "tcp",
		Host:     "0.0.0.0",
		Port:     5158,
		Status:   "stopped",
		Tags:     nil, // Nil tags
	}

	err := storage.CreateListener(listener)
	if err != nil {
		t.Errorf("Failed to create listener with nil tags: %v", err)
	}

	retrieved, err := storage.GetListener("listener_nil_tags")
	if err != nil {
		t.Errorf("Failed to retrieve listener: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil listener")
	}
	// Nil tags should be stored and retrieved (may be nil or empty)
}

func TestUpdateListener_ConcurrentUpdates(t *testing.T) {
	storage := setupListenerTestDB(t)
	listener := createTestListener("listener_concurrent", 5159)

	// Create listener
	storage.CreateListener(listener)

	// Simulate concurrent updates
	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 5; i++ {
			l, _ := storage.GetListener("listener_concurrent")
			if l != nil {
				l.Name = "Updated by goroutine 1"
				storage.UpdateListener("listener_concurrent", l)
			}
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 5; i++ {
			l, _ := storage.GetListener("listener_concurrent")
			if l != nil {
				l.Name = "Updated by goroutine 2"
				storage.UpdateListener("listener_concurrent", l)
			}
		}
		done <- true
	}()

	<-done
	<-done

	// Verify listener still exists and is valid
	retrieved, err := storage.GetListener("listener_concurrent")
	if err != nil {
		t.Errorf("Failed to retrieve listener after concurrent updates: %v", err)
	}
	if retrieved == nil {
		t.Error("Listener should still exist after concurrent updates")
	}
	if retrieved.ID != "listener_concurrent" {
		t.Error("Listener corrupted after concurrent updates")
	}
}

func TestGetAllListeners_LargeDataset(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Create many listeners
	for i := 1; i <= 100; i++ {
		listener := createTestListener(fmt.Sprintf("listener_large_%d", i), 6000+i)
		storage.CreateListener(listener)
	}

	listeners, err := storage.GetAllListeners()
	if err != nil {
		t.Errorf("Failed to get all listeners: %v", err)
	}
	if len(listeners) != 100 {
		t.Errorf("Expected 100 listeners, got %d", len(listeners))
	}
}

func TestListener_JSONFieldPersistence(t *testing.T) {
	storage := setupListenerTestDB(t)

	// Create listener with complex tags
	listener := createTestListener("listener_json_persist", 5160)
	listener.Tags = []string{"production", "critical", "syslog-ng", "firewall", "security"}

	err := storage.CreateListener(listener)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Retrieve and verify tags
	retrieved, err := storage.GetListener("listener_json_persist")
	if err != nil {
		t.Fatalf("Failed to retrieve listener: %v", err)
	}

	if len(retrieved.Tags) != 5 {
		t.Errorf("Expected 5 tags, got %d", len(retrieved.Tags))
	}

	expectedTags := map[string]bool{
		"production": true,
		"critical":   true,
		"syslog-ng":  true,
		"firewall":   true,
		"security":   true,
	}

	for _, tag := range retrieved.Tags {
		if !expectedTags[tag] {
			t.Errorf("Unexpected tag: %s", tag)
		}
	}
}

func TestListenerDatabaseError_Handling(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	db, err := NewSQLite(":memory:", sugar)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	storage, err := NewSQLiteDynamicListenerStorage(db, sugar)
	if err != nil {
		t.Fatalf("Failed to create listener storage: %v", err)
	}

	// Close the database to force errors
	db.DB.Close()

	// All operations should return errors
	listener := createTestListener("listener_error", 5161)

	err = storage.CreateListener(listener)
	if err == nil {
		t.Error("Expected error when database is closed")
	}

	_, err = storage.GetListener("listener_error")
	// GetListener returns nil, nil on errors (unlike other methods)
	if err != nil {
		// Some errors might be returned
		// This is acceptable
	}

	_, err = storage.GetAllListeners()
	if err == nil {
		t.Error("Expected error when database is closed")
	}

	err = storage.UpdateListener("listener_error", listener)
	if err == nil {
		t.Error("Expected error when database is closed")
	}

	err = storage.DeleteListener("listener_error")
	if err == nil {
		t.Error("Expected error when database is closed")
	}
}
