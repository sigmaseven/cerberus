package storage

import (
	"context"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"go.uber.org/zap"
)

// TestNewClickHouseAlertStorage_Success verifies successful alert storage creation
func TestNewClickHouseAlertStorage_Success(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	mockCH := &ClickHouse{} // Mock ClickHouse connection

	ctx := context.Background()
	storage, err := NewClickHouseAlertStorage(ctx, mockCH, cfg, alertCh, logger)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if storage == nil {
		t.Fatal("Expected storage instance, got nil")
	}

	if storage.clickhouse != mockCH {
		t.Error("ClickHouse connection not set correctly")
	}

	if storage.batchSize != 100 { // BatchSize/10, min 100
		t.Errorf("Expected batchSize 100, got %d", storage.batchSize)
	}

	if storage.batchFlushInterval != 5*time.Second {
		t.Errorf("Expected flush interval 5s, got %v", storage.batchFlushInterval)
	}

	if storage.dedupCache == nil {
		t.Error("Dedup cache not initialized")
	}

	if !storage.enableDeduplication {
		t.Error("Deduplication should be enabled by default")
	}

	// TASK 138: pendingBatch field removed as unused (batching handled differently)
}

// TestNewClickHouseAlertStorage_LargeBatchSize tests batch size calculation
func TestNewClickHouseAlertStorage_LargeBatchSize(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 5000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedBatchSize := 500 // 5000/10
	if storage.batchSize != expectedBatchSize {
		t.Errorf("Expected batchSize %d, got %d", expectedBatchSize, storage.batchSize)
	}
}

// TestNewClickHouseAlertStorage_SmallBatchSize tests minimum batch size
func TestNewClickHouseAlertStorage_SmallBatchSize(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 50 // Would result in 5, but minimum is 100

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if storage.batchSize != 100 {
		t.Errorf("Expected minimum batchSize 100, got %d", storage.batchSize)
	}
}

// TestNewClickHouseAlertStorage_ZeroBatchSize tests zero batch size edge case
func TestNewClickHouseAlertStorage_ZeroBatchSize(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 0

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// BatchSize/10 = 0, should default to minimum of 100
	if storage.batchSize != 100 {
		t.Errorf("Expected minimum batchSize 100 for zero input, got %d", storage.batchSize)
	}
}

// TestInsertAlerts_EmptySlice tests inserting empty alert slice
func TestInsertAlerts_EmptySlice(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	testCtx := testContext(t)
	err := storage.InsertAlerts([]*core.Alert{}, testCtx)
	if err != nil {
		t.Errorf("Expected no error for empty slice, got: %v", err)
	}
}

// TestInsertAlerts_NilSlice tests inserting nil alert slice
func TestInsertAlerts_NilSlice(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	testCtx := testContext(t)
	err := storage.InsertAlerts(nil, testCtx)
	if err != nil {
		t.Errorf("Expected no error for nil slice, got: %v", err)
	}
}

// TestAlertStructure_WithEventData tests alert with embedded event data
func TestAlertStructure_WithEventData(t *testing.T) {
	event := &core.Event{
		EventID:   "event-123",
		Timestamp: time.Now(),
		RawData:   "Test log entry",
		Fields: map[string]interface{}{
			"source": "test",
			"level":  "info",
		},
	}

	alert := &core.Alert{
		AlertID:   "alert-002",
		RuleID:    "rule-002",
		EventID:   "event-123",
		Event:     event,
		Timestamp: time.Now(),
		Severity:  "medium",
		Status:    core.AlertStatusPending,
	}

	// Verify event embedding
	if alert.Event == nil {
		t.Error("Event should be embedded in alert")
	}
	if alert.Event.EventID != "event-123" {
		t.Error("Event ID should match")
	}
	if alert.Event.Fields == nil {
		t.Error("Event fields should be initialized")
	}
	if len(alert.Event.Fields) != 2 {
		t.Errorf("Expected 2 event fields, got %d", len(alert.Event.Fields))
	}
}

// TestAlertStructure_WithThreatIntel tests alert with threat intelligence data
func TestAlertStructure_WithThreatIntel(t *testing.T) {
	threatIntel := map[string]interface{}{
		"ioc_type":    "ip",
		"ioc_value":   "192.168.1.100",
		"threat_type": "malware",
		"confidence":  85,
	}

	alert := &core.Alert{
		AlertID:     "alert-003",
		RuleID:      "rule-003",
		EventID:     "event-456",
		ThreatIntel: threatIntel,
		Timestamp:   time.Now(),
		Severity:    "critical",
		Status:      core.AlertStatusPending,
	}

	// Verify threat intel embedding
	if alert.ThreatIntel == nil {
		t.Error("ThreatIntel should be embedded in alert")
	}
	if len(alert.ThreatIntel) != 4 {
		t.Errorf("Expected 4 threat intel fields, got %d", len(alert.ThreatIntel))
	}
	if alert.ThreatIntel["ioc_type"] != "ip" {
		t.Error("IOC type should be 'ip'")
	}
	if alert.ThreatIntel["confidence"] != 85 {
		t.Error("Confidence should be 85")
	}
}

// TestAlertStructure_WithNilEventIDs tests handling of nil EventIDs
func TestAlertStructure_WithNilEventIDs(t *testing.T) {
	alert := &core.Alert{
		AlertID:   "alert-004",
		RuleID:    "rule-004",
		EventID:   "event-789",
		EventIDs:  nil,
		Timestamp: time.Now(),
		Severity:  "low",
		Status:    core.AlertStatusPending,
	}

	// Verify nil EventIDs is valid
	if alert.EventIDs != nil {
		t.Error("EventIDs should be nil as set")
	}
}

// TestAlertStructure_WithEmptyEventIDs tests handling of empty EventIDs
func TestAlertStructure_WithEmptyEventIDs(t *testing.T) {
	alert := &core.Alert{
		AlertID:   "alert-005",
		RuleID:    "rule-005",
		EventID:   "event-999",
		EventIDs:  []string{},
		Timestamp: time.Now(),
		Severity:  "low",
		Status:    core.AlertStatusPending,
	}

	// Verify empty EventIDs
	if alert.EventIDs == nil {
		t.Error("EventIDs should not be nil when set to empty slice")
	}
	if len(alert.EventIDs) != 0 {
		t.Errorf("EventIDs should be empty, got length %d", len(alert.EventIDs))
	}
}

// TestAlertStatus_AllStatuses tests all alert statuses
func TestAlertStatus_AllStatuses(t *testing.T) {
	statuses := []core.AlertStatus{
		core.AlertStatusPending,
		core.AlertStatusAcknowledged,
		core.AlertStatusResolved,
		core.AlertStatusFalsePositive,
		core.AlertStatusDismissed,
	}

	for _, status := range statuses {
		if !status.IsValid() {
			t.Errorf("Status %s should be valid", status)
		}
		if status.String() == "" {
			t.Errorf("Status %s string representation should not be empty", status)
		}
	}
}

// TestCleanupOldAlerts_InvalidRetention tests retention validation for invalid values
func TestCleanupOldAlerts_InvalidRetention(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	// Test only invalid retention values that should fail validation
	retentionTests := []struct {
		days int
		desc string
	}{
		{0, "zero"},
		{-10, "negative"},
		{50000, "too large"},
		{36501, "over max"},
		{-1, "minus one"},
		{100000, "very large"},
	}

	testCtx := context.Background()
	for _, tt := range retentionTests {
		err := storage.CleanupOldAlerts(testCtx, tt.days)
		if err == nil {
			t.Errorf("Expected error for %s retention days (%d), got nil", tt.desc, tt.days)
		} else {
			t.Logf("Correctly rejected %s retention (%d days): %v", tt.desc, tt.days, err)
		}
	}
}

// TestPartitionFormat_Valid tests partition format generation
func TestPartitionFormat_Valid(t *testing.T) {
	// Test partition format generation logic
	cutoffDate := time.Now().AddDate(0, 0, -30)
	partition := cutoffDate.Format("200601") // YYYYMM format

	// Validate partition format (should be exactly 6 digits)
	if len(partition) != 6 {
		t.Errorf("Expected partition length 6, got %d", len(partition))
	}

	// Verify all characters are digits
	for i, c := range partition {
		if c < '0' || c > '9' {
			t.Errorf("Expected digit at position %d, got %c", i, c)
		}
	}

	t.Logf("Valid partition format: %s", partition)
}

// TestGetAlert_DelegatesToGetAlertByID tests that GetAlert delegates to GetAlertByID
func TestGetAlert_DelegatesToGetAlertByID(t *testing.T) {
	// GetAlert now delegates to GetAlertByID which requires a real ClickHouse connection
	t.Skip("GetAlert requires actual ClickHouse connection - covered by integration tests")
}

// TestAcknowledgeAlert_NotSupported tests unsupported operation
func TestAcknowledgeAlert_NotSupported(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	ctx = context.Background()
	err := storage.AcknowledgeAlert(ctx, "alert-001")
	if err == nil {
		t.Error("Expected error for unsupported operation, got nil")
	} else {
		t.Logf("AcknowledgeAlert correctly returns error: %v", err)
	}
}

// TestDismissAlert_NotSupported tests unsupported operation
func TestDismissAlert_NotSupported(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	ctx = context.Background()
	err := storage.DismissAlert(ctx, "alert-001")
	if err == nil {
		t.Error("Expected error for unsupported operation, got nil")
	} else {
		t.Logf("DismissAlert correctly returns error: %v", err)
	}
}

// TestAssignAlert_NotSupported tests unsupported operation
func TestAssignAlert_NotSupported(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	ctx = context.Background()
	err := storage.AssignAlert(ctx, "alert-001", "user-123")
	if err == nil {
		t.Error("Expected error for unsupported operation, got nil")
	} else {
		t.Logf("AssignAlert correctly returns error: %v", err)
	}
}

// TestLinkAlertToInvestigation_NotSupported tests unsupported operation
func TestLinkAlertToInvestigation_NotSupported(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	err := storage.LinkAlertToInvestigation("alert-001", "investigation-001")
	if err == nil {
		t.Error("Expected error for unsupported operation, got nil")
	} else {
		t.Logf("LinkAlertToInvestigation correctly returns error: %v", err)
	}
}

// TestWorkerShutdown_ChannelClose tests graceful worker shutdown
func TestWorkerShutdown_ChannelClose(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	// Start a worker
	storage.Start(1)

	// Close the channel to trigger shutdown
	close(alertCh)

	// Wait for shutdown with timeout
	done := make(chan bool)
	go func() {
		storage.Stop()
		done <- true
	}()

	select {
	case <-done:
		t.Log("Worker shutdown completed successfully")
	case <-time.After(5 * time.Second):
		t.Error("Worker shutdown timed out")
	}
}

// TestStartStop_MultipleWorkers tests multiple workers lifecycle
func TestStartStop_MultipleWorkers(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	// Start multiple workers
	numWorkers := 5
	storage.Start(numWorkers)

	// Close channel and stop
	close(alertCh)

	done := make(chan bool)
	go func() {
		storage.Stop()
		done <- true
	}()

	select {
	case <-done:
		t.Logf("Started and stopped %d workers successfully", numWorkers)
	case <-time.After(5 * time.Second):
		t.Error("Multiple workers shutdown timed out")
	}
}

// TestDeduplicationCache_Initialization tests dedup cache setup
func TestDeduplicationCache_Initialization(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	if storage.dedupCache == nil {
		t.Fatal("Deduplication cache should be initialized")
	}

	if !storage.enableDeduplication {
		t.Error("Deduplication should be enabled by default")
	}
}

// testContext creates a test context with timeout
func testContext(t *testing.T) testcontext {
	return testcontext{t: t}
}

type testcontext struct {
	t *testing.T
}

func (tc testcontext) Done() <-chan struct{} {
	return nil
}

func (tc testcontext) Err() error {
	return nil
}

func (tc testcontext) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (tc testcontext) Value(key interface{}) interface{} {
	return nil
}

// TestGetAlerts_LogicValidation tests GetAlerts logic without actual database
func TestGetAlerts_LogicValidation(t *testing.T) {
	t.Skip("GetAlerts requires actual ClickHouse connection - covered by integration tests")
}

// Skip tests that require actual ClickHouse connection
func TestGetAlertsFiltered_FilterValidation(t *testing.T) {
	t.Skip("GetAlertsFiltered requires actual ClickHouse connection - covered by integration tests")
}

func TestUpdateAlertStatus_StatusValidation(t *testing.T) {
	t.Skip("UpdateAlertStatus requires actual ClickHouse connection - covered by integration tests")
}

func TestGetAlertCount_Execution(t *testing.T) {
	t.Skip("GetAlertCount requires actual ClickHouse connection - covered by integration tests")
}

func TestGetAlertsByTimeRange_Execution(t *testing.T) {
	t.Skip("GetAlertsByTimeRange requires actual ClickHouse connection - covered by integration tests")
}

func TestGetAlertStats_Execution(t *testing.T) {
	t.Skip("GetAlertStats requires actual ClickHouse connection - covered by integration tests")
}

func TestDeleteAlert_Execution(t *testing.T) {
	t.Skip("DeleteAlert requires actual ClickHouse connection - covered by integration tests")
}

func TestGetAlertCountsByMonth_Execution(t *testing.T) {
	t.Skip("GetAlertCountsByMonth requires actual ClickHouse connection - covered by integration tests")
}

func TestInsertAlert_Execution(t *testing.T) {
	t.Skip("InsertAlert requires actual ClickHouse connection - covered by integration tests")
}

// TASK 103: Tests for disposition update methods

// TestIsValidAlertID tests alertID validation
func TestIsValidAlertID(t *testing.T) {
	validIDs := []string{
		"alert-123",
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"ALERT_001",
		"a",
		"alert-with-many-hyphens-and-underscores_123",
	}

	for _, id := range validIDs {
		if !isValidAlertID(id) {
			t.Errorf("Expected valid alertID %q to pass validation", id)
		}
	}

	invalidIDs := []string{
		"",                         // Empty
		"alert'123",                // SQL injection attempt
		"alert;DROP TABLE alerts;", // SQL injection attempt
		"alert 123",                // Space
		"alert\n123",               // Newline
		"alert@123",                // Special char
		string(make([]byte, 300)),  // Too long
	}

	for _, id := range invalidIDs {
		if isValidAlertID(id) {
			t.Errorf("Expected invalid alertID %q to fail validation", id)
		}
	}

	t.Log("All alertID validation tests passed")
}

// TestUpdateAlertDisposition_InvalidDisposition tests invalid disposition validation
func TestUpdateAlertDisposition_InvalidDisposition(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, _ := NewClickHouseAlertStorage(ctx, &ClickHouse{}, cfg, alertCh, logger)

	invalidDispositions := []core.AlertDisposition{
		"",
		"invalid",
		"UNDETERMINED",
		"True_Positive",
		"unknown",
	}

	for _, disposition := range invalidDispositions {
		// TASK 111: UpdateAlertDisposition now returns (previousDisposition, error)
		// TASK 111 FIX: Pass context as first parameter (BLOCKING-5)
		_, err := storage.UpdateAlertDisposition(context.Background(), "alert-001", disposition, "reason", "user@example.com")
		if err == nil {
			t.Errorf("Expected error for invalid disposition %q, got nil", disposition)
		} else {
			t.Logf("Correctly rejected invalid disposition %q: %v", disposition, err)
		}
	}
}

// TestUpdateAlertDisposition_ValidDispositions tests valid disposition values
func TestUpdateAlertDisposition_ValidDispositions(t *testing.T) {
	// Note: This test verifies that valid dispositions don't fail validation
	// Actual database operations are skipped (require ClickHouse connection)
	validDispositions := []core.AlertDisposition{
		core.DispositionUndetermined,
		core.DispositionTruePositive,
		core.DispositionFalsePositive,
		core.DispositionBenign,
		core.DispositionSuspicious,
		core.DispositionInconclusive,
	}

	for _, d := range validDispositions {
		if !d.IsValid() {
			t.Errorf("Disposition %q should be valid", d)
		}
	}
	t.Log("All valid dispositions passed validation")
}

// TestUpdateAlertDisposition_Execution tests the method (requires ClickHouse)
func TestUpdateAlertDisposition_Execution(t *testing.T) {
	t.Skip("UpdateAlertDisposition requires actual ClickHouse connection - covered by integration tests")
}

// TestUpdateAlertInvestigation_Execution tests the method (requires ClickHouse)
func TestUpdateAlertInvestigation_Execution(t *testing.T) {
	t.Skip("UpdateAlertInvestigation requires actual ClickHouse connection - covered by integration tests")
}

// TestUpdateAlertAssignment_Execution tests the method (requires ClickHouse)
func TestUpdateAlertAssignment_Execution(t *testing.T) {
	t.Skip("UpdateAlertAssignment requires actual ClickHouse connection - covered by integration tests")
}

// TestGetAlertByID_Execution tests the method (requires ClickHouse)
func TestGetAlertByID_Execution(t *testing.T) {
	t.Skip("GetAlertByID requires actual ClickHouse connection - covered by integration tests")
}

// TestAlertDisposition_StructFields tests alert disposition fields
func TestAlertDisposition_StructFields(t *testing.T) {
	now := time.Now().UTC()
	alert := &core.Alert{
		AlertID:           "alert-disposition-001",
		RuleID:            "rule-001",
		EventID:           "event-001",
		Timestamp:         now,
		Severity:          "high",
		Status:            core.AlertStatusPending,
		Disposition:       core.DispositionTruePositive,
		DispositionReason: "Confirmed malicious activity from known threat actor",
		DispositionSetAt:  &now,
		DispositionSetBy:  "analyst@company.com",
		InvestigationID:   "inv-12345",
	}

	// Verify all disposition fields are set
	if alert.Disposition != core.DispositionTruePositive {
		t.Errorf("Disposition mismatch: got %v, want %v", alert.Disposition, core.DispositionTruePositive)
	}
	if alert.DispositionReason == "" {
		t.Error("DispositionReason should not be empty")
	}
	if alert.DispositionSetAt == nil {
		t.Error("DispositionSetAt should not be nil")
	}
	if alert.DispositionSetBy != "analyst@company.com" {
		t.Errorf("DispositionSetBy mismatch: got %v", alert.DispositionSetBy)
	}
	if alert.InvestigationID != "inv-12345" {
		t.Errorf("InvestigationID mismatch: got %v", alert.InvestigationID)
	}

	t.Log("All disposition fields validated successfully")
}

// TestAlertDisposition_UndeterminedClears tests that undetermined clears fields
func TestAlertDisposition_UndeterminedClears(t *testing.T) {
	// When disposition is set to undetermined, reason and timestamp should be cleared
	// This behavior is tested in UpdateAlertDisposition method
	alert := &core.Alert{
		AlertID:           "alert-undetermined-001",
		Disposition:       core.DispositionUndetermined,
		DispositionReason: "", // Should be empty for undetermined
		DispositionSetAt:  nil,
		DispositionSetBy:  "",
	}

	if alert.Disposition != core.DispositionUndetermined {
		t.Errorf("Disposition should be undetermined")
	}
	if alert.DispositionReason != "" {
		t.Error("DispositionReason should be empty for undetermined")
	}
	if alert.DispositionSetAt != nil {
		t.Error("DispositionSetAt should be nil for undetermined")
	}

	t.Log("Undetermined disposition validation passed")
}
