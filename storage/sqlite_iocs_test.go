package storage

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

func setupIOCTestDB(t *testing.T) (*SQLite, *SQLiteIOCStorage, func()) {
	// Create temp database
	tmpFile, err := os.CreateTemp("", "test_ioc_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	db, err := sql.Open("sqlite3", tmpPath+"?_journal=WAL&_timeout=5000&_fk=1")
	if err != nil {
		os.Remove(tmpPath)
		t.Fatalf("Failed to open database: %v", err)
	}

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	sqlite := &SQLite{
		DB:     db,
		logger: sugar,
	}

	iocStorage, err := NewSQLiteIOCStorage(sqlite, sugar)
	if err != nil {
		db.Close()
		os.Remove(tmpPath)
		t.Fatalf("Failed to create IOC storage: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.Remove(tmpPath)
	}

	return sqlite, iocStorage, cleanup
}

// =============================================================================
// BLOCKER-3 Test: JSON Size Limits
// =============================================================================

func TestSafeUnmarshalJSON_SizeLimit(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "empty string",
			input:       "",
			expectError: false,
		},
		{
			name:        "null string",
			input:       "null",
			expectError: false,
		},
		{
			name:        "valid small JSON",
			input:       `["tag1", "tag2"]`,
			expectError: false,
		},
		{
			name:        "valid large but under limit",
			input:       `["` + strings.Repeat("x", 1000) + `"]`,
			expectError: false,
		},
		{
			name:        "exceeds 1MB limit",
			input:       `["` + strings.Repeat("x", maxJSONFieldSize+1) + `"]`,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var result []string
			err := safeUnmarshalJSON(tc.input, &result)

			if tc.expectError && err == nil {
				t.Error("Expected error for oversized JSON, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestSafeUnmarshalJSON_MaxSize(t *testing.T) {
	// Test exactly at the 1MB boundary
	exactlyMaxSize := strings.Repeat("x", maxJSONFieldSize)
	var result string
	err := safeUnmarshalJSON(`"`+exactlyMaxSize+`"`, &result)
	// Should fail because the JSON string is larger than maxJSONFieldSize when including quotes
	if err == nil {
		t.Log("Note: String exactly at max size may succeed or fail depending on JSON overhead")
	}

	// Test just over the limit
	overMaxSize := strings.Repeat("x", maxJSONFieldSize+100)
	err = safeUnmarshalJSON(`"`+overMaxSize+`"`, &result)
	if err == nil {
		t.Error("Expected error for JSON exceeding max size")
	}
}

// =============================================================================
// IOC CRUD Tests
// =============================================================================

func TestIOCStorage_CreateAndGet(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create IOC
	ioc, err := core.NewIOC(core.IOCTypeIP, "192.168.1.100", "test-source", "test-user")
	if err != nil {
		t.Fatalf("Failed to create IOC: %v", err)
	}
	ioc.Tags = []string{"malware", "apt"}
	ioc.Description = "Test malicious IP"

	err = storage.CreateIOC(ctx, ioc)
	if err != nil {
		t.Fatalf("Failed to store IOC: %v", err)
	}

	// Retrieve IOC
	retrieved, err := storage.GetIOC(ctx, ioc.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve IOC: %v", err)
	}

	// Verify fields
	if retrieved.ID != ioc.ID {
		t.Errorf("ID mismatch: got %s, want %s", retrieved.ID, ioc.ID)
	}
	if retrieved.Type != core.IOCTypeIP {
		t.Errorf("Type mismatch: got %s, want %s", retrieved.Type, core.IOCTypeIP)
	}
	if retrieved.Value != "192.168.1.100" {
		t.Errorf("Value mismatch: got %s, want %s", retrieved.Value, "192.168.1.100")
	}
	if len(retrieved.Tags) != 2 {
		t.Errorf("Tags mismatch: got %v, want 2 tags", retrieved.Tags)
	}
}

func TestIOCStorage_Update(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create IOC
	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "user")
	storage.CreateIOC(ctx, ioc)

	// Update IOC
	ioc.Status = core.IOCStatusDeprecated
	ioc.Severity = core.IOCSeverityHigh
	ioc.Description = "Updated description"

	err := storage.UpdateIOC(ctx, ioc)
	if err != nil {
		t.Fatalf("Failed to update IOC: %v", err)
	}

	// Verify update
	updated, _ := storage.GetIOC(ctx, ioc.ID)
	if updated.Status != core.IOCStatusDeprecated {
		t.Errorf("Status not updated: got %s, want %s", updated.Status, core.IOCStatusDeprecated)
	}
	if updated.Severity != core.IOCSeverityHigh {
		t.Errorf("Severity not updated: got %s, want %s", updated.Severity, core.IOCSeverityHigh)
	}
}

func TestIOCStorage_Delete(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create and delete IOC
	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "user")
	storage.CreateIOC(ctx, ioc)

	err := storage.DeleteIOC(ctx, ioc.ID)
	if err != nil {
		t.Fatalf("Failed to delete IOC: %v", err)
	}

	// Verify deletion
	_, err = storage.GetIOC(ctx, ioc.ID)
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestIOCStorage_DuplicatePrevention(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create first IOC
	ioc1, _ := core.NewIOC(core.IOCTypeIP, "192.168.1.1", "test", "user")
	err := storage.CreateIOC(ctx, ioc1)
	if err != nil {
		t.Fatalf("First IOC creation should succeed: %v", err)
	}

	// Try to create duplicate (same type + value)
	ioc2, _ := core.NewIOC(core.IOCTypeIP, "192.168.1.1", "other-source", "user")
	err = storage.CreateIOC(ctx, ioc2)
	if err == nil {
		t.Error("Duplicate IOC creation should fail")
	}
}

// =============================================================================
// Bulk Operations Tests
// =============================================================================

func TestIOCStorage_BulkCreate(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create multiple IOCs
	iocs := make([]*core.IOC, 100)
	for i := 0; i < 100; i++ {
		ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0."+string(rune(i+1)), "bulk-test", "user")
		iocs[i] = ioc
	}

	created, skipped, err := storage.BulkCreateIOCs(ctx, iocs)
	if err != nil {
		t.Fatalf("Bulk create failed: %v", err)
	}

	if created != 100 {
		t.Errorf("Expected 100 created, got %d", created)
	}
	if skipped != 0 {
		t.Errorf("Expected 0 skipped, got %d", skipped)
	}

	// Verify count
	stats, _ := storage.GetIOCStats(ctx)
	if stats.TotalCount != 100 {
		t.Errorf("Expected 100 total IOCs, got %d", stats.TotalCount)
	}
}

func TestIOCStorage_BulkUpdateStatus(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create IOCs
	var ids []string
	for i := 0; i < 10; i++ {
		ioc, _ := core.NewIOC(core.IOCTypeIP, "192.168.0."+string(rune(i+1)), "test", "user")
		storage.CreateIOC(ctx, ioc)
		ids = append(ids, ioc.ID)
	}

	// Bulk update to deprecated
	err := storage.BulkUpdateStatus(ctx, ids, core.IOCStatusDeprecated)
	if err != nil {
		t.Fatalf("Bulk update failed: %v", err)
	}

	// Verify all updated
	for _, id := range ids {
		ioc, _ := storage.GetIOC(ctx, id)
		if ioc.Status != core.IOCStatusDeprecated {
			t.Errorf("IOC %s not updated: got %s", id, ioc.Status)
		}
	}
}

// =============================================================================
// Hunt Tests
// =============================================================================

func TestIOCStorage_HuntLifecycle(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create IOC for hunt
	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "user")
	storage.CreateIOC(ctx, ioc)

	// Create hunt
	hunt, _ := core.NewIOCHunt(
		[]string{ioc.ID},
		time.Now().Add(-24*time.Hour),
		time.Now(),
		"test-user",
	)

	err := storage.CreateHunt(ctx, hunt)
	if err != nil {
		t.Fatalf("Failed to create hunt: %v", err)
	}

	// Get hunt
	retrieved, err := storage.GetHunt(ctx, hunt.ID)
	if err != nil {
		t.Fatalf("Failed to get hunt: %v", err)
	}
	if retrieved.Status != core.HuntStatusPending {
		t.Errorf("Expected pending status, got %s", retrieved.Status)
	}

	// Update status
	storage.UpdateHuntStatus(ctx, hunt.ID, core.HuntStatusRunning)
	retrieved, _ = storage.GetHunt(ctx, hunt.ID)
	if retrieved.Status != core.HuntStatusRunning {
		t.Errorf("Expected running status, got %s", retrieved.Status)
	}

	// Update progress
	storage.UpdateHuntProgress(ctx, hunt.ID, 50.0, 100, 10000)
	retrieved, _ = storage.GetHunt(ctx, hunt.ID)
	if retrieved.Progress != 50.0 {
		t.Errorf("Expected progress 50, got %f", retrieved.Progress)
	}

	// Complete hunt
	storage.CompleteHunt(ctx, hunt.ID, 100, 10000, nil)
	retrieved, _ = storage.GetHunt(ctx, hunt.ID)
	if retrieved.Status != core.HuntStatusCompleted {
		t.Errorf("Expected completed status, got %s", retrieved.Status)
	}
}

// =============================================================================
// Match Recording Tests
// =============================================================================

func TestIOCStorage_MatchRecording(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create match
	match := core.NewIOCMatch("ioc-1", "hunt-1", "event-1", "src_ip", "10.0.0.1", time.Now())
	err := storage.RecordMatch(ctx, match)
	if err != nil {
		t.Fatalf("Failed to record match: %v", err)
	}

	// Get matches by hunt
	matches, total, err := storage.GetMatchesByHunt(ctx, "hunt-1", 10, 0)
	if err != nil {
		t.Fatalf("Failed to get matches: %v", err)
	}
	if total != 1 {
		t.Errorf("Expected 1 match, got %d", total)
	}
	if len(matches) != 1 {
		t.Errorf("Expected 1 match in results, got %d", len(matches))
	}
}

func TestIOCStorage_BulkMatchRecording(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create matches
	matches := make([]*core.IOCMatch, 500)
	for i := 0; i < 500; i++ {
		matches[i] = core.NewIOCMatch("ioc-1", "hunt-1", "event-"+string(rune(i)), "src_ip", "10.0.0.1", time.Now())
	}

	recorded, err := storage.BulkRecordMatches(ctx, matches)
	if err != nil {
		t.Fatalf("Bulk record failed: %v", err)
	}
	if recorded != 500 {
		t.Errorf("Expected 500 recorded, got %d", recorded)
	}

	// Verify count
	_, total, _ := storage.GetMatchesByHunt(ctx, "hunt-1", 1, 0)
	if total != 500 {
		t.Errorf("Expected 500 matches, got %d", total)
	}
}

// =============================================================================
// SQL Injection Prevention Tests
// =============================================================================

func TestIOCStorage_SortFieldValidation(t *testing.T) {
	tests := []struct {
		sortBy      string
		sortOrder   string
		expectError bool
	}{
		{"created_at", "asc", false},
		{"created_at", "desc", false},
		{"updated_at", "ASC", false},
		{"hit_count", "DESC", false},
		{"invalid_field", "asc", true},
		{"created_at; DROP TABLE iocs;--", "asc", true},
		{"created_at", "invalid", true},
		{"created_at", "asc; DROP TABLE--", true},
	}

	for _, tc := range tests {
		t.Run(tc.sortBy+"/"+tc.sortOrder, func(t *testing.T) {
			field, order, err := validateSortParams(tc.sortBy, tc.sortOrder)

			if tc.expectError {
				if err == nil {
					t.Error("Expected validation error for malicious input")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if field == "" || order == "" {
					t.Error("Expected valid field and order")
				}
			}
		})
	}
}

// =============================================================================
// IOC Value Validation Tests
// =============================================================================

func TestIOCStorage_ValidationOnCreate(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		iocType     core.IOCType
		value       string
		expectError bool
	}{
		{"valid IP", core.IOCTypeIP, "192.168.1.1", false},
		{"invalid IP", core.IOCTypeIP, "not-an-ip", true},
		{"valid domain", core.IOCTypeDomain, "example.com", false},
		{"invalid domain", core.IOCTypeDomain, "not a domain!", true},
		{"valid MD5", core.IOCTypeHash, "d41d8cd98f00b204e9800998ecf8427e", false},
		{"valid SHA256", core.IOCTypeHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"invalid hash", core.IOCTypeHash, "not-a-hash", true},
		{"valid CIDR", core.IOCTypeCIDR, "192.168.0.0/24", false},
		{"invalid CIDR", core.IOCTypeCIDR, "192.168.0.0/99", true},
		{"valid CVE", core.IOCTypeCVE, "CVE-2021-44228", false},
		{"invalid CVE", core.IOCTypeCVE, "not-a-cve", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ioc, err := core.NewIOC(tc.iocType, tc.value, "test", "user")

			if tc.expectError {
				if err == nil {
					t.Error("Expected validation error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				// Try to store valid IOC
				err = storage.CreateIOC(ctx, ioc)
				if err != nil {
					t.Errorf("Failed to store valid IOC: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// Context Timeout Tests
// =============================================================================

func TestIOCStorage_ContextTimeout(t *testing.T) {
	_, storage, cleanup := setupIOCTestDB(t)
	defer cleanup()

	// Use already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "user")

	err := storage.CreateIOC(ctx, ioc)
	if err == nil {
		t.Error("Expected error with cancelled context")
	}
}
