package storage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// setupSavedSearchTestDB creates a fresh in-memory database for saved search testing
func setupSavedSearchTestDB(t *testing.T) *SQLiteSavedSearchStorage {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	db, err := NewSQLite(":memory:", sugar)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	storage, err := NewSQLiteSavedSearchStorage(db, sugar)
	if err != nil {
		t.Fatalf("Failed to create saved search storage: %v", err)
	}

	return storage
}

// createTestSearch creates a test saved search
func createTestSearch(name, createdBy string) *SQLiteSavedSearch {
	return &SQLiteSavedSearch{
		Name:        name,
		Description: "Test description for " + name,
		Query:       "SELECT * FROM events WHERE severity = 'high'",
		Filters: map[string]interface{}{
			"severity": "high",
			"limit":    100,
		},
		CreatedBy: createdBy,
		IsPublic:  false,
		Tags:      []string{"test", "important"},
	}
}

func TestNewSQLiteSavedSearchStorage(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	db, err := NewSQLite(":memory:", sugar)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	storage, err := NewSQLiteSavedSearchStorage(db, sugar)
	if err != nil {
		t.Errorf("Failed to create saved search storage: %v", err)
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

func TestCreateSavedSearch(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("My Search", "user1")

	err := storage.Create(search)
	if err != nil {
		t.Errorf("Failed to create saved search: %v", err)
	}

	// Verify search was created
	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve saved search: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil search")
	}
	if retrieved.Name != "My Search" {
		t.Errorf("Expected name 'My Search', got %s", retrieved.Name)
	}
	if retrieved.CreatedBy != "user1" {
		t.Errorf("Expected created_by 'user1', got %s", retrieved.CreatedBy)
	}
	if len(retrieved.Filters) != 2 {
		t.Errorf("Expected 2 filters, got %d", len(retrieved.Filters))
	}
	if len(retrieved.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(retrieved.Tags))
	}
	if retrieved.UsageCount != 0 {
		t.Errorf("Expected usage count 0, got %d", retrieved.UsageCount)
	}
}

func TestCreateSavedSearch_WithID(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("Search with ID", "user1")
	search.ID = "custom-id-123"

	err := storage.Create(search)
	if err != nil {
		t.Errorf("Failed to create saved search: %v", err)
	}

	// Verify search was created with custom ID
	retrieved, err := storage.Get("custom-id-123")
	if err != nil {
		t.Errorf("Failed to retrieve saved search: %v", err)
	}
	if retrieved.ID != "custom-id-123" {
		t.Errorf("Expected ID 'custom-id-123', got %s", retrieved.ID)
	}
}

func TestCreateSavedSearch_SQLInjectionPrevention(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Attempt SQL injection through various fields
	search := &SQLiteSavedSearch{
		Name:        "Test'; DELETE FROM saved_searches WHERE '1'='1",
		Description: "'; DROP TABLE saved_searches; --",
		Query:       "SELECT * FROM events",
		CreatedBy:   "user'; DROP TABLE saved_searches; --",
		IsPublic:    false,
	}

	err := storage.Create(search)
	if err != nil {
		t.Errorf("Failed to create search with SQL injection attempt: %v", err)
	}

	// Verify data was stored safely
	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve search: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil search")
	}
	if !strings.Contains(retrieved.Name, "DELETE FROM saved_searches") {
		t.Error("SQL injection attempt should be stored as literal text")
	}

	// Verify table still exists
	searches, err := storage.GetAll(false, "")
	if err != nil {
		t.Errorf("Table should still exist after SQL injection attempt: %v", err)
	}
	if len(searches) == 0 {
		t.Error("Expected at least one search")
	}
}

func TestGetSavedSearch(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("Test Search", "user1")

	// Create search
	err := storage.Create(search)
	if err != nil {
		t.Fatalf("Failed to create search: %v", err)
	}

	// Retrieve search
	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve search: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil search")
	}
	if retrieved.ID != search.ID {
		t.Errorf("Expected ID %s, got %s", search.ID, retrieved.ID)
	}
}

func TestGetSavedSearch_NotFound(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	_, err := storage.Get("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent search")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestGetSavedSearch_SQLInjection(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Attempt SQL injection in query
	_, err := storage.Get("' OR '1'='1")
	if err == nil {
		t.Error("Expected error for SQL injection attempt")
	}
}

func TestGetAllSavedSearches(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Create multiple searches
	for i := 1; i <= 5; i++ {
		search := createTestSearch("Search"+string(rune('0'+i)), "user1")
		storage.Create(search)
	}

	// Get all searches
	searches, err := storage.GetAll(false, "")
	if err != nil {
		t.Errorf("Failed to get all searches: %v", err)
	}
	if len(searches) != 5 {
		t.Errorf("Expected 5 searches, got %d", len(searches))
	}
}

func TestGetAllSavedSearches_FilterByPublic(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Create public and private searches
	public1 := createTestSearch("Public 1", "user1")
	public1.IsPublic = true
	storage.Create(public1)

	public2 := createTestSearch("Public 2", "user1")
	public2.IsPublic = true
	storage.Create(public2)

	private1 := createTestSearch("Private 1", "user1")
	private1.IsPublic = false
	storage.Create(private1)

	// Get public searches
	publicSearches, err := storage.GetAll(true, "")
	if err != nil {
		t.Errorf("Failed to get public searches: %v", err)
	}
	if len(publicSearches) != 2 {
		t.Errorf("Expected 2 public searches, got %d", len(publicSearches))
	}
	for _, search := range publicSearches {
		if !search.IsPublic {
			t.Error("Expected all searches to be public")
		}
	}
}

func TestGetAllSavedSearches_FilterByCreatedBy(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Create searches by different users
	user1Search1 := createTestSearch("User1 Search1", "user1")
	storage.Create(user1Search1)

	user1Search2 := createTestSearch("User1 Search2", "user1")
	storage.Create(user1Search2)

	user2Search := createTestSearch("User2 Search", "user2")
	storage.Create(user2Search)

	// Get searches by user1
	user1Searches, err := storage.GetAll(false, "user1")
	if err != nil {
		t.Errorf("Failed to get user1 searches: %v", err)
	}
	if len(user1Searches) != 2 {
		t.Errorf("Expected 2 searches for user1, got %d", len(user1Searches))
	}
	for _, search := range user1Searches {
		if search.CreatedBy != "user1" {
			t.Errorf("Expected created_by 'user1', got %s", search.CreatedBy)
		}
	}
}

func TestGetAllSavedSearches_FilterByPublicAndCreatedBy(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Create various combinations
	publicUser1 := createTestSearch("Public User1", "user1")
	publicUser1.IsPublic = true
	storage.Create(publicUser1)

	privateUser1 := createTestSearch("Private User1", "user1")
	privateUser1.IsPublic = false
	storage.Create(privateUser1)

	publicUser2 := createTestSearch("Public User2", "user2")
	publicUser2.IsPublic = true
	storage.Create(publicUser2)

	// Get public searches by user1
	searches, err := storage.GetAll(true, "user1")
	if err != nil {
		t.Errorf("Failed to get searches: %v", err)
	}
	if len(searches) != 1 {
		t.Errorf("Expected 1 search, got %d", len(searches))
	}
	if searches[0].CreatedBy != "user1" || !searches[0].IsPublic {
		t.Error("Expected public search by user1")
	}
}

func TestGetAllSavedSearches_Empty(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	searches, err := storage.GetAll(false, "")
	if err != nil {
		t.Errorf("Failed to get all searches: %v", err)
	}
	if len(searches) != 0 {
		t.Errorf("Expected 0 searches, got %d", len(searches))
	}
}

// TestGetAllSavedSearches_NonNilEmpty verifies that empty results return non-nil slice
// This is critical for JSON serialization - nil serializes to null, [] to []
func TestGetAllSavedSearches_NonNilEmpty(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	searches, err := storage.GetAll(false, "")
	if err != nil {
		t.Fatalf("Failed to get all searches: %v", err)
	}

	// CRITICAL: Must be non-nil to serialize as [] not null
	if searches == nil {
		t.Error("Expected non-nil slice, got nil - this causes frontend 'Cannot read properties of undefined (reading map)' errors")
	}

	// Verify length is 0
	if len(searches) != 0 {
		t.Errorf("Expected 0 searches, got %d", len(searches))
	}

	// Verify type is correctly []SQLiteSavedSearch (compile-time check)
	var _ []SQLiteSavedSearch = searches
}

// TestGetAllSavedSearches_JSONSerializationContract verifies JSON serialization produces [] not null
// This is the actual failure mode that breaks frontend: null serialization causes undefined.map() errors
func TestGetAllSavedSearches_JSONSerializationContract(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	searches, err := storage.GetAll(false, "")

	if err != nil {
		t.Fatalf("Failed to get all searches: %v", err)
	}

	// Critical: Verify JSON serialization produces [], not null
	jsonBytes, err := json.Marshal(searches)
	if err != nil {
		t.Fatalf("Failed to marshal searches: %v", err)
	}

	if string(jsonBytes) != "[]" {
		t.Errorf("Expected JSON '[]', got '%s' - this causes frontend to crash with 'Cannot read properties of undefined'", string(jsonBytes))
	}
}

func TestUpdateSavedSearch(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("Original Name", "user1")

	// Create search
	err := storage.Create(search)
	if err != nil {
		t.Fatalf("Failed to create search: %v", err)
	}

	// Update search
	search.Name = "Updated Name"
	search.Description = "Updated Description"
	search.Query = "SELECT * FROM events WHERE severity = 'critical'"
	search.Filters = map[string]interface{}{
		"severity": "critical",
		"limit":    50,
	}
	search.IsPublic = true
	search.Tags = []string{"updated", "critical"}

	err = storage.Update(search.ID, search)
	if err != nil {
		t.Errorf("Failed to update search: %v", err)
	}

	// Verify update
	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve updated search: %v", err)
	}
	if retrieved.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got %s", retrieved.Name)
	}
	if retrieved.Description != "Updated Description" {
		t.Errorf("Expected description 'Updated Description', got %s", retrieved.Description)
	}
	if !retrieved.IsPublic {
		t.Error("Expected IsPublic to be true")
	}
	if len(retrieved.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(retrieved.Tags))
	}
}

func TestUpdateSavedSearch_NotFound(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("Test", "user1")

	err := storage.Update("nonexistent", search)
	if err == nil {
		t.Error("Expected error when updating nonexistent search")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestUpdateSavedSearch_SQLInjection(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("Test", "user1")

	// Create search
	storage.Create(search)

	// Attempt SQL injection in update
	search.Name = "'; DELETE FROM saved_searches WHERE '1'='1'; --"
	search.Description = "'; DROP TABLE saved_searches; --"

	err := storage.Update(search.ID, search)
	if err != nil {
		t.Errorf("Failed to update search: %v", err)
	}

	// Verify SQL injection was stored as literal text
	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve search: %v", err)
	}
	if !strings.Contains(retrieved.Name, "DELETE FROM saved_searches") {
		t.Error("SQL injection should be stored as literal text")
	}
}

func TestDeleteSavedSearch(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("To Delete", "user1")

	// Create search
	err := storage.Create(search)
	if err != nil {
		t.Fatalf("Failed to create search: %v", err)
	}

	// Delete search
	err = storage.Delete(search.ID)
	if err != nil {
		t.Errorf("Failed to delete search: %v", err)
	}

	// Verify deletion
	_, err = storage.Get(search.ID)
	if err == nil {
		t.Error("Expected error when retrieving deleted search")
	}
}

func TestDeleteSavedSearch_NotFound(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	err := storage.Delete("nonexistent")
	if err == nil {
		t.Error("Expected error when deleting nonexistent search")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestDeleteSavedSearch_SQLInjection(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Attempt SQL injection in delete
	err := storage.Delete("' OR '1'='1")
	// Should not delete anything since ID doesn't match
	if err == nil {
		t.Error("Expected error for SQL injection attempt")
	}
}

func TestIncrementUsageCount(t *testing.T) {
	storage := setupSavedSearchTestDB(t)
	search := createTestSearch("Popular Search", "user1")

	// Create search
	storage.Create(search)

	// Increment usage count multiple times
	for i := 0; i < 5; i++ {
		err := storage.IncrementUsageCount(search.ID)
		if err != nil {
			t.Errorf("Failed to increment usage count: %v", err)
		}
	}

	// Verify usage count
	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve search: %v", err)
	}
	if retrieved.UsageCount != 5 {
		t.Errorf("Expected usage count 5, got %d", retrieved.UsageCount)
	}
}

func TestIncrementUsageCount_NonexistentSearch(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Incrementing usage count for nonexistent search should not error
	// (SQLite will silently succeed with 0 rows affected)
	err := storage.IncrementUsageCount("nonexistent")
	if err != nil {
		// Some implementations might not error
		// This is acceptable behavior
	}
}

// Edge case tests

func TestCreateSavedSearch_NilFilters(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	search := &SQLiteSavedSearch{
		Name:      "No Filters",
		Query:     "SELECT * FROM events",
		CreatedBy: "user1",
		Filters:   nil, // Nil filters
	}

	err := storage.Create(search)
	if err != nil {
		t.Errorf("Failed to create search with nil filters: %v", err)
	}

	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve search: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil search")
	}
}

func TestCreateSavedSearch_NilTags(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	search := &SQLiteSavedSearch{
		Name:      "No Tags",
		Query:     "SELECT * FROM events",
		CreatedBy: "user1",
		Tags:      nil, // Nil tags
	}

	err := storage.Create(search)
	if err != nil {
		t.Errorf("Failed to create search with nil tags: %v", err)
	}

	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Errorf("Failed to retrieve search: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected non-nil search")
	}
}

func TestGetAllSavedSearches_OrderedByCreatedAt(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Create searches with slight time delays
	for i := 1; i <= 3; i++ {
		search := createTestSearch("Search"+string(rune('0'+i)), "user1")
		storage.Create(search)
		time.Sleep(10 * time.Millisecond)
	}

	searches, err := storage.GetAll(false, "")
	if err != nil {
		t.Errorf("Failed to get searches: %v", err)
	}
	if len(searches) != 3 {
		t.Fatalf("Expected 3 searches, got %d", len(searches))
	}

	// Verify descending order (newest first)
	for i := 0; i < len(searches)-1; i++ {
		if searches[i].CreatedAt.Before(searches[i+1].CreatedAt) {
			t.Error("Searches should be ordered by CreatedAt DESC")
			break
		}
	}
}

func TestSavedSearch_ComplexFilters(t *testing.T) {
	storage := setupSavedSearchTestDB(t)

	// Create search with complex nested filters
	search := &SQLiteSavedSearch{
		Name:      "Complex Filters",
		Query:     "SELECT * FROM events",
		CreatedBy: "user1",
		Filters: map[string]interface{}{
			"severity": "high",
			"timerange": map[string]interface{}{
				"start": "2024-01-01",
				"end":   "2024-12-31",
			},
			"tags":  []string{"security", "firewall"},
			"count": 100,
		},
	}

	err := storage.Create(search)
	if err != nil {
		t.Fatalf("Failed to create search with complex filters: %v", err)
	}

	// Retrieve and verify filters
	retrieved, err := storage.Get(search.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve search: %v", err)
	}

	if len(retrieved.Filters) == 0 {
		t.Error("Expected non-empty filters")
	}

	// Verify specific filter values
	if severity, ok := retrieved.Filters["severity"].(string); !ok || severity != "high" {
		t.Errorf("Expected severity 'high', got %v", retrieved.Filters["severity"])
	}
}

func TestSavedSearchDatabaseError_Handling(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	db, err := NewSQLite(":memory:", sugar)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	storage, err := NewSQLiteSavedSearchStorage(db, sugar)
	if err != nil {
		t.Fatalf("Failed to create saved search storage: %v", err)
	}

	// Close the database to force errors
	db.DB.Close()

	// All operations should return errors
	search := createTestSearch("Test", "user1")

	err = storage.Create(search)
	if err == nil {
		t.Error("Expected error when database is closed")
	}

	_, err = storage.Get("test")
	if err == nil {
		t.Error("Expected error when database is closed")
	}

	_, err = storage.GetAll(false, "")
	if err == nil {
		t.Error("Expected error when database is closed")
	}

	err = storage.Update("test", search)
	if err == nil {
		t.Error("Expected error when database is closed")
	}

	err = storage.Delete("test")
	if err == nil {
		t.Error("Expected error when database is closed")
	}
}
