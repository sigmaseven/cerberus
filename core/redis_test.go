package core

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"go.uber.org/zap/zaptest"
)

func TestRedisCache_SetGet(t *testing.T) {
	// Start a mini Redis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer mr.Close()

	logger := zaptest.NewLogger(t).Sugar()
	cache := NewRedisCache(mr.Addr(), "", 0, 10, logger)
	defer cache.Close()

	ctx := context.Background()

	// Test data
	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	testData := TestStruct{Name: "test", Value: 42}
	key := "test_key"

	// Set value
	err = cache.Set(ctx, key, testData, time.Minute)
	if err != nil {
		t.Fatalf("Failed to set cache value: %v", err)
	}

	// Get value
	var result TestStruct
	found, err := cache.Get(ctx, key, &result)
	if err != nil {
		t.Fatalf("Failed to get cache value: %v", err)
	}

	if !found {
		t.Fatal("Expected key to be found")
	}

	if result.Name != testData.Name || result.Value != testData.Value {
		t.Errorf("Expected %+v, got %+v", testData, result)
	}
}

func TestRedisCache_Get_NotFound(t *testing.T) {
	// Start a mini Redis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer mr.Close()

	logger := zaptest.NewLogger(t).Sugar()
	cache := NewRedisCache(mr.Addr(), "", 0, 10, logger)
	defer cache.Close()

	ctx := context.Background()

	var result string
	found, err := cache.Get(ctx, "nonexistent_key", &result)
	if err != nil {
		t.Fatalf("Failed to get cache value: %v", err)
	}

	if found {
		t.Error("Expected key to not be found")
	}
}

func TestRedisCache_Exists(t *testing.T) {
	// Start a mini Redis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer mr.Close()

	logger := zaptest.NewLogger(t).Sugar()
	cache := NewRedisCache(mr.Addr(), "", 0, 10, logger)
	defer cache.Close()

	ctx := context.Background()
	key := "test_key"

	// Key should not exist initially
	exists, err := cache.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Failed to check key existence: %v", err)
	}
	if exists {
		t.Error("Expected key to not exist initially")
	}

	// Set value
	err = cache.Set(ctx, key, "test_value", time.Minute)
	if err != nil {
		t.Fatalf("Failed to set cache value: %v", err)
	}

	// Key should exist now
	exists, err = cache.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Failed to check key existence: %v", err)
	}
	if !exists {
		t.Error("Expected key to exist after setting")
	}
}

func TestRedisCache_Delete(t *testing.T) {
	// Start a mini Redis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer mr.Close()

	logger := zaptest.NewLogger(t).Sugar()
	cache := NewRedisCache(mr.Addr(), "", 0, 10, logger)
	defer cache.Close()

	ctx := context.Background()
	key := "test_key"

	// Set value
	err = cache.Set(ctx, key, "test_value", time.Minute)
	if err != nil {
		t.Fatalf("Failed to set cache value: %v", err)
	}

	// Verify it exists
	exists, err := cache.Exists(ctx, key)
	if err != nil || !exists {
		t.Fatalf("Key should exist after setting")
	}

	// Delete key
	err = cache.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify it no longer exists
	exists, err = cache.Exists(ctx, key)
	if err != nil || exists {
		t.Fatalf("Key should not exist after deletion")
	}
}

func TestRedisCache_SetNX(t *testing.T) {
	// Start a mini Redis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer mr.Close()

	logger := zaptest.NewLogger(t).Sugar()
	cache := NewRedisCache(mr.Addr(), "", 0, 10, logger)
	defer cache.Close()

	ctx := context.Background()
	key := "test_key"

	// First SetNX should succeed
	set, err := cache.SetNX(ctx, key, "value1", time.Minute)
	if err != nil {
		t.Fatalf("Failed to set NX: %v", err)
	}
	if !set {
		t.Error("Expected first SetNX to succeed")
	}

	// Second SetNX should fail
	set, err = cache.SetNX(ctx, key, "value2", time.Minute)
	if err != nil {
		t.Fatalf("Failed to set NX: %v", err)
	}
	if set {
		t.Error("Expected second SetNX to fail")
	}

	// Verify the value is still the first one
	var result string
	found, err := cache.Get(ctx, key, &result)
	if err != nil || !found || result != "value1" {
		t.Errorf("Expected value to be 'value1', got '%s'", result)
	}
}

func TestCacheKeyFunctions(t *testing.T) {
	tests := []struct {
		name     string
		fn       func(string) string
		input    string
		expected string
	}{
		{"GetRuleCacheKey", GetRuleCacheKey, "rule123", "rule:rule123"},
		{"GetAlertCacheKey", GetAlertCacheKey, "alert456", "alert:alert456"},
		{"GetConfigCacheKey", GetConfigCacheKey, "config789", "config:config789"},
		{"GetStatsCacheKey", GetStatsCacheKey, "stats101", "stats:stats101"},
		{"GetUserCacheKey", GetUserCacheKey, "user202", "user:user202"},
		{"GetSessionCacheKey", GetSessionCacheKey, "session303", "session:session303"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
