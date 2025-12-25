package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cerberus/config"
	"go.uber.org/zap"
)

// TestGetAuthConfig_Disabled tests the /api/auth/config endpoint when auth is disabled
func TestGetAuthConfig_Disabled(t *testing.T) {
	// Create test config with auth disabled
	cfg := &config.Config{}
	cfg.Auth.Enabled = false

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Create API instance with minimal dependencies
	api := &API{
		config: cfg,
		logger: sugar,
	}

	// Create test request
	req := httptest.NewRequest("GET", "/api/auth/config", nil)
	w := httptest.NewRecorder()

	// Call handler
	api.getAuthConfig(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify authEnabled is false
	authEnabled, ok := response["authEnabled"].(bool)
	if !ok {
		t.Fatal("authEnabled field missing or wrong type")
	}
	if authEnabled {
		t.Error("Expected authEnabled to be false")
	}

	// Verify no other fields are present when auth is disabled
	if len(response) != 1 {
		t.Errorf("Expected only authEnabled field, got %d fields: %v", len(response), response)
	}
}

// TestGetAuthConfig_Enabled tests the /api/auth/config endpoint when auth is enabled
func TestGetAuthConfig_Enabled(t *testing.T) {
	// Create test config with auth enabled
	cfg := &config.Config{}
	cfg.Auth.Enabled = true

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Create API instance
	api := &API{
		config: cfg,
		logger: sugar,
	}

	// Create test request
	req := httptest.NewRequest("GET", "/api/auth/config", nil)
	w := httptest.NewRecorder()

	// Call handler
	api.getAuthConfig(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify authEnabled is true
	authEnabled, ok := response["authEnabled"].(bool)
	if !ok {
		t.Fatal("authEnabled field missing or wrong type")
	}
	if !authEnabled {
		t.Error("Expected authEnabled to be true")
	}

	// Verify sessionTimeout is present
	sessionTimeout, ok := response["sessionTimeout"].(float64)
	if !ok {
		t.Fatal("sessionTimeout field missing or wrong type")
	}
	if sessionTimeout <= 0 {
		t.Error("Expected positive sessionTimeout")
	}

	// Verify passwordPolicy is present
	passwordPolicy, ok := response["passwordPolicy"].(map[string]interface{})
	if !ok {
		t.Fatal("passwordPolicy field missing or wrong type")
	}
	if passwordPolicy["minLength"].(float64) != 8 {
		t.Errorf("Expected minLength 8, got %v", passwordPolicy["minLength"])
	}
	if passwordPolicy["maxLength"].(float64) != 128 {
		t.Errorf("Expected maxLength 128, got %v", passwordPolicy["maxLength"])
	}

	// Verify usernamePolicy is present
	usernamePolicy, ok := response["usernamePolicy"].(map[string]interface{})
	if !ok {
		t.Fatal("usernamePolicy field missing or wrong type")
	}
	if usernamePolicy["minLength"].(float64) != 3 {
		t.Errorf("Expected minLength 3, got %v", usernamePolicy["minLength"])
	}

	// SECURITY: Verify sensitive fields are NOT exposed
	if _, exists := response["maxLoginAttempts"]; exists {
		t.Error("SECURITY: maxLoginAttempts should not be exposed")
	}
	if _, exists := response["bcryptCost"]; exists {
		t.Error("SECURITY: bcryptCost should not be exposed")
	}
	if _, exists := response["jwtSecret"]; exists {
		t.Error("SECURITY: jwtSecret should NEVER be exposed")
	}
}
