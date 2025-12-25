package api

// Shared test helper functions for API testing
// These are used across multiple test files (auth_bypass_test.go, xss_protection_integration_test.go, etc.)

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/ingest"
	"cerberus/ml"
	"cerberus/storage"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupTestAPI creates a test API instance with SQLite storage for testing
// SECURITY PRODUCTION NOTE: This returns a fully functional API with auth enabled for security testing
func setupTestAPI(t *testing.T) (*API, func()) {
	// Create temporary database for testing
	dbPath := fmt.Sprintf("test_api_%d.db", time.Now().UnixNano())

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	// Create test configuration with realistic security settings
	cfg := &config.Config{}

	// Configure Auth section (using struct fields directly, not config.AuthConfig type)
	cfg.Auth.Enabled = true
	cfg.Auth.JWTSecret = "test-secret-key-for-jwt-testing-minimum-32-chars-long-for-hs256-security"
	cfg.Auth.JWTExpiry = 15 * time.Minute
	cfg.Auth.Username = "admin"
	cfg.Auth.HashedPassword = "$2a$10$test.hash.for.bcrypt.password.hashing" // Bcrypt hash placeholder
	cfg.Auth.BcryptCost = 10

	// Configure API section (using struct fields directly, not config.APIConfig type)
	cfg.API.Port = 8080
	cfg.API.TLS = false
	cfg.API.TrustProxy = false
	cfg.API.AllowedOrigins = []string{"http://localhost:3000"}
	// TASK 41: Increase rate limits for testing to avoid false test failures
	// Set extremely high limits for testing - tests run quickly and may hit limits
	cfg.API.RateLimit.RequestsPerSecond = 100000 // 100k requests/sec per IP
	cfg.API.RateLimit.Burst = 100000
	cfg.API.RateLimit.MaxAuthFailures = 100
	// Global rate limit for testing - very high to prevent test failures
	cfg.API.RateLimit.Global.Limit = 1000000 // 1M requests
	cfg.API.RateLimit.Global.Window = time.Second
	cfg.API.RateLimit.Global.Burst = 1000000
	// API tier limits (per-user rate limiting)
	cfg.API.RateLimit.API.Limit = 1000000
	cfg.API.RateLimit.API.Window = time.Second
	cfg.API.RateLimit.API.Burst = 1000000
	// Login tier limits (per-user login rate limiting) - very high for testing
	cfg.API.RateLimit.Login.Limit = 1000000
	cfg.API.RateLimit.Login.Window = time.Second
	cfg.API.RateLimit.Login.Burst = 1000000

	// Configure Security section (necessary for login body limit)
	cfg.Security.LoginBodyLimit = 10240 // 10KB - matches default from config

	// Create SQLite storage (base database connection)
	sqlite, err := storage.NewSQLite(dbPath, sugar)
	require.NoError(t, err, "Failed to create test database")

	// Create minimal mocks for ClickHouse storage (tests don't need real ClickHouse)
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}

	// Create SQLite-backed storage for rules, actions, etc.
	ruleStorage := storage.NewSQLiteRuleStorage(sqlite, 5*time.Second, sugar)
	actionStorage := storage.NewSQLiteActionStorage(sqlite, sugar)
	correlationRuleStorage := storage.NewSQLiteCorrelationRuleStorage(sqlite, sugar)
	investigationStorage, err := storage.NewSQLiteInvestigationStorage(sqlite, sugar)
	require.NoError(t, err, "Failed to create investigation storage")

	savedSearchStorage, err := storage.NewSQLiteSavedSearchStorage(sqlite, sugar)
	require.NoError(t, err, "Failed to create saved search storage")

	// Create user storage (wraps SQLite connection)
	userStorage := storage.NewSQLiteUserStorage(sqlite, sugar)

	// Create role storage for RBAC (wraps SQLite connection)
	roleStorage := storage.NewSQLiteRoleStorage(sqlite, sugar)

	// TASK 10: Seed default roles for RBAC testing
	ctx := context.Background()
	err = roleStorage.SeedDefaultRoles(ctx)
	require.NoError(t, err, "Failed to seed default roles")

	// Link role storage to user storage for permission checks
	// userStorage is already *SQLiteUserStorage, so we can call SetRoleStorage directly
	userStorage.SetRoleStorage(roleStorage)

	// TASK 10: Create admin test user for RBAC
	adminRoleID := int64(4) // Admin role ID from GetDefaultRoles
	adminUser := &storage.User{
		Username: "admin",
		Password: "admin123", // Will be hashed by CreateUser
		RoleID:   &adminRoleID,
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, adminUser)
	require.NoError(t, err, "Failed to create admin test user")

	// Create testuser for tests that use this username
	testuser := &storage.User{
		Username: "testuser",
		Password: "testpass123", // Will be hashed by CreateUser
		RoleID:   &adminRoleID,  // Give admin role for testing
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, testuser)
	require.NoError(t, err, "Failed to create testuser test user")

	// Create mock detector and ML detector for testing
	// PRODUCTION: These enable rule/correlation CRUD operations and ML endpoint testing
	mockDet := newMockDetector()
	mockML := newMockMLDetector()

	// Create DLQ for testing (TASK 7.4)
	dlq := ingest.NewDLQ(sqlite.DB, sugar)

	// Create MITRE storage for testing (TASK 9.6)
	mitreStorage := storage.NewSQLiteMitreStorage(sqlite, sugar)

	// Create API instance with proper storage implementations
	// BLOCKING-1 FIX: Pass nil for listenerManager in tests
	// Production code must handle nil listenerManager gracefully (handlers check for nil)
	api := NewAPI(
		eventStorage,           // event storage (mock)
		alertStorage,           // alert storage (mock)
		ruleStorage,            // rule storage (SQLite)
		actionStorage,          // action storage (SQLite)
		correlationRuleStorage, // correlation rule storage (SQLite)
		investigationStorage,   // investigation storage (SQLite)
		userStorage,            // user storage (SQLite wrapped)
		roleStorage,            // role storage for RBAC (SQLite wrapped)
		savedSearchStorage,     // saved search storage (SQLite)
		mockDet,                // detector (mock for rule reload testing)
		mockML,                 // ML detector (mock for ML endpoint testing)
		cfg,
		sugar,
		dlq,          // DLQ for malformed events (TASK 7.4)
		mitreStorage, // MITRE storage (TASK 9.6)
		nil,          // playbook executor (TASK 35) - nil for tests
		nil,          // playbook execution storage (TASK 35) - nil for tests
		storage.NewSQLitePasswordHistoryStorage(sqlite, sugar), // password history storage (TASK 38, TASK 41)
		nil, // ML model storage (TASK 37) - nil for tests
		nil, // field mapping storage - nil for tests
		nil, // listener manager (TASK 81) - nil for tests (BLOCKING-1: handlers must check for nil)
		nil, // playbook storage (TASK 99) - nil for tests (handlers check for nil)
		nil, // evidence storage - nil for tests (handlers check for nil)
		nil, // alert link storage - nil for tests (handlers check for nil)
		storage.NewSQLiteLifecycleAuditStorage(sqlite, sugar),        // lifecycle audit storage (TASK 169)
		storage.NewSQLiteFieldMappingAuditStorage(sqlite, sugar),     // field mapping audit storage (TASK 185)
	)

	// TASK #184 FIX: Set sqlite reference for tests that need direct access
	// Required for rule performance storage and other tests that use api.sqlite
	api.sqlite = sqlite

	// Cleanup function to remove test database
	cleanup := func() {
		sqlite.Close()
		os.RemoveAll(dbPath)
		os.RemoveAll(dbPath + "-wal")
		os.RemoveAll(dbPath + "-shm")
	}

	return api, cleanup
}

// createValidTestToken creates a valid JWT token for testing with proper claims
// SECURITY: Includes all required claims (Username, exp, iat, nbf, jti, iss) to pass validation
func createValidTestToken(t *testing.T, secret string, username string) string {
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: username,
		Roles:    []string{"admin"}, // Default to admin role for testing
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        fmt.Sprintf("test-jti-%d", time.Now().UnixNano()),
			Issuer:    "cerberus",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err, "Failed to create test token")

	return tokenString
}

// createExpiredTestToken creates an expired JWT token for testing
// SECURITY: Used to test that expired tokens are properly rejected
func createExpiredTestToken(t *testing.T, secret string, username string, expiredSince time.Duration) string {
	expirationTime := time.Now().Add(expiredSince) // Negative duration for past expiration
	claims := &Claims{
		Username: username,
		Roles:    []string{"admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(expiredSince - 1*time.Hour)), // Issued before expiration
			NotBefore: jwt.NewNumericDate(time.Now().Add(expiredSince - 1*time.Hour)),
			ID:        fmt.Sprintf("test-jti-expired-%d", time.Now().UnixNano()),
			Issuer:    "cerberus",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err, "Failed to create expired test token")

	return tokenString
}

// generateValidCSRFToken generates a cryptographically secure CSRF token for testing
// SECURITY: Uses crypto/rand for high-entropy tokens (32 bytes = 64 hex chars)
func generateValidCSRFToken(t *testing.T) string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	require.NoError(t, err, "Failed to generate random bytes for CSRF token")

	return fmt.Sprintf("%x", bytes) // 64 hex characters
}

// addCSRFToRequest adds a valid CSRF token to the request (both header and cookie)
// This is required for state-changing operations (POST, PUT, DELETE) when auth is enabled
func addCSRFToRequest(t *testing.T, req *http.Request) {
	csrfToken := generateValidCSRFToken(t)
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(&http.Cookie{
		Name:  "csrf_token",
		Value: csrfToken,
	})
}

// mockEventStorage is a minimal mock for EventStorer interface (used when ClickHouse unavailable in tests)
type mockEventStorage struct{}

func (m *mockEventStorage) GetEvents(ctx context.Context, limit int, offset int) ([]core.Event, error) {
	return []core.Event{}, nil
}
func (m *mockEventStorage) GetEventCount(ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockEventStorage) GetEventCountsByMonth(ctx context.Context) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

// mockAlertStorage is a minimal mock for AlertStorer interface (used when ClickHouse unavailable in tests)
type mockAlertStorage struct{}

func (m *mockAlertStorage) GetAlerts(ctx context.Context, limit int, offset int) ([]core.Alert, error) {
	return []core.Alert{}, nil
}
func (m *mockAlertStorage) GetAlert(ctx context.Context, id string) (*core.Alert, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockAlertStorage) GetAlertCount(ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockAlertStorage) GetAlertCountsByMonth(ctx context.Context) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}
func (m *mockAlertStorage) AcknowledgeAlert(ctx context.Context, id string) error {
	return nil
}
func (m *mockAlertStorage) DismissAlert(ctx context.Context, id string) error {
	return nil
}
func (m *mockAlertStorage) UpdateAlertStatus(ctx context.Context, id string, status core.AlertStatus) error {
	return nil
}
func (m *mockAlertStorage) AssignAlert(ctx context.Context, id string, assignedTo string) error {
	return nil
}
func (m *mockAlertStorage) DeleteAlert(ctx context.Context, id string) error {
	return nil
}

// TASK 145.2: Implement InsertAlert for AlertService integration
func (m *mockAlertStorage) InsertAlert(ctx context.Context, alert *core.Alert) error {
	return nil
}

func (m *mockAlertStorage) GetAlertsFiltered(ctx context.Context, limit, offset int, severity, status string) ([]*core.Alert, error) {
	// TASK 51.3: Implement GetAlertsFiltered for interface compliance
	return []*core.Alert{}, nil
}

// TASK 104: Implement UpdateAlertDisposition for interface compliance
// TASK 111: Returns previous disposition for audit logging
// TASK 111 FIX: Accepts context for request cancellation support (BLOCKING-5)
func (m *mockAlertStorage) UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, userID string) (string, error) {
	return string(core.DispositionUndetermined), nil
}

// TASK 105: Implement UpdateAlertAssignee for interface compliance
func (m *mockAlertStorage) UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error {
	return nil
}

// TASK 105: Implement GetAlertByID for interface compliance
func (m *mockAlertStorage) GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error) {
	return &core.Alert{AlertID: alertID, AssignedTo: ""}, nil
}

// TASK 106: Implement UpdateAlertInvestigation for interface compliance
func (m *mockAlertStorage) UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error {
	return nil
}

// TASK 110: Implement GetAlertsWithFilters for interface compliance
func (m *mockAlertStorage) GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error) {
	return []*core.Alert{}, 0, nil
}

// RecordStatusChange records a status change in the alert's history (mock)
func (m *mockAlertStorage) RecordStatusChange(ctx context.Context, change *core.StatusChange) error {
	return nil
}

// GetAlertHistory retrieves the status change history for an alert (mock)
func (m *mockAlertStorage) GetAlertHistory(ctx context.Context, alertID string) ([]*core.StatusChange, error) {
	return []*core.StatusChange{}, nil
}

// mockDetector is a minimal mock for DetectorInterface (used for rule CRUD tests)
// PRODUCTION: Implements DetectorInterface for testing rule/correlation CRUD operations
type mockDetector struct {
	rules        []core.Rule
	correlations []core.CorrelationRule
}

// newMockDetector creates a new mock detector instance
func newMockDetector() *mockDetector {
	return &mockDetector{
		rules:        make([]core.Rule, 0),
		correlations: make([]core.CorrelationRule, 0),
	}
}

// ReloadRules simulates reloading rules in the detector
// PRODUCTION: In real detector, this would reload rule engine with new rules
func (m *mockDetector) ReloadRules(rules []core.Rule) error {
	// Validate that rules are not nil (basic sanity check)
	if rules == nil {
		return fmt.Errorf("cannot reload nil rules")
	}

	// Store rules for potential verification in tests
	m.rules = rules
	return nil
}

// ReloadCorrelationRules simulates reloading correlation rules in the detector
// PRODUCTION: In real detector, this would reload correlation engine with new rules
func (m *mockDetector) ReloadCorrelationRules(rules []core.CorrelationRule) error {
	// Validate that rules are not nil (basic sanity check)
	if rules == nil {
		return fmt.Errorf("cannot reload nil correlation rules")
	}

	// Store correlation rules for potential verification in tests
	m.correlations = rules
	return nil
}

// mockMLDetector is a minimal mock for MLAnomalyDetector (used for ML API tests)
// PRODUCTION: Implements MLAnomalyDetector interface for testing ML endpoints
type mockMLDetector struct {
	status ml.TrainingPipelineStatus
}

// newMockMLDetector creates a new mock ML detector instance
func newMockMLDetector() *mockMLDetector {
	return &mockMLDetector{
		status: ml.TrainingPipelineStatus{
			IsRunning:          false,
			SampleCount:        0,
			BufferSize:         0,
			LastTraining:       time.Time{},
			PerformanceHistory: []ml.TrainingPerformance{},
		},
	}
}

// ProcessEvent simulates processing an event through ML detector
// PRODUCTION: In real ML detector, this would run anomaly detection
func (m *mockMLDetector) ProcessEvent(ctx context.Context, event *core.Event) (interface{}, error) {
	// Return a minimal mock response
	return map[string]interface{}{
		"is_anomaly":    false,
		"anomaly_score": 0.0,
	}, nil
}

// GetStatus returns the mock training pipeline status
// PRODUCTION: In real ML detector, this would return actual training status
func (m *mockMLDetector) GetStatus() ml.TrainingPipelineStatus {
	return m.status
}

// ForceTraining simulates forcing model training
// PRODUCTION: In real ML detector, this would trigger model retraining
func (m *mockMLDetector) ForceTraining(ctx context.Context) error {
	// Update status to indicate training was triggered
	m.status.IsRunning = true
	m.status.LastTraining = time.Now()
	return nil
}

// Reset simulates resetting the ML detector
// PRODUCTION: In real ML detector, this would reset training state
func (m *mockMLDetector) Reset() error {
	m.status = ml.TrainingPipelineStatus{
		IsRunning:          false,
		SampleCount:        0,
		BufferSize:         0,
		LastTraining:       time.Time{},
		PerformanceHistory: []ml.TrainingPerformance{},
	}
	return nil
}

// ============================================================================
// TASK 63.9: Mock Storage Layer and RBAC Test Utilities
// ============================================================================

// NewTestAlert creates a test alert with sensible defaults
func NewTestAlert(id, ruleID, severity string, event *core.Event) *core.Alert {
	if id == "" {
		id = fmt.Sprintf("test-alert-%d", time.Now().UnixNano())
	}
	if severity == "" {
		severity = "medium"
	}
	if event == nil {
		event = NewTestEvent("", "test", nil)
	}
	return &core.Alert{
		AlertID:   id,
		RuleID:    ruleID,
		EventID:   event.EventID,
		Timestamp: time.Now().UTC(),
		Severity:  severity,
		Status:    core.AlertStatusPending,
		Event:     event,
		RuleName:  "Test Rule",
	}
}

// NewTestRule creates a test rule with sensible defaults
// TASK 176: Updated to use SIGMA YAML format instead of legacy Conditions
func NewTestRule(id, name, ruleType string) *core.Rule {
	if id == "" {
		id = fmt.Sprintf("test-rule-%d", time.Now().UnixNano())
	}
	if name == "" {
		name = "Test Rule"
	}
	if ruleType == "" {
		ruleType = "sigma"
	}

	// Generate minimal SIGMA YAML for test rule
	sigmaYAML := fmt.Sprintf(`title: %s
id: %s
status: experimental
logsource:
  category: test
detection:
  selection:
    event.type: test
  condition: selection
level: medium`, name, id)

	return &core.Rule{
		ID:          id,
		Type:        ruleType,
		Name:        name,
		Description: "Test rule description",
		Severity:    "medium",
		SigmaYAML:   sigmaYAML,
		Version:     1,
		Enabled:     true,
		Actions:     []core.Action{},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
}

// NewTestAction creates a test action with sensible defaults
func NewTestAction(id, actionType string) *core.Action {
	if id == "" {
		id = fmt.Sprintf("test-action-%d", time.Now().UnixNano())
	}
	if actionType == "" {
		actionType = "webhook"
	}
	return &core.Action{
		ID:        id,
		Type:      actionType,
		Config:    map[string]interface{}{"url": "https://example.com/webhook"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// NewTestEvent creates a test event with sensible defaults
func NewTestEvent(eventID, sourceFormat string, fields map[string]interface{}) *core.Event {
	if eventID == "" {
		eventID = fmt.Sprintf("test-event-%d", time.Now().UnixNano())
	}
	if sourceFormat == "" {
		sourceFormat = "json"
	}
	if fields == nil {
		fields = map[string]interface{}{
			"message": "Test event",
		}
	}
	return &core.Event{
		EventID:      eventID,
		SourceIP:     "192.168.1.100",
		SourceFormat: sourceFormat,
		Timestamp:    time.Now().UTC(),
		RawData:      json.RawMessage(`{"message": "Test event"}`),
		Fields:       fields,
	}
}

// NewTestUser creates a test user with specified role
func NewTestUser(username, password, roleName string) *storage.User {
	var roleID *int64
	switch roleName {
	case "viewer":
		id := int64(1)
		roleID = &id
	case "analyst":
		id := int64(2)
		roleID = &id
	case "engineer":
		id := int64(3)
		roleID = &id
	case "admin":
		id := int64(4)
		roleID = &id
	default:
		// Default to admin if role name not recognized
		id := int64(4)
		roleID = &id
	}
	return &storage.User{
		Username: username,
		Password: password,
		RoleID:   roleID,
		Active:   true,
	}
}

// CreateTestUserWithRole creates a user in the database with the specified role
func CreateTestUserWithRole(t *testing.T, userStorage storage.UserStorage, username, password, roleName string) *storage.User {
	ctx := context.Background()
	user := NewTestUser(username, password, roleName)
	err := userStorage.CreateUser(ctx, user)
	require.NoError(t, err, "Failed to create test user: %s", username)
	return user
}

//lint:ignore U1000 Test helper reserved for RBAC testing scenarios
func createTestTokenWithRole(t *testing.T, secret, username string, roles []string) string {
	expirationTime := time.Now().Add(1 * time.Hour)
	if roles == nil || len(roles) == 0 {
		roles = []string{"admin"} // Default to admin
	}
	claims := &Claims{
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        fmt.Sprintf("test-jti-%d", time.Now().UnixNano()),
			Issuer:    "cerberus",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err, "Failed to create test token with role")
	return tokenString
}

// GetRoleID returns the role ID for a role name
func GetRoleID(roleName string) int64 {
	switch roleName {
	case "viewer":
		return 1
	case "analyst":
		return 2
	case "engineer":
		return 3
	case "admin":
		return 4
	default:
		return 4 // Default to admin
	}
}

// SeedTestUsers creates all standard test users (viewer, analyst, engineer, admin)
func SeedTestUsers(t *testing.T, userStorage storage.UserStorage) {
	ctx := context.Background()
	users := []*storage.User{
		NewTestUser("viewer", "viewer123", "viewer"),
		NewTestUser("analyst", "analyst123", "analyst"),
		NewTestUser("engineer", "engineer123", "engineer"),
		NewTestUser("admin", "admin123", "admin"),
	}
	for _, user := range users {
		err := userStorage.CreateUser(ctx, user)
		// Ignore errors if user already exists (for idempotency)
		if err != nil && err.Error() != "user already exists" {
			require.NoError(t, err, "Failed to seed test user: %s", user.Username)
		}
	}
}

// AuthenticateTestUser performs login for a test user and returns JWT and CSRF tokens
func AuthenticateTestUser(t *testing.T, api *API, username, password string) (jwtToken, csrfToken string) {
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	loginBody, err := json.Marshal(loginReq)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "Login should succeed for %s", username)

	// Extract tokens from cookies
	cookies := w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "auth_token" {
			jwtToken = cookie.Value
		}
		if cookie.Name == "csrf_token" {
			csrfToken = cookie.Value
		}
	}
	require.NotEmpty(t, jwtToken, "Response should contain auth_token cookie")
	require.NotEmpty(t, csrfToken, "Response should contain csrf_token cookie")
	return jwtToken, csrfToken
}

// MakeAuthenticatedRequestWithRole creates an authenticated HTTP request with a specific role
func MakeAuthenticatedRequestWithRole(t *testing.T, api *API, method, path string, body []byte, username, roleName string) *http.Request {
	// Get user's tokens by authenticating
	jwtToken, csrfToken := AuthenticateTestUser(t, api, username, fmt.Sprintf("%s123", username))
	return MakeAuthenticatedHTTPRequest(method, path, body, jwtToken, csrfToken)
}

// MakeAuthenticatedRequest creates an authenticated HTTP request (enhanced wrapper)
// This is a helper that combines authentication and request creation
func MakeAuthenticatedRequest(t *testing.T, api *API, method, path string, body []byte, username, password string) *http.Request {
	jwtToken, csrfToken := AuthenticateTestUser(t, api, username, password)
	return MakeAuthenticatedHTTPRequest(method, path, body, jwtToken, csrfToken)
}

// MakeAuthenticatedHTTPRequest creates an authenticated HTTP request
// TASK 63.9: Public wrapper for makeAuthenticatedRequest functionality
func MakeAuthenticatedHTTPRequest(method, path string, body []byte, jwtToken, csrfToken string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if jwtToken != "" {
		// JWT middleware checks Authorization header first, then cookie
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		// Also set cookie for compatibility
		req.AddCookie(&http.Cookie{
			Name:  "auth_token",
			Value: jwtToken,
		})
	}
	// CSRF protection is required for state-changing methods (POST, PUT, DELETE, PATCH)
	// CSRF validation requires both cookie AND header to match
	if csrfToken != "" && (method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH") {
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.AddCookie(&http.Cookie{
			Name:  "csrf_token",
			Value: csrfToken,
		})
	}
	return req
}

// AssertJSONResponse unmarshals and validates a JSON response
func AssertJSONResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, target interface{}) {
	require.Equal(t, expectedStatus, w.Code, "Expected status %d, got %d", expectedStatus, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "application/json", "Response should be JSON")
	err := json.Unmarshal(w.Body.Bytes(), target)
	require.NoError(t, err, "Failed to unmarshal JSON response: %s", w.Body.String())
}

// AssertErrorResponse validates an error response structure
func AssertErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, expectedError string) {
	require.Equal(t, expectedStatus, w.Code, "Expected status %d, got %d", expectedStatus, w.Code)
	var errorResp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &errorResp)
	require.NoError(t, err, "Failed to unmarshal error response")
	if expectedError != "" {
		errorMsg, ok := errorResp["error"].(string)
		if ok {
			assert.Contains(t, errorMsg, expectedError, "Error message should contain: %s", expectedError)
		}
	}
}

// Enhanced mock storage implementations for comprehensive testing

// EnhancedMockRuleStorage is an enhanced mock rule storage with configurable behavior
type EnhancedMockRuleStorage struct {
	rules     []core.Rule
	GetAllFn  func() ([]core.Rule, error)
	CreateFn  func(rule *core.Rule) error
	GetRuleFn func(id string) (*core.Rule, error)
}

// NewEnhancedMockRuleStorage creates a new enhanced mock rule storage
func NewEnhancedMockRuleStorage() *EnhancedMockRuleStorage {
	return &EnhancedMockRuleStorage{
		rules: make([]core.Rule, 0),
	}
}

func (m *EnhancedMockRuleStorage) GetAllRules() ([]core.Rule, error) {
	if m.GetAllFn != nil {
		return m.GetAllFn()
	}
	return m.rules, nil
}

func (m *EnhancedMockRuleStorage) GetRules(limit int, offset int) ([]core.Rule, error) {
	allRules, _ := m.GetAllRules()
	start := offset
	end := offset + limit
	if start > len(allRules) {
		return []core.Rule{}, nil
	}
	if end > len(allRules) {
		end = len(allRules)
	}
	return allRules[start:end], nil
}

func (m *EnhancedMockRuleStorage) GetRuleCount() (int64, error) {
	return int64(len(m.rules)), nil
}

func (m *EnhancedMockRuleStorage) GetRule(id string) (*core.Rule, error) {
	if m.GetRuleFn != nil {
		return m.GetRuleFn(id)
	}
	for i := range m.rules {
		if m.rules[i].ID == id {
			return &m.rules[i], nil
		}
	}
	return nil, storage.ErrNotFound
}

func (m *EnhancedMockRuleStorage) CreateRule(rule *core.Rule) error {
	if m.CreateFn != nil {
		return m.CreateFn(rule)
	}
	m.rules = append(m.rules, *rule)
	return nil
}

func (m *EnhancedMockRuleStorage) UpdateRule(id string, rule *core.Rule) error {
	for i := range m.rules {
		if m.rules[i].ID == id {
			m.rules[i] = *rule
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockRuleStorage) DeleteRule(id string) error {
	for i := range m.rules {
		if m.rules[i].ID == id {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockRuleStorage) GetEnabledRules() ([]core.Rule, error) {
	var enabled []core.Rule
	for _, r := range m.rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return enabled, nil
}

func (m *EnhancedMockRuleStorage) GetRulesByType(ruleType string, limit int, offset int) ([]core.Rule, error) {
	var filtered []core.Rule
	for _, r := range m.rules {
		if r.Type == ruleType {
			filtered = append(filtered, r)
		}
	}
	start := offset
	end := offset + limit
	if start > len(filtered) {
		return []core.Rule{}, nil
	}
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[start:end], nil
}

func (m *EnhancedMockRuleStorage) SearchRules(query string) ([]core.Rule, error) {
	var results []core.Rule
	for _, r := range m.rules {
		if r.Name == query || r.Description == query {
			results = append(results, r)
		}
	}
	return results, nil
}

func (m *EnhancedMockRuleStorage) GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error) {
	return m.rules, int64(len(m.rules)), nil
}

func (m *EnhancedMockRuleStorage) GetRuleFilterMetadata() (*core.RuleFilterMetadata, error) {
	return &core.RuleFilterMetadata{}, nil
}

func (m *EnhancedMockRuleStorage) EnableRule(id string) error {
	for i := range m.rules {
		if m.rules[i].ID == id {
			m.rules[i].Enabled = true
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockRuleStorage) DisableRule(id string) error {
	for i := range m.rules {
		if m.rules[i].ID == id {
			m.rules[i].Enabled = false
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockRuleStorage) EnsureIndexes() error {
	return nil
}

// EnhancedMockActionStorage is an enhanced mock action storage
type EnhancedMockActionStorage struct {
	actions []core.Action
}

func NewEnhancedMockActionStorage() *EnhancedMockActionStorage {
	return &EnhancedMockActionStorage{
		actions: make([]core.Action, 0),
	}
}

func (m *EnhancedMockActionStorage) GetActions() ([]core.Action, error) {
	return m.actions, nil
}

func (m *EnhancedMockActionStorage) GetAction(id string) (*core.Action, error) {
	for i := range m.actions {
		if m.actions[i].ID == id {
			return &m.actions[i], nil
		}
	}
	return nil, storage.ErrNotFound
}

func (m *EnhancedMockActionStorage) CreateAction(action *core.Action) error {
	m.actions = append(m.actions, *action)
	return nil
}

func (m *EnhancedMockActionStorage) UpdateAction(id string, action *core.Action) error {
	for i := range m.actions {
		if m.actions[i].ID == id {
			m.actions[i] = *action
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockActionStorage) DeleteAction(id string) error {
	for i := range m.actions {
		if m.actions[i].ID == id {
			m.actions = append(m.actions[:i], m.actions[i+1:]...)
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockActionStorage) EnsureIndexes() error {
	return nil
}

// EnhancedMockCorrelationRuleStorage is an enhanced mock correlation rule storage
type EnhancedMockCorrelationRuleStorage struct {
	rules []core.CorrelationRule
}

func NewEnhancedMockCorrelationRuleStorage() *EnhancedMockCorrelationRuleStorage {
	return &EnhancedMockCorrelationRuleStorage{
		rules: make([]core.CorrelationRule, 0),
	}
}

func (m *EnhancedMockCorrelationRuleStorage) GetCorrelationRules(limit int, offset int) ([]core.CorrelationRule, error) {
	start := offset
	end := offset + limit
	if start > len(m.rules) {
		return []core.CorrelationRule{}, nil
	}
	if end > len(m.rules) {
		end = len(m.rules)
	}
	return m.rules[start:end], nil
}

func (m *EnhancedMockCorrelationRuleStorage) GetAllCorrelationRules() ([]core.CorrelationRule, error) {
	return m.rules, nil
}

func (m *EnhancedMockCorrelationRuleStorage) GetCorrelationRuleCount() (int64, error) {
	return int64(len(m.rules)), nil
}

func (m *EnhancedMockCorrelationRuleStorage) GetCorrelationRule(id string) (*core.CorrelationRule, error) {
	for i := range m.rules {
		if m.rules[i].ID == id {
			return &m.rules[i], nil
		}
	}
	return nil, storage.ErrNotFound
}

func (m *EnhancedMockCorrelationRuleStorage) CreateCorrelationRule(rule *core.CorrelationRule) error {
	m.rules = append(m.rules, *rule)
	return nil
}

func (m *EnhancedMockCorrelationRuleStorage) UpdateCorrelationRule(id string, rule *core.CorrelationRule) error {
	for i := range m.rules {
		if m.rules[i].ID == id {
			m.rules[i] = *rule
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockCorrelationRuleStorage) DeleteCorrelationRule(id string) error {
	for i := range m.rules {
		if m.rules[i].ID == id {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *EnhancedMockCorrelationRuleStorage) EnsureIndexes() error {
	return nil
}
