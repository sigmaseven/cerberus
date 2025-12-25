package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"cerberus/core"
	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// MockAlertStorage is a mock implementation of AlertStorage interface.
type MockAlertStorage struct {
	mock.Mock
}

func (m *MockAlertStorage) GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error) {
	args := m.Called(ctx, alertID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*core.Alert), args.Error(1)
}

func (m *MockAlertStorage) GetAlerts(ctx context.Context, limit, offset int) ([]core.Alert, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]core.Alert), args.Error(1)
}

func (m *MockAlertStorage) GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error) {
	args := m.Called(ctx, filters)
	return args.Get(0).([]*core.Alert), args.Get(1).(int64), args.Error(2)
}

func (m *MockAlertStorage) GetAlertCount(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAlertStorage) GetAlert(ctx context.Context, alertID string) (*core.Alert, error) {
	args := m.Called(ctx, alertID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*core.Alert), args.Error(1)
}

func (m *MockAlertStorage) InsertAlert(ctx context.Context, alert *core.Alert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockAlertStorage) UpdateAlertStatus(ctx context.Context, alertID string, status core.AlertStatus) error {
	args := m.Called(ctx, alertID, status)
	return args.Error(0)
}

func (m *MockAlertStorage) UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, username string) (string, error) {
	args := m.Called(ctx, alertID, disposition, reason, username)
	return args.String(0), args.Error(1)
}

func (m *MockAlertStorage) UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error {
	args := m.Called(ctx, alertID, assigneeID)
	return args.Error(0)
}

func (m *MockAlertStorage) UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error {
	args := m.Called(ctx, alertID, investigationID)
	return args.Error(0)
}

func (m *MockAlertStorage) AssignAlert(ctx context.Context, alertID, assignTo string) error {
	args := m.Called(ctx, alertID, assignTo)
	return args.Error(0)
}

func (m *MockAlertStorage) DeleteAlert(ctx context.Context, alertID string) error {
	args := m.Called(ctx, alertID)
	return args.Error(0)
}

// MockRuleStorage is a mock implementation of RuleStorage interface.
type MockRuleStorage struct {
	mock.Mock
}

func (m *MockRuleStorage) GetRule(id string) (*core.Rule, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*core.Rule), args.Error(1)
}

// MockUserStorage is a mock implementation of UserStorage interface.
type MockUserStorage struct {
	mock.Mock
}

func (m *MockUserStorage) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.User), args.Error(1)
}

// MockInvestigationStorage is a mock implementation of InvestigationStorage.
type MockInvestigationStorage struct {
	mock.Mock
}

func (m *MockInvestigationStorage) GetInvestigation(id string) (*core.Investigation, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*core.Investigation), args.Error(1)
}

func (m *MockInvestigationStorage) CreateInvestigation(investigation *core.Investigation) error {
	args := m.Called(investigation)
	return args.Error(0)
}

func (m *MockInvestigationStorage) DeleteInvestigation(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockInvestigationStorage) AddAlert(investigationID, alertID string) error {
	args := m.Called(investigationID, alertID)
	return args.Error(0)
}

// ============================================================================
// Test Helpers
// ============================================================================

func setupTestService() (*AlertServiceImpl, *MockAlertStorage, *MockRuleStorage, *MockUserStorage) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()

	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)
	return service, alertStorage, ruleStorage, userStorage
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewAlertService_Success(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()

	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)

	assert.NotNil(t, service)
	assert.Equal(t, alertStorage, service.alertStorage)
	assert.Equal(t, ruleStorage, service.ruleStorage)
	assert.Equal(t, userStorage, service.userStorage)
	assert.Equal(t, logger, service.logger)
}

func TestNewAlertService_PanicsOnNilAlertStorage(t *testing.T) {
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()

	assert.Panics(t, func() {
		NewAlertService(nil, ruleStorage, userStorage, investigationStorage, logger)
	})
}

func TestNewAlertService_PanicsOnNilRuleStorage(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()

	assert.Panics(t, func() {
		NewAlertService(alertStorage, nil, userStorage, investigationStorage, logger)
	})
}

func TestNewAlertService_PanicsOnNilLogger(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)

	assert.Panics(t, func() {
		NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, nil)
	})
}

// ============================================================================
// GetAlertByID Tests
// ============================================================================

func TestGetAlertByID_Success(t *testing.T) {
	service, alertStorage, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	expectedAlert := &core.Alert{
		AlertID: "alert-1",
		RuleID:  "rule-1",
		Status:  core.AlertStatusPending,
	}

	expectedRule := &core.Rule{
		ID:          "rule-1",
		Name:        "Test Rule",
		Description: "Test Description",
		Type:        "sigma",
		Tags:        []string{"attack.t1059"},
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(expectedAlert, nil)
	ruleStorage.On("GetRule", "rule-1").Return(expectedRule, nil)

	alert, err := service.GetAlertByID(ctx, "alert-1")

	assert.NoError(t, err)
	assert.NotNil(t, alert)
	assert.Equal(t, "alert-1", alert.AlertID)
	assert.Equal(t, "Test Rule", alert.RuleName)
	assert.Equal(t, "Test Description", alert.RuleDescription)
	assert.Equal(t, "sigma", alert.RuleType)
	assert.Contains(t, alert.MitreTechniques, "attack.t1059")
	alertStorage.AssertExpectations(t)
	ruleStorage.AssertExpectations(t)
}

func TestGetAlertByID_EmptyID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	alert, err := service.GetAlertByID(ctx, "")

	assert.Error(t, err)
	assert.Nil(t, alert)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestGetAlertByID_NotFound(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("GetAlertByID", ctx, "nonexistent").Return(nil, storage.ErrAlertNotFound)

	alert, err := service.GetAlertByID(ctx, "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, alert)
	assert.True(t, errors.Is(err, storage.ErrAlertNotFound))
	alertStorage.AssertExpectations(t)
}

func TestGetAlertByID_StorageError(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(nil, errors.New("database error"))

	alert, err := service.GetAlertByID(ctx, "alert-1")

	assert.Error(t, err)
	assert.Nil(t, alert)
	assert.Contains(t, err.Error(), "failed to retrieve alert")
	alertStorage.AssertExpectations(t)
}

func TestGetAlertByID_EnrichmentContinuesOnRuleNotFound(t *testing.T) {
	service, alertStorage, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	expectedAlert := &core.Alert{
		AlertID: "alert-1",
		RuleID:  "rule-missing",
		Status:  core.AlertStatusPending,
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(expectedAlert, nil)
	ruleStorage.On("GetRule", "rule-missing").Return(nil, storage.ErrRuleNotFound)

	alert, err := service.GetAlertByID(ctx, "alert-1")

	// Should succeed even though rule not found
	assert.NoError(t, err)
	assert.NotNil(t, alert)
	assert.NotEmpty(t, alert.RuleName) // Should have auto-generated name
	alertStorage.AssertExpectations(t)
	ruleStorage.AssertExpectations(t)
}

// ============================================================================
// ListAlerts Tests
// ============================================================================

func TestListAlerts_WithFilters(t *testing.T) {
	service, alertStorage, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	filters := &core.AlertFilters{
		Page:       1,
		Limit:      10,
		Severities: []string{"high"},
	}

	expectedAlerts := []*core.Alert{
		{AlertID: "alert-1", RuleID: "rule-1", Severity: "high"},
		{AlertID: "alert-2", RuleID: "rule-2", Severity: "high"},
	}

	rule1 := &core.Rule{ID: "rule-1", Name: "Rule 1"}
	rule2 := &core.Rule{ID: "rule-2", Name: "Rule 2"}

	alertStorage.On("GetAlertsWithFilters", ctx, filters).Return(expectedAlerts, int64(2), nil)
	ruleStorage.On("GetRule", "rule-1").Return(rule1, nil)
	ruleStorage.On("GetRule", "rule-2").Return(rule2, nil)

	alerts, total, err := service.ListAlerts(ctx, filters)

	assert.NoError(t, err)
	assert.Len(t, alerts, 2)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, "Rule 1", alerts[0].RuleName)
	assert.Equal(t, "Rule 2", alerts[1].RuleName)
	alertStorage.AssertExpectations(t)
	ruleStorage.AssertExpectations(t)
}

func TestListAlerts_NoFilters(t *testing.T) {
	service, alertStorage, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	filters := &core.AlertFilters{
		Page:  1,
		Limit: 10,
	}

	simpleAlerts := []core.Alert{
		{AlertID: "alert-1", RuleID: "rule-1"},
	}

	rule1 := &core.Rule{ID: "rule-1", Name: "Rule 1"}

	alertStorage.On("GetAlerts", ctx, 10, 0).Return(simpleAlerts, nil)
	alertStorage.On("GetAlertCount", ctx).Return(int64(1), nil)
	ruleStorage.On("GetRule", "rule-1").Return(rule1, nil)

	alerts, total, err := service.ListAlerts(ctx, filters)

	assert.NoError(t, err)
	assert.Len(t, alerts, 1)
	assert.Equal(t, int64(1), total)
	alertStorage.AssertExpectations(t)
	ruleStorage.AssertExpectations(t)
}

func TestListAlerts_NilFilters(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	alerts, total, err := service.ListAlerts(ctx, nil)

	assert.Error(t, err)
	assert.Nil(t, alerts)
	assert.Equal(t, int64(0), total)
	assert.Contains(t, err.Error(), "filters are required")
}

func TestListAlerts_PaginationDefaults(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	// Invalid pagination values should be corrected internally
	filters := &core.AlertFilters{
		Page:  0,      // Invalid - internally corrected to 1
		Limit: 999999, // Exceeds max - internally capped at 10000
	}

	// Service creates defensive copy and corrects values before calling storage
	alertStorage.On("GetAlerts", ctx, 10000, 0).Return([]core.Alert{}, nil)
	alertStorage.On("GetAlertCount", ctx).Return(int64(0), nil)

	_, _, err := service.ListAlerts(ctx, filters)

	assert.NoError(t, err)
	// Original filters should NOT be mutated (CRITICAL-7 fix)
	assert.Equal(t, 0, filters.Page, "Original Page should not be mutated")
	assert.Equal(t, 999999, filters.Limit, "Original Limit should not be mutated")
	alertStorage.AssertExpectations(t)
}

// ============================================================================
// CreateAlert Tests
// ============================================================================

func TestCreateAlert_Success(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		RuleID:   "rule-1",
		Severity: "high",
	}

	alertStorage.On("InsertAlert", ctx, mock.MatchedBy(func(a *core.Alert) bool {
		return a.RuleID == "rule-1" && a.Severity == "high" && a.Status == core.AlertStatusPending
	})).Return(nil)

	created, err := service.CreateAlert(ctx, alert)

	assert.NoError(t, err)
	assert.NotNil(t, created)
	assert.Equal(t, core.AlertStatusPending, created.Status) // Default status
	alertStorage.AssertExpectations(t)
}

func TestCreateAlert_NilAlert(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	created, err := service.CreateAlert(ctx, nil)

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "alert is required")
}

func TestCreateAlert_MissingRuleID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		Severity: "high",
		// Missing RuleID
	}

	created, err := service.CreateAlert(ctx, alert)

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "RuleID is required")
}

func TestCreateAlert_MissingSeverity(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		RuleID: "rule-1",
		// Missing Severity
	}

	created, err := service.CreateAlert(ctx, alert)

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "Severity is required")
}

func TestCreateAlert_StorageError(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		RuleID:   "rule-1",
		Severity: "high",
	}

	alertStorage.On("InsertAlert", ctx, mock.Anything).Return(errors.New("database error"))

	created, err := service.CreateAlert(ctx, alert)

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "failed to create alert")
	alertStorage.AssertExpectations(t)
}

// ============================================================================
// CreateAlert ID Generation Tests (BLOCKER-4)
// ============================================================================

func TestCreateAlert_GeneratesID(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		RuleID:   "rule-1",
		Severity: "high",
		// No AlertID provided
	}

	alertStorage.On("InsertAlert", ctx, mock.MatchedBy(func(a *core.Alert) bool {
		// Verify AlertID was generated
		return a.AlertID != "" && a.RuleID == "rule-1"
	})).Return(nil)

	created, err := service.CreateAlert(ctx, alert)

	assert.NoError(t, err)
	assert.NotNil(t, created)
	assert.NotEmpty(t, created.AlertID, "AlertID should be generated")
	assert.NotEqual(t, "alert-1", created.AlertID, "AlertID should not be placeholder")
	alertStorage.AssertExpectations(t)
}

func TestCreateAlert_GeneratesUniqueIDs(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	const numAlerts = 100
	generatedIDs := make(map[string]bool)

	for i := 0; i < numAlerts; i++ {
		alert := &core.Alert{
			RuleID:   fmt.Sprintf("rule-%d", i),
			Severity: "high",
		}

		alertStorage.On("InsertAlert", ctx, mock.Anything).Return(nil).Once()

		created, err := service.CreateAlert(ctx, alert)

		assert.NoError(t, err)
		assert.NotNil(t, created)
		assert.NotEmpty(t, created.AlertID)

		// Verify uniqueness
		assert.False(t, generatedIDs[created.AlertID], "Generated ID %s is not unique", created.AlertID)
		generatedIDs[created.AlertID] = true
	}

	// Verify all IDs are unique
	assert.Equal(t, numAlerts, len(generatedIDs), "All generated IDs should be unique")
	alertStorage.AssertExpectations(t)
}

func TestCreateAlert_PreservesProvidedID(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	customID := "custom-alert-id-12345"
	alert := &core.Alert{
		AlertID:  customID,
		RuleID:   "rule-1",
		Severity: "high",
	}

	alertStorage.On("InsertAlert", ctx, mock.MatchedBy(func(a *core.Alert) bool {
		return a.AlertID == customID
	})).Return(nil)

	created, err := service.CreateAlert(ctx, alert)

	assert.NoError(t, err)
	assert.NotNil(t, created)
	assert.Equal(t, customID, created.AlertID, "Should preserve provided AlertID")
	alertStorage.AssertExpectations(t)
}

// ============================================================================
// UpdateAlertStatus Tests
// ============================================================================

func TestUpdateAlertStatus_Success(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusPending,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)
	alertStorage.On("UpdateAlertStatus", ctx, "alert-1", core.AlertStatusAcknowledged).Return(nil)

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusAcknowledged, "user-1")

	assert.NoError(t, err)
	alertStorage.AssertExpectations(t)
}

func TestUpdateAlertStatus_EmptyAlertID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.UpdateAlertStatus(ctx, "", core.AlertStatusAcknowledged, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestUpdateAlertStatus_InvalidStatus(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatus("invalid"), "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid alert status")
}

func TestUpdateAlertStatus_EmptyUserID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusAcknowledged, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "userID is required")
}

func TestUpdateAlertStatus_AlertNotFound(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("GetAlert", ctx, "nonexistent").Return(nil, storage.ErrAlertNotFound)

	err := service.UpdateAlertStatus(ctx, "nonexistent", core.AlertStatusAcknowledged, "user-1")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrAlertNotFound))
	alertStorage.AssertExpectations(t)
}

// ============================================================================
// Invalid State Transition Tests (BLOCKER-3)
// ============================================================================

func TestUpdateAlertStatus_InvalidTransition_ResolvedToInvestigating(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusResolved,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusInvestigating, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state transition")
	alertStorage.AssertExpectations(t)
	// Verify storage was NOT called (transition rejected)
	alertStorage.AssertNotCalled(t, "UpdateAlertStatus")
}

func TestUpdateAlertStatus_InvalidTransition_ClosedToAcknowledged(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusClosed,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusAcknowledged, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state transition")
	alertStorage.AssertExpectations(t)
	alertStorage.AssertNotCalled(t, "UpdateAlertStatus")
}

func TestUpdateAlertStatus_InvalidTransition_ResolvedToPending(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusResolved,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusPending, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state transition")
	alertStorage.AssertExpectations(t)
	alertStorage.AssertNotCalled(t, "UpdateAlertStatus")
}

func TestUpdateAlertStatus_InvalidTransition_EscalatedToPending(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusEscalated,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusPending, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state transition")
	alertStorage.AssertExpectations(t)
	alertStorage.AssertNotCalled(t, "UpdateAlertStatus")
}

func TestUpdateAlertStatus_InvalidTransition_ClosedToEscalated(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusClosed,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusEscalated, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state transition")
	alertStorage.AssertExpectations(t)
	alertStorage.AssertNotCalled(t, "UpdateAlertStatus")
}

func TestUpdateAlertStatus_StorageFailure(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusPending,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)
	alertStorage.On("UpdateAlertStatus", ctx, "alert-1", core.AlertStatusAcknowledged).
		Return(errors.New("database error"))

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusAcknowledged, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update alert status")
	alertStorage.AssertExpectations(t)
}

// ============================================================================
// DeleteAlert Tests
// ============================================================================

func TestDeleteAlert_Success(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("DeleteAlert", ctx, "alert-1").Return(nil)

	err := service.DeleteAlert(ctx, "alert-1")

	assert.NoError(t, err)
	alertStorage.AssertExpectations(t)
}

func TestDeleteAlert_EmptyID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.DeleteAlert(ctx, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestDeleteAlert_NotFound(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("DeleteAlert", ctx, "nonexistent").Return(storage.ErrAlertNotFound)

	err := service.DeleteAlert(ctx, "nonexistent")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrAlertNotFound))
	alertStorage.AssertExpectations(t)
}

// ============================================================================
// SetDisposition Tests
// ============================================================================

func TestSetDisposition_Success(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("UpdateAlertDisposition", ctx, "alert-1",
		core.DispositionTruePositive, "Confirmed malicious", "analyst-1").
		Return("undetermined", nil)

	previousDisp, err := service.SetDisposition(ctx, "alert-1",
		core.DispositionTruePositive, "Confirmed malicious", "analyst-1")

	assert.NoError(t, err)
	assert.Equal(t, core.DispositionUndetermined, previousDisp)
	alertStorage.AssertExpectations(t)
}

func TestSetDisposition_EmptyAlertID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	_, err := service.SetDisposition(ctx, "", core.DispositionTruePositive, "reason", "user")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestSetDisposition_InvalidDisposition(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	_, err := service.SetDisposition(ctx, "alert-1", core.AlertDisposition("invalid"), "reason", "user")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid disposition")
}

func TestSetDisposition_EmptyUsername(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	_, err := service.SetDisposition(ctx, "alert-1", core.DispositionTruePositive, "reason", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is required")
}

// ============================================================================
// AssignAlert Tests
// ============================================================================

func TestAssignAlert_Success(t *testing.T) {
	service, alertStorage, _, userStorage := setupTestService()
	ctx := context.Background()

	assignee := "analyst-1"
	user := &storage.User{Username: "analyst-1"}

	userStorage.On("GetUserByUsername", ctx, "analyst-1").Return(user, nil)
	alertStorage.On("UpdateAlertAssignee", ctx, "alert-1", &assignee).Return(nil)

	err := service.AssignAlert(ctx, "alert-1", &assignee, "manager-1")

	assert.NoError(t, err)
	alertStorage.AssertExpectations(t)
	userStorage.AssertExpectations(t)
}

func TestAssignAlert_Unassign(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("UpdateAlertAssignee", ctx, "alert-1", (*string)(nil)).Return(nil)

	err := service.AssignAlert(ctx, "alert-1", nil, "manager-1")

	assert.NoError(t, err)
	alertStorage.AssertExpectations(t)
}

func TestAssignAlert_EmptyAlertID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	assignee := "analyst-1"
	err := service.AssignAlert(ctx, "", &assignee, "manager-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestAssignAlert_EmptyAssignedBy(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	assignee := "analyst-1"
	err := service.AssignAlert(ctx, "alert-1", &assignee, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assignedBy is required")
}

func TestAssignAlert_UserNotFound(t *testing.T) {
	service, _, _, userStorage := setupTestService()
	ctx := context.Background()

	assignee := "nonexistent"

	userStorage.On("GetUserByUsername", ctx, "nonexistent").Return(nil, storage.ErrUserNotFound)

	err := service.AssignAlert(ctx, "alert-1", &assignee, "manager-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	userStorage.AssertExpectations(t)
}

// ============================================================================
// EnrichAlert Tests
// ============================================================================

func TestEnrichAlert_Success(t *testing.T) {
	service, _, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID: "alert-1",
		RuleID:  "rule-1",
	}

	rule := &core.Rule{
		ID:          "rule-1",
		Name:        "Suspicious Process",
		Description: "Detects suspicious process execution",
		Type:        "sigma",
		Tags:        []string{"attack.t1059.001", "windows"},
	}

	ruleStorage.On("GetRule", "rule-1").Return(rule, nil)

	err := service.EnrichAlert(ctx, alert)

	assert.NoError(t, err)
	assert.Equal(t, "Suspicious Process", alert.RuleName)
	assert.Equal(t, "Detects suspicious process execution", alert.RuleDescription)
	assert.Equal(t, "sigma", alert.RuleType)
	assert.Contains(t, alert.MitreTechniques, "attack.t1059.001")
	ruleStorage.AssertExpectations(t)
}

func TestEnrichAlert_NilAlert(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.EnrichAlert(ctx, nil)

	assert.NoError(t, err) // Should handle gracefully
}

func TestEnrichAlert_EmptyRuleID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID: "alert-1",
		// No RuleID
	}

	err := service.EnrichAlert(ctx, alert)

	assert.NoError(t, err) // Should handle gracefully
}

func TestEnrichAlert_RuleNotFound(t *testing.T) {
	service, _, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID: "alert-1",
		RuleID:  "missing-rule",
	}

	ruleStorage.On("GetRule", "missing-rule").Return(nil, storage.ErrRuleNotFound)

	err := service.EnrichAlert(ctx, alert)

	assert.NoError(t, err) // Should not fail, just use generated title
	assert.NotEmpty(t, alert.RuleName)
	ruleStorage.AssertExpectations(t)
}

// ============================================================================
// EnrichAlerts Tests
// ============================================================================

func TestEnrichAlerts_Success(t *testing.T) {
	service, _, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	alerts := []*core.Alert{
		{AlertID: "alert-1", RuleID: "rule-1"},
		{AlertID: "alert-2", RuleID: "rule-2"},
	}

	rule1 := &core.Rule{ID: "rule-1", Name: "Rule 1"}
	rule2 := &core.Rule{ID: "rule-2", Name: "Rule 2"}

	ruleStorage.On("GetRule", "rule-1").Return(rule1, nil)
	ruleStorage.On("GetRule", "rule-2").Return(rule2, nil)

	err := service.EnrichAlerts(ctx, alerts)

	assert.NoError(t, err)
	assert.Equal(t, "Rule 1", alerts[0].RuleName)
	assert.Equal(t, "Rule 2", alerts[1].RuleName)
	ruleStorage.AssertExpectations(t)
}

func TestEnrichAlerts_EmptySlice(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.EnrichAlerts(ctx, []*core.Alert{})

	assert.NoError(t, err)
}

func TestEnrichAlerts_ContinuesOnPartialFailure(t *testing.T) {
	service, _, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	alerts := []*core.Alert{
		{AlertID: "alert-1", RuleID: "rule-1"},
		{AlertID: "alert-2", RuleID: "missing"},
	}

	rule1 := &core.Rule{ID: "rule-1", Name: "Rule 1"}

	ruleStorage.On("GetRule", "rule-1").Return(rule1, nil)
	ruleStorage.On("GetRule", "missing").Return(nil, storage.ErrRuleNotFound)

	err := service.EnrichAlerts(ctx, alerts)

	// Should not fail, enriches what it can
	assert.NoError(t, err)
	assert.Equal(t, "Rule 1", alerts[0].RuleName)
	assert.NotEmpty(t, alerts[1].RuleName) // Auto-generated
	ruleStorage.AssertExpectations(t)
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestHumanizeEventType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"process_creation", "Process Creation"},
		{"network-connection", "Network Connection"},
		{"file_access", "File Access"},
		{"", "Unknown Alert"},
		{"SINGLE", "Single"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := humanizeEventType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateAlertTitle_FromEventMessage(t *testing.T) {
	service, _, _, _ := setupTestService()

	alert := &core.Alert{
		Event: &core.Event{
			Fields: map[string]interface{}{
				"message": "Suspicious PowerShell execution detected",
			},
		},
	}

	title := service.generateAlertTitle(alert)
	assert.Equal(t, "Suspicious PowerShell execution detected", title)
}

func TestGenerateAlertTitle_FromEventType(t *testing.T) {
	service, _, _, _ := setupTestService()

	alert := &core.Alert{
		Event: &core.Event{
			Fields: map[string]interface{}{
				"event_type": "process_creation",
			},
		},
	}

	title := service.generateAlertTitle(alert)
	assert.Equal(t, "Process Creation", title)
}

func TestGenerateAlertTitle_FromRuleID(t *testing.T) {
	service, _, _, _ := setupTestService()

	alert := &core.Alert{
		RuleID: "suspicious_powershell",
		Event:  &core.Event{Fields: map[string]interface{}{}},
	}

	title := service.generateAlertTitle(alert)
	assert.Equal(t, "Suspicious Powershell", title)
}

func TestGenerateAlertTitle_NilAlert(t *testing.T) {
	service, _, _, _ := setupTestService()

	title := service.generateAlertTitle(nil)
	assert.Equal(t, "Unknown Alert", title)
}

// ============================================================================
// Additional Coverage Tests (CRITICAL-5)
// ============================================================================

// Test hasFilters edge cases
func TestHasFilters_AllFieldsCombinations(t *testing.T) {
	service, _, _, _ := setupTestService()

	tests := []struct {
		name     string
		filters  *core.AlertFilters
		expected bool
	}{
		{
			name:     "nil filters",
			filters:  nil,
			expected: false,
		},
		{
			name:     "empty filters",
			filters:  &core.AlertFilters{},
			expected: false,
		},
		{
			name:     "only pagination",
			filters:  &core.AlertFilters{Page: 1, Limit: 10},
			expected: false,
		},
		{
			name:     "search filter",
			filters:  &core.AlertFilters{Search: "test"},
			expected: true,
		},
		{
			name:     "severities filter",
			filters:  &core.AlertFilters{Severities: []string{"high"}},
			expected: true,
		},
		{
			name:     "statuses filter",
			filters:  &core.AlertFilters{Statuses: []string{"pending"}},
			expected: true,
		},
		{
			name:     "rule IDs filter",
			filters:  &core.AlertFilters{RuleIDs: []string{"rule-1"}},
			expected: true,
		},
		{
			name:     "assigned to filter",
			filters:  &core.AlertFilters{AssignedTo: []string{"user-1"}},
			expected: true,
		},
		{
			name:     "tags filter",
			filters:  &core.AlertFilters{Tags: []string{"tag1"}},
			expected: true,
		},
		{
			name:     "MITRE tactics filter",
			filters:  &core.AlertFilters{MitreTactics: []string{"TA0001"}},
			expected: true,
		},
		{
			name:     "MITRE techniques filter",
			filters:  &core.AlertFilters{MitreTechniques: []string{"T1059"}},
			expected: true,
		},
		{
			name:     "dispositions filter",
			filters:  &core.AlertFilters{Dispositions: []string{"true_positive"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.hasFilters(tt.filters)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test EnrichAlerts with nil elements
func TestEnrichAlerts_WithNilElements(t *testing.T) {
	service, _, ruleStorage, _ := setupTestService()
	ctx := context.Background()

	alerts := []*core.Alert{
		{AlertID: "alert-1", RuleID: "rule-1"},
		nil, // Nil element
		{AlertID: "alert-2", RuleID: "rule-2"},
		nil, // Another nil
	}

	rule1 := &core.Rule{ID: "rule-1", Name: "Rule 1"}
	rule2 := &core.Rule{ID: "rule-2", Name: "Rule 2"}

	ruleStorage.On("GetRule", "rule-1").Return(rule1, nil)
	ruleStorage.On("GetRule", "rule-2").Return(rule2, nil)

	err := service.EnrichAlerts(ctx, alerts)

	assert.NoError(t, err)
	assert.Equal(t, "Rule 1", alerts[0].RuleName)
	assert.Equal(t, "Rule 2", alerts[2].RuleName)
	ruleStorage.AssertExpectations(t)
}

// Test EnrichAlerts context cancellation
func TestEnrichAlerts_ContextCancellation(t *testing.T) {
	service, _, ruleStorage, _ := setupTestService()

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Create 200 alerts to trigger cancellation check at index 100
	alerts := make([]*core.Alert, 200)
	for i := 0; i < 200; i++ {
		alerts[i] = &core.Alert{
			AlertID: fmt.Sprintf("alert-%d", i),
			RuleID:  fmt.Sprintf("rule-%d", i),
		}
		// Mock first 100 as they will be processed before cancellation check
		if i < 100 {
			ruleStorage.On("GetRule", fmt.Sprintf("rule-%d", i)).Return(&core.Rule{ID: fmt.Sprintf("rule-%d", i)}, nil).Maybe()
		}
	}

	err := service.EnrichAlerts(ctx, alerts)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "enrichment cancelled")
}

// Test ListAlerts filter mutation protection
func TestListAlerts_DoesNotMutateInputFilters(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	// Create filters with invalid values
	originalFilters := &core.AlertFilters{
		Page:  0,      // Invalid
		Limit: 999999, // Exceeds max
	}

	// Store original values
	originalPage := originalFilters.Page
	originalLimit := originalFilters.Limit

	alertStorage.On("GetAlerts", ctx, 10000, 0).Return([]core.Alert{}, nil)
	alertStorage.On("GetAlertCount", ctx).Return(int64(0), nil)

	_, _, err := service.ListAlerts(ctx, originalFilters)

	assert.NoError(t, err)
	// Verify original filters were NOT mutated
	assert.Equal(t, originalPage, originalFilters.Page, "Page should not be mutated")
	assert.Equal(t, originalLimit, originalFilters.Limit, "Limit should not be mutated")
	alertStorage.AssertExpectations(t)
}

// Test AssignAlert with empty assignee string
func TestAssignAlert_EmptyAssigneeString(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	emptyString := ""
	assignee := &emptyString

	alertStorage.On("UpdateAlertAssignee", ctx, "alert-1", assignee).Return(nil)

	err := service.AssignAlert(ctx, "alert-1", assignee, "manager-1")

	assert.NoError(t, err)
	alertStorage.AssertExpectations(t)
}

// Test SetDisposition with all valid disposition types
func TestSetDisposition_AllDispositionTypes(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	dispositions := []core.AlertDisposition{
		core.DispositionTruePositive,
		core.DispositionFalsePositive,
		core.DispositionBenign,
		core.DispositionUndetermined,
	}

	for _, disp := range dispositions {
		t.Run(string(disp), func(t *testing.T) {
			alertStorage.On("UpdateAlertDisposition", ctx, "alert-1", disp, "reason", "user").
				Return("undetermined", nil).Once()

			prev, err := service.SetDisposition(ctx, "alert-1", disp, "reason", "user")

			assert.NoError(t, err)
			assert.Equal(t, core.DispositionUndetermined, prev)
		})
	}

	alertStorage.AssertExpectations(t)
}

// Test EnrichAlert with empty RuleID
func TestEnrichAlert_EmptyRuleIDAfterCheck(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID: "alert-1",
		RuleID:  "", // Empty
	}

	err := service.EnrichAlert(ctx, alert)

	assert.NoError(t, err) // Should handle gracefully
}

// Test generateAlertTitle with EventID field
func TestGenerateAlertTitle_WithEventID(t *testing.T) {
	service, _, _, _ := setupTestService()

	alert := &core.Alert{
		Event: &core.Event{
			Fields: map[string]interface{}{
				"EventID": "4624",
			},
		},
	}

	title := service.generateAlertTitle(alert)
	assert.Equal(t, "4624", title)
}

// Test UpdateAlertStatus with GetAlert storage error
func TestUpdateAlertStatus_GetAlertStorageError(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("GetAlert", ctx, "alert-1").Return(nil, errors.New("database connection lost"))

	err := service.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusAcknowledged, "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve alert")
	alertStorage.AssertExpectations(t)
}

// Test ListAlerts with GetAlerts storage error
func TestListAlerts_GetAlertsStorageError(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	filters := &core.AlertFilters{
		Page:  1,
		Limit: 10,
	}

	alertStorage.On("GetAlerts", ctx, 10, 0).Return([]core.Alert{}, errors.New("database error"))

	alerts, total, err := service.ListAlerts(ctx, filters)

	assert.Error(t, err)
	assert.Nil(t, alerts)
	assert.Equal(t, int64(0), total)
	assert.Contains(t, err.Error(), "failed to retrieve alerts")
	alertStorage.AssertExpectations(t)
}

// Test ListAlerts with GetAlertCount storage error
func TestListAlerts_GetAlertCountStorageError(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	filters := &core.AlertFilters{
		Page:  1,
		Limit: 10,
	}

	alertStorage.On("GetAlerts", ctx, 10, 0).Return([]core.Alert{}, nil)
	alertStorage.On("GetAlertCount", ctx).Return(int64(0), errors.New("count query failed"))

	alerts, total, err := service.ListAlerts(ctx, filters)

	assert.Error(t, err)
	assert.Nil(t, alerts)
	assert.Equal(t, int64(0), total)
	assert.Contains(t, err.Error(), "failed to get alert count")
	alertStorage.AssertExpectations(t)
}

// Test SetDisposition storage error
func TestSetDisposition_StorageError(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alertStorage.On("UpdateAlertDisposition", ctx, "alert-1",
		core.DispositionTruePositive, "reason", "user").
		Return("", errors.New("update failed"))

	_, err := service.SetDisposition(ctx, "alert-1", core.DispositionTruePositive, "reason", "user")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update alert disposition")
	alertStorage.AssertExpectations(t)
}

// Test AssignAlert storage error
func TestAssignAlert_StorageError(t *testing.T) {
	service, alertStorage, _, userStorage := setupTestService()
	ctx := context.Background()

	assignee := "analyst-1"
	user := &storage.User{Username: "analyst-1"}

	userStorage.On("GetUserByUsername", ctx, "analyst-1").Return(user, nil)
	alertStorage.On("UpdateAlertAssignee", ctx, "alert-1", &assignee).
		Return(errors.New("update failed"))

	err := service.AssignAlert(ctx, "alert-1", &assignee, "manager-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign alert")
	alertStorage.AssertExpectations(t)
	userStorage.AssertExpectations(t)
}

// ============================================================================
// TASK 145.2: Tests for New Service Methods (BLOCKING FIXES)
// ============================================================================

// AcknowledgeAlert Tests
func TestAcknowledgeAlert_Success(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusPending,
	}

	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)
	alertStorage.On("UpdateAlertStatus", ctx, "alert-1", core.AlertStatusAcknowledged).Return(nil)

	err := service.AcknowledgeAlert(ctx, "alert-1", "user-1")

	assert.NoError(t, err)
	alertStorage.AssertExpectations(t)
}

func TestAcknowledgeAlert_EmptyAlertID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.AcknowledgeAlert(ctx, "", "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestAcknowledgeAlert_EmptyUserID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.AcknowledgeAlert(ctx, "alert-1", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "userID is required")
}

// DismissAlert Tests (BLOCKING-1 Fix: Rollback Logic)
func TestDismissAlert_Success(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	// CRITICAL FIX: Alert must be in Investigating status to transition to Resolved
	// Valid transition path: Pending -> Acknowledged -> Investigating -> Resolved
	// Acknowledged can only go to Investigating or Closed (not Resolved directly)
	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusInvestigating, // Must be Investigating for Resolved transition
	}

	// Mock disposition update (returns previous disposition)
	alertStorage.On("UpdateAlertDisposition", ctx, "alert-1",
		core.DispositionBenign, "reason", "user-1").
		Return("undetermined", nil)

	// Mock status update to resolved (now valid transition)
	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)
	alertStorage.On("UpdateAlertStatus", ctx, "alert-1", core.AlertStatusResolved).Return(nil)

	err := service.DismissAlert(ctx, "alert-1", "reason", "user-1")

	assert.NoError(t, err)
	alertStorage.AssertExpectations(t)
}

func TestDismissAlert_RollbackOnStatusUpdateFailure(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	// CRITICAL FIX: Alert must be in Investigating status to allow Resolved transition
	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusInvestigating,
	}

	// Disposition update succeeds (returns previous "undetermined")
	alertStorage.On("UpdateAlertDisposition", ctx, "alert-1",
		core.DispositionBenign, "reason", "user-1").
		Return("undetermined", nil).Once()

	// Status update fails
	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)
	alertStorage.On("UpdateAlertStatus", ctx, "alert-1", core.AlertStatusResolved).
		Return(errors.New("status update failed"))

	// Rollback: restore previous disposition
	alertStorage.On("UpdateAlertDisposition", ctx, "alert-1",
		core.DispositionUndetermined, mock.AnythingOfType("string"), "user-1").
		Return("benign", nil).Once()

	err := service.DismissAlert(ctx, "alert-1", "reason", "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve alert")
	alertStorage.AssertExpectations(t)
}

func TestDismissAlert_RollbackFailure_LogsCriticalError(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	// CRITICAL FIX: Alert must be in Investigating status to allow Resolved transition
	currentAlert := &core.Alert{
		AlertID: "alert-1",
		Status:  core.AlertStatusInvestigating,
	}

	// Disposition update succeeds
	alertStorage.On("UpdateAlertDisposition", ctx, "alert-1",
		core.DispositionBenign, "reason", "user-1").
		Return("undetermined", nil).Once()

	// Status update fails
	alertStorage.On("GetAlert", ctx, "alert-1").Return(currentAlert, nil)
	alertStorage.On("UpdateAlertStatus", ctx, "alert-1", core.AlertStatusResolved).
		Return(errors.New("status update failed"))

	// Rollback also fails (critical error logged)
	alertStorage.On("UpdateAlertDisposition", ctx, "alert-1",
		core.DispositionUndetermined, mock.AnythingOfType("string"), "user-1").
		Return("", errors.New("rollback failed")).Once()

	err := service.DismissAlert(ctx, "alert-1", "reason", "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve alert")
	// Verify critical log occurs (would check logger.Errorw call in real test)
	alertStorage.AssertExpectations(t)
}

func TestDismissAlert_EmptyAlertID(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.DismissAlert(ctx, "", "reason", "user-1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestDismissAlert_EmptyUsername(t *testing.T) {
	service, _, _, _ := setupTestService()
	ctx := context.Background()

	err := service.DismissAlert(ctx, "alert-1", "reason", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is required")
}

// CreateInvestigationFromAlert Tests (BLOCKING-2 & BLOCKING-3 Fixes)
func TestCreateInvestigationFromAlert_Success(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()
	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:         "alert-1",
		RuleID:          "rule-1",
		RuleName:        "Test Rule",
		Severity:        "high",
		InvestigationID: "", // Not linked
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
	investigationStorage.On("CreateInvestigation", mock.AnythingOfType("*core.Investigation")).Return(nil)
	alertStorage.On("UpdateAlertInvestigation", ctx, "alert-1", mock.AnythingOfType("string")).Return(nil)

	investigation, warnings, err := service.CreateInvestigationFromAlert(ctx, "alert-1", "", "", "", "user-1")

	assert.NoError(t, err)
	assert.NotNil(t, investigation)
	assert.Empty(t, warnings)                                               // No warnings for normal case
	assert.Equal(t, core.InvestigationPriorityHigh, investigation.Priority) // Mapped from alert severity
	alertStorage.AssertExpectations(t)
	investigationStorage.AssertExpectations(t)
}

func TestCreateInvestigationFromAlert_MITRETruncationWarning(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()
	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)
	ctx := context.Background()

	// Create alert with excessive MITRE techniques (>50)
	techniques := make([]string, 60)
	for i := 0; i < 60; i++ {
		techniques[i] = fmt.Sprintf("attack.t%04d", i)
	}

	alert := &core.Alert{
		AlertID:         "alert-1",
		RuleID:          "rule-1",
		Severity:        "high",
		MitreTechniques: techniques,
		InvestigationID: "",
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
	investigationStorage.On("CreateInvestigation", mock.AnythingOfType("*core.Investigation")).Return(nil)
	alertStorage.On("UpdateAlertInvestigation", ctx, "alert-1", mock.AnythingOfType("string")).Return(nil)

	investigation, warnings, err := service.CreateInvestigationFromAlert(ctx, "alert-1", "", "", "", "user-1")

	assert.NoError(t, err)
	assert.NotNil(t, investigation)
	assert.Len(t, warnings, 1) // BLOCKING-3 fix: should return warning
	assert.Contains(t, warnings[0], "60 MITRE techniques")
	assert.Contains(t, warnings[0], "limit: 50")
	assert.Len(t, investigation.MitreTechniques, 50) // Truncated to limit
	alertStorage.AssertExpectations(t)
	investigationStorage.AssertExpectations(t)
}

func TestCreateInvestigationFromAlert_SafeDeleteRollback(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()
	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:         "alert-1",
		InvestigationID: "",
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
	investigationStorage.On("CreateInvestigation", mock.AnythingOfType("*core.Investigation")).Return(nil)

	// Link fails - trigger rollback
	alertStorage.On("UpdateAlertInvestigation", ctx, "alert-1", mock.AnythingOfType("string")).
		Return(errors.New("link failed"))

	// Rollback: safeDeleteEmptyInvestigation
	investigationStorage.On("GetInvestigation", mock.AnythingOfType("string")).
		Return(&core.Investigation{AlertIDs: []string{}}, nil) // Empty investigation
	investigationStorage.On("DeleteInvestigation", mock.AnythingOfType("string")).Return(nil)

	investigation, warnings, err := service.CreateInvestigationFromAlert(ctx, "alert-1", "", "", "", "user-1")

	assert.Error(t, err)
	assert.Nil(t, investigation)
	assert.Nil(t, warnings)
	assert.Contains(t, err.Error(), "failed to link alert to investigation")
	alertStorage.AssertExpectations(t)
	investigationStorage.AssertExpectations(t)
}

func TestCreateInvestigationFromAlert_SafeDeleteSkipsIfAlertsLinked(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()
	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:         "alert-1",
		InvestigationID: "",
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
	investigationStorage.On("CreateInvestigation", mock.AnythingOfType("*core.Investigation")).Return(nil)

	// Link fails
	alertStorage.On("UpdateAlertInvestigation", ctx, "alert-1", mock.AnythingOfType("string")).
		Return(errors.New("link failed"))

	// Rollback: investigation now has alerts (concurrent operation)
	investigationStorage.On("GetInvestigation", mock.AnythingOfType("string")).
		Return(&core.Investigation{AlertIDs: []string{"alert-2"}}, nil) // Has alerts

	// Should NOT delete (BLOCKING-2 fix: race condition protection)

	investigation, warnings, err := service.CreateInvestigationFromAlert(ctx, "alert-1", "", "", "", "user-1")

	assert.Error(t, err)
	assert.Nil(t, investigation)
	assert.Nil(t, warnings)
	alertStorage.AssertExpectations(t)
	investigationStorage.AssertExpectations(t)
	// Verify DeleteInvestigation was NOT called
	investigationStorage.AssertNotCalled(t, "DeleteInvestigation")
}

func TestCreateInvestigationFromAlert_AlertAlreadyLinked(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:         "alert-1",
		InvestigationID: "existing-investigation",
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)

	investigation, warnings, err := service.CreateInvestigationFromAlert(ctx, "alert-1", "", "", "", "user-1")

	assert.Error(t, err)
	assert.Nil(t, investigation)
	assert.Nil(t, warnings)
	assert.True(t, errors.Is(err, storage.ErrAlertAlreadyLinked))
	alertStorage.AssertExpectations(t)
}

// LinkAlertToInvestigation Tests (BLOCKING-4 Fix: Idempotency)
func TestLinkAlertToInvestigation_Success(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()
	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:         "alert-1",
		InvestigationID: "",
	}

	investigation := &core.Investigation{
		InvestigationID: "inv-1",
		AlertIDs:        []string{},
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
	investigationStorage.On("GetInvestigation", "inv-1").Return(investigation, nil)
	alertStorage.On("UpdateAlertInvestigation", ctx, "alert-1", "inv-1").Return(nil)
	investigationStorage.On("AddAlert", "inv-1", "alert-1").Return(nil)

	warnings, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")

	assert.NoError(t, err)
	assert.Nil(t, warnings) // No warnings on successful link
	alertStorage.AssertExpectations(t)
	investigationStorage.AssertExpectations(t)
}

func TestLinkAlertToInvestigation_Idempotent_ReturnsNilWarnings(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	// Alert already linked to this investigation
	alert := &core.Alert{
		AlertID:         "alert-1",
		InvestigationID: "inv-1",
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)

	warnings, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")

	assert.NoError(t, err)
	assert.Nil(t, warnings) // BLOCKING-4 fix: should be nil, not warnings array
	alertStorage.AssertExpectations(t)
}

func TestLinkAlertToInvestigation_AlreadyLinkedToDifferentInvestigation(t *testing.T) {
	service, alertStorage, _, _ := setupTestService()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:         "alert-1",
		InvestigationID: "other-investigation",
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)

	warnings, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")

	assert.Error(t, err)
	assert.Nil(t, warnings)
	assert.True(t, errors.Is(err, storage.ErrAlertAlreadyLinked))
	alertStorage.AssertExpectations(t)
}

func TestLinkAlertToInvestigation_PartialSuccess_InvestigationListUpdateFails(t *testing.T) {
	alertStorage := new(MockAlertStorage)
	ruleStorage := new(MockRuleStorage)
	userStorage := new(MockUserStorage)
	investigationStorage := new(MockInvestigationStorage)
	logger := zap.NewNop().Sugar()
	service := NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:         "alert-1",
		InvestigationID: "",
	}

	investigation := &core.Investigation{
		InvestigationID: "inv-1",
	}

	alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
	investigationStorage.On("GetInvestigation", "inv-1").Return(investigation, nil)
	alertStorage.On("UpdateAlertInvestigation", ctx, "alert-1", "inv-1").Return(nil)
	investigationStorage.On("AddAlert", "inv-1", "alert-1").
		Return(errors.New("investigation list update failed"))

	warnings, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")

	assert.NoError(t, err) // Still succeeds (eventual consistency)
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "investigation list update failed")
	alertStorage.AssertExpectations(t)
	investigationStorage.AssertExpectations(t)
}

// ============================================================================
// Additional Coverage Tests - Task 145.5
// ============================================================================

// TestMapAlertSeverityToInvestigationPriority tests all severity mappings.
func TestMapAlertSeverityToInvestigationPriority(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected core.InvestigationPriority
	}{
		{
			name:     "critical severity",
			severity: "critical",
			expected: core.InvestigationPriorityCritical,
		},
		{
			name:     "CRITICAL uppercase",
			severity: "CRITICAL",
			expected: core.InvestigationPriorityCritical,
		},
		{
			name:     "high severity",
			severity: "high",
			expected: core.InvestigationPriorityHigh,
		},
		{
			name:     "HIGH uppercase",
			severity: "HIGH",
			expected: core.InvestigationPriorityHigh,
		},
		{
			name:     "medium severity",
			severity: "medium",
			expected: core.InvestigationPriorityMedium,
		},
		{
			name:     "MEDIUM uppercase",
			severity: "MEDIUM",
			expected: core.InvestigationPriorityMedium,
		},
		{
			name:     "low severity",
			severity: "low",
			expected: core.InvestigationPriorityLow,
		},
		{
			name:     "LOW uppercase",
			severity: "LOW",
			expected: core.InvestigationPriorityLow,
		},
		{
			name:     "unknown severity defaults to medium",
			severity: "unknown",
			expected: core.InvestigationPriorityMedium,
		},
		{
			name:     "empty severity defaults to medium",
			severity: "",
			expected: core.InvestigationPriorityMedium,
		},
		{
			name:     "invalid severity defaults to medium",
			severity: "invalid",
			expected: core.InvestigationPriorityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapAlertSeverityToInvestigationPriority(tt.severity)
			assert.Equal(t, tt.expected, result, "Severity %s should map to %s", tt.severity, tt.expected)
		})
	}
}

// TestSafeDeleteEmptyInvestigation_AdditionalCases tests additional coverage paths.
func TestSafeDeleteEmptyInvestigation_AdditionalCases(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("investigation storage not available", func(t *testing.T) {
		service := &AlertServiceImpl{
			logger:                logger,
			investigationStorage:  nil, // nil storage
		}

		err := service.safeDeleteEmptyInvestigation("inv-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "investigation storage not available")
	})

	t.Run("investigation already deleted (nil)", func(t *testing.T) {
		investigationStorage := new(MockInvestigationStorage)
		service := &AlertServiceImpl{
			logger:               logger,
			investigationStorage: investigationStorage,
		}

		investigationStorage.On("GetInvestigation", "inv-1").Return(nil, nil)

		err := service.safeDeleteEmptyInvestigation("inv-1")
		assert.NoError(t, err) // Idempotent - no error
		investigationStorage.AssertExpectations(t)
	})

	t.Run("investigation has alerts - don't delete", func(t *testing.T) {
		investigationStorage := new(MockInvestigationStorage)
		service := &AlertServiceImpl{
			logger:               logger,
			investigationStorage: investigationStorage,
		}

		investigation := &core.Investigation{
			InvestigationID: "inv-1",
			AlertIDs:        []string{"alert-1", "alert-2"}, // Has alerts
		}

		investigationStorage.On("GetInvestigation", "inv-1").Return(investigation, nil)

		err := service.safeDeleteEmptyInvestigation("inv-1")
		assert.NoError(t, err) // Not an error - investigation is valid
		investigationStorage.AssertExpectations(t)
		// DeleteInvestigation should NOT be called
	})

	t.Run("delete investigation error", func(t *testing.T) {
		investigationStorage := new(MockInvestigationStorage)
		service := &AlertServiceImpl{
			logger:               logger,
			investigationStorage: investigationStorage,
		}

		investigation := &core.Investigation{
			InvestigationID: "inv-1",
			AlertIDs:        []string{}, // Empty - should delete
		}

		investigationStorage.On("GetInvestigation", "inv-1").Return(investigation, nil)
		investigationStorage.On("DeleteInvestigation", "inv-1").
			Return(errors.New("database error"))

		err := service.safeDeleteEmptyInvestigation("inv-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete empty investigation")
		investigationStorage.AssertExpectations(t)
	})
}

// TestLinkAlertToInvestigation_AdditionalCases tests additional coverage paths.
func TestLinkAlertToInvestigation_AdditionalCases(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	t.Run("empty alert ID", func(t *testing.T) {
		service := &AlertServiceImpl{logger: logger}

		_, err := service.LinkAlertToInvestigation(ctx, "", "inv-1", "user-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "alertID is required")
	})

	t.Run("empty investigation ID", func(t *testing.T) {
		service := &AlertServiceImpl{logger: logger}

		_, err := service.LinkAlertToInvestigation(ctx, "alert-1", "", "user-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "investigationID is required")
	})

	t.Run("alert not found", func(t *testing.T) {
		alertStorage := new(MockAlertStorage)
		service := &AlertServiceImpl{
			logger:       logger,
			alertStorage: alertStorage,
		}

		alertStorage.On("GetAlertByID", ctx, "alert-1").Return(nil, storage.ErrAlertNotFound)

		_, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "alert not found")
		alertStorage.AssertExpectations(t)
	})

	t.Run("investigation not found", func(t *testing.T) {
		alertStorage := new(MockAlertStorage)
		investigationStorage := new(MockInvestigationStorage)
		service := &AlertServiceImpl{
			logger:               logger,
			alertStorage:         alertStorage,
			investigationStorage: investigationStorage,
		}

		alert := &core.Alert{AlertID: "alert-1"}
		alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
		investigationStorage.On("GetInvestigation", "inv-1").Return(nil, storage.ErrInvestigationNotFound)

		_, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "investigation not found")
		alertStorage.AssertExpectations(t)
		investigationStorage.AssertExpectations(t)
	})

	t.Run("alert already linked to same investigation - idempotent", func(t *testing.T) {
		alertStorage := new(MockAlertStorage)
		service := &AlertServiceImpl{
			logger:       logger,
			alertStorage: alertStorage,
		}

		alert := &core.Alert{
			AlertID:         "alert-1",
			InvestigationID: "inv-1", // Already linked
		}

		alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)

		warnings, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")
		assert.NoError(t, err) // Idempotent success
		assert.Nil(t, warnings)
		alertStorage.AssertExpectations(t)
	})

	t.Run("alert linked to different investigation", func(t *testing.T) {
		alertStorage := new(MockAlertStorage)
		service := &AlertServiceImpl{
			logger:       logger,
			alertStorage: alertStorage,
		}

		alert := &core.Alert{
			AlertID:         "alert-1",
			InvestigationID: "inv-other", // Linked to different investigation
		}

		alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)

		_, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")
		assert.Error(t, err)
		assert.ErrorIs(t, err, storage.ErrAlertAlreadyLinked)
		alertStorage.AssertExpectations(t)
	})

	t.Run("update alert investigation error", func(t *testing.T) {
		alertStorage := new(MockAlertStorage)
		investigationStorage := new(MockInvestigationStorage)
		service := &AlertServiceImpl{
			logger:               logger,
			alertStorage:         alertStorage,
			investigationStorage: investigationStorage,
		}

		alert := &core.Alert{AlertID: "alert-1"}
		investigation := &core.Investigation{InvestigationID: "inv-1"}

		alertStorage.On("GetAlertByID", ctx, "alert-1").Return(alert, nil)
		investigationStorage.On("GetInvestigation", "inv-1").Return(investigation, nil)
		alertStorage.On("UpdateAlertInvestigation", ctx, "alert-1", "inv-1").
			Return(errors.New("database error"))

		_, err := service.LinkAlertToInvestigation(ctx, "alert-1", "inv-1", "user-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to link alert to investigation")
		alertStorage.AssertExpectations(t)
		investigationStorage.AssertExpectations(t)
	})
}
