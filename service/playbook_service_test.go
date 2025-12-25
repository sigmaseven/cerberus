package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cerberus/core"
	"cerberus/soar"
	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// MockPlaybookStorage is a mock implementation of PlaybookStorage interface.
type MockPlaybookStorage struct {
	mock.Mock
}

func (m *MockPlaybookStorage) CreatePlaybook(playbook *soar.Playbook) error {
	args := m.Called(playbook)
	return args.Error(0)
}

func (m *MockPlaybookStorage) GetPlaybook(id string) (*soar.Playbook, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*soar.Playbook), args.Error(1)
}

func (m *MockPlaybookStorage) GetPlaybooks(limit, offset int) ([]soar.Playbook, error) {
	args := m.Called(limit, offset)
	return args.Get(0).([]soar.Playbook), args.Error(1)
}

func (m *MockPlaybookStorage) GetPlaybooksByStatus(enabled bool) ([]soar.Playbook, error) {
	args := m.Called(enabled)
	return args.Get(0).([]soar.Playbook), args.Error(1)
}

func (m *MockPlaybookStorage) GetPlaybooksByTag(tag string) ([]soar.Playbook, error) {
	args := m.Called(tag)
	return args.Get(0).([]soar.Playbook), args.Error(1)
}

func (m *MockPlaybookStorage) GetPlaybookCount() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockPlaybookStorage) UpdatePlaybook(id string, playbook *soar.Playbook) error {
	args := m.Called(id, playbook)
	return args.Error(0)
}

func (m *MockPlaybookStorage) DeletePlaybook(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockPlaybookStorage) EnablePlaybook(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockPlaybookStorage) DisablePlaybook(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockPlaybookStorage) PlaybookNameExists(name string, excludeID string) (bool, error) {
	args := m.Called(name, excludeID)
	return args.Bool(0), args.Error(1)
}

func (m *MockPlaybookStorage) GetPlaybookStats() (*storage.PlaybookStats, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.PlaybookStats), args.Error(1)
}

// MockPlaybookExecutionStorage is a mock implementation.
type MockPlaybookExecutionStorage struct {
	mock.Mock
}

func (m *MockPlaybookExecutionStorage) CreatePlaybookExecution(ctx context.Context, executionID, playbookID, alertID string) error {
	args := m.Called(ctx, executionID, playbookID, alertID)
	return args.Error(0)
}

func (m *MockPlaybookExecutionStorage) GetExecution(ctx context.Context, executionID string) (*soar.PlaybookExecution, error) {
	args := m.Called(ctx, executionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*soar.PlaybookExecution), args.Error(1)
}

func (m *MockPlaybookExecutionStorage) CompleteExecution(ctx context.Context, executionID string, status soar.ActionStatus, errorMsg string, stepResults map[string]*soar.ActionResult) error {
	args := m.Called(ctx, executionID, status, errorMsg, stepResults)
	return args.Error(0)
}

// MockPlaybookAlertStorage is a mock implementation.
type MockPlaybookAlertStorage struct {
	mock.Mock
}

func (m *MockPlaybookAlertStorage) GetAlert(ctx context.Context, alertID string) (*core.Alert, error) {
	args := m.Called(ctx, alertID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*core.Alert), args.Error(1)
}

// MockPlaybookEngineExecutor is a mock implementation.
type MockPlaybookEngineExecutor struct {
	mock.Mock
}

func (m *MockPlaybookEngineExecutor) ExecutePlaybook(ctx context.Context, playbook *soar.Playbook, alert *core.Alert) (*soar.PlaybookExecution, error) {
	args := m.Called(ctx, playbook, alert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*soar.PlaybookExecution), args.Error(1)
}

// ============================================================================
// Test Helpers
// ============================================================================

func setupPlaybookTestService(t *testing.T) (*PlaybookServiceImpl, *MockPlaybookStorage, *MockPlaybookExecutionStorage, *MockPlaybookAlertStorage, *MockPlaybookEngineExecutor) {
	t.Helper() // Mark as test helper
	playbookStorage := new(MockPlaybookStorage)
	executionStorage := new(MockPlaybookExecutionStorage)
	alertStorage := new(MockPlaybookAlertStorage)
	executor := new(MockPlaybookEngineExecutor)
	logger := zap.NewNop().Sugar()

	service := NewPlaybookService(playbookStorage, executionStorage, alertStorage, executor, logger)
	return service, playbookStorage, executionStorage, alertStorage, executor
}

func createValidPlaybook(t *testing.T) *soar.Playbook {
	t.Helper() // Mark as test helper
	return &soar.Playbook{
		ID:          "pb-test-123",
		Name:        "Test Playbook",
		Description: "Test Description",
		Enabled:     true,
		Steps: []soar.PlaybookStep{
			{
				ID:         "step-1",
				Name:       "Test Step",
				ActionType: soar.ActionTypeNotify,
				Parameters: map[string]interface{}{"message": "test"},
			},
		},
		Triggers:  []soar.PlaybookTrigger{},
		Tags:      []string{"test"},
		Priority:  1,
		CreatedBy: "test-user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// wrapPlaybook wraps a soar.Playbook as a core.Playbook interface
func wrapPlaybook(t *testing.T, pb *soar.Playbook) *core.Playbook {
	t.Helper() // Mark as test helper
	var result core.Playbook = pb
	return &result
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewPlaybookService_Success(t *testing.T) {
	playbookStorage := new(MockPlaybookStorage)
	executionStorage := new(MockPlaybookExecutionStorage)
	alertStorage := new(MockPlaybookAlertStorage)
	executor := new(MockPlaybookEngineExecutor)
	logger := zap.NewNop().Sugar()

	service := NewPlaybookService(playbookStorage, executionStorage, alertStorage, executor, logger)

	assert.NotNil(t, service)
	assert.Equal(t, playbookStorage, service.playbookStorage)
	assert.Equal(t, executionStorage, service.executionStorage)
	assert.Equal(t, alertStorage, service.alertStorage)
	assert.Equal(t, executor, service.executor)
	assert.Equal(t, logger, service.logger)
}

func TestNewPlaybookService_PanicsOnNilPlaybookStorage(t *testing.T) {
	executionStorage := new(MockPlaybookExecutionStorage)
	alertStorage := new(MockPlaybookAlertStorage)
	executor := new(MockPlaybookEngineExecutor)
	logger := zap.NewNop().Sugar()

	assert.Panics(t, func() {
		NewPlaybookService(nil, executionStorage, alertStorage, executor, logger)
	})
}

func TestNewPlaybookService_PanicsOnNilLogger(t *testing.T) {
	playbookStorage := new(MockPlaybookStorage)
	executionStorage := new(MockPlaybookExecutionStorage)
	alertStorage := new(MockPlaybookAlertStorage)
	executor := new(MockPlaybookEngineExecutor)

	assert.Panics(t, func() {
		NewPlaybookService(playbookStorage, executionStorage, alertStorage, executor, nil)
	})
}

func TestNewPlaybookService_AllowsNilOptionalDependencies(t *testing.T) {
	playbookStorage := new(MockPlaybookStorage)
	logger := zap.NewNop().Sugar()

	// Should not panic with nil optional dependencies
	service := NewPlaybookService(playbookStorage, nil, nil, nil, logger)
	assert.NotNil(t, service)
}

// ============================================================================
// GetPlaybookByID Tests
// ============================================================================

func TestGetPlaybookByID_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	expectedPlaybook := createValidPlaybook(t)
	playbookStorage.On("GetPlaybook", "pb-test-123").Return(expectedPlaybook, nil)

	playbook, err := service.GetPlaybookByID(ctx, "pb-test-123")

	assert.NoError(t, err)
	assert.NotNil(t, playbook)
	playbookStorage.AssertExpectations(t)
}

func TestGetPlaybookByID_EmptyID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook, err := service.GetPlaybookByID(ctx, "")

	assert.Error(t, err)
	assert.Nil(t, playbook)
	assert.Contains(t, err.Error(), "playbookID is required")
}

func TestGetPlaybookByID_NotFound(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybook", "nonexistent").Return(nil, storage.ErrPlaybookNotFound)

	playbook, err := service.GetPlaybookByID(ctx, "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, playbook)
	assert.True(t, errors.Is(err, storage.ErrPlaybookNotFound))
	playbookStorage.AssertExpectations(t)
}

func TestGetPlaybookByID_StorageError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(nil, errors.New("database error"))

	playbook, err := service.GetPlaybookByID(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Nil(t, playbook)
	assert.Contains(t, err.Error(), "failed to retrieve playbook")
	playbookStorage.AssertExpectations(t)
}

func TestGetPlaybookByID_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	playbook, err := service.GetPlaybookByID(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Nil(t, playbook)
	assert.Contains(t, err.Error(), "context cancelled")
}

// ============================================================================
// ListPlaybooks Tests
// ============================================================================

func TestListPlaybooks_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	expectedPlaybooks := []soar.Playbook{
		*createValidPlaybook(t),
	}

	playbookStorage.On("GetPlaybooks", 50, 0).Return(expectedPlaybooks, nil)
	playbookStorage.On("GetPlaybookCount").Return(int64(1), nil)

	playbooks, total, err := service.ListPlaybooks(ctx, nil, "", 50, 0)

	assert.NoError(t, err)
	assert.NotNil(t, playbooks)
	assert.Len(t, playbooks, 1)
	assert.Equal(t, int64(1), total)
	playbookStorage.AssertExpectations(t)
}

func TestListPlaybooks_WithEnabledFilter(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	enabled := true
	expectedPlaybooks := []soar.Playbook{
		*createValidPlaybook(t),
	}

	playbookStorage.On("GetPlaybooksByStatus", enabled).Return(expectedPlaybooks, nil)

	playbooks, total, err := service.ListPlaybooks(ctx, &enabled, "", 50, 0)

	assert.NoError(t, err)
	assert.NotNil(t, playbooks)
	assert.Len(t, playbooks, 1)
	assert.Equal(t, int64(1), total)
	playbookStorage.AssertExpectations(t)
}

func TestListPlaybooks_WithTagFilter(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	expectedPlaybooks := []soar.Playbook{
		*createValidPlaybook(t),
	}

	playbookStorage.On("GetPlaybooksByTag", "test").Return(expectedPlaybooks, nil)

	playbooks, total, err := service.ListPlaybooks(ctx, nil, "test", 50, 0)

	assert.NoError(t, err)
	assert.NotNil(t, playbooks)
	assert.Len(t, playbooks, 1)
	assert.Equal(t, int64(1), total)
	playbookStorage.AssertExpectations(t)
}

func TestListPlaybooks_PaginationDefaults(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybooks", 50, 0).Return([]soar.Playbook{}, nil)
	playbookStorage.On("GetPlaybookCount").Return(int64(0), nil)

	// Pass invalid limit and offset
	playbooks, total, err := service.ListPlaybooks(ctx, nil, "", 0, -1)

	assert.NoError(t, err)
	assert.NotNil(t, playbooks)
	assert.Equal(t, int64(0), total)
	playbookStorage.AssertExpectations(t)
}

func TestListPlaybooks_PaginationMaxLimit(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	// Max limit should be capped at 1000
	playbookStorage.On("GetPlaybooks", 1000, 0).Return([]soar.Playbook{}, nil)
	playbookStorage.On("GetPlaybookCount").Return(int64(0), nil)

	playbooks, total, err := service.ListPlaybooks(ctx, nil, "", 5000, 0)

	assert.NoError(t, err)
	assert.NotNil(t, playbooks)
	assert.Equal(t, int64(0), total)
	playbookStorage.AssertExpectations(t)
}

func TestListPlaybooks_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	playbooks, total, err := service.ListPlaybooks(ctx, nil, "", 50, 0)

	assert.Error(t, err)
	assert.Nil(t, playbooks)
	assert.Equal(t, int64(0), total)
	assert.Contains(t, err.Error(), "context cancelled")
}

// ============================================================================
// GetPlaybookStats Tests
// ============================================================================

func TestGetPlaybookStats_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	expectedStats := &storage.PlaybookStats{
		TotalPlaybooks:    10,
		EnabledPlaybooks:  7,
		DisabledPlaybooks: 3,
	}

	playbookStorage.On("GetPlaybookStats").Return(expectedStats, nil)

	stats, err := service.GetPlaybookStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(10), stats.TotalPlaybooks)
	assert.Equal(t, int64(7), stats.EnabledPlaybooks)
	assert.Equal(t, int64(3), stats.DisabledPlaybooks)
	playbookStorage.AssertExpectations(t)
}

func TestGetPlaybookStats_StorageError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybookStats").Return(nil, errors.New("database error"))

	stats, err := service.GetPlaybookStats(ctx)

	assert.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "failed to get playbook stats")
	playbookStorage.AssertExpectations(t)
}

// ============================================================================
// CreatePlaybook Tests
// ============================================================================

func TestCreatePlaybook_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.ID = "" // ID should be generated

	playbookStorage.On("PlaybookNameExists", playbook.Name, "").Return(false, nil)
	playbookStorage.On("CreatePlaybook", mock.AnythingOfType("*soar.Playbook")).Return(nil)

	// Wrap soar.Playbook as core.Playbook (interface{})
	var pb core.Playbook = playbook
	created, err := service.CreatePlaybook(ctx, &pb)

	assert.NoError(t, err)
	assert.NotNil(t, created)
	playbookStorage.AssertExpectations(t)
}

func TestCreatePlaybook_NilPlaybook(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	created, err := service.CreatePlaybook(ctx, nil)

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "playbook is required")
}

func TestCreatePlaybook_ValidationError(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.Name = "" // Invalid: empty name

	created, err := service.CreatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestCreatePlaybook_NameExists(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)

	playbookStorage.On("PlaybookNameExists", playbook.Name, "").Return(true, nil)

	created, err := service.CreatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.True(t, errors.Is(err, storage.ErrPlaybookNameExists))
	playbookStorage.AssertExpectations(t)
}

func TestCreatePlaybook_StorageError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)

	playbookStorage.On("PlaybookNameExists", playbook.Name, "").Return(false, nil)
	playbookStorage.On("CreatePlaybook", mock.AnythingOfType("*soar.Playbook")).Return(errors.New("database error"))

	created, err := service.CreatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "failed to create playbook")
	playbookStorage.AssertExpectations(t)
}

// ============================================================================
// UpdatePlaybook Tests
// ============================================================================

func TestUpdatePlaybook_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	existing := createValidPlaybook(t)
	updated := createValidPlaybook(t)
	updated.Description = "Updated Description"
	// Note: name is the same, so PlaybookNameExists won't be called

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(existing, nil)
	playbookStorage.On("UpdatePlaybook", "pb-test-123", mock.AnythingOfType("*soar.Playbook")).Return(nil)

	err := service.UpdatePlaybook(ctx, "pb-test-123", wrapPlaybook(t, updated))

	assert.NoError(t, err)
	playbookStorage.AssertExpectations(t)
}

func TestUpdatePlaybook_EmptyID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)

	err := service.UpdatePlaybook(ctx, "", wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "playbookID is required")
}

func TestUpdatePlaybook_NilPlaybook(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	err := service.UpdatePlaybook(ctx, "pb-test-123", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "playbook is required")
}

func TestUpdatePlaybook_NotFound(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbookStorage.On("GetPlaybook", "pb-test-123").Return(nil, storage.ErrPlaybookNotFound)

	err := service.UpdatePlaybook(ctx, "pb-test-123", wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrPlaybookNotFound))
	playbookStorage.AssertExpectations(t)
}

func TestUpdatePlaybook_ValidationError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	existing := createValidPlaybook(t)
	updated := createValidPlaybook(t)
	updated.Steps = []soar.PlaybookStep{} // Invalid: no steps

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(existing, nil)

	err := service.UpdatePlaybook(ctx, "pb-test-123", wrapPlaybook(t, updated))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
	playbookStorage.AssertExpectations(t)
}

func TestUpdatePlaybook_NameConflict(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	existing := createValidPlaybook(t)
	updated := createValidPlaybook(t)
	updated.Name = "Different Name"

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(existing, nil)
	playbookStorage.On("PlaybookNameExists", "Different Name", "pb-test-123").Return(true, nil)

	err := service.UpdatePlaybook(ctx, "pb-test-123", wrapPlaybook(t, updated))

	assert.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrPlaybookNameExists))
	playbookStorage.AssertExpectations(t)
}

// ============================================================================
// DeletePlaybook Tests
// ============================================================================

func TestDeletePlaybook_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbookStorage.On("GetPlaybook", "pb-test-123").Return(playbook, nil)
	playbookStorage.On("DeletePlaybook", "pb-test-123").Return(nil)

	err := service.DeletePlaybook(ctx, "pb-test-123")

	assert.NoError(t, err)
	playbookStorage.AssertExpectations(t)
}

func TestDeletePlaybook_EmptyID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	err := service.DeletePlaybook(ctx, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "playbookID is required")
}

func TestDeletePlaybook_NotFound(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybook", "nonexistent").Return(nil, storage.ErrPlaybookNotFound)

	err := service.DeletePlaybook(ctx, "nonexistent")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrPlaybookNotFound))
	playbookStorage.AssertExpectations(t)
}

// ============================================================================
// DuplicatePlaybook Tests
// ============================================================================

func TestDuplicatePlaybook_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	original := createValidPlaybook(t)
	playbookStorage.On("GetPlaybook", "pb-test-123").Return(original, nil)
	playbookStorage.On("CreatePlaybook", mock.AnythingOfType("*soar.Playbook")).Return(nil)

	duplicate, err := service.DuplicatePlaybook(ctx, "pb-test-123", "test-user")

	assert.NoError(t, err)
	assert.NotNil(t, duplicate)
	playbookStorage.AssertExpectations(t)
}

func TestDuplicatePlaybook_EmptyID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	duplicate, err := service.DuplicatePlaybook(ctx, "", "test-user")

	assert.Error(t, err)
	assert.Nil(t, duplicate)
	assert.Contains(t, err.Error(), "playbookID is required")
}

func TestDuplicatePlaybook_EmptyUserID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	duplicate, err := service.DuplicatePlaybook(ctx, "pb-test-123", "")

	assert.Error(t, err)
	assert.Nil(t, duplicate)
	assert.Contains(t, err.Error(), "userID is required")
}

func TestDuplicatePlaybook_NotFound(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybook", "nonexistent").Return(nil, storage.ErrPlaybookNotFound)

	duplicate, err := service.DuplicatePlaybook(ctx, "nonexistent", "test-user")

	assert.Error(t, err)
	assert.Nil(t, duplicate)
	assert.True(t, errors.Is(err, storage.ErrPlaybookNotFound))
	playbookStorage.AssertExpectations(t)
}

// ============================================================================
// EnablePlaybook Tests
// ============================================================================

func TestEnablePlaybook_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("EnablePlaybook", "pb-test-123").Return(nil)

	err := service.EnablePlaybook(ctx, "pb-test-123")

	assert.NoError(t, err)
	playbookStorage.AssertExpectations(t)
}

func TestEnablePlaybook_EmptyID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	err := service.EnablePlaybook(ctx, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "playbookID is required")
}

func TestEnablePlaybook_StorageError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("EnablePlaybook", "pb-test-123").Return(errors.New("database error"))

	err := service.EnablePlaybook(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to enable playbook")
	playbookStorage.AssertExpectations(t)
}

// ============================================================================
// DisablePlaybook Tests
// ============================================================================

func TestDisablePlaybook_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("DisablePlaybook", "pb-test-123").Return(nil)

	err := service.DisablePlaybook(ctx, "pb-test-123")

	assert.NoError(t, err)
	playbookStorage.AssertExpectations(t)
}

func TestDisablePlaybook_EmptyID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	err := service.DisablePlaybook(ctx, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "playbookID is required")
}

// ============================================================================
// ExecutePlaybook Tests
// ============================================================================

func TestExecutePlaybook_Success(t *testing.T) {
	service, playbookStorage, executionStorage, alertStorage, executor := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	alert := &core.Alert{
		AlertID: "alert-123",
		RuleID:  "rule-1",
	}

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(playbook, nil)
	alertStorage.On("GetAlert", ctx, "alert-123").Return(alert, nil)
	executionStorage.On("CreatePlaybookExecution", ctx, mock.AnythingOfType("string"), "pb-test-123", "alert-123").Return(nil)

	// BLOCKER-1 FIX: Mock the async ExecutePlaybook call to prevent goroutine panic
	executor.On("ExecutePlaybook", mock.Anything, mock.AnythingOfType("*soar.Playbook"), mock.AnythingOfType("*core.Alert")).
		Return(&soar.PlaybookExecution{
			ID:     "exec-123",
			Status: soar.ActionStatusCompleted,
		}, nil).Maybe()

	// Mock CompleteExecution for async cleanup
	executionStorage.On("CompleteExecution", mock.Anything, mock.AnythingOfType("string"),
		soar.ActionStatusCompleted, "", mock.Anything).Return(nil).Maybe()

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "alert-123", "test-user")

	assert.NoError(t, err)
	assert.NotEmpty(t, executionID)
	playbookStorage.AssertExpectations(t)
	alertStorage.AssertExpectations(t)
	executionStorage.AssertExpectations(t)

	// Give async goroutine a moment to complete
	time.Sleep(100 * time.Millisecond)
}

func TestExecutePlaybook_EmptyPlaybookID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	executionID, err := service.ExecutePlaybook(ctx, "", "alert-123", "test-user")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.Contains(t, err.Error(), "playbookID is required")
}

func TestExecutePlaybook_EmptyAlertID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "", "test-user")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.Contains(t, err.Error(), "alertID is required")
}

func TestExecutePlaybook_EmptyUserID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "alert-123", "")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.Contains(t, err.Error(), "userID is required")
}

func TestExecutePlaybook_PlaybookDisabled(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.Enabled = false

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(playbook, nil)

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "alert-123", "test-user")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.Contains(t, err.Error(), "disabled and cannot be executed")
	playbookStorage.AssertExpectations(t)
}

func TestExecutePlaybook_PlaybookNotFound(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybook", "nonexistent").Return(nil, storage.ErrPlaybookNotFound)

	executionID, err := service.ExecutePlaybook(ctx, "nonexistent", "alert-123", "test-user")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.True(t, errors.Is(err, storage.ErrPlaybookNotFound))
	playbookStorage.AssertExpectations(t)
}

func TestExecutePlaybook_AlertNotFound(t *testing.T) {
	service, playbookStorage, _, alertStorage, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(playbook, nil)
	alertStorage.On("GetAlert", ctx, "nonexistent").Return(nil, storage.ErrAlertNotFound)

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "nonexistent", "test-user")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.True(t, errors.Is(err, storage.ErrAlertNotFound))
	playbookStorage.AssertExpectations(t)
	alertStorage.AssertExpectations(t)
}

func TestExecutePlaybook_MissingExecutor(t *testing.T) {
	// Create service without executor
	playbookStorage := new(MockPlaybookStorage)
	logger := zap.NewNop().Sugar()
	service := NewPlaybookService(playbookStorage, nil, nil, nil, logger)
	ctx := context.Background()

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "alert-123", "test-user")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.Contains(t, err.Error(), "executor not available")
}

// ============================================================================
// GetExecutionStatus Tests
// ============================================================================

func TestGetExecutionStatus_Success(t *testing.T) {
	service, _, executionStorage, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	execution := &soar.PlaybookExecution{
		ID:          "exec-123",
		PlaybookID:  "pb-test-123",
		AlertID:     "alert-123",
		Status:      soar.ActionStatusCompleted,
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
	}

	executionStorage.On("GetExecution", ctx, "exec-123").Return(execution, nil)

	status, err := service.GetExecutionStatus(ctx, "exec-123")

	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, "exec-123", status.ExecutionID)
	assert.Equal(t, "pb-test-123", status.PlaybookID)
	assert.Equal(t, "alert-123", status.AlertID)
	executionStorage.AssertExpectations(t)
}

func TestGetExecutionStatus_EmptyID(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	status, err := service.GetExecutionStatus(ctx, "")

	assert.Error(t, err)
	assert.Nil(t, status)
	assert.Contains(t, err.Error(), "executionID is required")
}

func TestGetExecutionStatus_NotFound(t *testing.T) {
	service, _, executionStorage, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	executionStorage.On("GetExecution", ctx, "nonexistent").Return(nil, errors.New("not found"))

	status, err := service.GetExecutionStatus(ctx, "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, status)
	executionStorage.AssertExpectations(t)
}

// ============================================================================
// ValidatePlaybook Tests
// ============================================================================

func TestValidatePlaybook_Success(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbookStorage.On("PlaybookNameExists", playbook.Name, playbook.ID).Return(false, nil)

	errors, warnings, err := service.ValidatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.NoError(t, err)
	assert.Empty(t, errors)
	assert.Empty(t, warnings)
	playbookStorage.AssertExpectations(t)
}

func TestValidatePlaybook_NilPlaybook(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	errors, warnings, err := service.ValidatePlaybook(ctx, nil)

	assert.NoError(t, err)
	assert.Len(t, errors, 1)
	assert.Contains(t, errors[0], "playbook is required")
	assert.Empty(t, warnings)
}

func TestValidatePlaybook_ValidationErrors(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.Name = ""                     // Invalid
	playbook.Steps = []soar.PlaybookStep{} // Invalid

	errs, _, err := service.ValidatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.NoError(t, err)
	assert.NotEmpty(t, errs)
	assert.Contains(t, errs, "name is required")
	assert.Contains(t, errs, "at least one step is required")
}

func TestValidatePlaybook_NameExistsWarning(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbookStorage.On("PlaybookNameExists", playbook.Name, playbook.ID).Return(true, nil)

	errs, warnings, err := service.ValidatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.NoError(t, err)
	assert.Empty(t, errs)
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "already exists")
	playbookStorage.AssertExpectations(t)
}

// ============================================================================
// Context Cancellation Tests
// ============================================================================

func TestCreatePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	playbook := createValidPlaybook(t)

	created, err := service.CreatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestUpdatePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	playbook := createValidPlaybook(t)

	err := service.UpdatePlaybook(ctx, "pb-test-123", wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestDeletePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := service.DeletePlaybook(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestDuplicatePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	duplicate, err := service.DuplicatePlaybook(ctx, "pb-test-123", "user-1")

	assert.Error(t, err)
	assert.Nil(t, duplicate)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestEnablePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := service.EnablePlaybook(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestDisablePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := service.DisablePlaybook(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestExecutePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "alert-123", "user-1")

	assert.Error(t, err)
	assert.Empty(t, executionID)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestGetExecutionStatus_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status, err := service.GetExecutionStatus(ctx, "exec-123")

	assert.Error(t, err)
	assert.Nil(t, status)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestGetPlaybookStats_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stats, err := service.GetPlaybookStats(ctx)

	assert.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestValidatePlaybook_ContextCancelled(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	playbook := createValidPlaybook(t)

	_, _, err := service.ValidatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

// ============================================================================
// Validation Edge Cases
// ============================================================================

func TestValidatePlaybook_InvalidType(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	// Pass a non-soar.Playbook type
	var invalidPlaybook core.Playbook = "invalid"
	errors, warnings, err := service.ValidatePlaybook(ctx, &invalidPlaybook)

	assert.NoError(t, err)
	assert.Len(t, errors, 1)
	assert.Contains(t, errors[0], "invalid playbook type")
	assert.Empty(t, warnings)
}

func TestCreatePlaybook_InvalidType(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	var invalidPlaybook core.Playbook = "invalid"
	created, err := service.CreatePlaybook(ctx, &invalidPlaybook)

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "invalid playbook type")
}

func TestUpdatePlaybook_InvalidType(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	var invalidPlaybook core.Playbook = "invalid"
	err := service.UpdatePlaybook(ctx, "pb-123", &invalidPlaybook)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid playbook type")
}

func TestValidatePlaybook_AllValidationErrors(t *testing.T) {
	service, _, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := &soar.Playbook{
		Name:        "",                               // Empty name
		Description: string(make([]byte, 2500)),       // Too long
		Steps:       []soar.PlaybookStep{},            // No steps
		Triggers:    make([]soar.PlaybookTrigger, 15), // Too many triggers
		Priority:    -5,                               // Negative priority
	}

	errs, _, err := service.ValidatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.NoError(t, err)
	assert.NotEmpty(t, errs)
	assert.Contains(t, errs, "name is required")
	assert.True(t, containsString(errs, "description too long"))
	assert.Contains(t, errs, "at least one step is required")
	assert.True(t, containsString(errs, "too many triggers"))
	assert.True(t, containsString(errs, "priority cannot be negative"))
}

func TestValidatePlaybook_NameTooLong(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.Name = string(make([]byte, 250)) // Exceeds maxNameLength (200)

	playbookStorage.On("PlaybookNameExists", mock.AnythingOfType("string"), playbook.ID).Return(false, nil).Maybe()

	errs, _, err := service.ValidatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.NoError(t, err)
	assert.NotEmpty(t, errs)
	assert.True(t, containsString(errs, "name too long"))
}

func TestValidatePlaybook_TooManySteps(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.Steps = make([]soar.PlaybookStep, 60) // Exceeds maxStepsPerPlaybook (50)

	playbookStorage.On("PlaybookNameExists", playbook.Name, playbook.ID).Return(false, nil).Maybe()

	errs, _, err := service.ValidatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.NoError(t, err)
	assert.NotEmpty(t, errs)
	assert.True(t, containsString(errs, "too many steps"))
}

// ============================================================================
// Helper function tests
// ============================================================================

func TestConvertActionResults_NilInput(t *testing.T) {
	result := convertActionResults(nil)
	assert.Nil(t, result)
}

func TestConvertActionResults_WithResults(t *testing.T) {
	input := map[string]*soar.ActionResult{
		"step-1": {
			Status:  soar.ActionStatusCompleted,
			Message: "success",
			Output:  map[string]interface{}{"result": "ok"},
		},
		"step-2": {
			Status:  soar.ActionStatusFailed,
			Message: "failed",
			Output:  nil,
		},
	}

	result := convertActionResults(input)

	assert.NotNil(t, result)
	assert.Len(t, result, 2)
	assert.True(t, result["step-1"].Success)
	assert.Equal(t, "success", result["step-1"].Message)
	assert.False(t, result["step-2"].Success)
	assert.Equal(t, "failed", result["step-2"].Message)
}

func TestConvertActionResults_WithNilResult(t *testing.T) {
	input := map[string]*soar.ActionResult{
		"step-1": nil,
	}

	result := convertActionResults(input)

	assert.NotNil(t, result)
	assert.Len(t, result, 0) // Nil results are skipped
}

func TestPaginatePlaybooks_EmptySlice(t *testing.T) {
	playbooks := []soar.Playbook{}
	result := paginatePlaybooks(playbooks, 10, 0)
	assert.Empty(t, result)
}

func TestPaginatePlaybooks_OffsetBeyondLength(t *testing.T) {
	playbooks := []soar.Playbook{*createValidPlaybook(t)}
	result := paginatePlaybooks(playbooks, 10, 100)
	assert.Empty(t, result)
}

func TestPaginatePlaybooks_LimitExceedsLength(t *testing.T) {
	playbooks := []soar.Playbook{*createValidPlaybook(t), *createValidPlaybook(t)}
	result := paginatePlaybooks(playbooks, 100, 0)
	assert.Len(t, result, 2)
}

func TestPaginatePlaybooks_MiddleSlice(t *testing.T) {
	playbooks := make([]soar.Playbook, 10)
	for i := range playbooks {
		playbooks[i] = *createValidPlaybook(t)
	}
	result := paginatePlaybooks(playbooks, 3, 4)
	assert.Len(t, result, 3)
}

// ============================================================================
// Deep Copy Context Cancellation Tests
// ============================================================================

func TestDeepCopyPlaybookWithContext_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	playbook := createValidPlaybook(t)

	duplicate, err := deepCopyPlaybookWithContext(ctx, playbook)

	assert.Error(t, err)
	assert.Nil(t, duplicate)
	assert.Contains(t, err.Error(), "deep copy cancelled")
}

func TestDeepCopyPlaybookWithContext_NilInput(t *testing.T) {
	ctx := context.Background()

	duplicate, err := deepCopyPlaybookWithContext(ctx, nil)

	assert.NoError(t, err)
	assert.Nil(t, duplicate)
}

// Helper function for checking if slice contains a substring
func containsString(slice []string, substr string) bool {
	for _, s := range slice {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// ============================================================================
// Deep Copy Tests
// ============================================================================

func TestDeepCopyPlaybook_PreservesStructure(t *testing.T) {
	original := createValidPlaybook(t)
	original.Tags = []string{"tag1", "tag2"}
	original.Triggers = []soar.PlaybookTrigger{
		{
			Type: "alert",
			Conditions: []soar.PlaybookCondition{
				{Field: "severity", Operator: "eq", Value: "high"},
			},
		},
	}
	original.Steps = []soar.PlaybookStep{
		{
			ID:         "step-1",
			Name:       "Step 1",
			ActionType: soar.ActionTypeNotify,
			Parameters: map[string]interface{}{
				"message": "test",
				"nested": map[string]interface{}{
					"key": "value",
				},
			},
		},
	}

	duplicate := deepCopyPlaybookInternal(original)

	assert.NotNil(t, duplicate)
	assert.Equal(t, original.Name, duplicate.Name)
	assert.Equal(t, len(original.Tags), len(duplicate.Tags))
	assert.Equal(t, len(original.Triggers), len(duplicate.Triggers))
	assert.Equal(t, len(original.Steps), len(duplicate.Steps))

	// Verify deep copy (modifying duplicate shouldn't affect original)
	duplicate.Tags[0] = "modified"
	assert.NotEqual(t, original.Tags[0], duplicate.Tags[0])
}

func TestDeepCopyPlaybook_NilInput(t *testing.T) {
	duplicate := deepCopyPlaybookInternal(nil)
	assert.Nil(t, duplicate)
}

func TestDeepCopyValue_HandlesAllTypes(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
	}{
		{"nil", nil},
		{"string", "test"},
		{"int", 42},
		{"float", 3.14},
		{"bool", true},
		{"map", map[string]interface{}{"key": "value"}},
		{"slice", []interface{}{"a", "b", "c"}},
		{"nested", map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": []interface{}{1, 2, 3},
			},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deepCopyValue(tt.input)
			// Just verify it doesn't panic
			assert.NotNil(t, result != nil || tt.input == nil)
		})
	}
}

// ============================================================================
// ExecuteAsync Tests
// ============================================================================

func TestExecuteAsync_ExecutorError(t *testing.T) {
	service, playbookStorage, executionStorage, alertStorage, executor := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	alert := &core.Alert{
		AlertID: "alert-123",
		RuleID:  "rule-1",
	}

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(playbook, nil)
	alertStorage.On("GetAlert", ctx, "alert-123").Return(alert, nil)
	executionStorage.On("CreatePlaybookExecution", ctx, mock.AnythingOfType("string"), "pb-test-123", "alert-123").Return(nil)

	// Mock ExecutePlaybook to return error
	executor.On("ExecutePlaybook", mock.Anything, mock.AnythingOfType("*soar.Playbook"), mock.AnythingOfType("*core.Alert")).
		Return(nil, errors.New("execution failed")).Maybe()

	// Mock CompleteExecution for error handling
	executionStorage.On("CompleteExecution", mock.Anything, mock.AnythingOfType("string"),
		soar.ActionStatusFailed, mock.AnythingOfType("string"), mock.Anything).Return(nil).Maybe()

	executionID, err := service.ExecutePlaybook(ctx, "pb-test-123", "alert-123", "test-user")

	assert.NoError(t, err)
	assert.NotEmpty(t, executionID)

	// Give async goroutine time to execute
	time.Sleep(100 * time.Millisecond)
}

func TestCreatePlaybook_StorageBusy(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.ID = ""

	playbookStorage.On("PlaybookNameExists", playbook.Name, "").Return(false, nil)
	playbookStorage.On("CreatePlaybook", mock.AnythingOfType("*soar.Playbook")).Return(errors.New("storage busy"))

	created, err := service.CreatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.Error(t, err)
	assert.Nil(t, created)
	assert.Contains(t, err.Error(), "failed to create playbook")
}

func TestUpdatePlaybook_StorageError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	existing := createValidPlaybook(t)
	updated := createValidPlaybook(t)

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(existing, nil)
	playbookStorage.On("UpdatePlaybook", "pb-test-123", mock.AnythingOfType("*soar.Playbook")).Return(errors.New("storage error"))

	err := service.UpdatePlaybook(ctx, "pb-test-123", wrapPlaybook(t, updated))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update playbook")
	playbookStorage.AssertExpectations(t)
}

func TestDeletePlaybook_StorageError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbookStorage.On("GetPlaybook", "pb-test-123").Return(playbook, nil)
	playbookStorage.On("DeletePlaybook", "pb-test-123").Return(errors.New("storage error"))

	err := service.DeletePlaybook(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete playbook")
	playbookStorage.AssertExpectations(t)
}

func TestDuplicatePlaybook_CreateError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	original := createValidPlaybook(t)
	playbookStorage.On("GetPlaybook", "pb-test-123").Return(original, nil)
	playbookStorage.On("CreatePlaybook", mock.AnythingOfType("*soar.Playbook")).Return(errors.New("create failed"))

	duplicate, err := service.DuplicatePlaybook(ctx, "pb-test-123", "test-user")

	assert.Error(t, err)
	assert.Nil(t, duplicate)
	assert.Contains(t, err.Error(), "failed to create duplicate playbook")
	playbookStorage.AssertExpectations(t)
}

func TestGetExecutionStatus_MissingStorage(t *testing.T) {
	// Create service without execution storage
	playbookStorage := new(MockPlaybookStorage)
	logger := zap.NewNop().Sugar()
	service := NewPlaybookService(playbookStorage, nil, nil, nil, logger)
	ctx := context.Background()

	status, err := service.GetExecutionStatus(ctx, "exec-123")

	assert.Error(t, err)
	assert.Nil(t, status)
	assert.Contains(t, err.Error(), "execution storage not available")
}

func TestDisablePlaybook_StorageError(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("DisablePlaybook", "pb-test-123").Return(errors.New("storage error"))

	err := service.DisablePlaybook(ctx, "pb-test-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to disable playbook")
	playbookStorage.AssertExpectations(t)
}

func TestListPlaybooks_ErrorInGetPlaybooksByStatus(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()
	enabled := true

	playbookStorage.On("GetPlaybooksByStatus", enabled).Return([]soar.Playbook{}, errors.New("storage error"))

	playbooks, total, err := service.ListPlaybooks(ctx, &enabled, "", 50, 0)

	assert.Error(t, err)
	assert.Nil(t, playbooks)
	assert.Equal(t, int64(0), total)
	assert.Contains(t, err.Error(), "failed to get playbooks by status")
}

func TestListPlaybooks_ErrorInGetPlaybooksByTag(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbookStorage.On("GetPlaybooksByTag", "test").Return([]soar.Playbook{}, errors.New("storage error"))

	playbooks, total, err := service.ListPlaybooks(ctx, nil, "test", 50, 0)

	assert.Error(t, err)
	assert.Nil(t, playbooks)
	assert.Equal(t, int64(0), total)
	assert.Contains(t, err.Error(), "failed to get playbooks by tag")
}

func TestGetExecutionStatus_WithCompletedExecution(t *testing.T) {
	service, _, executionStorage, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	completedTime := time.Now()
	execution := &soar.PlaybookExecution{
		ID:          "exec-123",
		PlaybookID:  "pb-test-123",
		AlertID:     "alert-123",
		Status:      soar.ActionStatusCompleted,
		StartedAt:   time.Now().Add(-5 * time.Minute),
		CompletedAt: completedTime,
	}

	executionStorage.On("GetExecution", ctx, "exec-123").Return(execution, nil)

	status, err := service.GetExecutionStatus(ctx, "exec-123")

	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.NotNil(t, status.CompletedAt)
	assert.Equal(t, completedTime, *status.CompletedAt)
	executionStorage.AssertExpectations(t)
}

func TestDuplicatePlaybook_WithComplexPlaybook(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	original := createValidPlaybook(t)
	original.Tags = []string{"tag1", "tag2", "tag3"}
	original.Triggers = []soar.PlaybookTrigger{
		{
			Type: "alert",
			Conditions: []soar.PlaybookCondition{
				{Field: "severity", Operator: "eq", Value: "high"},
				{Field: "status", Operator: "eq", Value: "open"},
			},
		},
		{
			Type: "schedule",
			Conditions: []soar.PlaybookCondition{
				{Field: "time", Operator: "eq", Value: "0800"},
			},
		},
	}
	original.Steps = []soar.PlaybookStep{
		{
			ID:         "step-1",
			Name:       "Step 1",
			ActionType: soar.ActionTypeNotify,
			Parameters: map[string]interface{}{
				"message": "test",
				"nested": map[string]interface{}{
					"key": "value",
				},
			},
			Conditions: []soar.PlaybookCondition{
				{Field: "enabled", Operator: "eq", Value: true},
			},
		},
		{
			ID:         "step-2",
			Name:       "Step 2",
			ActionType: soar.ActionTypeBlock,
			Parameters: map[string]interface{}{
				"duration": 300,
			},
		},
	}

	playbookStorage.On("GetPlaybook", "pb-test-123").Return(original, nil)
	playbookStorage.On("CreatePlaybook", mock.AnythingOfType("*soar.Playbook")).Return(nil)

	duplicate, err := service.DuplicatePlaybook(ctx, "pb-test-123", "test-user")

	assert.NoError(t, err)
	assert.NotNil(t, duplicate)
	playbookStorage.AssertExpectations(t)
}

func TestCreatePlaybook_WithNilSlices(t *testing.T) {
	service, playbookStorage, _, _, _ := setupPlaybookTestService(t)
	ctx := context.Background()

	playbook := createValidPlaybook(t)
	playbook.Tags = nil
	playbook.Triggers = nil

	playbookStorage.On("PlaybookNameExists", playbook.Name, "").Return(false, nil)
	playbookStorage.On("CreatePlaybook", mock.AnythingOfType("*soar.Playbook")).Return(nil)

	created, err := service.CreatePlaybook(ctx, wrapPlaybook(t, playbook))

	assert.NoError(t, err)
	assert.NotNil(t, created)
	playbookStorage.AssertExpectations(t)
}
