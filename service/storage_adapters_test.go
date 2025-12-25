package service

import (
	"context"
	"errors"
	"testing"

	"cerberus/core"
	"cerberus/storage"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Storage Adapter Tests - For Complete Coverage
// ============================================================================
//
// These tests verify that storage adapters properly delegate to underlying
// storage implementations. They're simple passthrough tests to achieve 90%+
// coverage requirement.

// Mock storage implementations for adapter testing
type mockUnderlyingAlertStorage struct {
	GetAlertByIDFunc             func(ctx context.Context, alertID string) (*core.Alert, error)
	GetAlertsFunc                func(ctx context.Context, limit, offset int) ([]core.Alert, error)
	GetAlertsWithFiltersFunc     func(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error)
	GetAlertCountFunc            func(ctx context.Context) (int64, error)
	GetAlertFunc                 func(ctx context.Context, alertID string) (*core.Alert, error)
	InsertAlertFunc              func(ctx context.Context, alert *core.Alert) error
	UpdateAlertStatusFunc        func(ctx context.Context, alertID string, status core.AlertStatus) error
	UpdateAlertDispositionFunc   func(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, username string) (string, error)
	UpdateAlertAssigneeFunc      func(ctx context.Context, alertID string, assigneeID *string) error
	UpdateAlertInvestigationFunc func(ctx context.Context, alertID, investigationID string) error
	AssignAlertFunc              func(ctx context.Context, alertID, assignTo string) error
	DeleteAlertFunc              func(ctx context.Context, alertID string) error
}

func (m *mockUnderlyingAlertStorage) GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error) {
	return m.GetAlertByIDFunc(ctx, alertID)
}

func (m *mockUnderlyingAlertStorage) GetAlerts(ctx context.Context, limit, offset int) ([]core.Alert, error) {
	return m.GetAlertsFunc(ctx, limit, offset)
}

func (m *mockUnderlyingAlertStorage) GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error) {
	return m.GetAlertsWithFiltersFunc(ctx, filters)
}

func (m *mockUnderlyingAlertStorage) GetAlertCount(ctx context.Context) (int64, error) {
	return m.GetAlertCountFunc(ctx)
}

func (m *mockUnderlyingAlertStorage) GetAlert(ctx context.Context, alertID string) (*core.Alert, error) {
	return m.GetAlertFunc(ctx, alertID)
}

func (m *mockUnderlyingAlertStorage) InsertAlert(ctx context.Context, alert *core.Alert) error {
	return m.InsertAlertFunc(ctx, alert)
}

func (m *mockUnderlyingAlertStorage) UpdateAlertStatus(ctx context.Context, alertID string, status core.AlertStatus) error {
	return m.UpdateAlertStatusFunc(ctx, alertID, status)
}

func (m *mockUnderlyingAlertStorage) UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, username string) (string, error) {
	return m.UpdateAlertDispositionFunc(ctx, alertID, disposition, reason, username)
}

func (m *mockUnderlyingAlertStorage) UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error {
	return m.UpdateAlertAssigneeFunc(ctx, alertID, assigneeID)
}

func (m *mockUnderlyingAlertStorage) UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error {
	return m.UpdateAlertInvestigationFunc(ctx, alertID, investigationID)
}

func (m *mockUnderlyingAlertStorage) AssignAlert(ctx context.Context, alertID, assignTo string) error {
	return m.AssignAlertFunc(ctx, alertID, assignTo)
}

func (m *mockUnderlyingAlertStorage) DeleteAlert(ctx context.Context, alertID string) error {
	return m.DeleteAlertFunc(ctx, alertID)
}

type mockUnderlyingRuleStorage struct {
	GetRuleFunc func(id string) (*core.Rule, error)
}

func (m *mockUnderlyingRuleStorage) GetRule(id string) (*core.Rule, error) {
	return m.GetRuleFunc(id)
}

type mockUnderlyingInvestigationStorage struct {
	GetInvestigationFunc func(id string) (*core.Investigation, error)
	AddAlertFunc         func(investigationID, alertID string) error
}

func (m *mockUnderlyingInvestigationStorage) GetInvestigation(id string) (*core.Investigation, error) {
	if m.GetInvestigationFunc != nil {
		return m.GetInvestigationFunc(id)
	}
	return nil, nil
}

func (m *mockUnderlyingInvestigationStorage) AddAlert(investigationID, alertID string) error {
	if m.AddAlertFunc != nil {
		return m.AddAlertFunc(investigationID, alertID)
	}
	return nil
}

// ============================================================================
// Alert Storage Adapter Tests
// ============================================================================

func TestAlertStorageAdapter_AllMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("GetAlertByID", func(t *testing.T) {
		expectedAlert := &core.Alert{AlertID: "alert-1"}
		underlying := &mockUnderlyingAlertStorage{
			GetAlertByIDFunc: func(ctx context.Context, alertID string) (*core.Alert, error) {
				assert.Equal(t, "alert-1", alertID)
				return expectedAlert, nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		result, err := adapter.GetAlertByID(ctx, "alert-1")

		assert.NoError(t, err)
		assert.Equal(t, expectedAlert, result)
	})

	t.Run("GetAlerts", func(t *testing.T) {
		expectedAlerts := []core.Alert{{AlertID: "alert-1"}}
		underlying := &mockUnderlyingAlertStorage{
			GetAlertsFunc: func(ctx context.Context, limit, offset int) ([]core.Alert, error) {
				assert.Equal(t, 10, limit)
				assert.Equal(t, 0, offset)
				return expectedAlerts, nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		result, err := adapter.GetAlerts(ctx, 10, 0)

		assert.NoError(t, err)
		assert.Equal(t, expectedAlerts, result)
	})

	t.Run("GetAlertsWithFilters", func(t *testing.T) {
		expectedAlerts := []*core.Alert{{AlertID: "alert-1"}}
		filters := &core.AlertFilters{Page: 1, Limit: 10}
		underlying := &mockUnderlyingAlertStorage{
			GetAlertsWithFiltersFunc: func(ctx context.Context, f *core.AlertFilters) ([]*core.Alert, int64, error) {
				assert.Equal(t, filters, f)
				return expectedAlerts, int64(1), nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		result, total, err := adapter.GetAlertsWithFilters(ctx, filters)

		assert.NoError(t, err)
		assert.Equal(t, expectedAlerts, result)
		assert.Equal(t, int64(1), total)
	})

	t.Run("GetAlertCount", func(t *testing.T) {
		underlying := &mockUnderlyingAlertStorage{
			GetAlertCountFunc: func(ctx context.Context) (int64, error) {
				return int64(42), nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		result, err := adapter.GetAlertCount(ctx)

		assert.NoError(t, err)
		assert.Equal(t, int64(42), result)
	})

	t.Run("GetAlert", func(t *testing.T) {
		expectedAlert := &core.Alert{AlertID: "alert-1"}
		underlying := &mockUnderlyingAlertStorage{
			GetAlertFunc: func(ctx context.Context, alertID string) (*core.Alert, error) {
				assert.Equal(t, "alert-1", alertID)
				return expectedAlert, nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		result, err := adapter.GetAlert(ctx, "alert-1")

		assert.NoError(t, err)
		assert.Equal(t, expectedAlert, result)
	})

	t.Run("InsertAlert", func(t *testing.T) {
		alert := &core.Alert{AlertID: "alert-1"}
		underlying := &mockUnderlyingAlertStorage{
			InsertAlertFunc: func(ctx context.Context, a *core.Alert) error {
				assert.Equal(t, alert, a)
				return nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		err := adapter.InsertAlert(ctx, alert)

		assert.NoError(t, err)
	})

	t.Run("UpdateAlertStatus", func(t *testing.T) {
		underlying := &mockUnderlyingAlertStorage{
			UpdateAlertStatusFunc: func(ctx context.Context, alertID string, status core.AlertStatus) error {
				assert.Equal(t, "alert-1", alertID)
				assert.Equal(t, core.AlertStatusAcknowledged, status)
				return nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		err := adapter.UpdateAlertStatus(ctx, "alert-1", core.AlertStatusAcknowledged)

		assert.NoError(t, err)
	})

	t.Run("UpdateAlertDisposition", func(t *testing.T) {
		underlying := &mockUnderlyingAlertStorage{
			UpdateAlertDispositionFunc: func(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, username string) (string, error) {
				assert.Equal(t, "alert-1", alertID)
				assert.Equal(t, core.DispositionTruePositive, disposition)
				assert.Equal(t, "test reason", reason)
				assert.Equal(t, "user1", username)
				return "undetermined", nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		result, err := adapter.UpdateAlertDisposition(ctx, "alert-1", core.DispositionTruePositive, "test reason", "user1")

		assert.NoError(t, err)
		assert.Equal(t, "undetermined", result)
	})

	t.Run("UpdateAlertAssignee", func(t *testing.T) {
		assignee := "user1"
		underlying := &mockUnderlyingAlertStorage{
			UpdateAlertAssigneeFunc: func(ctx context.Context, alertID string, assigneeID *string) error {
				assert.Equal(t, "alert-1", alertID)
				assert.Equal(t, &assignee, assigneeID)
				return nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		err := adapter.UpdateAlertAssignee(ctx, "alert-1", &assignee)

		assert.NoError(t, err)
	})

	t.Run("UpdateAlertInvestigation", func(t *testing.T) {
		underlying := &mockUnderlyingAlertStorage{
			UpdateAlertInvestigationFunc: func(ctx context.Context, alertID, investigationID string) error {
				assert.Equal(t, "alert-1", alertID)
				assert.Equal(t, "inv-1", investigationID)
				return nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		err := adapter.UpdateAlertInvestigation(ctx, "alert-1", "inv-1")

		assert.NoError(t, err)
	})

	t.Run("AssignAlert", func(t *testing.T) {
		underlying := &mockUnderlyingAlertStorage{
			AssignAlertFunc: func(ctx context.Context, alertID, assignTo string) error {
				assert.Equal(t, "alert-1", alertID)
				assert.Equal(t, "user1", assignTo)
				return nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		err := adapter.AssignAlert(ctx, "alert-1", "user1")

		assert.NoError(t, err)
	})

	t.Run("DeleteAlert", func(t *testing.T) {
		underlying := &mockUnderlyingAlertStorage{
			DeleteAlertFunc: func(ctx context.Context, alertID string) error {
				assert.Equal(t, "alert-1", alertID)
				return nil
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		err := adapter.DeleteAlert(ctx, "alert-1")

		assert.NoError(t, err)
	})
}

// ============================================================================
// Rule Storage Adapter Tests
// ============================================================================

func TestRuleStorageAdapter_GetRule(t *testing.T) {
	expectedRule := &core.Rule{ID: "rule-1"}
	underlying := &mockUnderlyingRuleStorage{
		GetRuleFunc: func(id string) (*core.Rule, error) {
			assert.Equal(t, "rule-1", id)
			return expectedRule, nil
		},
	}
	adapter := &ruleStorageAdapter{underlying: underlying}

	result, err := adapter.GetRule("rule-1")

	assert.NoError(t, err)
	assert.Equal(t, expectedRule, result)
}

// ============================================================================
// User Storage Adapter Tests
// ============================================================================

type simpleUserStorage struct {
	users map[string]*storage.User
}

func (s *simpleUserStorage) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	if s.users == nil {
		return nil, storage.ErrUserNotFound
	}
	user, ok := s.users[username]
	if !ok {
		return nil, storage.ErrUserNotFound
	}
	return user, nil
}

// Stub implementations for full storage.UserStorage interface
func (s *simpleUserStorage) CreateUser(ctx context.Context, user *storage.User) error {
	return errors.New("not implemented")
}

func (s *simpleUserStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	return errors.New("not implemented")
}

func (s *simpleUserStorage) DeleteUser(ctx context.Context, username string) error {
	return errors.New("not implemented")
}

func (s *simpleUserStorage) ListUsers(ctx context.Context) ([]*storage.User, error) {
	return nil, errors.New("not implemented")
}

func (s *simpleUserStorage) ValidateCredentials(ctx context.Context, username string, password string) (*storage.User, error) {
	return nil, errors.New("not implemented")
}

func (s *simpleUserStorage) UpdateUserRole(ctx context.Context, username string, roleID int64) error {
	return errors.New("not implemented")
}

func (s *simpleUserStorage) GetUserWithRole(ctx context.Context, username string) (*storage.User, *storage.Role, error) {
	return nil, nil, errors.New("not implemented")
}

func (s *simpleUserStorage) GetUserByID(ctx context.Context, userID string) (*storage.User, error) {
	return nil, errors.New("not implemented")
}

func (s *simpleUserStorage) UpdateLastLogin(ctx context.Context, username string) error {
	return errors.New("not implemented")
}

func (s *simpleUserStorage) GetUserPermissions(ctx context.Context, username string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func TestUserStorageAdapter_GetUserByUsername(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		expectedUser := &storage.User{Username: "user1"}
		underlying := &simpleUserStorage{
			users: map[string]*storage.User{
				"user1": expectedUser,
			},
		}

		adapter := &userStorageAdapter{underlying: underlying}

		result, err := adapter.GetUserByUsername(ctx, "user1")

		assert.NoError(t, err)
		assert.Equal(t, expectedUser, result)
	})

	t.Run("nil underlying storage", func(t *testing.T) {
		ctx := context.Background()
		adapter := &userStorageAdapter{underlying: nil}

		result, err := adapter.GetUserByUsername(ctx, "user1")

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, storage.ErrUserNotFound, err)
	})
}

// ============================================================================
// Investigation Storage Adapter Tests
// ============================================================================

func TestInvestigationStorageAdapter_GetInvestigation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedInv := &core.Investigation{InvestigationID: "inv-1"}
		underlying := &mockUnderlyingInvestigationStorage{
			GetInvestigationFunc: func(id string) (*core.Investigation, error) {
				assert.Equal(t, "inv-1", id)
				return expectedInv, nil
			},
		}
		adapter := &investigationStorageAdapter{underlying: underlying}

		result, err := adapter.GetInvestigation("inv-1")

		assert.NoError(t, err)
		assert.Equal(t, expectedInv, result)
	})

	t.Run("nil underlying storage", func(t *testing.T) {
		adapter := &investigationStorageAdapter{underlying: nil}

		result, err := adapter.GetInvestigation("inv-1")

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, storage.ErrInvestigationNotFound, err)
	})
}

func TestInvestigationStorageAdapter_AddAlert(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		underlying := &mockUnderlyingInvestigationStorage{
			AddAlertFunc: func(investigationID, alertID string) error {
				assert.Equal(t, "inv-1", investigationID)
				assert.Equal(t, "alert-1", alertID)
				return nil
			},
		}
		adapter := &investigationStorageAdapter{underlying: underlying}

		err := adapter.AddAlert("inv-1", "alert-1")

		assert.NoError(t, err)
	})

	t.Run("nil underlying storage", func(t *testing.T) {
		adapter := &investigationStorageAdapter{underlying: nil}

		err := adapter.AddAlert("inv-1", "alert-1")

		assert.Error(t, err)
		assert.Equal(t, storage.ErrInvestigationNotFound, err)
	})
}

// ============================================================================
// Error Propagation Tests
// ============================================================================

func TestStorageAdapters_ErrorPropagation(t *testing.T) {
	ctx := context.Background()
	testError := errors.New("storage error")

	t.Run("alertStorage GetAlertByID error", func(t *testing.T) {
		underlying := &mockUnderlyingAlertStorage{
			GetAlertByIDFunc: func(ctx context.Context, alertID string) (*core.Alert, error) {
				return nil, testError
			},
		}
		adapter := &alertStorageAdapter{underlying: underlying}

		_, err := adapter.GetAlertByID(ctx, "alert-1")

		assert.Error(t, err)
		assert.Equal(t, testError, err)
	})

	t.Run("ruleStorage GetRule error", func(t *testing.T) {
		underlying := &mockUnderlyingRuleStorage{
			GetRuleFunc: func(id string) (*core.Rule, error) {
				return nil, testError
			},
		}
		adapter := &ruleStorageAdapter{underlying: underlying}

		_, err := adapter.GetRule("rule-1")

		assert.Error(t, err)
		assert.Equal(t, testError, err)
	})
}
