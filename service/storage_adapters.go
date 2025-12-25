package service

import (
	"context"

	"cerberus/core"
	"cerberus/storage"
)

// ============================================================================
// Storage Adapters - Bridge API storage interfaces to service interfaces
// ============================================================================
//
// DESIGN RATIONALE:
// The API package has its own storage interface definitions (AlertStorer, etc.)
// while the service package defines minimal, focused interfaces (AlertStorage).
//
// These adapters bridge the two worlds, allowing the service layer to work
// with the actual storage implementations used by the API.
//
// This is a temporary solution. In a future refactoring (Task 146+), we should:
// 1. Standardize on one set of storage interfaces
// 2. Move interfaces to core or storage package
// 3. Remove these adapters
//
// For now, this approach allows us to introduce the service layer incrementally
// without rewriting the entire codebase.

// ============================================================================
// Alert Storage Adapter
// ============================================================================

// alertStorageAdapter adapts API's AlertStorer interface to service's AlertStorage interface.
type alertStorageAdapter struct {
	underlying interface {
		GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error)
		GetAlerts(ctx context.Context, limit, offset int) ([]core.Alert, error)
		GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error)
		GetAlertCount(ctx context.Context) (int64, error)
		GetAlert(ctx context.Context, alertID string) (*core.Alert, error)
		InsertAlert(ctx context.Context, alert *core.Alert) error
		UpdateAlertStatus(ctx context.Context, alertID string, status core.AlertStatus) error
		UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, username string) (string, error)
		UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error
		UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error
		AssignAlert(ctx context.Context, alertID, assignTo string) error
		DeleteAlert(ctx context.Context, alertID string) error
	}
}

func (a *alertStorageAdapter) GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error) {
	return a.underlying.GetAlertByID(ctx, alertID)
}

func (a *alertStorageAdapter) GetAlerts(ctx context.Context, limit, offset int) ([]core.Alert, error) {
	return a.underlying.GetAlerts(ctx, limit, offset)
}

func (a *alertStorageAdapter) GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error) {
	return a.underlying.GetAlertsWithFilters(ctx, filters)
}

func (a *alertStorageAdapter) GetAlertCount(ctx context.Context) (int64, error) {
	return a.underlying.GetAlertCount(ctx)
}

func (a *alertStorageAdapter) GetAlert(ctx context.Context, alertID string) (*core.Alert, error) {
	return a.underlying.GetAlert(ctx, alertID)
}

func (a *alertStorageAdapter) InsertAlert(ctx context.Context, alert *core.Alert) error {
	return a.underlying.InsertAlert(ctx, alert)
}

func (a *alertStorageAdapter) UpdateAlertStatus(ctx context.Context, alertID string, status core.AlertStatus) error {
	return a.underlying.UpdateAlertStatus(ctx, alertID, status)
}

func (a *alertStorageAdapter) UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, username string) (string, error) {
	return a.underlying.UpdateAlertDisposition(ctx, alertID, disposition, reason, username)
}

func (a *alertStorageAdapter) UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error {
	return a.underlying.UpdateAlertAssignee(ctx, alertID, assigneeID)
}

func (a *alertStorageAdapter) UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error {
	return a.underlying.UpdateAlertInvestigation(ctx, alertID, investigationID)
}

func (a *alertStorageAdapter) AssignAlert(ctx context.Context, alertID, assignTo string) error {
	return a.underlying.AssignAlert(ctx, alertID, assignTo)
}

func (a *alertStorageAdapter) DeleteAlert(ctx context.Context, alertID string) error {
	return a.underlying.DeleteAlert(ctx, alertID)
}

// ============================================================================
// Rule Storage Adapter
// ============================================================================

// ruleStorageAdapter adapts API's RuleStorer interface to service's RuleStorage interface.
type ruleStorageAdapter struct {
	underlying interface {
		GetRule(id string) (*core.Rule, error)
	}
}

func (a *ruleStorageAdapter) GetRule(id string) (*core.Rule, error) {
	return a.underlying.GetRule(id)
}

// ============================================================================
// User Storage Adapter
// ============================================================================

// userStorageAdapter adapts API's UserStorage interface to service's UserStorage interface.
type userStorageAdapter struct {
	underlying storage.UserStorage
}

func (a *userStorageAdapter) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	if a.underlying == nil {
		return nil, storage.ErrUserNotFound
	}
	return a.underlying.GetUserByUsername(ctx, username)
}

// ============================================================================
// Investigation Storage Adapter
// ============================================================================

// investigationStorageAdapter adapts API's InvestigationStorer to service's InvestigationStorage.
type investigationStorageAdapter struct {
	underlying interface {
		GetInvestigation(id string) (*core.Investigation, error)
		AddAlert(investigationID, alertID string) error
	}
}

func (a *investigationStorageAdapter) GetInvestigation(id string) (*core.Investigation, error) {
	if a.underlying == nil {
		return nil, storage.ErrInvestigationNotFound
	}
	return a.underlying.GetInvestigation(id)
}

func (a *investigationStorageAdapter) AddAlert(investigationID, alertID string) error {
	if a.underlying == nil {
		return storage.ErrInvestigationNotFound
	}
	return a.underlying.AddAlert(investigationID, alertID)
}
