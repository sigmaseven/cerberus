package api

import (
	"context"

	"cerberus/core"
	"cerberus/storage"
)

// ============================================================================
// Storage Adapters for Service Layer Integration
// ============================================================================
//
// These adapters bridge API storage interfaces to service layer interfaces.
// They exist in the API package to avoid circular imports.
//
// See service/storage_adapters.go for the reverse direction.
// ============================================================================

// alertStorageAdapter adapts API's AlertStorer interface to service's AlertStorage interface.
type alertStorageAdapter struct {
	underlying AlertStorer
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
	// InsertAlert is not part of the AlertStorer interface in api package.
	// This would only be needed if we were creating alerts through the API.
	// For now, return not implemented error.
	return storage.ErrNotImplemented
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

// ruleStorageAdapter adapts API's RuleStorer interface to service's RuleStorage interface.
type ruleStorageAdapter struct {
	underlying RuleStorer
}

func (a *ruleStorageAdapter) GetRule(id string) (*core.Rule, error) {
	return a.underlying.GetRule(id)
}

// userStorageAdapter adapts API's UserStorage to service's UserStorage.
type userStorageAdapter struct {
	underlying storage.UserStorage
}

func (a *userStorageAdapter) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	if a.underlying == nil {
		return nil, storage.ErrUserNotFound
	}
	return a.underlying.GetUserByUsername(ctx, username)
}

// investigationStorageAdapter adapts API's InvestigationStorer to service's InvestigationStorage.
type investigationStorageAdapter struct {
	underlying InvestigationStorer
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
