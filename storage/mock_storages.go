package storage

import (
	"context"

	"cerberus/core"
)

// MockEventStorage implements EventStorer interface for testing
type MockEventStorage struct{}

func NewMockEventStorage() *MockEventStorage {
	return &MockEventStorage{}
}

func (m *MockEventStorage) GetEvents(limit int, offset int) ([]core.Event, error) {
	return []core.Event{}, nil
}

func (m *MockEventStorage) GetEventCount() (int64, error) {
	return 0, nil
}

func (m *MockEventStorage) GetEventCountsByMonth() ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

// MockAlertStorage implements AlertStorer interface for testing
type MockAlertStorage struct{}

func NewMockAlertStorage() *MockAlertStorage {
	return &MockAlertStorage{}
}

func (m *MockAlertStorage) GetAlerts(limit int, offset int) ([]core.Alert, error) {
	return []core.Alert{}, nil
}

func (m *MockAlertStorage) GetAlertCount() (int64, error) {
	return 0, nil
}

func (m *MockAlertStorage) GetAlertCountsByMonth() ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

func (m *MockAlertStorage) AcknowledgeAlert(id string) error {
	return nil
}

func (m *MockAlertStorage) DismissAlert(id string) error {
	return nil
}

func (m *MockAlertStorage) UpdateAlertStatus(id string, status core.AlertStatus) error {
	return nil
}

func (m *MockAlertStorage) AssignAlert(id string, assignTo string) error {
	return nil
}

func (m *MockAlertStorage) DeleteAlert(id string) error {
	return nil
}

func (m *MockAlertStorage) GetAlert(id string) (*core.Alert, error) {
	return nil, nil
}

func (m *MockAlertStorage) LinkAlertToInvestigation(alertID string, investigationID string) error {
	return nil
}

func (m *MockAlertStorage) GetAlertsFiltered(limit, offset int, severity, status string) ([]*core.Alert, error) {
	return []*core.Alert{}, nil
}

// TASK 104: Implement UpdateAlertDisposition for interface compliance
// TASK 111: Returns previous disposition for audit logging
// TASK 111 FIX: Accepts context for request cancellation support (BLOCKING-5)
func (m *MockAlertStorage) UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, userID string) (string, error) {
	return string(core.DispositionUndetermined), nil
}

// TASK 105: Implement UpdateAlertAssignee for interface compliance
func (m *MockAlertStorage) UpdateAlertAssignee(alertID string, assigneeID *string) error {
	return nil
}

// TASK 105: Implement GetAlertByID for interface compliance
func (m *MockAlertStorage) GetAlertByID(alertID string) (*core.Alert, error) {
	return &core.Alert{AlertID: alertID, AssignedTo: ""}, nil
}

// TASK 106: Implement UpdateAlertInvestigation for interface compliance
func (m *MockAlertStorage) UpdateAlertInvestigation(alertID, investigationID string) error {
	return nil
}

// TASK 110: Implement GetAlertsWithFilters for interface compliance
func (m *MockAlertStorage) GetAlertsWithFilters(filters *core.AlertFilters) ([]*core.Alert, int64, error) {
	return []*core.Alert{}, 0, nil
}

// MockRuleStorage implements RuleStorer interface for testing
type MockRuleStorage struct{}

func NewMockRuleStorage() *MockRuleStorage {
	return &MockRuleStorage{}
}

func (m *MockRuleStorage) GetRules(limit int, offset int) ([]core.Rule, error) {
	return []core.Rule{}, nil
}

func (m *MockRuleStorage) GetAllRules() ([]core.Rule, error) {
	return []core.Rule{}, nil
}

func (m *MockRuleStorage) GetRuleCount() (int64, error) {
	return 0, nil
}

func (m *MockRuleStorage) GetRule(id string) (*core.Rule, error) {
	return nil, nil
}

func (m *MockRuleStorage) CreateRule(rule *core.Rule) error {
	return nil
}

func (m *MockRuleStorage) UpdateRule(id string, rule *core.Rule) error {
	return nil
}

func (m *MockRuleStorage) DeleteRule(id string) error {
	return nil
}

func (m *MockRuleStorage) DisableRule(id string) error {
	return nil
}

func (m *MockRuleStorage) EnableRule(id string) error {
	return nil
}

func (m *MockRuleStorage) GetEnabledRules() ([]core.Rule, error) {
	return []core.Rule{}, nil
}

func (m *MockRuleStorage) GetRulesByType(ruleType string, limit int, offset int) ([]core.Rule, error) {
	return []core.Rule{}, nil
}

func (m *MockRuleStorage) SearchRules(query string) ([]core.Rule, error) {
	return []core.Rule{}, nil
}

func (m *MockRuleStorage) GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error) {
	return []core.Rule{}, 0, nil
}

func (m *MockRuleStorage) GetRuleFilterMetadata() (*core.RuleFilterMetadata, error) {
	return &core.RuleFilterMetadata{}, nil
}

func (m *MockRuleStorage) EnsureIndexes() error {
	return nil
}

// MockActionStorage implements ActionStorer interface for testing
type MockActionStorage struct{}

func NewMockActionStorage() *MockActionStorage {
	return &MockActionStorage{}
}

func (m *MockActionStorage) GetActions() ([]core.Action, error) {
	return []core.Action{}, nil
}

func (m *MockActionStorage) GetAction(id string) (*core.Action, error) {
	return nil, nil
}

func (m *MockActionStorage) CreateAction(action *core.Action) error {
	return nil
}

func (m *MockActionStorage) UpdateAction(id string, action *core.Action) error {
	return nil
}

func (m *MockActionStorage) DeleteAction(id string) error {
	return nil
}

func (m *MockActionStorage) EnsureIndexes() error {
	return nil
}

// MockCorrelationRuleStorage implements CorrelationRuleStorer interface for testing
type MockCorrelationRuleStorage struct{}

func NewMockCorrelationRuleStorage() *MockCorrelationRuleStorage {
	return &MockCorrelationRuleStorage{}
}

func (m *MockCorrelationRuleStorage) GetCorrelationRules() ([]core.CorrelationRule, error) {
	return []core.CorrelationRule{}, nil
}

func (m *MockCorrelationRuleStorage) GetCorrelationRule(id string) (*core.CorrelationRule, error) {
	return nil, nil
}

func (m *MockCorrelationRuleStorage) CreateCorrelationRule(rule *core.CorrelationRule) error {
	return nil
}

func (m *MockCorrelationRuleStorage) UpdateCorrelationRule(id string, rule *core.CorrelationRule) error {
	return nil
}

func (m *MockCorrelationRuleStorage) DeleteCorrelationRule(id string) error {
	return nil
}

func (m *MockCorrelationRuleStorage) GetAllCorrelationRules() ([]core.CorrelationRule, error) {
	return []core.CorrelationRule{}, nil
}

func (m *MockCorrelationRuleStorage) GetCorrelationRuleCount() (int64, error) {
	return 0, nil
}

func (m *MockCorrelationRuleStorage) EnsureIndexes() error {
	return nil
}
