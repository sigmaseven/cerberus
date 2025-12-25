package testing

import (
	"fmt"
	"sync"

	"cerberus/core"
	"cerberus/storage"
)

// ==============================================================================
// MOCK CONFIGURATION
// ==============================================================================

// MockConfig configures mock behavior for testing various scenarios
type MockConfig struct {
	// Error injection
	GetError    error // Error to return for Get operations
	CreateError error // Error to return for Create operations
	UpdateError error // Error to return for Update operations
	DeleteError error // Error to return for Delete operations

	// Conditional errors
	FailAfter int // Fail after N successful operations (0 = never fail)
	FailEvery int // Fail every Nth operation (0 = never fail)

	// Data to return
	Rules            []core.Rule
	Actions          []core.Action
	CorrelationRules []core.CorrelationRule

	// Validation flags
	ValidateInput bool // If true, validate input parameters
}

// ==============================================================================
// MOCK RULE STORAGE
// ==============================================================================

// MockRuleStorage provides a configurable mock for rule storage testing
type MockRuleStorage struct {
	config         MockConfig
	operationCount int
	mu             sync.Mutex // Protects operationCount and data

	// Track method calls for verification
	GetRulesCalled        int
	GetAllRulesCalled     int
	GetEnabledRulesCalled int
	CreateRuleCalled      int
	UpdateRuleCalled      int
	DeleteRuleCalled      int
}

// NewMockRuleStorage creates a new mock rule storage with the given configuration
func NewMockRuleStorage(config MockConfig) *MockRuleStorage {
	if config.Rules == nil {
		config.Rules = []core.Rule{}
	}
	return &MockRuleStorage{
		config: config,
	}
}

// shouldFail determines if this operation should fail based on configuration
func (m *MockRuleStorage) shouldFail() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.operationCount++

	// Check FailAfter condition
	if m.config.FailAfter > 0 && m.operationCount > m.config.FailAfter {
		return true
	}

	// Check FailEvery condition
	if m.config.FailEvery > 0 && m.operationCount%m.config.FailEvery == 0 {
		return true
	}

	return false
}

// GetRules returns mock rules with pagination
func (m *MockRuleStorage) GetRules(limit int, offset int) ([]core.Rule, error) {
	m.mu.Lock()
	m.GetRulesCalled++
	m.mu.Unlock()

	if m.shouldFail() {
		return nil, storage.ErrDatabaseClosed
	}

	if m.config.GetError != nil {
		return nil, m.config.GetError
	}

	// Input validation if enabled
	if m.config.ValidateInput {
		if limit < 0 {
			return nil, storage.ErrInvalidRule
		}
		if offset < 0 {
			return nil, storage.ErrInvalidRule
		}
	}

	// Apply pagination
	start := offset
	if start > len(m.config.Rules) {
		return []core.Rule{}, nil
	}

	end := start + limit
	if end > len(m.config.Rules) {
		end = len(m.config.Rules)
	}

	return m.config.Rules[start:end], nil
}

// GetAllRules returns all mock rules
func (m *MockRuleStorage) GetAllRules() ([]core.Rule, error) {
	m.mu.Lock()
	m.GetAllRulesCalled++
	m.mu.Unlock()

	if m.shouldFail() {
		return nil, storage.ErrDatabaseClosed
	}

	if m.config.GetError != nil {
		return nil, m.config.GetError
	}

	return m.config.Rules, nil
}

// GetRulesByType returns rules filtered by type
func (m *MockRuleStorage) GetRulesByType(ruleType string, limit int, offset int) ([]core.Rule, error) {
	if m.config.GetError != nil {
		return nil, m.config.GetError
	}

	// Filter by type
	filtered := []core.Rule{}
	for _, rule := range m.config.Rules {
		if rule.Type == ruleType {
			filtered = append(filtered, rule)
		}
	}

	// Apply pagination
	start := offset
	if start > len(filtered) {
		return []core.Rule{}, nil
	}

	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[start:end], nil
}

// GetEnabledRules returns only enabled rules
func (m *MockRuleStorage) GetEnabledRules() ([]core.Rule, error) {
	m.mu.Lock()
	m.GetEnabledRulesCalled++
	m.mu.Unlock()

	if m.config.GetError != nil {
		return nil, m.config.GetError
	}

	enabled := []core.Rule{}
	for _, rule := range m.config.Rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}

	return enabled, nil
}

// GetRuleCount returns the count of rules
func (m *MockRuleStorage) GetRuleCount() (int64, error) {
	if m.config.GetError != nil {
		return 0, m.config.GetError
	}

	return int64(len(m.config.Rules)), nil
}

// GetRule returns a single rule by ID
func (m *MockRuleStorage) GetRule(id string) (*core.Rule, error) {
	if m.config.ValidateInput && id == "" {
		return nil, storage.ErrInvalidRule
	}

	if m.config.GetError != nil {
		return nil, m.config.GetError
	}

	for _, rule := range m.config.Rules {
		if rule.ID == id {
			return &rule, nil
		}
	}

	return nil, storage.ErrNotFound
}

// CreateRule creates a new rule
func (m *MockRuleStorage) CreateRule(rule *core.Rule) error {
	m.mu.Lock()
	m.CreateRuleCalled++
	m.mu.Unlock()

	if m.config.ValidateInput && rule == nil {
		return storage.ErrInvalidRule
	}

	if m.config.ValidateInput && rule.ID == "" {
		return storage.ErrInvalidRule
	}

	if m.config.CreateError != nil {
		return m.config.CreateError
	}

	// Check for duplicate
	for _, r := range m.config.Rules {
		if r.ID == rule.ID {
			return storage.ErrDuplicateRule
		}
	}

	m.mu.Lock()
	m.config.Rules = append(m.config.Rules, *rule)
	m.mu.Unlock()

	return nil
}

// UpdateRule updates an existing rule
func (m *MockRuleStorage) UpdateRule(id string, rule *core.Rule) error {
	m.mu.Lock()
	m.UpdateRuleCalled++
	m.mu.Unlock()

	if m.config.ValidateInput {
		if id == "" || rule == nil {
			return storage.ErrInvalidRule
		}
	}

	if m.config.UpdateError != nil {
		return m.config.UpdateError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i, r := range m.config.Rules {
		if r.ID == id {
			m.config.Rules[i] = *rule
			return nil
		}
	}

	return storage.ErrNotFound
}

// DeleteRule deletes a rule
func (m *MockRuleStorage) DeleteRule(id string) error {
	m.mu.Lock()
	m.DeleteRuleCalled++
	m.mu.Unlock()

	if m.config.ValidateInput && id == "" {
		return storage.ErrInvalidRule
	}

	if m.config.DeleteError != nil {
		return m.config.DeleteError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i, r := range m.config.Rules {
		if r.ID == id {
			m.config.Rules = append(m.config.Rules[:i], m.config.Rules[i+1:]...)
			return nil
		}
	}

	return storage.ErrNotFound
}

// EnableRule enables a rule
func (m *MockRuleStorage) EnableRule(id string) error {
	if m.config.UpdateError != nil {
		return m.config.UpdateError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i, r := range m.config.Rules {
		if r.ID == id {
			m.config.Rules[i].Enabled = true
			return nil
		}
	}

	return storage.ErrNotFound
}

// DisableRule disables a rule
func (m *MockRuleStorage) DisableRule(id string) error {
	if m.config.UpdateError != nil {
		return m.config.UpdateError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i, r := range m.config.Rules {
		if r.ID == id {
			m.config.Rules[i].Enabled = false
			return nil
		}
	}

	return storage.ErrNotFound
}

// SearchRules searches rules (simple implementation for testing)
func (m *MockRuleStorage) SearchRules(query string) ([]core.Rule, error) {
	if m.config.GetError != nil {
		return nil, m.config.GetError
	}

	// Simple search implementation for testing
	return m.config.Rules, nil
}

// GetRulesWithFilters returns rules with advanced filtering
func (m *MockRuleStorage) GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error) {
	if m.config.GetError != nil {
		return nil, 0, m.config.GetError
	}

	// Simple implementation returns all rules for testing
	return m.config.Rules, int64(len(m.config.Rules)), nil
}

// GetRuleFilterMetadata returns filter metadata
func (m *MockRuleStorage) GetRuleFilterMetadata() (*core.RuleFilterMetadata, error) {
	return &core.RuleFilterMetadata{}, nil
}

// EnsureIndexes is a no-op for mocks
func (m *MockRuleStorage) EnsureIndexes() error {
	return nil
}

// ==============================================================================
// MOCK ACTION STORAGE
// ==============================================================================

// MockActionStorage provides a configurable mock for action storage testing
type MockActionStorage struct {
	config         MockConfig
	operationCount int //lint:ignore U1000 Reserved for future operation counting in test assertions
	mu             sync.Mutex
}

// NewMockActionStorage creates a new mock action storage
func NewMockActionStorage(config MockConfig) *MockActionStorage {
	if config.Actions == nil {
		config.Actions = []core.Action{}
	}
	return &MockActionStorage{
		config: config,
	}
}

// GetActions returns all actions
func (m *MockActionStorage) GetActions() ([]core.Action, error) {
	if m.config.GetError != nil {
		return nil, m.config.GetError
	}
	return m.config.Actions, nil
}

// GetAction returns a single action by ID
func (m *MockActionStorage) GetAction(id string) (*core.Action, error) {
	if m.config.ValidateInput && id == "" {
		return nil, fmt.Errorf("invalid action ID")
	}

	if m.config.GetError != nil {
		return nil, m.config.GetError
	}

	for _, action := range m.config.Actions {
		if action.ID == id {
			return &action, nil
		}
	}

	return nil, storage.ErrNotFound
}

// CreateAction creates a new action
func (m *MockActionStorage) CreateAction(action *core.Action) error {
	if m.config.ValidateInput && action == nil {
		return fmt.Errorf("action is nil")
	}

	if m.config.CreateError != nil {
		return m.config.CreateError
	}

	m.mu.Lock()
	m.config.Actions = append(m.config.Actions, *action)
	m.mu.Unlock()

	return nil
}

// UpdateAction updates an existing action
func (m *MockActionStorage) UpdateAction(id string, action *core.Action) error {
	if m.config.ValidateInput && (id == "" || action == nil) {
		return fmt.Errorf("invalid parameters")
	}

	if m.config.UpdateError != nil {
		return m.config.UpdateError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i, a := range m.config.Actions {
		if a.ID == id {
			m.config.Actions[i] = *action
			return nil
		}
	}

	return storage.ErrNotFound
}

// DeleteAction deletes an action
func (m *MockActionStorage) DeleteAction(id string) error {
	if m.config.DeleteError != nil {
		return m.config.DeleteError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i, a := range m.config.Actions {
		if a.ID == id {
			m.config.Actions = append(m.config.Actions[:i], m.config.Actions[i+1:]...)
			return nil
		}
	}

	return storage.ErrNotFound
}

// EnsureIndexes is a no-op for mocks
func (m *MockActionStorage) EnsureIndexes() error {
	return nil
}

// ==============================================================================
// MOCK HELPERS
// ==============================================================================

// CreateTestRule creates a test rule with standard values
// TASK 176: Updated to use SIGMA YAML format instead of legacy Conditions
func CreateTestRule(id string) core.Rule {
	sigmaYAML := fmt.Sprintf(`title: %s
id: %s
status: experimental
logsource:
  category: test
detection:
  selection:
    event.type: test
  condition: selection
level: medium`, TestRuleName, id)

	return core.Rule{
		ID:          id,
		Name:        TestRuleName,
		Description: "Test rule for unit testing",
		Severity:    TestAlertSeverity,
		Enabled:     true,
		Type:        "sigma",
		SigmaYAML:   sigmaYAML,
	}
}

// CreateTestAction creates a test action with standard values
func CreateTestAction(id string) core.Action {
	return core.Action{
		ID:   id,
		Type: TestActionType,
		Config: map[string]interface{}{
			"url": TestWebhookURL,
		},
	}
}
