package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// Mock implementations using gomock
// Note: In a real scenario, use mockgen to generate these

type mockEventStorage struct {
	getEvents             func(limit int) ([]core.Event, error)
	getEventCount         func() (int64, error)
	getEventCountsByMonth func() ([]map[string]interface{}, error)
}

func (m *mockEventStorage) GetEvents(limit int) ([]core.Event, error) {
	if m.getEvents != nil {
		return m.getEvents(limit)
	}
	return []core.Event{}, nil
}

func (m *mockEventStorage) GetEventCount() (int64, error) {
	if m.getEventCount != nil {
		return m.getEventCount()
	}
	return 0, nil
}

func (m *mockEventStorage) GetEventCountsByMonth() ([]map[string]interface{}, error) {
	if m.getEventCountsByMonth != nil {
		return m.getEventCountsByMonth()
	}
	return []map[string]interface{}{}, nil
}

type mockAlertStorage struct {
	getAlerts             func(limit int) ([]core.Alert, error)
	getAlertCount         func() (int64, error)
	getAlertCountsByMonth func() ([]map[string]interface{}, error)
	acknowledgeAlert      func(id string) error
	dismissAlert          func(id string) error
}

func (m *mockAlertStorage) GetAlerts(limit int) ([]core.Alert, error) {
	if m.getAlerts != nil {
		return m.getAlerts(limit)
	}
	return []core.Alert{}, nil
}

func (m *mockAlertStorage) GetAlertCount() (int64, error) {
	if m.getAlertCount != nil {
		return m.getAlertCount()
	}
	return 0, nil
}

func (m *mockAlertStorage) GetAlertCountsByMonth() ([]map[string]interface{}, error) {
	if m.getAlertCountsByMonth != nil {
		return m.getAlertCountsByMonth()
	}
	return []map[string]interface{}{}, nil
}

func (m *mockAlertStorage) AcknowledgeAlert(id string) error {
	if m.acknowledgeAlert != nil {
		return m.acknowledgeAlert(id)
	}
	return nil
}

func (m *mockAlertStorage) DismissAlert(id string) error {
	if m.dismissAlert != nil {
		return m.dismissAlert(id)
	}
	return nil
}

type mockRuleStorage struct {
	getRules   func() ([]core.Rule, error)
	getRule    func(id string) (*core.Rule, error)
	createRule func(rule *core.Rule) error
	updateRule func(id string, rule *core.Rule) error
	deleteRule func(id string) error
}

func (m *mockRuleStorage) GetRules() ([]core.Rule, error) {
	if m.getRules != nil {
		return m.getRules()
	}
	return []core.Rule{}, nil
}

func (m *mockRuleStorage) GetRule(id string) (*core.Rule, error) {
	if m.getRule != nil {
		return m.getRule(id)
	}
	return &core.Rule{}, nil
}

func (m *mockRuleStorage) CreateRule(rule *core.Rule) error {
	if m.createRule != nil {
		return m.createRule(rule)
	}
	return nil
}

func (m *mockRuleStorage) UpdateRule(id string, rule *core.Rule) error {
	if m.updateRule != nil {
		return m.updateRule(id, rule)
	}
	return nil
}

func (m *mockRuleStorage) DeleteRule(id string) error {
	if m.deleteRule != nil {
		return m.deleteRule(id)
	}
	return nil
}

type mockActionStorage struct {
	getActions   func() ([]core.Action, error)
	getAction    func(id string) (*core.Action, error)
	createAction func(action *core.Action) error
	updateAction func(id string, action *core.Action) error
	deleteAction func(id string) error
}

func (m *mockActionStorage) GetActions() ([]core.Action, error) {
	if m.getActions != nil {
		return m.getActions()
	}
	return []core.Action{}, nil
}

func (m *mockActionStorage) GetAction(id string) (*core.Action, error) {
	if m.getAction != nil {
		return m.getAction(id)
	}
	return &core.Action{}, nil
}

func (m *mockActionStorage) CreateAction(action *core.Action) error {
	if m.createAction != nil {
		return m.createAction(action)
	}
	return nil
}

func (m *mockActionStorage) UpdateAction(id string, action *core.Action) error {
	if m.updateAction != nil {
		return m.updateAction(id, action)
	}
	return nil
}

func (m *mockActionStorage) DeleteAction(id string) error {
	if m.deleteAction != nil {
		return m.deleteAction(id)
	}
	return nil
}

type mockCorrelationRuleStorage struct {
	getCorrelationRules   func() ([]core.CorrelationRule, error)
	getCorrelationRule    func(id string) (*core.CorrelationRule, error)
	createCorrelationRule func(rule *core.CorrelationRule) error
	updateCorrelationRule func(id string, rule *core.CorrelationRule) error
	deleteCorrelationRule func(id string) error
}

func (m *mockCorrelationRuleStorage) GetCorrelationRules() ([]core.CorrelationRule, error) {
	if m.getCorrelationRules != nil {
		return m.getCorrelationRules()
	}
	return []core.CorrelationRule{}, nil
}

func (m *mockCorrelationRuleStorage) GetCorrelationRule(id string) (*core.CorrelationRule, error) {
	if m.getCorrelationRule != nil {
		return m.getCorrelationRule(id)
	}
	return &core.CorrelationRule{}, nil
}

func (m *mockCorrelationRuleStorage) CreateCorrelationRule(rule *core.CorrelationRule) error {
	if m.createCorrelationRule != nil {
		return m.createCorrelationRule(rule)
	}
	return nil
}

func (m *mockCorrelationRuleStorage) UpdateCorrelationRule(id string, rule *core.CorrelationRule) error {
	if m.updateCorrelationRule != nil {
		return m.updateCorrelationRule(id, rule)
	}
	return nil
}

func (m *mockCorrelationRuleStorage) DeleteCorrelationRule(id string) error {
	if m.deleteCorrelationRule != nil {
		return m.deleteCorrelationRule(id)
	}
	return nil
}

func TestNewAPI(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	assert.NotNil(t, api)
	assert.NotNil(t, api.router)
	assert.Equal(t, eventStorage, api.eventStorage)
	assert.Equal(t, alertStorage, api.alertStorage)
	assert.Equal(t, ruleStorage, api.ruleStorage)
	assert.Equal(t, actionStorage, api.actionStorage)
	assert.Equal(t, correlationRuleStorage, api.correlationRuleStorage)
	assert.Equal(t, cfg, api.config)
	assert.Equal(t, logger, api.logger)
	assert.NotNil(t, api.rateLimiters)
	assert.NotNil(t, api.authFailures)
	assert.NotNil(t, api.stopCh)
}

func TestGetEvents_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedEvents := []core.Event{{EventID: "1"}}
	eventStorage := &mockEventStorage{
		getEvents: func(limit int) ([]core.Event, error) {
			assert.Equal(t, 100, limit)
			return expectedEvents, nil
		},
	}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()

	api.getEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var events []core.Event
	err := json.Unmarshal(w.Body.Bytes(), &events)
	assert.NoError(t, err)
	assert.Equal(t, expectedEvents, events)
}

func TestGetEvents_CustomLimit(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedEvents := []core.Event{{EventID: "1"}}
	eventStorage := &mockEventStorage{
		getEvents: func(limit int) ([]core.Event, error) {
			assert.Equal(t, 50, limit)
			return expectedEvents, nil
		},
	}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/events?limit=50", nil)
	w := httptest.NewRecorder()

	api.getEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var events []core.Event
	err := json.Unmarshal(w.Body.Bytes(), &events)
	assert.NoError(t, err)
	assert.Equal(t, expectedEvents, events)
}

func TestGetEvents_InvalidLimit(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedEvents := []core.Event{}
	eventStorage := &mockEventStorage{
		getEvents: func(limit int) ([]core.Event, error) {
			assert.Equal(t, 100, limit) // default
			return expectedEvents, nil
		},
	}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/events?limit=invalid", nil)
	w := httptest.NewRecorder()

	api.getEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetEvents_LimitTooHigh(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedEvents := []core.Event{}
	eventStorage := &mockEventStorage{
		getEvents: func(limit int) ([]core.Event, error) {
			assert.Equal(t, 100, limit) // default, since 2000 >1000 not set
			return expectedEvents, nil
		},
	}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/events?limit=2000", nil)
	w := httptest.NewRecorder()

	api.getEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetEvents_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventStorage := &mockEventStorage{
		getEvents: func(limit int) ([]core.Event, error) {
			return nil, assert.AnError
		},
	}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()

	api.getEvents(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to get events")
}

func TestGetEvents_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(nil, &mockAlertStorage{}, &mockRuleStorage{}, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()

	api.getEvents(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Event storage not available")
}

func TestGetAlerts_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedAlerts := []core.Alert{{AlertID: "1"}}
	alertStorage := &mockAlertStorage{
		getAlerts: func(limit int) ([]core.Alert, error) {
			assert.Equal(t, 100, limit)
			return expectedAlerts, nil
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	w := httptest.NewRecorder()

	api.getAlerts(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var alerts []core.Alert
	err := json.Unmarshal(w.Body.Bytes(), &alerts)
	assert.NoError(t, err)
	assert.Equal(t, expectedAlerts, alerts)
}

func TestGetAlerts_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	alertStorage := &mockAlertStorage{
		getAlerts: func(limit int) ([]core.Alert, error) {
			return nil, assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	w := httptest.NewRecorder()

	api.getAlerts(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to get alerts")
}

func TestGetAlerts_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, nil, &mockRuleStorage{}, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	w := httptest.NewRecorder()

	api.getAlerts(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Alert storage not available")
}

func TestAcknowledgeAlert_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	alertStorage := &mockAlertStorage{
		acknowledgeAlert: func(id string) error {
			assert.Equal(t, "123", id)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/acknowledge", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.acknowledgeAlert(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "acknowledged", resp["status"])
}

func TestAcknowledgeAlert_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	alertStorage := &mockAlertStorage{
		acknowledgeAlert: func(id string) error {
			return storage.ErrAlertNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/acknowledge", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.acknowledgeAlert(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Alert not found")
}

func TestAcknowledgeAlert_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	alertStorage := &mockAlertStorage{
		acknowledgeAlert: func(id string) error {
			return assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/acknowledge", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.acknowledgeAlert(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAcknowledgeAlert_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, nil, &mockRuleStorage{}, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/acknowledge", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.acknowledgeAlert(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Alert storage not available")
}

func TestDismissAlert_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	alertStorage := &mockAlertStorage{
		dismissAlert: func(id string) error {
			assert.Equal(t, "123", id)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/dismiss", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.dismissAlert(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "dismissed", resp["status"])
}

func TestDismissAlert_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	alertStorage := &mockAlertStorage{
		dismissAlert: func(id string) error {
			return storage.ErrAlertNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/dismiss", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.dismissAlert(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Alert not found")
}

func TestDismissAlert_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	alertStorage := &mockAlertStorage{
		dismissAlert: func(id string) error {
			return assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/dismiss", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.dismissAlert(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDismissAlert_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, nil, &mockRuleStorage{}, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("POST", "/api/alerts/123/dismiss", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.dismissAlert(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Alert storage not available")
}

func TestGetRules_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedRules := []core.Rule{{ID: "1", Name: "test"}}
	ruleStorage := &mockRuleStorage{
		getRules: func() ([]core.Rule, error) {
			return expectedRules, nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/rules", nil)
	w := httptest.NewRecorder()

	api.getRules(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var rules []core.Rule
	err := json.Unmarshal(w.Body.Bytes(), &rules)
	assert.NoError(t, err)
	assert.Equal(t, expectedRules, rules)
}

func TestGetRules_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	ruleStorage := &mockRuleStorage{
		getRules: func() ([]core.Rule, error) {
			return nil, assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/rules", nil)
	w := httptest.NewRecorder()

	api.getRules(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetRules_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, &mockAlertStorage{}, nil, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("GET", "/api/rules", nil)
	w := httptest.NewRecorder()

	api.getRules(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Rule storage not available")
}

func TestGetRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedRule := &core.Rule{ID: "123", Name: "test"}
	ruleStorage := &mockRuleStorage{
		getRule: func(id string) (*core.Rule, error) {
			assert.Equal(t, "123", id)
			return expectedRule, nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getRule(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var rule core.Rule
	err := json.Unmarshal(w.Body.Bytes(), &rule)
	assert.NoError(t, err)
	assert.Equal(t, *expectedRule, rule)
}

func TestGetRule_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	ruleStorage := &mockRuleStorage{
		getRule: func(id string) (*core.Rule, error) {
			return nil, storage.ErrRuleNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getRule(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Rule not found")
}

func TestGetRule_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	ruleStorage := &mockRuleStorage{
		getRule: func(id string) (*core.Rule, error) {
			return nil, assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getRule(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetRule_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, &mockAlertStorage{}, nil, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("GET", "/api/rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getRule(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Rule storage not available")
}

func TestCreateRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.Rule{Name: "test", Severity: "High", Version: 1, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}}
	ruleJSON, _ := json.Marshal(rule)
	ruleStorage := &mockRuleStorage{
		createRule: func(r *core.Rule) error {
			assert.Equal(t, "test", r.Name)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createRule(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var createdRule core.Rule
	err := json.Unmarshal(w.Body.Bytes(), &createdRule)
	assert.NoError(t, err)
	assert.NotEmpty(t, createdRule.ID)
}

func TestCreateRule_InvalidJSON(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	ruleStorage := &mockRuleStorage{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/rules", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	api.createRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid JSON")
}

func TestCreateRule_ValidationError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.Rule{Name: "", Severity: "High", Version: 1} // invalid name
	ruleJSON, _ := json.Marshal(rule)
	ruleStorage := &mockRuleStorage{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name is required")
}

func TestCreateRule_StorageError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.Rule{Name: "test", Severity: "High", Version: 1, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}}
	ruleJSON, _ := json.Marshal(rule)
	ruleStorage := &mockRuleStorage{
		createRule: func(r *core.Rule) error {
			return assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createRule(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateRule_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.Rule{Name: "test", Severity: "High", Version: 1, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}}
	ruleJSON, _ := json.Marshal(rule)
	api := NewAPI(&mockEventStorage{}, &mockAlertStorage{}, nil, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("POST", "/api/rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createRule(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Rule storage not available")
}

func TestUpdateRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.Rule{Name: "updated", Severity: "High", Version: 1, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}}
	ruleJSON, _ := json.Marshal(rule)
	ruleStorage := &mockRuleStorage{
		updateRule: func(id string, r *core.Rule) error {
			assert.Equal(t, "123", id)
			assert.Equal(t, "updated", r.Name)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("PUT", "/api/rules/123", bytes.NewReader(ruleJSON))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.updateRule(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var updatedRule core.Rule
	err := json.Unmarshal(w.Body.Bytes(), &updatedRule)
	assert.NoError(t, err)
	assert.Equal(t, "123", updatedRule.ID)
}

func TestUpdateRule_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.Rule{Name: "updated", Severity: "High", Version: 1, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}}
	ruleJSON, _ := json.Marshal(rule)
	ruleStorage := &mockRuleStorage{
		updateRule: func(id string, r *core.Rule) error {
			return storage.ErrRuleNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("PUT", "/api/rules/123", bytes.NewReader(ruleJSON))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.updateRule(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Rule not found")
}

func TestDeleteRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	ruleStorage := &mockRuleStorage{
		deleteRule: func(id string) error {
			assert.Equal(t, "123", id)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("DELETE", "/api/rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.deleteRule(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "deleted", resp["status"])
}

func TestGetActions_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedActions := []core.Action{{ID: "1", Type: "webhook"}}
	actionStorage := &mockActionStorage{
		getActions: func() ([]core.Action, error) {
			return expectedActions, nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/actions", nil)
	w := httptest.NewRecorder()

	api.getActions(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var actions []core.Action
	err := json.Unmarshal(w.Body.Bytes(), &actions)
	assert.NoError(t, err)
	assert.Equal(t, expectedActions, actions)
}

func TestCreateAction_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	action := core.Action{Type: "webhook", Config: map[string]interface{}{"url": "http://example.com"}}
	actionJSON, _ := json.Marshal(action)
	actionStorage := &mockActionStorage{
		createAction: func(a *core.Action) error {
			assert.Equal(t, "webhook", a.Type)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/actions", bytes.NewReader(actionJSON))
	w := httptest.NewRecorder()

	api.createAction(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var createdAction core.Action
	err := json.Unmarshal(w.Body.Bytes(), &createdAction)
	assert.NoError(t, err)
	assert.NotEmpty(t, createdAction.ID)
}

func TestGetDashboardStats_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventStorage := &mockEventStorage{
		getEventCount: func() (int64, error) {
			return 100, nil
		},
	}
	alertStorage := &mockAlertStorage{
		getAlertCount: func() (int64, error) {
			return 10, nil
		},
	}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	w := httptest.NewRecorder()

	api.getDashboardStats(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	assert.NoError(t, err)
	assert.Equal(t, float64(100), stats["events"])
	assert.Equal(t, float64(10), stats["alerts"])
}

func TestHealthCheck_Healthy(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	api.healthCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", resp["status"])
}

func TestHealthCheck_Degraded(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(nil, nil, &mockRuleStorage{}, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	api.healthCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "degraded", resp["status"])
}

func TestValidateRule_Valid(t *testing.T) {
	rule := &core.Rule{
		ID: "1", Name: "test", Description: "desc", Severity: "High", Version: 1,
		Conditions: []core.Condition{{Field: "f", Operator: "equals", Value: "v"}},
	}
	err := validateRule(rule)
	assert.NoError(t, err)
}

func TestValidateRule_InvalidName(t *testing.T) {
	rule := &core.Rule{ID: "1", Name: "", Severity: "High", Version: 1, Conditions: []core.Condition{{Field: "f", Operator: "equals", Value: "v"}}}
	err := validateRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestValidateRule_InvalidSeverity(t *testing.T) {
	rule := &core.Rule{ID: "1", Name: "test", Severity: "Invalid", Version: 1, Conditions: []core.Condition{{Field: "f", Operator: "equals", Value: "v"}}}
	err := validateRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "severity must be Low, Medium, High, or Critical")
}

func TestValidateRule_NoConditions(t *testing.T) {
	rule := &core.Rule{ID: "1", Name: "test", Severity: "High", Version: 1, Conditions: []core.Condition{}}
	err := validateRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one condition is required")
}

func TestValidateAction_Valid(t *testing.T) {
	action := &core.Action{Type: "webhook", Config: map[string]interface{}{"url": "http://example.com"}}
	err := validateAction(action)
	assert.NoError(t, err)
}

func TestValidateAction_InvalidType(t *testing.T) {
	action := &core.Action{Type: "invalid"}
	err := validateAction(action)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "action type must be webhook, jira, email, or slack")
}

func TestValidateAction_InvalidWebhook(t *testing.T) {
	action := &core.Action{Type: "webhook", Config: map[string]interface{}{"url": ""}}
	err := validateAction(action)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "webhook action requires a valid url")
}

func TestGetRealIP_TrustProxy(t *testing.T) {
	r := &http.Request{
		Header:     http.Header{"X-Forwarded-For": []string{"192.168.1.1"}},
		RemoteAddr: "127.0.0.1:1234",
	}
	ip := getRealIP(r, true)
	assert.Equal(t, "192.168.1.1", ip)
}

func TestGetRealIP_NoTrust(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
	}
	ip := getRealIP(r, false)
	assert.Equal(t, "127.0.0.1", ip)
}

func TestGetAction_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedAction := &core.Action{ID: "123", Type: "webhook"}
	actionStorage := &mockActionStorage{
		getAction: func(id string) (*core.Action, error) {
			assert.Equal(t, "123", id)
			return expectedAction, nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/actions/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getAction(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var action core.Action
	err := json.Unmarshal(w.Body.Bytes(), &action)
	assert.NoError(t, err)
	assert.Equal(t, *expectedAction, action)
}

func TestGetAction_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	actionStorage := &mockActionStorage{
		getAction: func(id string) (*core.Action, error) {
			return nil, storage.ErrActionNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/actions/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getAction(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Action not found")
}

func TestGetAction_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	actionStorage := &mockActionStorage{
		getAction: func(id string) (*core.Action, error) {
			return nil, assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/actions/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getAction(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetAction_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, &mockAlertStorage{}, &mockRuleStorage{}, nil, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("GET", "/api/actions/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getAction(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Action storage not available")
}

func TestUpdateAction_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	action := core.Action{Type: "webhook", Config: map[string]interface{}{"url": "http://example.com"}}
	actionJSON, _ := json.Marshal(action)
	actionStorage := &mockActionStorage{
		updateAction: func(id string, a *core.Action) error {
			assert.Equal(t, "123", id)
			assert.Equal(t, "webhook", a.Type)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("PUT", "/api/actions/123", bytes.NewReader(actionJSON))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.updateAction(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var updatedAction core.Action
	err := json.Unmarshal(w.Body.Bytes(), &updatedAction)
	assert.NoError(t, err)
	assert.Equal(t, "123", updatedAction.ID)
}

func TestUpdateAction_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	action := core.Action{Type: "webhook", Config: map[string]interface{}{"url": "http://example.com"}}
	actionJSON, _ := json.Marshal(action)
	actionStorage := &mockActionStorage{
		updateAction: func(id string, a *core.Action) error {
			return storage.ErrActionNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("PUT", "/api/actions/123", bytes.NewReader(actionJSON))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.updateAction(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Action not found")
}

func TestDeleteAction_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	actionStorage := &mockActionStorage{
		deleteAction: func(id string) error {
			assert.Equal(t, "123", id)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("DELETE", "/api/actions/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.deleteAction(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "deleted", resp["status"])
}

func TestGetCorrelationRules_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedRules := []core.CorrelationRule{{ID: "1", Name: "test"}}
	correlationRuleStorage := &mockCorrelationRuleStorage{
		getCorrelationRules: func() ([]core.CorrelationRule, error) {
			return expectedRules, nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/correlation-rules", nil)
	w := httptest.NewRecorder()

	api.getCorrelationRules(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var rules []core.CorrelationRule
	err := json.Unmarshal(w.Body.Bytes(), &rules)
	assert.NoError(t, err)
	assert.Equal(t, expectedRules, rules)
}

func TestGetCorrelationRules_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	correlationRuleStorage := &mockCorrelationRuleStorage{
		getCorrelationRules: func() ([]core.CorrelationRule, error) {
			return nil, assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/correlation-rules", nil)
	w := httptest.NewRecorder()

	api.getCorrelationRules(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetCorrelationRules_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, &mockAlertStorage{}, &mockRuleStorage{}, &mockActionStorage{}, nil, cfg, logger)

	req := httptest.NewRequest("GET", "/api/correlation-rules", nil)
	w := httptest.NewRecorder()

	api.getCorrelationRules(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Correlation rule storage not available")
}

func TestGetCorrelationRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	expectedRule := &core.CorrelationRule{ID: "123", Name: "test"}
	correlationRuleStorage := &mockCorrelationRuleStorage{
		getCorrelationRule: func(id string) (*core.CorrelationRule, error) {
			assert.Equal(t, "123", id)
			return expectedRule, nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/correlation-rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getCorrelationRule(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var rule core.CorrelationRule
	err := json.Unmarshal(w.Body.Bytes(), &rule)
	assert.NoError(t, err)
	assert.Equal(t, *expectedRule, rule)
}

func TestGetCorrelationRule_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	correlationRuleStorage := &mockCorrelationRuleStorage{
		getCorrelationRule: func(id string) (*core.CorrelationRule, error) {
			return nil, storage.ErrCorrelationRuleNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/correlation-rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getCorrelationRule(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Correlation rule not found")
}

func TestGetCorrelationRule_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	correlationRuleStorage := &mockCorrelationRuleStorage{
		getCorrelationRule: func(id string) (*core.CorrelationRule, error) {
			return nil, assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/correlation-rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getCorrelationRule(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetCorrelationRule_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(&mockEventStorage{}, &mockAlertStorage{}, &mockRuleStorage{}, &mockActionStorage{}, nil, cfg, logger)

	req := httptest.NewRequest("GET", "/api/correlation-rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.getCorrelationRule(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Correlation rule storage not available")
}

func TestCreateCorrelationRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.CorrelationRule{Name: "test", Severity: "High", Version: 1, Window: 300000000000, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}, Sequence: []string{"event1"}}
	ruleJSON, _ := json.Marshal(rule)
	correlationRuleStorage := &mockCorrelationRuleStorage{
		createCorrelationRule: func(r *core.CorrelationRule) error {
			assert.Equal(t, "test", r.Name)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/correlation-rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createCorrelationRule(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var createdRule core.CorrelationRule
	err := json.Unmarshal(w.Body.Bytes(), &createdRule)
	assert.NoError(t, err)
	assert.NotEmpty(t, createdRule.ID)
}

func TestCreateCorrelationRule_InvalidJSON(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/correlation-rules", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	api.createCorrelationRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid JSON")
}

func TestCreateCorrelationRule_ValidationError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.CorrelationRule{Name: "", Severity: "High", Version: 1} // invalid name
	ruleJSON, _ := json.Marshal(rule)
	correlationRuleStorage := &mockCorrelationRuleStorage{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/correlation-rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createCorrelationRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name is required")
}

func TestCreateCorrelationRule_StorageError(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.CorrelationRule{Name: "test", Severity: "High", Version: 1, Window: 300000000000, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}, Sequence: []string{"event1"}}
	ruleJSON, _ := json.Marshal(rule)
	correlationRuleStorage := &mockCorrelationRuleStorage{
		createCorrelationRule: func(r *core.CorrelationRule) error {
			return assert.AnError
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("POST", "/api/correlation-rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createCorrelationRule(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateCorrelationRule_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.CorrelationRule{Name: "test", Severity: "High", Version: 1, Window: 300000000000, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}, Sequence: []string{"event1"}}
	ruleJSON, _ := json.Marshal(rule)
	api := NewAPI(&mockEventStorage{}, &mockAlertStorage{}, &mockRuleStorage{}, &mockActionStorage{}, nil, cfg, logger)

	req := httptest.NewRequest("POST", "/api/correlation-rules", bytes.NewReader(ruleJSON))
	w := httptest.NewRecorder()

	api.createCorrelationRule(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Correlation rule storage not available")
}

func TestUpdateCorrelationRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.CorrelationRule{Name: "updated", Severity: "High", Version: 1, Window: 300000000000, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}, Sequence: []string{"event1"}}
	ruleJSON, _ := json.Marshal(rule)
	correlationRuleStorage := &mockCorrelationRuleStorage{
		updateCorrelationRule: func(id string, r *core.CorrelationRule) error {
			assert.Equal(t, "123", id)
			assert.Equal(t, "updated", r.Name)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("PUT", "/api/correlation-rules/123", bytes.NewReader(ruleJSON))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.updateCorrelationRule(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var updatedRule core.CorrelationRule
	err := json.Unmarshal(w.Body.Bytes(), &updatedRule)
	assert.NoError(t, err)
	assert.Equal(t, "123", updatedRule.ID)
}

func TestUpdateCorrelationRule_NotFound(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	rule := core.CorrelationRule{Name: "updated", Severity: "High", Version: 1, Window: 300000000000, Conditions: []core.Condition{{Field: "test", Operator: "equals", Value: "value"}}, Sequence: []string{"event1"}}
	ruleJSON, _ := json.Marshal(rule)
	correlationRuleStorage := &mockCorrelationRuleStorage{
		updateCorrelationRule: func(id string, r *core.CorrelationRule) error {
			return storage.ErrCorrelationRuleNotFound
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("PUT", "/api/correlation-rules/123", bytes.NewReader(ruleJSON))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.updateCorrelationRule(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Correlation rule not found")
}

func TestDeleteCorrelationRule_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	correlationRuleStorage := &mockCorrelationRuleStorage{
		deleteCorrelationRule: func(id string) error {
			assert.Equal(t, "123", id)
			return nil
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("DELETE", "/api/correlation-rules/123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	w := httptest.NewRecorder()

	api.deleteCorrelationRule(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "deleted", resp["status"])
}

func TestGetListeners_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{
		Listeners: struct {
			Syslog struct {
				Port int    `mapstructure:"port"`
				Host string `mapstructure:"host"`
			} `mapstructure:"syslog"`
			CEF struct {
				Port int    `mapstructure:"port"`
				Host string `mapstructure:"host"`
			} `mapstructure:"cef"`
			JSON struct {
				Port     int    `mapstructure:"port"`
				Host     string `mapstructure:"host"`
				TLS      bool   `mapstructure:"tls"`
				CertFile string `mapstructure:"cert_file"`
				KeyFile  string `mapstructure:"key_file"`
			} `mapstructure:"json"`
			SkipOnError bool `mapstructure:"skip_on_error"`
		}{
			Syslog: struct {
				Port int    `mapstructure:"port"`
				Host string `mapstructure:"host"`
			}{Port: 514, Host: "0.0.0.0"},
			CEF: struct {
				Port int    `mapstructure:"port"`
				Host string `mapstructure:"host"`
			}{Port: 515, Host: "0.0.0.0"},
			JSON: struct {
				Port     int    `mapstructure:"port"`
				Host     string `mapstructure:"host"`
				TLS      bool   `mapstructure:"tls"`
				CertFile string `mapstructure:"cert_file"`
				KeyFile  string `mapstructure:"key_file"`
			}{Port: 8080, Host: "0.0.0.0", TLS: true},
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/listeners", nil)
	w := httptest.NewRecorder()

	api.getListeners(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var listeners map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &listeners)
	assert.NoError(t, err)
	assert.Equal(t, "0.0.0.0", listeners["syslog"].(map[string]interface{})["host"])
	assert.Equal(t, float64(514), listeners["syslog"].(map[string]interface{})["port"])
}

func TestGetDashboardChart_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventData := []map[string]interface{}{
		{"name": "2023-10", "events": 100},
	}
	alertData := []map[string]interface{}{
		{"name": "2023-10", "alerts": 10},
	}
	eventStorage := &mockEventStorage{
		getEventCountsByMonth: func() ([]map[string]interface{}, error) {
			return eventData, nil
		},
	}
	alertStorage := &mockAlertStorage{
		getAlertCountsByMonth: func() ([]map[string]interface{}, error) {
			return alertData, nil
		},
	}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/dashboard/chart", nil)
	w := httptest.NewRecorder()

	api.getDashboardChart(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var chartData []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &chartData)
	assert.NoError(t, err)
	assert.Len(t, chartData, 1)
	assert.Equal(t, "2023-10", chartData[0]["name"])
	assert.Equal(t, float64(100), chartData[0]["events"])
	assert.Equal(t, float64(10), chartData[0]["alerts"])
}

func TestGetDashboardChart_Error(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventStorage := &mockEventStorage{
		getEventCountsByMonth: func() ([]map[string]interface{}, error) {
			return nil, assert.AnError
		},
	}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	req := httptest.NewRequest("GET", "/api/dashboard/chart", nil)
	w := httptest.NewRecorder()

	api.getDashboardChart(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to retrieve event data")
}

func TestGetDashboardChart_NoStorage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	api := NewAPI(nil, nil, &mockRuleStorage{}, &mockActionStorage{}, &mockCorrelationRuleStorage{}, cfg, logger)

	req := httptest.NewRequest("GET", "/api/dashboard/chart", nil)
	w := httptest.NewRecorder()

	api.getDashboardChart(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Storage not available")
}

func TestRateLimitMiddleware_Allow(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{
		API: struct {
			Version        string   `mapstructure:"version"`
			Port           int      `mapstructure:"port"`
			TLS            bool     `mapstructure:"tls"`
			CertFile       string   `mapstructure:"cert_file"`
			KeyFile        string   `mapstructure:"key_file"`
			AllowedOrigins []string `mapstructure:"allowed_origins"`
			TrustProxy     bool     `mapstructure:"trust_proxy"`
			RateLimit      struct {
				RequestsPerSecond int `mapstructure:"requests_per_second"`
				Burst             int `mapstructure:"burst"`
			} `mapstructure:"rate_limit"`
		}{
			RateLimit: struct {
				RequestsPerSecond int `mapstructure:"requests_per_second"`
				Burst             int `mapstructure:"burst"`
			}{RequestsPerSecond: 10, Burst: 10},
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	handler := api.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimitMiddleware_TooManyRequests(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{
		API: struct {
			Version        string   `mapstructure:"version"`
			Port           int      `mapstructure:"port"`
			TLS            bool     `mapstructure:"tls"`
			CertFile       string   `mapstructure:"cert_file"`
			KeyFile        string   `mapstructure:"key_file"`
			AllowedOrigins []string `mapstructure:"allowed_origins"`
			TrustProxy     bool     `mapstructure:"trust_proxy"`
			RateLimit      struct {
				RequestsPerSecond int `mapstructure:"requests_per_second"`
				Burst             int `mapstructure:"burst"`
			} `mapstructure:"rate_limit"`
		}{
			RateLimit: struct {
				RequestsPerSecond int `mapstructure:"requests_per_second"`
				Burst             int `mapstructure:"burst"`
			}{RequestsPerSecond: 1, Burst: 1},
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	handler := api.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request
	req1 := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second request immediately, should be rate limited
	req2 := httptest.NewRequest("GET", "/", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
}

func TestCorsMiddleware_AllowOrigin(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{
		API: struct {
			Version        string   `mapstructure:"version"`
			Port           int      `mapstructure:"port"`
			TLS            bool     `mapstructure:"tls"`
			CertFile       string   `mapstructure:"cert_file"`
			KeyFile        string   `mapstructure:"key_file"`
			AllowedOrigins []string `mapstructure:"allowed_origins"`
			TrustProxy     bool     `mapstructure:"trust_proxy"`
			RateLimit      struct {
				RequestsPerSecond int `mapstructure:"requests_per_second"`
				Burst             int `mapstructure:"burst"`
			} `mapstructure:"rate_limit"`
		}{
			AllowedOrigins: []string{"http://example.com"},
			TLS:            true,
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	handler := api.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "max-age=31536000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
}

func TestCorsMiddleware_Options(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	handler := api.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_Success(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{
		Auth: struct {
			Enabled        bool   `mapstructure:"enabled"`
			Username       string `mapstructure:"username"`
			Password       string `mapstructure:"password"`
			HashedPassword string
			BcryptCost     int `mapstructure:"bcrypt_cost"`
		}{
			Enabled:        true,
			Username:       "testuser",
			HashedPassword: "$2a$10$examplehash", // mock hash
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	handler := api.basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("testuser", "password") // assuming password matches the hash, but since it's mock, we need to adjust
	// For testing, perhaps mock the bcrypt.CompareHashAndPassword, but since it's hard, maybe skip or use a known hash
	// For simplicity, let's assume the hash is for "password"
	// But to make it work, perhaps set HashedPassword to a known hash for "password"
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password"), 4) // low cost for test
	cfg.Auth.HashedPassword = string(hashed)

	req.SetBasicAuth("testuser", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_Failure(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{
		Auth: struct {
			Enabled        bool   `mapstructure:"enabled"`
			Username       string `mapstructure:"username"`
			Password       string `mapstructure:"password"`
			HashedPassword string
			BcryptCost     int `mapstructure:"bcrypt_cost"`
		}{
			Enabled:        true,
			Username:       "testuser",
			HashedPassword: "$2a$10$examplehash",
		},
	}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	handler := api.basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("wrong", "wrong")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `Basic realm="Cerberus API"`, w.Header().Get("WWW-Authenticate"))
}

func TestValidateBaseRule_Valid(t *testing.T) {
	err := validateBaseRule("1", "test", "desc", "High", 1)
	assert.NoError(t, err)
}

func TestValidateBaseRule_InvalidName(t *testing.T) {
	err := validateBaseRule("1", "", "desc", "High", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestValidateBaseRule_InvalidSeverity(t *testing.T) {
	err := validateBaseRule("1", "test", "desc", "Invalid", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "severity must be Low, Medium, High, or Critical")
}

func TestValidateBaseRule_InvalidVersion(t *testing.T) {
	err := validateBaseRule("1", "test", "desc", "High", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version must be positive")
}

func TestValidateConditions_Valid(t *testing.T) {
	conditions := []core.Condition{
		{Field: "f", Operator: "equals", Value: "v"},
	}
	err := validateConditions(conditions)
	assert.NoError(t, err)
}

func TestValidateConditions_InvalidField(t *testing.T) {
	conditions := []core.Condition{
		{Field: "", Operator: "equals", Value: "v"},
	}
	err := validateConditions(conditions)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field is required")
}

func TestValidateConditions_InvalidOperator(t *testing.T) {
	conditions := []core.Condition{
		{Field: "f", Operator: "invalid", Value: "v"},
	}
	err := validateConditions(conditions)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid operator")
}

func TestValidateConditions_InvalidLogic(t *testing.T) {
	conditions := []core.Condition{
		{Field: "f", Operator: "equals", Value: "v", Logic: "INVALID"},
	}
	err := validateConditions(conditions)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logic must be AND or OR")
}

func TestValidateWebhookAction_Valid(t *testing.T) {
	config := map[string]interface{}{"url": "http://example.com"}
	err := validateWebhookAction(config)
	assert.NoError(t, err)
}

func TestValidateWebhookAction_InvalidURL(t *testing.T) {
	config := map[string]interface{}{"url": ""}
	err := validateWebhookAction(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "webhook action requires a valid url")
}

func TestValidateWebhookAction_InvalidScheme(t *testing.T) {
	config := map[string]interface{}{"url": "ftp://example.com"}
	err := validateWebhookAction(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "webhook URL must use http or https scheme")
}

func TestValidateSlackAction_Valid(t *testing.T) {
	config := map[string]interface{}{"webhook_url": "http://example.com"}
	err := validateSlackAction(config)
	assert.NoError(t, err)
}

func TestValidateSlackAction_Invalid(t *testing.T) {
	config := map[string]interface{}{"webhook_url": ""}
	err := validateSlackAction(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "slack action requires a valid webhook_url")
}

func TestValidateJiraAction_Valid(t *testing.T) {
	config := map[string]interface{}{"base_url": "http://example.com", "project": "PROJ"}
	err := validateJiraAction(config)
	assert.NoError(t, err)
}

func TestValidateJiraAction_InvalidBaseURL(t *testing.T) {
	config := map[string]interface{}{"base_url": "", "project": "PROJ"}
	err := validateJiraAction(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "jira action requires a valid base_url")
}

func TestValidateJiraAction_InvalidProject(t *testing.T) {
	config := map[string]interface{}{"base_url": "http://example.com", "project": ""}
	err := validateJiraAction(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "jira action requires a valid project")
}

func TestValidateEmailAction_Valid(t *testing.T) {
	config := map[string]interface{}{"smtp_server": "smtp.example.com", "port": 587, "from": "from@example.com", "to": "to@example.com"}
	err := validateEmailAction(config)
	assert.NoError(t, err)
}

func TestValidateEmailAction_InvalidPort(t *testing.T) {
	config := map[string]interface{}{"smtp_server": "smtp.example.com", "port": 70000, "from": "from@example.com", "to": "to@example.com"}
	err := validateEmailAction(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email action requires a valid port")
}

func TestValidateCorrelationRule_Valid(t *testing.T) {
	rule := &core.CorrelationRule{
		ID: "1", Name: "test", Description: "desc", Severity: "High", Version: 1,
		Window: 300000000000, Conditions: []core.Condition{{Field: "f", Operator: "equals", Value: "v"}}, Sequence: []string{"event1"},
	}
	err := validateCorrelationRule(rule)
	assert.NoError(t, err)
}

func TestValidateCorrelationRule_InvalidWindow(t *testing.T) {
	rule := &core.CorrelationRule{
		ID: "1", Name: "test", Description: "desc", Severity: "High", Version: 1,
		Window: 0, Conditions: []core.Condition{{Field: "f", Operator: "equals", Value: "v"}}, Sequence: []string{"event1"},
	}
	err := validateCorrelationRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "correlation rule window must be positive")
}

func TestValidateCorrelationRule_NoSequence(t *testing.T) {
	rule := &core.CorrelationRule{
		ID: "1", Name: "test", Description: "desc", Severity: "High", Version: 1,
		Window: 300000000000, Conditions: []core.Condition{{Field: "f", Operator: "equals", Value: "v"}}, Sequence: []string{},
	}
	err := validateCorrelationRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sequence is required")
}

func TestStart_Stop(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	eventStorage := &mockEventStorage{}
	alertStorage := &mockAlertStorage{}
	ruleStorage := &mockRuleStorage{}
	actionStorage := &mockActionStorage{}
	correlationRuleStorage := &mockCorrelationRuleStorage{}

	api := NewAPI(eventStorage, alertStorage, ruleStorage, actionStorage, correlationRuleStorage, cfg, logger)

	assert.Nil(t, api.server)

	// Start in a goroutine since it blocks
	go func() {
		_ = api.Start(":0") // use port 0 for auto assign
		// It will fail or something, but for test, we stop it
	}()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	assert.NoError(t, api.Stop(ctx))
}
