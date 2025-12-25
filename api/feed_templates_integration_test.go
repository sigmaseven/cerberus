// Package api provides HTTP API handlers for Cerberus SIEM.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cerberus/sigma/feeds"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// mockFeedManagerWithTemplates implements FeedManagerInterface for template testing
type mockFeedManagerWithTemplates struct {
	feeds           []*feeds.RuleFeed
	templates       []feeds.FeedTemplate
	createFeedCalls int
	templateCalls   map[string]map[string]interface{} // Track template calls with overrides
}

func newMockFeedManagerWithTemplates() *mockFeedManagerWithTemplates {
	// Create some basic templates for testing
	templates := []feeds.FeedTemplate{
		{
			ID:                  "test-template",
			Name:                "Test Template",
			Description:         "Template for testing",
			Type:                "git",
			URL:                 "https://github.com/test/repo.git",
			Branch:              "main",
			RecommendedPriority: 100,
			EstimatedRuleCount:  500,
			Tags:                []string{"test"},
		},
		{
			ID:                  "sigmahq-windows",
			Name:                "SigmaHQ Windows Rules",
			Description:         "Windows detection rules",
			Type:                "git",
			URL:                 "https://github.com/SigmaHQ/sigma.git",
			Branch:              "master",
			IncludePaths:        []string{"rules/windows/"},
			RecommendedPriority: 100,
			EstimatedRuleCount:  2000,
			Tags:                []string{"official", "windows"},
		},
	}

	return &mockFeedManagerWithTemplates{
		feeds:         make([]*feeds.RuleFeed, 0),
		templates:     templates,
		templateCalls: make(map[string]map[string]interface{}),
	}
}

func (m *mockFeedManagerWithTemplates) ListFeeds(ctx context.Context) ([]*feeds.RuleFeed, error) {
	return m.feeds, nil
}

func (m *mockFeedManagerWithTemplates) GetFeed(ctx context.Context, id string) (*feeds.RuleFeed, error) {
	for _, feed := range m.feeds {
		if feed.ID == id {
			return feed, nil
		}
	}
	return nil, feeds.ErrFeedNotFound
}

func (m *mockFeedManagerWithTemplates) CreateFeed(ctx context.Context, feed *feeds.RuleFeed) error {
	m.createFeedCalls++
	m.feeds = append(m.feeds, feed)
	return nil
}

func (m *mockFeedManagerWithTemplates) UpdateFeed(ctx context.Context, id string, feed *feeds.RuleFeed) error {
	return nil
}

func (m *mockFeedManagerWithTemplates) DeleteFeed(ctx context.Context, id string) error {
	return nil
}

func (m *mockFeedManagerWithTemplates) SyncFeed(ctx context.Context, id string) (*feeds.FeedSyncResult, error) {
	return nil, nil
}

func (m *mockFeedManagerWithTemplates) SyncAllFeeds(ctx context.Context) ([]*feeds.FeedSyncResult, error) {
	return nil, nil
}

func (m *mockFeedManagerWithTemplates) ValidateFeed(ctx context.Context, id string) error {
	return nil
}

func (m *mockFeedManagerWithTemplates) TestFeedConnection(ctx context.Context, id string) error {
	return nil
}

func (m *mockFeedManagerWithTemplates) GetFeedStats(ctx context.Context, id string) (*feeds.FeedStats, error) {
	return &feeds.FeedStats{}, nil
}

func (m *mockFeedManagerWithTemplates) GetFeedHealth(ctx context.Context) (map[string]string, error) {
	return make(map[string]string), nil
}

func (m *mockFeedManagerWithTemplates) GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error) {
	return nil, nil
}

// Template operations
func (m *mockFeedManagerWithTemplates) GetTemplates() ([]feeds.FeedTemplate, error) {
	return m.templates, nil
}

func (m *mockFeedManagerWithTemplates) GetTemplate(id string) *feeds.FeedTemplate {
	for i := range m.templates {
		if m.templates[i].ID == id {
			return &m.templates[i]
		}
	}
	return nil
}

func (m *mockFeedManagerWithTemplates) CreateFeedFromTemplate(ctx context.Context, templateID string, overrides map[string]interface{}) error {
	m.templateCalls[templateID] = overrides

	// Find template
	template := m.GetTemplate(templateID)
	if template == nil {
		return feeds.ErrFeedNotFound
	}

	// Create feed from template
	feed := &feeds.RuleFeed{
		Name:        template.Name,
		Description: template.Description,
		Type:        template.Type,
		URL:         template.URL,
		Branch:      template.Branch,
		Priority:    template.RecommendedPriority,
	}

	// Apply overrides
	if name, ok := overrides["name"].(string); ok {
		feed.Name = name
	}
	if priority, ok := overrides["priority"].(int); ok {
		feed.Priority = priority
	} else if priorityFloat, ok := overrides["priority"].(float64); ok {
		feed.Priority = int(priorityFloat)
	}
	if enabled, ok := overrides["enabled"].(bool); ok {
		feed.Enabled = enabled
	}
	if branch, ok := overrides["branch"].(string); ok {
		feed.Branch = branch
	}

	m.feeds = append(m.feeds, feed)
	return nil
}

func TestAPI_CreateFeedFromTemplate_Success(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mockManager := newMockFeedManagerWithTemplates()
	api := &API{
		logger:      logger.Sugar(),
		feedManager: mockManager,
	}

	requestBody := CreateFeedRequest{
		TemplateID: "test-template",
		Name:       "My Test Feed",
		Enabled:    true,
		Priority:   150,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Create router
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds", api.createFeed).Methods(http.MethodPost)
	router.ServeHTTP(w, req)

	// Check status code
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// Verify feed was created
	if len(mockManager.feeds) != 1 {
		t.Fatalf("Expected 1 feed to be created, got %d", len(mockManager.feeds))
	}

	feed := mockManager.feeds[0]
	if feed.Name != "My Test Feed" {
		t.Errorf("Expected feed name 'My Test Feed', got %s", feed.Name)
	}
	if feed.Priority != 150 {
		t.Errorf("Expected priority 150, got %d", feed.Priority)
	}
	if !feed.Enabled {
		t.Error("Expected feed to be enabled")
	}

	// Verify template was used
	if _, exists := mockManager.templateCalls["test-template"]; !exists {
		t.Error("Expected CreateFeedFromTemplate to be called with test-template")
	}

	// Parse response
	var response FeedResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Feed == nil {
		t.Fatal("Expected feed in response")
	}
	if response.Feed.Name != "My Test Feed" {
		t.Errorf("Expected response feed name 'My Test Feed', got %s", response.Feed.Name)
	}
}

func TestAPI_CreateFeedFromTemplate_WithBranchOverride(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mockManager := newMockFeedManagerWithTemplates()
	api := &API{
		logger:      logger.Sugar(),
		feedManager: mockManager,
	}

	requestBody := CreateFeedRequest{
		TemplateID: "sigmahq-windows",
		Name:       "Windows Detection - Dev",
		Branch:     "develop",
		Enabled:    true,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds", api.createFeed).Methods(http.MethodPost)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	if len(mockManager.feeds) != 1 {
		t.Fatalf("Expected 1 feed, got %d", len(mockManager.feeds))
	}

	feed := mockManager.feeds[0]
	if feed.Branch != "develop" {
		t.Errorf("Expected branch 'develop', got %s", feed.Branch)
	}

	// Verify override was passed
	overrides := mockManager.templateCalls["sigmahq-windows"]
	if branch, ok := overrides["branch"].(string); !ok || branch != "develop" {
		t.Error("Expected branch override to be passed to CreateFeedFromTemplate")
	}
}

func TestAPI_CreateFeedFromTemplate_TemplateNotFound(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mockManager := newMockFeedManagerWithTemplates()
	api := &API{
		logger:      logger.Sugar(),
		feedManager: mockManager,
	}

	requestBody := CreateFeedRequest{
		TemplateID: "nonexistent-template",
		Name:       "Should Fail",
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds", api.createFeed).Methods(http.MethodPost)
	router.ServeHTTP(w, req)

	// Should return not found or bad request
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d or %d, got %d", http.StatusNotFound, http.StatusBadRequest, w.Code)
	}

	// No feed should be created
	if len(mockManager.feeds) != 0 {
		t.Errorf("Expected no feeds to be created, got %d", len(mockManager.feeds))
	}
}

func TestAPI_CreateFeedFromTemplate_MissingName(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mockManager := newMockFeedManagerWithTemplates()
	api := &API{
		logger:      logger.Sugar(),
		feedManager: mockManager,
	}

	requestBody := CreateFeedRequest{
		TemplateID: "test-template",
		// Name is missing
		Enabled: true,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds", api.createFeed).Methods(http.MethodPost)
	router.ServeHTTP(w, req)

	// Should return bad request
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestAPI_CreateFeed_ManualCreationStillWorks(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	mockManager := newMockFeedManagerWithTemplates()
	api := &API{
		logger:      logger.Sugar(),
		feedManager: mockManager,
	}

	// Create feed without template_id (manual creation)
	requestBody := CreateFeedRequest{
		Name:    "Manual Feed",
		Type:    "git",
		URL:     "https://github.com/test/rules.git",
		Enabled: true,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds", api.createFeed).Methods(http.MethodPost)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// Verify feed was created via CreateFeed, not CreateFeedFromTemplate
	if mockManager.createFeedCalls != 1 {
		t.Errorf("Expected CreateFeed to be called once, got %d calls", mockManager.createFeedCalls)
	}

	if len(mockManager.templateCalls) != 0 {
		t.Error("Expected CreateFeedFromTemplate not to be called for manual creation")
	}
}
