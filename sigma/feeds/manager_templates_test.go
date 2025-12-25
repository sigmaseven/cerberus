// Package feeds provides SIGMA rule feed management capabilities.
package feeds

import (
	"context"
	"sync"
	"testing"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// mockFeedStorage implements FeedStorage interface for testing
type mockFeedStorage struct {
	feeds       map[string]*RuleFeed
	syncResults []*FeedSyncResult
}

func newMockFeedStorage() *mockFeedStorage {
	return &mockFeedStorage{
		feeds:       make(map[string]*RuleFeed),
		syncResults: make([]*FeedSyncResult, 0),
	}
}

func (m *mockFeedStorage) CreateFeed(ctx context.Context, feed *RuleFeed) error {
	if _, exists := m.feeds[feed.ID]; exists {
		return ErrDuplicateFeedID
	}
	m.feeds[feed.ID] = feed
	return nil
}

func (m *mockFeedStorage) GetFeed(ctx context.Context, id string) (*RuleFeed, error) {
	feed, exists := m.feeds[id]
	if !exists {
		return nil, ErrFeedNotFound
	}
	return feed, nil
}

func (m *mockFeedStorage) GetAllFeeds(ctx context.Context) ([]*RuleFeed, error) {
	feeds := make([]*RuleFeed, 0, len(m.feeds))
	for _, feed := range m.feeds {
		feeds = append(feeds, feed)
	}
	return feeds, nil
}

func (m *mockFeedStorage) UpdateFeed(ctx context.Context, id string, feed *RuleFeed) error {
	if _, exists := m.feeds[id]; !exists {
		return ErrFeedNotFound
	}
	m.feeds[id] = feed
	return nil
}

func (m *mockFeedStorage) DeleteFeed(ctx context.Context, id string) error {
	delete(m.feeds, id)
	return nil
}

func (m *mockFeedStorage) UpdateFeedStatus(ctx context.Context, id string, status string) error {
	if feed, exists := m.feeds[id]; exists {
		feed.Status = status
	}
	return nil
}

func (m *mockFeedStorage) UpdateFeedStats(ctx context.Context, id string, stats *FeedStats) error {
	if feed, exists := m.feeds[id]; exists {
		feed.Stats = *stats
	}
	return nil
}

func (m *mockFeedStorage) UpdateLastSync(ctx context.Context, id string, syncTime time.Time) error {
	if feed, exists := m.feeds[id]; exists {
		feed.LastSync = syncTime
	}
	return nil
}

func (m *mockFeedStorage) SaveSyncResult(ctx context.Context, result *FeedSyncResult) error {
	m.syncResults = append(m.syncResults, result)
	return nil
}

func (m *mockFeedStorage) GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*FeedSyncResult, error) {
	var results []*FeedSyncResult
	for _, r := range m.syncResults {
		if r.FeedID == feedID {
			results = append(results, r)
		}
	}
	return results, nil
}

func (m *mockFeedStorage) GetSyncResult(ctx context.Context, syncID string) (*FeedSyncResult, error) {
	for _, r := range m.syncResults {
		if r.FeedID == syncID {
			return r, nil
		}
	}
	return nil, ErrFeedNotFound
}

func (m *mockFeedStorage) Close() error {
	return nil
}

// mockRuleStorage implements RuleStorage interface for testing
type mockRuleStorage struct {
	rules map[string]*core.Rule
}

func newMockRuleStorage() *mockRuleStorage {
	return &mockRuleStorage{
		rules: make(map[string]*core.Rule),
	}
}

func (m *mockRuleStorage) CreateRule(ctx context.Context, rule *core.Rule) error {
	m.rules[rule.ID] = rule
	return nil
}

func (m *mockRuleStorage) GetRuleByID(ctx context.Context, id string) (*core.Rule, error) {
	rule, exists := m.rules[id]
	if !exists {
		return nil, nil
	}
	return rule, nil
}

func (m *mockRuleStorage) UpdateRule(ctx context.Context, rule *core.Rule) error {
	m.rules[rule.ID] = rule
	return nil
}

// Test helper to create a test manager
func newTestManager(t *testing.T) *Manager {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	feedStorage := newMockFeedStorage()
	ruleStorage := newMockRuleStorage()

	manager, err := NewManager(feedStorage, ruleStorage, t.TempDir(), logger.Sugar())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	return manager
}

func TestManager_GetTemplates(t *testing.T) {
	manager := newTestManager(t)

	templates, err := manager.GetTemplates()
	if err != nil {
		t.Fatalf("GetTemplates() returned error: %v", err)
	}

	// Verify templates were loaded
	if len(templates) == 0 {
		t.Error("Expected templates to be loaded, got none")
	}

	// Verify known templates exist
	expectedTemplates := []string{
		"sigmahq-core",
		"sigmahq-windows",
		"sigmahq-linux",
		"sigmahq-network",
		"sigmahq-cloud",
	}

	foundTemplates := make(map[string]bool)
	for _, template := range templates {
		foundTemplates[template.ID] = true
	}

	for _, expectedID := range expectedTemplates {
		if !foundTemplates[expectedID] {
			t.Errorf("Expected template %s not found", expectedID)
		}
	}
}

func TestManager_GetTemplate(t *testing.T) {
	_ = newTestManager // Prevent unused warning in case we need it
	manager := newTestManager(t)

	// Test retrieving existing template
	template := manager.GetTemplate("sigmahq-core")
	if template == nil {
		t.Fatal("Expected to get sigmahq-core template, got nil")
	}

	if template.ID != "sigmahq-core" {
		t.Errorf("Expected template ID sigmahq-core, got %s", template.ID)
	}

	if template.Name == "" {
		t.Error("Template name should not be empty")
	}

	if template.Type != FeedTypeGit {
		t.Errorf("Expected template type %s, got %s", FeedTypeGit, template.Type)
	}

	// Test retrieving non-existent template
	nonExistent := manager.GetTemplate("nonexistent-template")
	if nonExistent != nil {
		t.Error("Expected nil for non-existent template")
	}
}

func TestManager_CreateFeedFromTemplate(t *testing.T) {
	_ = newTestManager // Prevent unused warning
	ctx := context.Background()

	tests := []struct {
		name        string
		templateID  string
		overrides   map[string]interface{}
		expectError bool
		validate    func(t *testing.T, manager *Manager)
	}{
		{
			name:       "Create feed from template with minimal overrides",
			templateID: "sigmahq-windows",
			overrides: map[string]interface{}{
				"name": "My Windows Rules",
			},
			expectError: false,
			validate: func(t *testing.T, m *Manager) {
				feeds, err := m.ListFeeds(ctx)
				if err != nil {
					t.Fatalf("Failed to list feeds: %v", err)
				}
				if len(feeds) != 1 {
					t.Fatalf("Expected 1 feed, got %d", len(feeds))
				}
				feed := feeds[0]
				if feed.Name != "My Windows Rules" {
					t.Errorf("Expected name 'My Windows Rules', got %s", feed.Name)
				}
				if feed.Type != FeedTypeGit {
					t.Errorf("Expected type %s, got %s", FeedTypeGit, feed.Type)
				}
				if feed.URL == "" {
					t.Error("Expected URL to be set from template")
				}
			},
		},
		{
			name:       "Create feed with priority override",
			templateID: "sigmahq-linux",
			overrides: map[string]interface{}{
				"name":     "Linux Detection",
				"priority": 150,
				"enabled":  true,
			},
			expectError: false,
			validate: func(t *testing.T, m *Manager) {
				feeds, err := m.ListFeeds(ctx)
				if err != nil {
					t.Fatalf("Failed to list feeds: %v", err)
				}
				// Find the Linux feed
				var feed *RuleFeed
				for _, f := range feeds {
					if f.Name == "Linux Detection" {
						feed = f
						break
					}
				}
				if feed == nil {
					t.Fatal("Linux Detection feed not found")
				}
				if feed.Priority != 150 {
					t.Errorf("Expected priority 150, got %d", feed.Priority)
				}
				if !feed.Enabled {
					t.Error("Expected feed to be enabled")
				}
			},
		},
		{
			name:       "Create feed with custom branch",
			templateID: "sigmahq-cloud",
			overrides: map[string]interface{}{
				"name":   "Cloud Rules",
				"branch": "develop",
			},
			expectError: false,
			validate: func(t *testing.T, m *Manager) {
				feeds, err := m.ListFeeds(ctx)
				if err != nil {
					t.Fatalf("Failed to list feeds: %v", err)
				}
				var feed *RuleFeed
				for _, f := range feeds {
					if f.Name == "Cloud Rules" {
						feed = f
						break
					}
				}
				if feed == nil {
					t.Fatal("Cloud Rules feed not found")
				}
				if feed.Branch != "develop" {
					t.Errorf("Expected branch 'develop', got %s", feed.Branch)
				}
			},
		},
		{
			name:       "Create feed with update strategy",
			templateID: "sigmahq-network",
			overrides: map[string]interface{}{
				"name":            "Network Detection",
				"update_strategy": UpdateScheduled,
				"update_schedule": "0 */6 * * *",
			},
			expectError: false,
			validate: func(t *testing.T, m *Manager) {
				feeds, err := m.ListFeeds(ctx)
				if err != nil {
					t.Fatalf("Failed to list feeds: %v", err)
				}
				var feed *RuleFeed
				for _, f := range feeds {
					if f.Name == "Network Detection" {
						feed = f
						break
					}
				}
				if feed == nil {
					t.Fatal("Network Detection feed not found")
				}
				if feed.UpdateStrategy != UpdateScheduled {
					t.Errorf("Expected update strategy %s, got %s", UpdateScheduled, feed.UpdateStrategy)
				}
				if feed.UpdateSchedule != "0 */6 * * *" {
					t.Errorf("Expected schedule '0 */6 * * *', got %s", feed.UpdateSchedule)
				}
			},
		},
		{
			name:       "Fail with non-existent template",
			templateID: "nonexistent-template",
			overrides: map[string]interface{}{
				"name": "Should Fail",
			},
			expectError: true,
		},
		{
			name:       "Create feed with template defaults (no name override)",
			templateID: "sigmahq-core",
			overrides:  map[string]interface{}{},
			expectError: false,
			validate: func(t *testing.T, m *Manager) {
				feeds, err := m.ListFeeds(ctx)
				if err != nil {
					t.Fatalf("Failed to list feeds: %v", err)
				}
				// Should use the template's default name
				if len(feeds) != 1 {
					t.Fatalf("Expected 1 feed, got %d", len(feeds))
				}
				feed := feeds[0]
				if feed.Name == "" {
					t.Error("Feed name should not be empty, should use template default")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh manager for each test
			testManager := newTestManager(t)

			err := testManager.CreateFeedFromTemplate(ctx, tt.templateID, tt.overrides)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, testManager)
				}
			}
		})
	}
}

func TestManager_CreateFeedFromTemplate_ValidationErrors(t *testing.T) {
	_ = newTestManager // Prevent unused warning
	manager := newTestManager(t)
	ctx := context.Background()

	// Test with invalid update strategy
	err := manager.CreateFeedFromTemplate(ctx, "sigmahq-core", map[string]interface{}{
		"name":            "Test Feed",
		"update_strategy": "invalid-strategy",
	})
	if err == nil {
		t.Error("Expected error for invalid update strategy")
	}
}

func TestManager_GetTemplates_NilTemplateManager(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create manager with nil template manager by manually setting it
	feedStorage := newMockFeedStorage()
	ruleStorage := newMockRuleStorage()
	manager := &Manager{
		storage:         feedStorage,
		ruleStorage:     ruleStorage,
		handlers:        make(map[string]FeedHandler),
		logger:          logger.Sugar(),
		templateManager: nil, // Force nil template manager
		syncLocks:       make(map[string]*sync.Mutex),
	}

	// BLOCKER-1 FIX: Should return error, not empty list
	templates, err := manager.GetTemplates()
	if err == nil {
		t.Error("Expected error when template manager is nil")
	}
	if templates != nil {
		t.Errorf("Expected nil template list on error, got %d templates", len(templates))
	}

	// GetTemplate should return nil
	template := manager.GetTemplate("sigmahq-core")
	if template != nil {
		t.Error("Expected nil template when manager not initialized")
	}

	// CreateFeedFromTemplate should return error
	ctx := context.Background()
	err = manager.CreateFeedFromTemplate(ctx, "sigmahq-core", map[string]interface{}{
		"name": "Test",
	})
	if err == nil {
		t.Error("Expected error when template manager not initialized")
	}
}

func TestManager_CreateFeedFromTemplate_WithTags(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	err := manager.CreateFeedFromTemplate(ctx, "sigmahq-core", map[string]interface{}{
		"name": "Tagged Feed",
		"tags": []string{"production", "high-priority"},
	})

	if err != nil {
		t.Fatalf("Failed to create feed: %v", err)
	}

	feeds, err := manager.ListFeeds(ctx)
	if err != nil {
		t.Fatalf("Failed to list feeds: %v", err)
	}

	if len(feeds) != 1 {
		t.Fatalf("Expected 1 feed, got %d", len(feeds))
	}

	feed := feeds[0]
	if len(feed.Tags) < 2 {
		t.Errorf("Expected at least 2 tags, got %d", len(feed.Tags))
	}

	// Check for our custom tags
	hasProduction := false
	hasHighPriority := false
	for _, tag := range feed.Tags {
		if tag == "production" {
			hasProduction = true
		}
		if tag == "high-priority" {
			hasHighPriority = true
		}
	}

	if !hasProduction || !hasHighPriority {
		t.Error("Expected custom tags to be present")
	}
}

func TestManager_CreateFeedFromTemplate_WithPathOverrides(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	err := manager.CreateFeedFromTemplate(ctx, "sigmahq-core", map[string]interface{}{
		"name":          "Custom Paths Feed",
		"include_paths": []string{"rules/windows/process_creation/"},
		"exclude_paths": []string{"rules/deprecated/"},
	})

	if err != nil {
		t.Fatalf("Failed to create feed: %v", err)
	}

	feeds, err := manager.ListFeeds(ctx)
	if err != nil {
		t.Fatalf("Failed to list feeds: %v", err)
	}

	if len(feeds) != 1 {
		t.Fatalf("Expected 1 feed, got %d", len(feeds))
	}

	feed := feeds[0]
	if len(feed.IncludePaths) != 1 || feed.IncludePaths[0] != "rules/windows/process_creation/" {
		t.Errorf("Include paths not set correctly: %v", feed.IncludePaths)
	}
	if len(feed.ExcludePaths) != 1 || feed.ExcludePaths[0] != "rules/deprecated/" {
		t.Errorf("Exclude paths not set correctly: %v", feed.ExcludePaths)
	}
}
