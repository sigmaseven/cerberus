package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cerberus/sigma/feeds"
	"cerberus/storage"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockFeedManager is a mock implementation of FeedManagerInterface for testing
type MockFeedManager struct {
	ListFeedsFunc              func(ctx context.Context) ([]*feeds.RuleFeed, error)
	GetFeedFunc                func(ctx context.Context, id string) (*feeds.RuleFeed, error)
	CreateFeedFunc             func(ctx context.Context, feed *feeds.RuleFeed) error
	UpdateFeedFunc             func(ctx context.Context, id string, feed *feeds.RuleFeed) error
	DeleteFeedFunc             func(ctx context.Context, id string) error
	SyncFeedFunc               func(ctx context.Context, id string) (*feeds.FeedSyncResult, error)
	SyncAllFeedsFunc           func(ctx context.Context) ([]*feeds.FeedSyncResult, error)
	ValidateFeedFunc           func(ctx context.Context, id string) error
	TestFeedConnectionFunc     func(ctx context.Context, id string) error
	GetFeedStatsFunc           func(ctx context.Context, id string) (*feeds.FeedStats, error)
	GetFeedHealthFunc          func(ctx context.Context) (map[string]string, error)
	GetSyncHistoryFunc         func(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error)
	GetTemplatesFunc           func() ([]feeds.FeedTemplate, error)
	GetTemplateFunc            func(id string) *feeds.FeedTemplate
	CreateFeedFromTemplateFunc func(ctx context.Context, templateID string, overrides map[string]interface{}) error
}

func (m *MockFeedManager) ListFeeds(ctx context.Context) ([]*feeds.RuleFeed, error) {
	if m.ListFeedsFunc != nil {
		return m.ListFeedsFunc(ctx)
	}
	return nil, nil
}

func (m *MockFeedManager) GetFeed(ctx context.Context, id string) (*feeds.RuleFeed, error) {
	if m.GetFeedFunc != nil {
		return m.GetFeedFunc(ctx, id)
	}
	return nil, feeds.ErrFeedNotFound
}

func (m *MockFeedManager) CreateFeed(ctx context.Context, feed *feeds.RuleFeed) error {
	if m.CreateFeedFunc != nil {
		return m.CreateFeedFunc(ctx, feed)
	}
	return nil
}

func (m *MockFeedManager) UpdateFeed(ctx context.Context, id string, feed *feeds.RuleFeed) error {
	if m.UpdateFeedFunc != nil {
		return m.UpdateFeedFunc(ctx, id, feed)
	}
	return nil
}

func (m *MockFeedManager) DeleteFeed(ctx context.Context, id string) error {
	if m.DeleteFeedFunc != nil {
		return m.DeleteFeedFunc(ctx, id)
	}
	return nil
}

func (m *MockFeedManager) SyncFeed(ctx context.Context, id string) (*feeds.FeedSyncResult, error) {
	if m.SyncFeedFunc != nil {
		return m.SyncFeedFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockFeedManager) SyncAllFeeds(ctx context.Context) ([]*feeds.FeedSyncResult, error) {
	if m.SyncAllFeedsFunc != nil {
		return m.SyncAllFeedsFunc(ctx)
	}
	return nil, nil
}

func (m *MockFeedManager) ValidateFeed(ctx context.Context, id string) error {
	if m.ValidateFeedFunc != nil {
		return m.ValidateFeedFunc(ctx, id)
	}
	return nil
}

func (m *MockFeedManager) TestFeedConnection(ctx context.Context, id string) error {
	if m.TestFeedConnectionFunc != nil {
		return m.TestFeedConnectionFunc(ctx, id)
	}
	return nil
}

func (m *MockFeedManager) GetFeedStats(ctx context.Context, id string) (*feeds.FeedStats, error) {
	if m.GetFeedStatsFunc != nil {
		return m.GetFeedStatsFunc(ctx, id)
	}
	return nil, feeds.ErrFeedNotFound
}

func (m *MockFeedManager) GetFeedHealth(ctx context.Context) (map[string]string, error) {
	if m.GetFeedHealthFunc != nil {
		return m.GetFeedHealthFunc(ctx)
	}
	return nil, nil
}

func (m *MockFeedManager) GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error) {
	if m.GetSyncHistoryFunc != nil {
		return m.GetSyncHistoryFunc(ctx, feedID, limit)
	}
	return nil, nil
}

func (m *MockFeedManager) GetTemplates() ([]feeds.FeedTemplate, error) {
	if m.GetTemplatesFunc != nil {
		return m.GetTemplatesFunc()
	}
	return []feeds.FeedTemplate{}, nil
}

func (m *MockFeedManager) GetTemplate(id string) *feeds.FeedTemplate {
	if m.GetTemplateFunc != nil {
		return m.GetTemplateFunc(id)
	}
	return nil
}

func (m *MockFeedManager) CreateFeedFromTemplate(ctx context.Context, templateID string, overrides map[string]interface{}) error {
	if m.CreateFeedFromTemplateFunc != nil {
		return m.CreateFeedFromTemplateFunc(ctx, templateID, overrides)
	}
	return nil
}

// Helper function to create a test feed
func createTestFeed(id, name string) *feeds.RuleFeed {
	return &feeds.RuleFeed{
		ID:             id,
		Name:           name,
		Description:    "Test feed description",
		Type:           feeds.FeedTypeGit,
		Status:         feeds.FeedStatusActive,
		Enabled:        true,
		URL:            "https://github.com/test/repo.git",
		Branch:         "main",
		UpdateStrategy: feeds.UpdateManual,
		Priority:       100,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Stats: feeds.FeedStats{
			TotalRules:    100,
			ImportedRules: 50,
		},
	}
}

// =============================================================================
// List Feeds Tests
// =============================================================================

func TestListFeeds_Success(t *testing.T) {
	mockFeeds := []*feeds.RuleFeed{
		createTestFeed("feed-1", "Feed 1"),
		createTestFeed("feed-2", "Feed 2"),
	}

	mockFeedMgr := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return mockFeeds, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds", nil)
	w := httptest.NewRecorder()

	testAPI.listFeeds(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response FeedsListResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Len(t, response.Feeds, 2)
	assert.Equal(t, 2, response.Total)
}

func TestListFeeds_WithPagination(t *testing.T) {
	mockFeeds := []*feeds.RuleFeed{
		createTestFeed("feed-1", "Feed 1"),
		createTestFeed("feed-2", "Feed 2"),
		createTestFeed("feed-3", "Feed 3"),
	}

	mockFeedMgr := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return mockFeeds, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds?page=2&limit=2", nil)
	w := httptest.NewRecorder()

	testAPI.listFeeds(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response FeedsListResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Len(t, response.Feeds, 1) // Last page with 1 item
	assert.Equal(t, 3, response.Total)
	assert.Equal(t, 2, response.Page)
}

func TestListFeeds_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("GET", "/api/v1/feeds", nil)
	w := httptest.NewRecorder()

	testAPI.listFeeds(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestListFeeds_Error(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		ListFeedsFunc: func(ctx context.Context) ([]*feeds.RuleFeed, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds", nil)
	w := httptest.NewRecorder()

	testAPI.listFeeds(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// Get Feed By ID Tests
// =============================================================================

func TestGetFeedByID_Success(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			if id == "feed-1" {
				return testFeed, nil
			}
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedByID(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response FeedResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "feed-1", response.Feed.ID)
	assert.Equal(t, "Test Feed", response.Feed.Name)
}

func TestGetFeedByID_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.getFeedByID(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFeedByID_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedByID(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// =============================================================================
// Create Feed Tests
// =============================================================================

func TestCreateFeed_Success(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		CreateFeedFunc: func(ctx context.Context, feed *feeds.RuleFeed) error {
			return nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	reqBody := CreateFeedRequest{
		Name:        "New Feed",
		Description: "Test description",
		Type:        feeds.FeedTypeGit,
		Enabled:     true,
		URL:         "https://github.com/test/repo.git",
		Branch:      "main",
		Priority:    100,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/feeds", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	testAPI.createFeed(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response FeedResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "New Feed", response.Feed.Name)
	assert.NotEmpty(t, response.Feed.ID) // ID should be generated
}

func TestCreateFeed_MissingName(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = &MockFeedManager{}

	reqBody := CreateFeedRequest{
		Type: feeds.FeedTypeGit,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/feeds", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	testAPI.createFeed(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateFeed_DuplicateID(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		CreateFeedFunc: func(ctx context.Context, feed *feeds.RuleFeed) error {
			return feeds.ErrDuplicateFeedID
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	reqBody := CreateFeedRequest{
		ID:   "feed-1",
		Name: "Duplicate Feed",
		Type: feeds.FeedTypeGit,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/feeds", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	testAPI.createFeed(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestCreateFeed_ValidationError(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		CreateFeedFunc: func(ctx context.Context, feed *feeds.RuleFeed) error {
			return feeds.ErrInvalidFeedType
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	reqBody := CreateFeedRequest{
		Name: "Invalid Feed",
		Type: "invalid-type",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/feeds", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	testAPI.createFeed(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// Update Feed Tests
// =============================================================================

func TestUpdateFeed_Success(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Original Name")

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		UpdateFeedFunc: func(ctx context.Context, id string, feed *feeds.RuleFeed) error {
			return nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	newName := "Updated Name"
	reqBody := UpdateFeedRequest{
		Name: &newName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("PUT", "/api/v1/feeds/feed-1", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.updateFeed(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateFeed_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	newName := "Updated Name"
	reqBody := UpdateFeedRequest{
		Name: &newName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("PUT", "/api/v1/feeds/nonexistent", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.updateFeed(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateFeed_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	newName := "Updated Name"
	reqBody := UpdateFeedRequest{
		Name: &newName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("PUT", "/api/v1/feeds/feed-1", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.updateFeed(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestUpdateFeed_InvalidJSON(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("PUT", "/api/v1/feeds/feed-1", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.updateFeed(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateFeed_ValidationError(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		UpdateFeedFunc: func(ctx context.Context, id string, feed *feeds.RuleFeed) error {
			return feeds.ErrMissingURL
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	newURL := ""
	reqBody := UpdateFeedRequest{
		URL: &newURL,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("PUT", "/api/v1/feeds/feed-1", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.updateFeed(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateFeed_GetError(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	newName := "Updated Name"
	reqBody := UpdateFeedRequest{
		Name: &newName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("PUT", "/api/v1/feeds/feed-1", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.updateFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// Delete Feed Tests
// =============================================================================

func TestDeleteFeed_Success(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		DeleteFeedFunc: func(ctx context.Context, id string) error {
			return nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("DELETE", "/api/v1/feeds/feed-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.deleteFeed(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteFeed_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("DELETE", "/api/v1/feeds/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.deleteFeed(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteFeed_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("DELETE", "/api/v1/feeds/feed-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.deleteFeed(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestDeleteFeed_GetError(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("DELETE", "/api/v1/feeds/feed-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.deleteFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteFeed_DeleteError(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		DeleteFeedFunc: func(ctx context.Context, id string) error {
			return errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("DELETE", "/api/v1/feeds/feed-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.deleteFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// Sync Feed Tests
// =============================================================================

func TestSyncFeed_Success(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")
	testFeed.Enabled = true

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		// Provide a mock SyncFeed function for the background goroutine
		// Note: It runs async so we can't test the result, just that it doesn't panic
		SyncFeedFunc: func(ctx context.Context, id string) (*feeds.FeedSyncResult, error) {
			return &feeds.FeedSyncResult{
				FeedID:   id,
				FeedName: "Test Feed",
				Success:  true,
			}, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/sync", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.syncFeed(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)

	var result SyncStatusResponse
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "accepted", result.Status)
	assert.Equal(t, "feed-1", result.FeedID)
	assert.Contains(t, result.StatusURL, "/stats")
}

func TestSyncFeed_FeedDisabled(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")
	testFeed.Enabled = false

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/sync", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.syncFeed(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSyncFeed_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/nonexistent/sync", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.syncFeed(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSyncFeed_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/sync", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.syncFeed(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestSyncFeed_GetError(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/sync", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.syncFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// Sync All Feeds Tests
// =============================================================================

func TestSyncAllFeeds_Success(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		// Provide a mock SyncAllFeeds function for the background goroutine
		// Note: It runs async so we can't test the result, just that it doesn't panic
		SyncAllFeedsFunc: func(ctx context.Context) ([]*feeds.FeedSyncResult, error) {
			return []*feeds.FeedSyncResult{
				{FeedID: "feed-1", Success: true},
			}, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/sync-all", nil)
	w := httptest.NewRecorder()

	testAPI.syncAllFeeds(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)

	var response SyncStatusResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "accepted", response.Status)
	assert.Contains(t, response.Message, "background")
}

func TestSyncAllFeeds_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("POST", "/api/v1/feeds/sync-all", nil)
	w := httptest.NewRecorder()

	testAPI.syncAllFeeds(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// =============================================================================
// Get Feed Stats Tests
// =============================================================================

func TestGetFeedStats_Success(t *testing.T) {
	stats := &feeds.FeedStats{
		TotalRules:       100,
		ImportedRules:    50,
		UpdatedRules:     30,
		FailedRules:      5,
		LastSyncDuration: 30.5,
		SyncCount:        10,
	}

	mockFeedMgr := &MockFeedManager{
		GetFeedStatsFunc: func(ctx context.Context, id string) (*feeds.FeedStats, error) {
			return stats, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1/stats", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedStats(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response feeds.FeedStats
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, 100, response.TotalRules)
}

func TestGetFeedStats_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1/stats", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedStats(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestGetFeedStats_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedStatsFunc: func(ctx context.Context, id string) (*feeds.FeedStats, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/nonexistent/stats", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.getFeedStats(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFeedStats_Error(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedStatsFunc: func(ctx context.Context, id string) (*feeds.FeedStats, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1/stats", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedStats(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// Feed Templates Tests
// =============================================================================

func TestGetFeedTemplates_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/feeds/templates", nil)
	w := httptest.NewRecorder()

	testAPI.getFeedTemplates(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var templates []feeds.FeedTemplate
	err := json.NewDecoder(w.Body).Decode(&templates)
	require.NoError(t, err)
	assert.Greater(t, len(templates), 0) // Should have at least one template
}

// =============================================================================
// Test Feed Connection Tests
// =============================================================================

func TestTestFeed_Success(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		TestFeedConnectionFunc: func(ctx context.Context, id string) error {
			return nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/test", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.testFeed(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "success", response["status"])
}

func TestTestFeed_ConnectionFailed(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		TestFeedConnectionFunc: func(ctx context.Context, id string) error {
			return feeds.ErrConnectionFailed
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/test", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.testFeed(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// Enable/Disable Feed Tests
// =============================================================================

func TestEnableFeed_Success(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")
	testFeed.Enabled = false

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		UpdateFeedFunc: func(ctx context.Context, id string, feed *feeds.RuleFeed) error {
			assert.True(t, feed.Enabled)
			return nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/enable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.enableFeed(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDisableFeed_Success(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")
	testFeed.Enabled = true

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		UpdateFeedFunc: func(ctx context.Context, id string, feed *feeds.RuleFeed) error {
			assert.False(t, feed.Enabled)
			return nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/disable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.disableFeed(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEnableFeed_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/nonexistent/enable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.enableFeed(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEnableFeed_GetError(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/enable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.enableFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestEnableFeed_UpdateError(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")
	testFeed.Enabled = false

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		UpdateFeedFunc: func(ctx context.Context, id string, feed *feeds.RuleFeed) error {
			return errors.New("update failed")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/enable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.enableFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestEnableFeed_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/enable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.enableFeed(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestDisableFeed_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/nonexistent/disable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.disableFeed(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDisableFeed_GetError(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/disable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.disableFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDisableFeed_UpdateError(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")
	testFeed.Enabled = true

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		UpdateFeedFunc: func(ctx context.Context, id string, feed *feeds.RuleFeed) error {
			return errors.New("update failed")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/disable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.disableFeed(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDisableFeed_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("POST", "/api/v1/feeds/feed-1/disable", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.disableFeed(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// =============================================================================
// Get Feed History Tests
// =============================================================================

func TestGetFeedHistory_Success(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")

	now := time.Now()
	syncHistory := []*feeds.FeedSyncResult{
		{
			FeedID:    "feed-1",
			FeedName:  "Test Feed",
			StartTime: now.Add(-1 * time.Hour),
			EndTime:   now.Add(-55 * time.Minute),
			Duration:  300,
			Success:   true,
			Stats: feeds.FeedStats{
				TotalRules:    100,
				ImportedRules: 50,
			},
		},
		{
			FeedID:    "feed-1",
			FeedName:  "Test Feed",
			StartTime: now.Add(-2 * time.Hour),
			EndTime:   now.Add(-115 * time.Minute),
			Duration:  300,
			Success:   true,
			Stats: feeds.FeedStats{
				TotalRules:    95,
				ImportedRules: 45,
			},
		},
	}

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		GetSyncHistoryFunc: func(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error) {
			assert.Equal(t, "feed-1", feedID)
			assert.Equal(t, 10, limit)
			return syncHistory, nil
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1/history?limit=10", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedHistory(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var history []*feeds.FeedSyncResult
	err := json.NewDecoder(w.Body).Decode(&history)
	require.NoError(t, err)
	assert.Len(t, history, 2)
	assert.Equal(t, "feed-1", history[0].FeedID)
}

func TestGetFeedHistory_NotFound(t *testing.T) {
	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return nil, feeds.ErrFeedNotFound
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/nonexistent/history", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	testAPI.getFeedHistory(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFeedHistory_HistoryError(t *testing.T) {
	testFeed := createTestFeed("feed-1", "Test Feed")

	mockFeedMgr := &MockFeedManager{
		GetFeedFunc: func(ctx context.Context, id string) (*feeds.RuleFeed, error) {
			return testFeed, nil
		},
		GetSyncHistoryFunc: func(ctx context.Context, feedID string, limit int) ([]*feeds.FeedSyncResult, error) {
			return nil, errors.New("database error")
		},
	}

	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = mockFeedMgr

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1/history", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedHistory(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetFeedHistory_NoManager(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = nil

	req := httptest.NewRequest("GET", "/api/v1/feeds/feed-1/history", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "feed-1"})
	w := httptest.NewRecorder()

	testAPI.getFeedHistory(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestGetFeedHistory_MissingID(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()
	testAPI.feedManager = &MockFeedManager{}

	req := httptest.NewRequest("GET", "/api/v1/feeds//history", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()

	testAPI.getFeedHistory(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestGetUserFromContext(t *testing.T) {
	// Test with user in context - use type-safe ContextKeyUser
	user := &storage.User{Username: "testuser"}
	ctx := context.WithValue(context.Background(), ContextKeyUser, user)
	result := getUserFromContext(ctx)
	assert.NotNil(t, result, "Should extract user from context with ContextKeyUser")
	assert.Equal(t, "testuser", result.Username)

	// Test with no user in context
	ctx = context.Background()
	result = getUserFromContext(ctx)
	assert.Nil(t, result, "Should return nil when no user in context")

	// Test with wrong key type (string instead of contextKey)
	ctx = context.WithValue(context.Background(), "user", user)
	result = getUserFromContext(ctx)
	assert.Nil(t, result, "Should return nil when wrong key type is used")
}

func TestParsePaginationParams(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		defaultLimit  int
		maxLimit      int
		expectedPage  int
		expectedLimit int
	}{
		{
			name:          "default values",
			query:         "",
			defaultLimit:  50,
			maxLimit:      100,
			expectedPage:  1,
			expectedLimit: 50,
		},
		{
			name:          "custom page and limit",
			query:         "page=2&limit=25",
			defaultLimit:  50,
			maxLimit:      100,
			expectedPage:  2,
			expectedLimit: 25,
		},
		{
			name:          "limit exceeds max",
			query:         "page=1&limit=150",
			defaultLimit:  50,
			maxLimit:      100,
			expectedPage:  1,
			expectedLimit: 50, // Should use default
		},
		{
			name:          "invalid page",
			query:         "page=-1&limit=20",
			defaultLimit:  50,
			maxLimit:      100,
			expectedPage:  1, // Should use default
			expectedLimit: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test?"+tt.query, nil)
			page, limit := parsePaginationParams(req, tt.defaultLimit, tt.maxLimit)
			assert.Equal(t, tt.expectedPage, page)
			assert.Equal(t, tt.expectedLimit, limit)
		})
	}
}
