// Package api provides HTTP API handlers for Cerberus SIEM.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cerberus/sigma/feeds"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func TestGetFeedTemplates(t *testing.T) {
	// Create test API instance
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	sugar := logger.Sugar()

	api := &API{
		logger: sugar,
	}

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/templates", nil)
	w := httptest.NewRecorder()

	// Create router and register handler
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds/templates", api.getFeedTemplates).Methods(http.MethodGet)

	// Execute request
	router.ServeHTTP(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var templates []feeds.FeedTemplate
	if err := json.NewDecoder(w.Body).Decode(&templates); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify templates were returned
	if len(templates) == 0 {
		t.Error("Expected templates in response, got none")
	}

	// Verify known templates exist
	expectedTemplates := map[string]bool{
		"sigmahq-core":             false,
		"sigmahq-windows":          false,
		"sigmahq-linux":            false,
		"sigmahq-network":          false,
		"sigmahq-cloud":            false,
		"sigmahq-emerging-threats": false,
	}

	for _, template := range templates {
		if _, exists := expectedTemplates[template.ID]; exists {
			expectedTemplates[template.ID] = true
		}

		// Validate required fields
		if template.ID == "" {
			t.Error("Template has empty ID")
		}
		if template.Name == "" {
			t.Error("Template has empty name")
		}
		if template.Type == "" {
			t.Error("Template has empty type")
		}
		if template.Description == "" {
			t.Error("Template has empty description")
		}
	}

	// Check that all expected templates were found
	for id, found := range expectedTemplates {
		if !found {
			t.Errorf("Expected template %s not found in response", id)
		}
	}
}

func TestGetFeedTemplates_ContentType(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	sugar := logger.Sugar()

	api := &API{
		logger: sugar,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/templates", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds/templates", api.getFeedTemplates).Methods(http.MethodGet)
	router.ServeHTTP(w, req)

	// Verify content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}

func TestGetFeedTemplates_ValidJSON(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	sugar := logger.Sugar()

	api := &API{
		logger: sugar,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/templates", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds/templates", api.getFeedTemplates).Methods(http.MethodGet)
	router.ServeHTTP(w, req)

	// Verify valid JSON response
	var templates []feeds.FeedTemplate
	if err := json.NewDecoder(w.Body).Decode(&templates); err != nil {
		t.Errorf("Response is not valid JSON: %v", err)
	}
}

func TestGetFeedTemplates_TemplateStructure(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	sugar := logger.Sugar()

	api := &API{
		logger: sugar,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/templates", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds/templates", api.getFeedTemplates).Methods(http.MethodGet)
	router.ServeHTTP(w, req)

	var templates []feeds.FeedTemplate
	if err := json.NewDecoder(w.Body).Decode(&templates); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Validate first template structure
	if len(templates) == 0 {
		t.Fatal("No templates returned")
	}

	template := templates[0]

	// Check all required fields
	requiredFields := map[string]interface{}{
		"ID":                  template.ID,
		"Name":                template.Name,
		"Description":         template.Description,
		"Type":                template.Type,
		"RecommendedPriority": template.RecommendedPriority,
	}

	for field, value := range requiredFields {
		switch v := value.(type) {
		case string:
			if v == "" {
				t.Errorf("Template field %s is empty", field)
			}
		case int:
			if field == "RecommendedPriority" && v == 0 {
				t.Errorf("Template field %s is zero", field)
			}
		}
	}
}

func TestGetFeedTemplates_GitTemplatesHaveURL(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	sugar := logger.Sugar()

	api := &API{
		logger: sugar,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/templates", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds/templates", api.getFeedTemplates).Methods(http.MethodGet)
	router.ServeHTTP(w, req)

	var templates []feeds.FeedTemplate
	if err := json.NewDecoder(w.Body).Decode(&templates); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify git templates have URL
	for _, template := range templates {
		if template.Type == feeds.FeedTypeGit && template.URL == "" {
			t.Errorf("Git template %s has empty URL", template.ID)
		}
	}
}

func TestGetFeedTemplates_TagsPresent(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	sugar := logger.Sugar()

	api := &API{
		logger: sugar,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/templates", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/feeds/templates", api.getFeedTemplates).Methods(http.MethodGet)
	router.ServeHTTP(w, req)

	var templates []feeds.FeedTemplate
	if err := json.NewDecoder(w.Body).Decode(&templates); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify templates have tags
	for _, template := range templates {
		if len(template.Tags) == 0 {
			t.Errorf("Template %s has no tags", template.ID)
		}
	}
}
