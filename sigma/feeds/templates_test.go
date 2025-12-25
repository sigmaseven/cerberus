// Package feeds provides SIGMA rule feed management capabilities.
package feeds

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewTemplateManager(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	if tm == nil {
		t.Fatal("Template manager is nil")
	}

	// Verify templates were loaded
	if tm.GetTemplateCount() == 0 {
		t.Error("No templates loaded from embedded file")
	}

	// Verify last load time is recent
	if time.Since(tm.GetLastLoadTime()) > time.Second {
		t.Error("Last load time is not recent")
	}
}

func TestLoadEmbeddedTemplates(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	templates := tm.ListTemplates()
	if len(templates) == 0 {
		t.Fatal("No templates loaded")
	}

	// Verify known templates exist
	expectedTemplates := []string{
		"sigmahq-core",
		"sigmahq-windows",
		"sigmahq-linux",
		"sigmahq-network",
		"sigmahq-cloud",
		"sigmahq-emerging-threats",
	}

	for _, expectedID := range expectedTemplates {
		template := tm.GetTemplate(expectedID)
		if template == nil {
			t.Errorf("Expected template %s not found", expectedID)
			continue
		}

		// Validate required fields
		if template.ID != expectedID {
			t.Errorf("Template ID mismatch: got %s, want %s", template.ID, expectedID)
		}
		if template.Name == "" {
			t.Errorf("Template %s has empty name", expectedID)
		}
		if template.Type == "" {
			t.Errorf("Template %s has empty type", expectedID)
		}
		if template.URL == "" && template.Type == FeedTypeGit {
			t.Errorf("Git template %s has empty URL", expectedID)
		}
	}
}

func TestGetTemplate(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Test existing template
	template := tm.GetTemplate("sigmahq-core")
	if template == nil {
		t.Fatal("Failed to get sigmahq-core template")
	}

	if template.ID != "sigmahq-core" {
		t.Errorf("Template ID mismatch: got %s, want sigmahq-core", template.ID)
	}

	// Test non-existent template
	notFound := tm.GetTemplate("nonexistent-template")
	if notFound != nil {
		t.Error("Expected nil for non-existent template")
	}

	// Verify returned template is a copy (modification doesn't affect cache)
	originalName := template.Name
	template.Name = "Modified Name"

	templateAgain := tm.GetTemplate("sigmahq-core")
	if templateAgain.Name != originalName {
		t.Error("Template modification affected cached template")
	}
}

func TestListTemplates(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	templates := tm.ListTemplates()
	if len(templates) == 0 {
		t.Fatal("No templates returned from ListTemplates")
	}

	// Verify all templates have required fields
	for _, template := range templates {
		if template.ID == "" {
			t.Error("Template has empty ID")
		}
		if template.Name == "" {
			t.Error("Template has empty name")
		}
		if template.Type == "" {
			t.Error("Template has empty type")
		}
	}

	// Verify returned list is a copy (modification doesn't affect cache)
	templates[0].Name = "Modified Name"
	templatesAgain := tm.ListTemplates()
	if templatesAgain[0].Name == "Modified Name" {
		t.Error("List modification affected cached templates")
	}
}

func TestApplyTemplate(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	tests := []struct {
		name        string
		templateID  string
		overrides   map[string]interface{}
		expectError bool
		validate    func(*testing.T, *RuleFeed)
	}{
		{
			name:       "basic template application",
			templateID: "sigmahq-core",
			overrides: map[string]interface{}{
				"name": "My Custom Feed",
			},
			expectError: false,
			validate: func(t *testing.T, feed *RuleFeed) {
				if feed.Name != "My Custom Feed" {
					t.Errorf("Feed name not overridden: got %s", feed.Name)
				}
				if feed.Type != FeedTypeGit {
					t.Errorf("Feed type mismatch: got %s, want %s", feed.Type, FeedTypeGit)
				}
				if feed.URL == "" {
					t.Error("Feed URL is empty")
				}
			},
		},
		{
			name:       "template with all overrides",
			templateID: "sigmahq-windows",
			overrides: map[string]interface{}{
				"name":              "Custom Windows Feed",
				"description":       "Custom description",
				"enabled":           false,
				"auto_enable_rules": true,
				"priority":          150,
				"update_strategy":   UpdateScheduled,
				"update_schedule":   "0 */6 * * *",
				"branch":            "develop",
			},
			expectError: false,
			validate: func(t *testing.T, feed *RuleFeed) {
				if feed.Name != "Custom Windows Feed" {
					t.Errorf("Name not overridden: got %s", feed.Name)
				}
				if feed.Description != "Custom description" {
					t.Errorf("Description not overridden: got %s", feed.Description)
				}
				if feed.Enabled {
					t.Error("Enabled should be false")
				}
				if !feed.AutoEnableRules {
					t.Error("AutoEnableRules should be true")
				}
				if feed.Priority != 150 {
					t.Errorf("Priority not overridden: got %d", feed.Priority)
				}
				if feed.UpdateStrategy != UpdateScheduled {
					t.Errorf("UpdateStrategy not overridden: got %s", feed.UpdateStrategy)
				}
				if feed.UpdateSchedule != "0 */6 * * *" {
					t.Errorf("UpdateSchedule not overridden: got %s", feed.UpdateSchedule)
				}
				if feed.Branch != "develop" {
					t.Errorf("Branch not overridden: got %s", feed.Branch)
				}
			},
		},
		{
			name:       "template with path overrides",
			templateID: "sigmahq-linux",
			overrides: map[string]interface{}{
				"name":          "Custom Linux Feed",
				"include_paths": []string{"/custom/path1", "/custom/path2"},
				"exclude_paths": []string{"/exclude/path"},
				"tags":          []string{"custom-tag", "test-tag"},
			},
			expectError: false,
			validate: func(t *testing.T, feed *RuleFeed) {
				if len(feed.IncludePaths) != 2 {
					t.Errorf("IncludePaths count mismatch: got %d, want 2", len(feed.IncludePaths))
				}
				if len(feed.ExcludePaths) != 1 {
					t.Errorf("ExcludePaths count mismatch: got %d, want 1", len(feed.ExcludePaths))
				}
				// Tags should be appended to template tags
				if len(feed.Tags) < 2 {
					t.Errorf("Tags should include custom tags: got %v", feed.Tags)
				}
			},
		},
		{
			name:       "nonexistent template",
			templateID: "nonexistent",
			overrides: map[string]interface{}{
				"name": "Test Feed",
			},
			expectError: true,
		},
		{
			name:       "invalid name override type",
			templateID: "sigmahq-core",
			overrides: map[string]interface{}{
				"name": 12345, // Should be string
			},
			expectError: true,
		},
		{
			name:       "invalid enabled override type",
			templateID: "sigmahq-core",
			overrides: map[string]interface{}{
				"name":    "Test Feed",
				"enabled": "true", // Should be bool
			},
			expectError: true,
		},
		{
			name:       "invalid priority override type",
			templateID: "sigmahq-core",
			overrides: map[string]interface{}{
				"name":     "Test Feed",
				"priority": "high", // Should be int
			},
			expectError: true,
		},
		{
			name:       "invalid update strategy",
			templateID: "sigmahq-core",
			overrides: map[string]interface{}{
				"name":            "Test Feed",
				"update_strategy": "invalid-strategy",
			},
			expectError: true,
		},
		{
			name:       "priority as float64 (JSON unmarshaling)",
			templateID: "sigmahq-core",
			overrides: map[string]interface{}{
				"name":     "Test Feed",
				"priority": float64(150), // JSON unmarshals numbers as float64
			},
			expectError: false,
			validate: func(t *testing.T, feed *RuleFeed) {
				if feed.Priority != 150 {
					t.Errorf("Priority not converted from float64: got %d", feed.Priority)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feed, err := tm.ApplyTemplate(tt.templateID, tt.overrides)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if feed == nil {
				t.Fatal("Feed is nil")
			}

			// Validate basic fields
			if feed.ID == "" {
				t.Error("Feed ID is empty")
			}
			if feed.CreatedAt.IsZero() {
				t.Error("CreatedAt not set")
			}
			if feed.UpdatedAt.IsZero() {
				t.Error("UpdatedAt not set")
			}

			// Run custom validation
			if tt.validate != nil {
				tt.validate(t, feed)
			}
		})
	}
}

func TestLoadTemplatesFromFile(t *testing.T) {
	// Create temporary template file
	tempFile, err := os.CreateTemp("", "templates-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write test templates
	yamlContent := `templates:
  - id: test-template-1
    name: "Test Template 1"
    description: "Test template for unit testing"
    type: git
    url: https://github.com/test/repo.git
    branch: main
    recommended_priority: 100
    estimated_rule_count: 500
    tags:
      - test
      - unit-test
  - id: test-template-2
    name: "Test Template 2"
    description: "Another test template"
    type: filesystem
    path: /test/path
    recommended_priority: 90
    estimated_rule_count: 200
    tags:
      - test
`
	if _, err := tempFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tempFile.Close()

	// Load templates
	tm := &TemplateManager{
		templateIndex: make(map[string]*FeedTemplate),
		cacheTTL:      DefaultTemplateCacheTTL,
	}

	err = tm.LoadTemplatesFromFile(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to load templates from file: %v", err)
	}

	// Verify templates were loaded
	if tm.GetTemplateCount() != 2 {
		t.Errorf("Expected 2 templates, got %d", tm.GetTemplateCount())
	}

	template1 := tm.GetTemplate("test-template-1")
	if template1 == nil {
		t.Fatal("test-template-1 not found")
	}
	if template1.Type != FeedTypeGit {
		t.Errorf("Template type mismatch: got %s, want %s", template1.Type, FeedTypeGit)
	}

	template2 := tm.GetTemplate("test-template-2")
	if template2 == nil {
		t.Fatal("test-template-2 not found")
	}
	if template2.Type != FeedTypeFilesystem {
		t.Errorf("Template type mismatch: got %s, want %s", template2.Type, FeedTypeFilesystem)
	}
}

func TestLoadTemplatesFromReader(t *testing.T) {
	yamlContent := `templates:
  - id: reader-test
    name: "Reader Test Template"
    description: "Template loaded from reader"
    type: git
    url: https://github.com/test/repo.git
    recommended_priority: 100
    estimated_rule_count: 300
`

	tm := &TemplateManager{
		templateIndex: make(map[string]*FeedTemplate),
		cacheTTL:      DefaultTemplateCacheTTL,
	}

	reader := strings.NewReader(yamlContent)
	err := tm.LoadTemplatesFromReader(reader)
	if err != nil {
		t.Fatalf("Failed to load templates from reader: %v", err)
	}

	template := tm.GetTemplate("reader-test")
	if template == nil {
		t.Fatal("reader-test template not found")
	}
	if template.Name != "Reader Test Template" {
		t.Errorf("Template name mismatch: got %s", template.Name)
	}
}

func TestLoadTemplatesFromReader_SizeLimit(t *testing.T) {
	// Create a large content that exceeds the limit
	largeContent := strings.Repeat("x", 6*1024*1024) // 6MB

	tm := &TemplateManager{
		templateIndex: make(map[string]*FeedTemplate),
		cacheTTL:      DefaultTemplateCacheTTL,
	}

	reader := strings.NewReader(largeContent)
	err := tm.LoadTemplatesFromReader(reader)
	if err == nil {
		t.Error("Expected error for oversized content")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("Expected 'too large' error, got: %v", err)
	}
}

func TestLoadTemplatesFromFile_SizeLimit(t *testing.T) {
	// Create temporary file with large content
	tempFile, err := os.CreateTemp("", "large-templates-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write content larger than limit
	largeContent := make([]byte, 6*1024*1024) // 6MB
	if _, err := tempFile.Write(largeContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tempFile.Close()

	tm := &TemplateManager{
		templateIndex: make(map[string]*FeedTemplate),
		cacheTTL:      DefaultTemplateCacheTTL,
	}

	err = tm.LoadTemplatesFromFile(tempFile.Name())
	if err == nil {
		t.Error("Expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("Expected 'too large' error, got: %v", err)
	}
}

func TestValidateTemplate(t *testing.T) {
	tm := &TemplateManager{}

	tests := []struct {
		name        string
		template    FeedTemplate
		expectError bool
	}{
		{
			name: "valid git template",
			template: FeedTemplate{
				ID:   "valid-git",
				Name: "Valid Git Template",
				Type: FeedTypeGit,
				URL:  "https://github.com/test/repo.git",
			},
			expectError: false,
		},
		{
			name: "valid filesystem template",
			template: FeedTemplate{
				ID:   "valid-fs",
				Name: "Valid Filesystem Template",
				Type: FeedTypeFilesystem,
			},
			expectError: false,
		},
		{
			name: "missing ID",
			template: FeedTemplate{
				Name: "Missing ID Template",
				Type: FeedTypeGit,
				URL:  "https://github.com/test/repo.git",
			},
			expectError: true,
		},
		{
			name: "missing name",
			template: FeedTemplate{
				ID:   "missing-name",
				Type: FeedTypeGit,
				URL:  "https://github.com/test/repo.git",
			},
			expectError: true,
		},
		{
			name: "missing type",
			template: FeedTemplate{
				ID:   "missing-type",
				Name: "Missing Type Template",
			},
			expectError: true,
		},
		{
			name: "invalid type",
			template: FeedTemplate{
				ID:   "invalid-type",
				Name: "Invalid Type Template",
				Type: "invalid-type",
			},
			expectError: true,
		},
		{
			name: "git template missing URL",
			template: FeedTemplate{
				ID:   "git-no-url",
				Name: "Git Template Missing URL",
				Type: FeedTypeGit,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tm.validateTemplate(&tt.template)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestGetTemplatesByTag(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Test filtering by 'official' tag
	official := tm.GetTemplatesByTag("official")
	if len(official) == 0 {
		t.Error("Expected templates with 'official' tag")
	}

	// Verify all returned templates have the tag
	for _, template := range official {
		hasTag := false
		for _, tag := range template.Tags {
			if tag == "official" {
				hasTag = true
				break
			}
		}
		if !hasTag {
			t.Errorf("Template %s does not have 'official' tag", template.ID)
		}
	}

	// Test non-existent tag
	nonExistent := tm.GetTemplatesByTag("nonexistent-tag")
	if len(nonExistent) != 0 {
		t.Error("Expected no templates for nonexistent tag")
	}
}

func TestGetTemplatesByType(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Test filtering by git type
	gitTemplates := tm.GetTemplatesByType(FeedTypeGit)
	if len(gitTemplates) == 0 {
		t.Error("Expected git templates")
	}

	// Verify all returned templates are git type
	for _, template := range gitTemplates {
		if template.Type != FeedTypeGit {
			t.Errorf("Template %s has incorrect type: got %s, want %s",
				template.ID, template.Type, FeedTypeGit)
		}
	}

	// Test non-existent type
	invalidType := tm.GetTemplatesByType("invalid-type")
	if len(invalidType) != 0 {
		t.Error("Expected no templates for invalid type")
	}
}

func TestReloadTemplates(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	initialCount := tm.GetTemplateCount()
	initialLoadTime := tm.GetLastLoadTime()

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Reload templates
	err = tm.ReloadTemplates()
	if err != nil {
		t.Fatalf("Failed to reload templates: %v", err)
	}

	// Verify count remains the same
	if tm.GetTemplateCount() != initialCount {
		t.Errorf("Template count changed after reload: got %d, want %d",
			tm.GetTemplateCount(), initialCount)
	}

	// Verify last load time updated
	if !tm.GetLastLoadTime().After(initialLoadTime) {
		t.Error("Last load time did not update after reload")
	}
}

func TestConcurrentAccess(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			// List templates
			_ = tm.ListTemplates()

			// Get specific template
			_ = tm.GetTemplate("sigmahq-core")

			// Get by tag
			_ = tm.GetTemplatesByTag("official")

			// Apply template
			_, _ = tm.ApplyTemplate("sigmahq-core", map[string]interface{}{
				"name": "Concurrent Test",
			})

			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestConvertToStringSlice(t *testing.T) {
	tm := &TemplateManager{}

	tests := []struct {
		name     string
		input    interface{}
		expected []string
		ok       bool
	}{
		{
			name:     "direct string slice",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
			ok:       true,
		},
		{
			name:     "interface slice with strings",
			input:    []interface{}{"x", "y", "z"},
			expected: []string{"x", "y", "z"},
			ok:       true,
		},
		{
			name:  "interface slice with non-string",
			input: []interface{}{"a", 123, "c"},
			ok:    false,
		},
		{
			name:  "invalid type",
			input: "not a slice",
			ok:    false,
		},
		{
			name:  "empty string slice",
			input: []string{},
			ok:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := tm.convertToStringSlice(tt.input)
			if ok != tt.ok {
				t.Errorf("Expected ok=%v, got ok=%v", tt.ok, ok)
			}
			if tt.ok && len(result) != len(tt.expected) {
				t.Errorf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
			}
		})
	}
}

// BLOCKER-4 TEST: Malicious template count DoS prevention
func TestConvertToStringSlice_MaxElements(t *testing.T) {
	tm := &TemplateManager{}

	// Test with exactly max allowed elements (should pass)
	maxAllowed := make([]string, 1000)
	for i := range maxAllowed {
		maxAllowed[i] = "item"
	}
	result, ok := tm.convertToStringSlice(maxAllowed)
	if !ok {
		t.Error("Should accept exactly 1000 elements")
	}
	if len(result) != 1000 {
		t.Errorf("Expected 1000 elements, got %d", len(result))
	}

	// Test with over max allowed elements (should fail)
	overMax := make([]string, 1001)
	for i := range overMax {
		overMax[i] = "item"
	}
	_, ok = tm.convertToStringSlice(overMax)
	if ok {
		t.Error("Should reject more than 1000 elements")
	}

	// Test with interface{} slice over limit
	overMaxInterface := make([]interface{}, 2000)
	for i := range overMaxInterface {
		overMaxInterface[i] = "item"
	}
	_, ok = tm.convertToStringSlice(overMaxInterface)
	if ok {
		t.Error("Should reject interface{} slice with more than 1000 elements")
	}

	// Test with malicious attacker scenario - millions of elements
	malicious := make([]interface{}, 1000000)
	for i := range malicious {
		malicious[i] = "attack"
	}
	_, ok = tm.convertToStringSlice(malicious)
	if ok {
		t.Error("Should reject malicious slice with millions of elements")
	}
}

// BLOCKER-1 TEST: Re-entrant lock deadlock prevention
func TestApplyTemplate_NoReentrantLock(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// This test ensures ApplyTemplate doesn't call GetTemplate while holding lock
	// If it does, this will deadlock (or panic with race detector)
	done := make(chan bool, 10)
	errors := make(chan error, 10)

	// Run multiple concurrent ApplyTemplate calls
	for i := 0; i < 10; i++ {
		go func(idx int) {
			_, err := tm.ApplyTemplate("sigmahq-core", map[string]interface{}{
				"name": "Concurrent Test",
			})
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines with timeout
	timeout := time.After(5 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case err := <-errors:
			t.Errorf("ApplyTemplate failed: %v", err)
		case <-timeout:
			t.Fatal("ApplyTemplate deadlocked - re-entrant lock issue detected")
		}
	}
}

// BLOCKER-5 TEST: Better error context for empty template IDs
func TestParseTemplatesData_EmptyTemplateID(t *testing.T) {
	tm := &TemplateManager{
		templateIndex: make(map[string]*FeedTemplate),
		cacheTTL:      DefaultTemplateCacheTTL,
	}

	// YAML with template missing ID at index 1
	yamlContent := `templates:
  - id: valid-template
    name: "Valid Template"
    type: git
    url: https://github.com/test/repo.git
  - name: "Missing ID Template"
    type: git
    url: https://github.com/test/repo2.git
`

	reader := strings.NewReader(yamlContent)
	err := tm.LoadTemplatesFromReader(reader)
	if err == nil {
		t.Error("Expected error for empty template ID")
	}

	// Error message should contain index information
	if !strings.Contains(err.Error(), "index 1") && !strings.Contains(err.Error(), "unnamed") {
		t.Errorf("Error should reference index or unnamed template, got: %v", err)
	}
}

// BLOCKER-6 TEST: Nil check in applyOverrides
func TestApplyOverrides_NilFeed(t *testing.T) {
	tm := &TemplateManager{}

	err := tm.applyOverrides(nil, map[string]interface{}{
		"name": "Test",
	})

	if err == nil {
		t.Error("Expected error for nil feed")
	}

	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("Error should mention nil feed, got: %v", err)
	}
}

// BLOCKER-7 TEST: Dangling pointer race condition prevention
func TestParseTemplatesData_NoPointerAliasing(t *testing.T) {
	tm := &TemplateManager{
		templateIndex: make(map[string]*FeedTemplate),
		cacheTTL:      DefaultTemplateCacheTTL,
	}

	yamlContent := `templates:
  - id: test-1
    name: "Test 1"
    type: git
    url: https://github.com/test/repo1.git
  - id: test-2
    name: "Test 2"
    type: git
    url: https://github.com/test/repo2.git
`

	// Load templates
	reader := strings.NewReader(yamlContent)
	if err := tm.LoadTemplatesFromReader(reader); err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Get pointer to template from index
	template1 := tm.templateIndex["test-1"]
	originalName := template1.Name

	// Reload templates (causes slice re-allocation in vulnerable code)
	reader = strings.NewReader(yamlContent)
	if err := tm.LoadTemplatesFromReader(reader); err != nil {
		t.Fatalf("Failed to reload templates: %v", err)
	}

	// Original pointer should NOT be affected by reload
	// In buggy code, template1 might point to invalid memory after slice re-allocation
	// Deep copy prevents this by creating a new slice
	newTemplate1 := tm.templateIndex["test-1"]
	if newTemplate1.Name != originalName {
		t.Errorf("Template name changed after reload: got %s, want %s",
			newTemplate1.Name, originalName)
	}

	// Verify templates are different objects (deep copy)
	if template1 == newTemplate1 {
		t.Error("Templates should be different objects after reload (deep copy)")
	}
}

// CONCERN-3 TEST: Deep copy in GetTemplate
func TestGetTemplate_DeepCopy(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Get template
	template1 := tm.GetTemplate("sigmahq-core")
	if template1 == nil {
		t.Fatal("Failed to get template")
	}

	// Modify returned template's slices
	originalTagsLen := len(template1.Tags)
	template1.Tags = append(template1.Tags, "malicious-tag")
	template1.IncludePaths = append(template1.IncludePaths, "/malicious/path")
	template1.ExcludePaths = append(template1.ExcludePaths, "/exclude/malicious")

	// Get template again - should not be affected
	template2 := tm.GetTemplate("sigmahq-core")
	if template2 == nil {
		t.Fatal("Failed to get template again")
	}

	// Verify slices were not modified in cache
	if len(template2.Tags) != originalTagsLen {
		t.Errorf("Tags slice was modified in cache: got %d tags, want %d",
			len(template2.Tags), originalTagsLen)
	}

	// Check for malicious tags
	for _, tag := range template2.Tags {
		if tag == "malicious-tag" {
			t.Error("Cached template was modified - deep copy failed")
		}
	}

	// Check for malicious paths
	for _, path := range template2.IncludePaths {
		if path == "/malicious/path" {
			t.Error("Cached template IncludePaths was modified - deep copy failed")
		}
	}

	for _, path := range template2.ExcludePaths {
		if path == "/exclude/malicious" {
			t.Error("Cached template ExcludePaths was modified - deep copy failed")
		}
	}
}

// Additional security test: Ensure overrides with massive slice don't succeed
func TestApplyTemplate_MassiveSliceRejection(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Attempt to apply template with massive include_paths
	massivePaths := make([]interface{}, 2000)
	for i := range massivePaths {
		massivePaths[i] = "/some/path"
	}

	_, err = tm.ApplyTemplate("sigmahq-core", map[string]interface{}{
		"name":          "Attack Feed",
		"include_paths": massivePaths,
	})

	if err == nil {
		t.Error("Should reject template with massive slice override")
	}

	if !strings.Contains(err.Error(), "include_paths") {
		t.Errorf("Error should mention include_paths, got: %v", err)
	}
}
