// Package feeds provides SIGMA rule feed management capabilities.
// This file implements feed template functionality for simplified feed creation.
package feeds

import (
	"embed"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

//go:embed templates.yaml
var embeddedTemplates embed.FS

// TemplateManager manages feed templates with caching and validation.
// Thread-safe for concurrent access.
type TemplateManager struct {
	mu            sync.RWMutex
	templates     []FeedTemplate
	templateIndex map[string]*FeedTemplate
	lastLoaded    time.Time
	cacheTTL      time.Duration
}

// DefaultTemplateCacheTTL is the default cache duration for loaded templates
const DefaultTemplateCacheTTL = 5 * time.Minute

// NewTemplateManager creates a new template manager with default settings.
// The manager automatically loads embedded templates on creation.
func NewTemplateManager() (*TemplateManager, error) {
	tm := &TemplateManager{
		templateIndex: make(map[string]*FeedTemplate),
		cacheTTL:      DefaultTemplateCacheTTL,
	}

	// Load embedded templates on initialization
	if err := tm.LoadEmbeddedTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load embedded templates: %w", err)
	}

	return tm, nil
}

// LoadEmbeddedTemplates loads templates from the embedded templates.yaml file.
// This is called automatically during manager initialization.
// Thread-safe for concurrent access.
func (tm *TemplateManager) LoadEmbeddedTemplates() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Read embedded template file
	data, err := embeddedTemplates.ReadFile("templates.yaml")
	if err != nil {
		return fmt.Errorf("failed to read embedded templates: %w", err)
	}

	return tm.parseTemplatesData(data)
}

// LoadTemplatesFromFile loads templates from an external YAML file.
// This allows organizations to define custom templates beyond the embedded ones.
// Security: File path should be validated by caller to prevent path traversal.
// Thread-safe for concurrent access.
func (tm *TemplateManager) LoadTemplatesFromFile(path string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Security: Check file size before reading to prevent memory exhaustion
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat template file: %w", err)
	}

	const maxTemplateFileSize = 5 * 1024 * 1024 // 5MB limit
	if fileInfo.Size() > maxTemplateFileSize {
		return fmt.Errorf("template file too large: maximum %d bytes, got %d bytes",
			maxTemplateFileSize, fileInfo.Size())
	}

	// Read template file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read template file: %w", err)
	}

	return tm.parseTemplatesData(data)
}

// LoadTemplatesFromReader loads templates from an io.Reader.
// Useful for testing and loading templates from non-file sources.
// Security: Limits read size to prevent memory exhaustion.
// Thread-safe for concurrent access.
func (tm *TemplateManager) LoadTemplatesFromReader(reader io.Reader) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Security: Limit read size to prevent memory exhaustion
	const maxReadSize = 5 * 1024 * 1024 // 5MB
	limitedReader := io.LimitReader(reader, maxReadSize)

	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read templates: %w", err)
	}

	// Check if we hit the size limit
	if len(data) == maxReadSize {
		return fmt.Errorf("template data too large: exceeds maximum size of %d bytes", maxReadSize)
	}

	return tm.parseTemplatesData(data)
}

// parseTemplatesData parses YAML template data and updates internal state.
// Must be called with lock held.
func (tm *TemplateManager) parseTemplatesData(data []byte) error {
	// BLOCKER-4 FIX: Validate YAML complexity before parsing
	const maxTemplates = 100         // Maximum number of templates
	const maxYAMLDepth = 10          // Maximum nesting depth
	const maxYAMLSize = 5 * 1024 * 1024 // 5MB maximum (already enforced by caller, double check)

	if len(data) > maxYAMLSize {
		return fmt.Errorf("YAML data too large: %d bytes exceeds maximum %d bytes", len(data), maxYAMLSize)
	}

	// Check for malformed YAML indicators (excessive nesting, recursion markers)
	if err := validateYAMLComplexity(data, maxYAMLDepth); err != nil {
		return fmt.Errorf("YAML complexity validation failed: %w", err)
	}

	var parsed struct {
		Templates []FeedTemplate `yaml:"templates"`
	}

	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("failed to parse template YAML: %w", err)
	}

	// BLOCKER-4 FIX: Validate template count after parsing
	if len(parsed.Templates) > maxTemplates {
		return fmt.Errorf("too many templates: %d exceeds maximum %d", len(parsed.Templates), maxTemplates)
	}

	// Validate templates
	for i := range parsed.Templates {
		if err := tm.validateTemplate(&parsed.Templates[i]); err != nil {
			// BLOCKER-5 FIX: Provide better error context for empty template IDs
			templateID := parsed.Templates[i].ID
			if templateID == "" {
				templateID = fmt.Sprintf("<unnamed at index %d>", i)
			}
			return fmt.Errorf("invalid template %s: %w", templateID, err)
		}
	}

	// BLOCKER-7 FIX: Deep copy slice to prevent dangling pointer issues
	// Create new slice to ensure re-allocation doesn't invalidate pointers
	tm.templates = make([]FeedTemplate, len(parsed.Templates))
	copy(tm.templates, parsed.Templates)

	// BLOCKER-7 FIX: Build index with duplicate ID detection
	tm.templateIndex = make(map[string]*FeedTemplate, len(tm.templates))
	for i := range tm.templates {
		templateID := tm.templates[i].ID
		if _, exists := tm.templateIndex[templateID]; exists {
			return fmt.Errorf("duplicate template ID detected: %s", templateID)
		}
		tm.templateIndex[templateID] = &tm.templates[i]
	}
	tm.lastLoaded = time.Now()

	return nil
}

// validateTemplate validates a template's required fields and values.
func (tm *TemplateManager) validateTemplate(template *FeedTemplate) error {
	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if template.Type == "" {
		return fmt.Errorf("template type is required")
	}

	// Validate feed type
	validTypes := map[string]bool{
		FeedTypeGit:        true,
		FeedTypeHTTP:       true,
		FeedTypeFilesystem: true,
		FeedTypeAPI:        true,
		FeedTypeS3:         true,
		FeedTypeWebhook:    true,
	}
	if !validTypes[template.Type] {
		return fmt.Errorf("invalid template type: %s", template.Type)
	}

	// Type-specific validation
	switch template.Type {
	case FeedTypeGit:
		if template.URL == "" {
			return fmt.Errorf("git template requires URL")
		}
	case FeedTypeHTTP, FeedTypeAPI:
		if template.URL == "" {
			return fmt.Errorf("%s template requires URL", template.Type)
		}
	}

	return nil
}

// ListTemplates returns all available templates.
// Returns a copy to prevent external modification.
// Thread-safe for concurrent access.
func (tm *TemplateManager) ListTemplates() []FeedTemplate {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Return a copy to prevent external modification
	templates := make([]FeedTemplate, len(tm.templates))
	copy(templates, tm.templates)
	return templates
}

// GetTemplate retrieves a template by ID.
// Returns nil if template not found.
// Thread-safe for concurrent access.
func (tm *TemplateManager) GetTemplate(id string) *FeedTemplate {
	tm.mu.RLock()
	template, exists := tm.templateIndex[id]
	// BLOCKER-3 FIX: Release read lock BEFORE deep copying to avoid holding lock during allocation
	tm.mu.RUnlock()

	if !exists {
		return nil
	}

	// Deep copy to prevent modification of cached template's slices
	// Lock is already released, so this allocation doesn't block other readers
	templateCopy := *template
	templateCopy.Tags = append([]string{}, template.Tags...)
	templateCopy.IncludePaths = append([]string{}, template.IncludePaths...)
	templateCopy.ExcludePaths = append([]string{}, template.ExcludePaths...)
	return &templateCopy
}

// ApplyTemplate creates a RuleFeed from a template with optional overrides.
//
// The overrides map supports the following keys:
//   - "name": string - Feed name (required if not in template)
//   - "description": string - Feed description
//   - "enabled": bool - Whether feed is enabled
//   - "auto_enable_rules": bool - Auto-enable imported rules
//   - "priority": int - Feed priority
//   - "update_strategy": string - Update strategy (manual, scheduled, etc.)
//   - "update_schedule": string - Cron schedule for updates
//   - "include_paths": []string - Override include paths
//   - "exclude_paths": []string - Override exclude paths
//   - "tags": []string - Additional tags
//   - "branch": string - Git branch (for git feeds)
//
// Security: Validates all override values to prevent injection.
// Thread-safe for concurrent access.
func (tm *TemplateManager) ApplyTemplate(templateID string, overrides map[string]interface{}) (*RuleFeed, error) {
	// BLOCKER-1 FIX: Access templateIndex directly to avoid re-entrant lock deadlock
	tm.mu.RLock()
	template, exists := tm.templateIndex[templateID]
	tm.mu.RUnlock()

	if !exists || template == nil {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	// Create base feed from template
	feed := &RuleFeed{
		ID:              uuid.New().String(),
		Name:            template.Name,
		Description:     template.Description,
		Type:            template.Type,
		URL:             template.URL,
		Branch:          template.Branch,
		Enabled:         true, // Default to enabled
		IncludePaths:    append([]string{}, template.IncludePaths...),
		ExcludePaths:    append([]string{}, template.ExcludePaths...),
		Priority:        template.RecommendedPriority,
		Tags:            append([]string{}, template.Tags...),
		AutoEnableRules: false, // Default to manual rule enabling for safety
		UpdateStrategy:  UpdateManual,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Apply overrides with type checking and validation
	if err := tm.applyOverrides(feed, overrides); err != nil {
		return nil, fmt.Errorf("failed to apply overrides: %w", err)
	}

	// Validate final feed configuration
	if err := feed.Validate(); err != nil {
		return nil, fmt.Errorf("invalid feed configuration after applying template: %w", err)
	}

	return feed, nil
}

// applyOverrides applies override values to a feed with type checking and validation.
// Security: Validates all inputs to prevent injection and invalid configurations.
func (tm *TemplateManager) applyOverrides(feed *RuleFeed, overrides map[string]interface{}) error {
	// BLOCKER-6 FIX: Validate that feed is non-nil
	if feed == nil {
		return fmt.Errorf("feed cannot be nil")
	}

	for key, value := range overrides {
		switch key {
		case "id":
			// Allow custom ID override
			if strVal, ok := value.(string); ok && strVal != "" {
				feed.ID = strVal
			} else {
				return fmt.Errorf("invalid ID override: must be non-empty string")
			}

		case "name":
			if strVal, ok := value.(string); ok && strVal != "" {
				feed.Name = strVal
			} else {
				return fmt.Errorf("invalid name override: must be non-empty string")
			}

		case "description":
			if strVal, ok := value.(string); ok {
				feed.Description = strVal
			} else {
				return fmt.Errorf("invalid description override: must be string")
			}

		case "enabled":
			if boolVal, ok := value.(bool); ok {
				feed.Enabled = boolVal
			} else {
				return fmt.Errorf("invalid enabled override: must be boolean")
			}

		case "auto_enable_rules":
			if boolVal, ok := value.(bool); ok {
				feed.AutoEnableRules = boolVal
			} else {
				return fmt.Errorf("invalid auto_enable_rules override: must be boolean")
			}

		case "priority":
			// Handle both int and float64 (JSON unmarshaling uses float64)
			switch v := value.(type) {
			case int:
				feed.Priority = v
			case float64:
				feed.Priority = int(v)
			default:
				return fmt.Errorf("invalid priority override: must be integer")
			}

		case "update_strategy":
			if strVal, ok := value.(string); ok {
				// Validate strategy
				validStrategies := map[string]bool{
					UpdateManual:    true,
					UpdateStartup:   true,
					UpdateScheduled: true,
					UpdateWebhook:   true,
				}
				if !validStrategies[strVal] {
					return fmt.Errorf("invalid update_strategy: must be one of manual, startup, scheduled, webhook")
				}
				feed.UpdateStrategy = strVal
			} else {
				return fmt.Errorf("invalid update_strategy override: must be string")
			}

		case "update_schedule":
			if strVal, ok := value.(string); ok {
				feed.UpdateSchedule = strVal
			} else {
				return fmt.Errorf("invalid update_schedule override: must be string")
			}

		case "include_paths":
			if paths, ok := tm.convertToStringSlice(value); ok {
				feed.IncludePaths = paths
			} else {
				return fmt.Errorf("invalid include_paths override: must be string array")
			}

		case "exclude_paths":
			if paths, ok := tm.convertToStringSlice(value); ok {
				feed.ExcludePaths = paths
			} else {
				return fmt.Errorf("invalid exclude_paths override: must be string array")
			}

		case "tags":
			if tags, ok := tm.convertToStringSlice(value); ok {
				// Append to existing template tags
				feed.Tags = append(feed.Tags, tags...)
			} else {
				return fmt.Errorf("invalid tags override: must be string array")
			}

		case "branch":
			if strVal, ok := value.(string); ok {
				feed.Branch = strVal
			} else {
				return fmt.Errorf("invalid branch override: must be string")
			}

		case "url":
			if strVal, ok := value.(string); ok && strVal != "" {
				feed.URL = strVal
			} else {
				return fmt.Errorf("invalid url override: must be non-empty string")
			}

		case "path":
			if strVal, ok := value.(string); ok {
				feed.Path = strVal
			} else {
				return fmt.Errorf("invalid path override: must be string")
			}

		default:
			// Ignore unknown overrides to allow for forward compatibility
			continue
		}
	}

	return nil
}

// convertToStringSlice converts an interface{} to []string with type checking.
// Handles both []string and []interface{} (from JSON unmarshaling).
// Security: Limits slice length to prevent DoS attacks.
func (tm *TemplateManager) convertToStringSlice(value interface{}) ([]string, bool) {
	// BLOCKER-4 FIX: Maximum slice elements to prevent DoS
	const maxSliceElements = 1000

	// Try direct []string conversion
	if strSlice, ok := value.([]string); ok {
		if len(strSlice) > maxSliceElements {
			return nil, false
		}
		return strSlice, true
	}

	// Try []interface{} conversion (common from JSON)
	if ifaceSlice, ok := value.([]interface{}); ok {
		// Check length before processing
		if len(ifaceSlice) > maxSliceElements {
			return nil, false
		}

		result := make([]string, 0, len(ifaceSlice))
		for _, item := range ifaceSlice {
			if strVal, ok := item.(string); ok {
				result = append(result, strVal)
			} else {
				return nil, false // Non-string item found
			}
		}
		return result, true
	}

	return nil, false
}

// ReloadTemplates forces a reload of templates from the embedded source.
// Useful for testing or when templates need to be refreshed.
// Thread-safe for concurrent access.
func (tm *TemplateManager) ReloadTemplates() error {
	return tm.LoadEmbeddedTemplates()
}

// GetTemplateCount returns the number of loaded templates.
// Thread-safe for concurrent access.
func (tm *TemplateManager) GetTemplateCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.templates)
}

// GetLastLoadTime returns when templates were last loaded.
// Thread-safe for concurrent access.
func (tm *TemplateManager) GetLastLoadTime() time.Time {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.lastLoaded
}

// GetTemplatesByTag returns all templates matching the specified tag.
// Thread-safe for concurrent access.
func (tm *TemplateManager) GetTemplatesByTag(tag string) []FeedTemplate {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var matching []FeedTemplate
	for _, template := range tm.templates {
		for _, t := range template.Tags {
			if t == tag {
				matching = append(matching, template)
				break
			}
		}
	}

	return matching
}

// GetTemplatesByType returns all templates of the specified feed type.
// Thread-safe for concurrent access.
func (tm *TemplateManager) GetTemplatesByType(feedType string) []FeedTemplate {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var matching []FeedTemplate
	for _, template := range tm.templates {
		if template.Type == feedType {
			matching = append(matching, template)
		}
	}

	return matching
}

// validateYAMLComplexity performs basic validation on YAML data to detect
// complexity attacks (excessive nesting, anchors/aliases, etc.)
// Security: Prevents YAML bombs and billion laughs attacks.
func validateYAMLComplexity(data []byte, maxDepth int) error {
	// Check for excessive indentation (indicator of deep nesting)
	lines := 0
	maxIndent := 0
	currentIndent := 0

	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines++
			if currentIndent > maxIndent {
				maxIndent = currentIndent
			}
			currentIndent = 0
			continue
		}
		if data[i] == ' ' || data[i] == '\t' {
			currentIndent++
		} else {
			// Reset on non-whitespace
			if currentIndent > maxIndent {
				maxIndent = currentIndent
			}
			currentIndent = 0
		}
	}

	// Estimate depth from indentation (assuming 2 spaces per level)
	estimatedDepth := maxIndent / 2
	if estimatedDepth > maxDepth {
		return fmt.Errorf("excessive YAML nesting detected: estimated depth %d exceeds maximum %d", estimatedDepth, maxDepth)
	}

	// Check for YAML anchors and aliases which can be used for billion laughs attack
	// Count occurrences - a few are fine, but many indicate potential attack
	anchorCount := 0
	aliasCount := 0
	for i := 0; i < len(data)-1; i++ {
		// Look for anchor definition: &anchor
		if data[i] == '&' && (i == 0 || data[i-1] == ' ' || data[i-1] == '\n' || data[i-1] == '\t') {
			anchorCount++
		}
		// Look for alias reference: *anchor
		if data[i] == '*' && (i == 0 || data[i-1] == ' ' || data[i-1] == '\n' || data[i-1] == '\t') {
			aliasCount++
		}
	}

	// Allow reasonable use of anchors/aliases, but reject excessive use
	const maxAnchors = 10
	const maxAliases = 50
	if anchorCount > maxAnchors {
		return fmt.Errorf("excessive YAML anchors detected: %d exceeds maximum %d", anchorCount, maxAnchors)
	}
	if aliasCount > maxAliases {
		return fmt.Errorf("excessive YAML aliases detected: %d exceeds maximum %d", aliasCount, maxAliases)
	}

	// Reject if we have many more aliases than anchors (indicator of expansion attack)
	if anchorCount > 0 && aliasCount > anchorCount*5 {
		return fmt.Errorf("suspicious YAML alias pattern: %d aliases for %d anchors", aliasCount, anchorCount)
	}

	return nil
}
