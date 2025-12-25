package feeds

import (
	"cerberus/sigma"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// FilesystemHandler handles local filesystem feeds
type FilesystemHandler struct {
	logger *zap.SugaredLogger
}

// NewFilesystemHandler creates a new filesystem feed handler
func NewFilesystemHandler(logger *zap.SugaredLogger) *FilesystemHandler {
	return &FilesystemHandler{
		logger: logger,
	}
}

// Connect validates that the directory exists and is accessible
func (h *FilesystemHandler) Connect(ctx context.Context, feed *RuleFeed) error {
	if feed.Type != FeedTypeFilesystem {
		return ErrInvalidFeedType
	}

	if feed.Path == "" {
		return ErrMissingPath
	}

	// Check if directory exists
	info, err := os.Stat(feed.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %s", feed.Path)
		}
		return fmt.Errorf("failed to access directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", feed.Path)
	}

	return nil
}

// FetchRules fetches rules from the local filesystem
func (h *FilesystemHandler) FetchRules(ctx context.Context, feed *RuleFeed) ([]*sigma.SigmaRule, error) {
	parser := sigma.NewParser()

	// Parse rules from directory
	rules, err := parser.ParseDirectory(feed.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules from %s: %w", feed.Path, err)
	}

	// Filter rules based on tags if specified
	if len(feed.IncludeTags) > 0 || len(feed.ExcludeTags) > 0 {
		rules = h.filterRulesByTags(rules, feed.IncludeTags, feed.ExcludeTags)
	}

	// Filter rules by severity if specified
	if feed.MinSeverity != "" {
		rules = h.filterRulesBySeverity(rules, feed.MinSeverity)
	}

	h.logger.Infof("Fetched %d rules from filesystem feed: %s", len(rules), feed.Name)
	return rules, nil
}

// Validate validates the feed configuration
func (h *FilesystemHandler) Validate(feed *RuleFeed) error {
	if feed.Type != FeedTypeFilesystem {
		return ErrInvalidFeedType
	}

	if feed.Path == "" {
		return ErrMissingPath
	}

	return nil
}

// Test tests access to the filesystem directory
func (h *FilesystemHandler) Test(ctx context.Context, feed *RuleFeed) error {
	if err := h.Validate(feed); err != nil {
		return err
	}

	// Check if directory exists and is accessible
	info, err := os.Stat(feed.Path)
	if err != nil {
		return fmt.Errorf("failed to access directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	// Try to read directory contents
	if _, err := os.ReadDir(feed.Path); err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	return nil
}

// GetMetadata retrieves metadata about the filesystem feed
func (h *FilesystemHandler) GetMetadata(ctx context.Context, feed *RuleFeed) (map[string]interface{}, error) {
	metadata := make(map[string]interface{})
	metadata["path"] = feed.Path

	// Get directory info
	info, err := os.Stat(feed.Path)
	if err == nil {
		metadata["exists"] = true
		metadata["mod_time"] = info.ModTime()

		// Count YAML files
		count, err := h.countYAMLFiles(feed.Path)
		if err == nil {
			metadata["yaml_file_count"] = count
		}
	} else {
		metadata["exists"] = false
	}

	return metadata, nil
}

// Close cleans up resources
func (h *FilesystemHandler) Close() error {
	// Nothing to clean up for filesystem handler
	return nil
}

// Helper methods

func (h *FilesystemHandler) countYAMLFiles(dir string) (int, error) {
	count := 0

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".yml" || ext == ".yaml" {
				count++
			}
		}

		return nil
	})

	return count, err
}

func (h *FilesystemHandler) filterRulesByTags(rules []*sigma.SigmaRule, includeTags []string, excludeTags []string) []*sigma.SigmaRule {
	var filtered []*sigma.SigmaRule

	for _, rule := range rules {
		// Check exclude tags first
		if len(excludeTags) > 0 {
			excluded := false
			for _, excludeTag := range excludeTags {
				if h.hasMatchingTag(rule.Tags, excludeTag) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		// Check include tags
		if len(includeTags) > 0 {
			included := false
			for _, includeTag := range includeTags {
				if h.hasMatchingTag(rule.Tags, includeTag) {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		filtered = append(filtered, rule)
	}

	return filtered
}

func (h *FilesystemHandler) hasMatchingTag(ruleTags []string, pattern string) bool {
	for _, tag := range ruleTags {
		// Support wildcard matching
		matched, err := filepath.Match(pattern, tag)
		if err == nil && matched {
			return true
		}

		// Exact match
		if tag == pattern {
			return true
		}
	}
	return false
}

func (h *FilesystemHandler) filterRulesBySeverity(rules []*sigma.SigmaRule, minSeverity string) []*sigma.SigmaRule {
	severityLevels := map[string]int{
		"informational": 1,
		"low":           2,
		"medium":        3,
		"high":          4,
		"critical":      5,
	}

	minLevel, ok := severityLevels[minSeverity]
	if !ok {
		// Invalid min severity, return all rules
		return rules
	}

	var filtered []*sigma.SigmaRule
	for _, rule := range rules {
		ruleLevel, ok := severityLevels[rule.Level]
		if !ok {
			// Unknown severity, include by default
			filtered = append(filtered, rule)
			continue
		}

		if ruleLevel >= minLevel {
			filtered = append(filtered, rule)
		}
	}

	return filtered
}
