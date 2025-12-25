package feeds

import (
	"cerberus/sigma"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// GitHandler handles Git repository feeds
type GitHandler struct {
	logger     *zap.SugaredLogger
	workingDir string // Base directory for cloning repos
}

// NewGitHandler creates a new Git feed handler
func NewGitHandler(workingDir string, logger *zap.SugaredLogger) *GitHandler {
	return &GitHandler{
		logger:     logger,
		workingDir: workingDir,
	}
}

// Connect initializes connection to the Git repository
func (h *GitHandler) Connect(ctx context.Context, feed *RuleFeed) error {
	if feed.Type != FeedTypeGit {
		return ErrInvalidFeedType
	}

	if feed.URL == "" {
		return ErrMissingURL
	}

	// Check if git is available
	if err := h.checkGitAvailable(); err != nil {
		return fmt.Errorf("git not available: %w", err)
	}

	// Ensure working directory exists
	repoPath := h.getRepoPath(feed)
	if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}

	return nil
}

// FetchRules fetches rules from the Git repository
func (h *GitHandler) FetchRules(ctx context.Context, feed *RuleFeed) ([]*sigma.SigmaRule, error) {
	repoPath := h.getRepoPath(feed)

	// Clone or update repository
	if err := h.syncRepository(ctx, feed, repoPath); err != nil {
		return nil, fmt.Errorf("failed to sync repository: %w", err)
	}

	// Parse SIGMA rules from repository
	parser := sigma.NewParser()
	var allRules []*sigma.SigmaRule

	// Process include paths
	if len(feed.IncludePaths) > 0 {
		for _, pattern := range feed.IncludePaths {
			fullPattern := filepath.Join(repoPath, pattern)
			rules, err := h.parseRulesFromPattern(parser, fullPattern)
			if err != nil {
				h.logger.Warnf("Failed to parse rules from pattern %s: %v", pattern, err)
				continue
			}
			allRules = append(allRules, rules...)
		}
	} else {
		// No include paths specified, parse entire repository
		rules, err := parser.ParseDirectory(repoPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rules: %w", err)
		}
		allRules = rules
	}

	// Filter rules based on exclude paths
	if len(feed.ExcludePaths) > 0 {
		allRules = h.filterExcludedRules(allRules, feed.ExcludePaths, repoPath)
	}

	// Filter rules based on tags
	if len(feed.IncludeTags) > 0 || len(feed.ExcludeTags) > 0 {
		allRules = h.filterRulesByTags(allRules, feed.IncludeTags, feed.ExcludeTags)
	}

	// Filter rules by severity
	if feed.MinSeverity != "" {
		allRules = h.filterRulesBySeverity(allRules, feed.MinSeverity)
	}

	h.logger.Infof("Fetched %d rules from Git feed: %s", len(allRules), feed.Name)
	return allRules, nil
}

// Validate validates the feed configuration
func (h *GitHandler) Validate(feed *RuleFeed) error {
	if feed.Type != FeedTypeGit {
		return ErrInvalidFeedType
	}

	if feed.URL == "" {
		return ErrMissingURL
	}

	// Validate URL format (basic check)
	if !strings.Contains(feed.URL, "://") && !strings.HasSuffix(feed.URL, ".git") {
		return fmt.Errorf("invalid git URL format")
	}

	return nil
}

// Test tests the connection to the Git repository
func (h *GitHandler) Test(ctx context.Context, feed *RuleFeed) error {
	if err := h.Validate(feed); err != nil {
		return err
	}

	// Check if git is available
	if err := h.checkGitAvailable(); err != nil {
		return err
	}

	// Validate URL to prevent command injection
	if err := h.validateGitURL(feed.URL); err != nil {
		return err
	}

	// Try to do a shallow ls-remote to test connectivity
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--heads", feed.URL)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to connect to repository: %w", err)
	}

	return nil
}

// GetMetadata retrieves metadata about the Git repository
func (h *GitHandler) GetMetadata(ctx context.Context, feed *RuleFeed) (map[string]interface{}, error) {
	repoPath := h.getRepoPath(feed)

	metadata := make(map[string]interface{})
	metadata["url"] = feed.URL
	metadata["branch"] = feed.Branch

	// Check if repository is cloned
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil {
		metadata["cloned"] = true

		// Get current commit hash
		cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "rev-parse", "HEAD")
		if output, err := cmd.Output(); err == nil {
			metadata["commit"] = strings.TrimSpace(string(output))
		}

		// Get last commit date
		cmd = exec.CommandContext(ctx, "git", "-C", repoPath, "log", "-1", "--format=%ci")
		if output, err := cmd.Output(); err == nil {
			metadata["last_commit_date"] = strings.TrimSpace(string(output))
		}
	} else {
		metadata["cloned"] = false
	}

	return metadata, nil
}

// Close cleans up resources
func (h *GitHandler) Close() error {
	// Nothing to clean up for git handler
	return nil
}

// Helper methods

// validateGitURL validates that the git URL uses only safe schemes
func (h *GitHandler) validateGitURL(gitURL string) error {
	parsedURL, err := url.Parse(gitURL)
	if err != nil {
		return fmt.Errorf("invalid git URL: %w", err)
	}

	if parsedURL.Scheme != "https" && parsedURL.Scheme != "git" {
		return fmt.Errorf("invalid git URL scheme - only https:// and git:// schemes allowed, got: %s", parsedURL.Scheme)
	}

	return nil
}

// validateBranchName validates that the branch name contains only safe characters
func (h *GitHandler) validateBranchName(branch string) error {
	// Strict validation to prevent command injection
	// Branch names:
	// - Cannot start with '-' (prevents git flags like --help)
	// - Cannot start or end with '/' (git restriction)
	// - Cannot contain '..' (path traversal)
	// - Cannot contain spaces or special chars
	// - Must be 1-255 chars long

	if len(branch) == 0 || len(branch) > 255 {
		return fmt.Errorf("invalid branch name length - must be 1-255 characters")
	}

	// Cannot start with dash (prevents injection of git flags)
	if branch[0] == '-' {
		return fmt.Errorf("invalid branch name - cannot start with '-'")
	}

	// Cannot start or end with slash
	if branch[0] == '/' || branch[len(branch)-1] == '/' {
		return fmt.Errorf("invalid branch name - cannot start or end with '/'")
	}

	// Check for path traversal attempts
	if strings.Contains(branch, "..") {
		return fmt.Errorf("invalid branch name - cannot contain '..'")
	}

	// Only allow alphanumeric, forward slash, dash, underscore, and dot
	// Must not start with dash (already checked above)
	validBranch := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9/_.-]*$`)
	if !validBranch.MatchString(branch) {
		return fmt.Errorf("invalid branch name - only alphanumeric characters, /, -, _, and . allowed (cannot start with -)")
	}

	return nil
}

func (h *GitHandler) checkGitAvailable() error {
	cmd := exec.Command("git", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git is not installed or not in PATH")
	}
	return nil
}

func (h *GitHandler) getRepoPath(feed *RuleFeed) string {
	// Create a sanitized directory name from the feed ID
	return filepath.Join(h.workingDir, "feeds", feed.ID)
}

func (h *GitHandler) syncRepository(ctx context.Context, feed *RuleFeed, repoPath string) error {
	branch := feed.Branch
	if branch == "" {
		branch = "master"
	}

	// Validate URL and branch to prevent command injection
	if err := h.validateGitURL(feed.URL); err != nil {
		return err
	}
	if err := h.validateBranchName(branch); err != nil {
		return err
	}

	// Check if repository already exists
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil {
		// Repository exists, pull latest changes
		h.logger.Infof("Updating existing repository: %s", feed.Name)

		// Fetch latest changes
		cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "fetch", "origin", branch)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to fetch: %w", err)
		}

		// Reset to origin/branch
		cmd = exec.CommandContext(ctx, "git", "-C", repoPath, "reset", "--hard", "origin/"+branch)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to reset: %w", err)
		}

		h.logger.Infof("Repository updated successfully: %s", feed.Name)
	} else {
		// Repository doesn't exist, clone it
		h.logger.Infof("Cloning repository: %s from %s", feed.Name, feed.URL)

		// Create parent directory
		if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		// Clone with depth=1 for faster cloning
		args := []string{"clone", "--depth", "1", "--branch", branch, feed.URL, repoPath}
		cmd := exec.CommandContext(ctx, "git", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to clone repository: %w (output: %s)", err, string(output))
		}

		h.logger.Infof("Repository cloned successfully: %s", feed.Name)
	}

	return nil
}

func (h *GitHandler) parseRulesFromPattern(parser *sigma.Parser, pattern string) ([]*sigma.SigmaRule, error) {
	// If pattern contains wildcards, use filepath.Glob
	if strings.Contains(pattern, "*") {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}

		var rules []*sigma.SigmaRule
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue
			}

			if info.IsDir() {
				dirRules, err := parser.ParseDirectory(match)
				if err != nil {
					h.logger.Warnf("Failed to parse directory %s: %v", match, err)
					continue
				}
				rules = append(rules, dirRules...)
			} else if strings.HasSuffix(match, ".yml") || strings.HasSuffix(match, ".yaml") {
				rule, err := parser.ParseFile(match)
				if err != nil {
					h.logger.Warnf("Failed to parse file %s: %v", match, err)
					continue
				}
				if rule != nil {
					rules = append(rules, rule)
				}
			}
		}

		return rules, nil
	}

	// No wildcards, treat as single path
	info, err := os.Stat(pattern)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return parser.ParseDirectory(pattern)
	}

	rule, err := parser.ParseFile(pattern)
	if err != nil {
		return nil, err
	}

	return []*sigma.SigmaRule{rule}, nil
}

func (h *GitHandler) filterExcludedRules(rules []*sigma.SigmaRule, excludePaths []string, repoPath string) []*sigma.SigmaRule {
	var filtered []*sigma.SigmaRule

	for _, rule := range rules {
		excluded := false

		// Check if rule path matches any exclude pattern
		for _, excludePattern := range excludePaths {
			fullPattern := filepath.Join(repoPath, excludePattern)

			// Convert to glob pattern if needed
			if strings.Contains(excludePattern, "*") {
				matched, err := filepath.Match(fullPattern, rule.FilePath)
				if err == nil && matched {
					excluded = true
					break
				}
			} else {
				// Direct path comparison
				if strings.Contains(rule.FilePath, excludePattern) {
					excluded = true
					break
				}
			}
		}

		if !excluded {
			filtered = append(filtered, rule)
		}
	}

	return filtered
}

func (h *GitHandler) filterRulesByTags(rules []*sigma.SigmaRule, includeTags []string, excludeTags []string) []*sigma.SigmaRule {
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

func (h *GitHandler) hasMatchingTag(ruleTags []string, pattern string) bool {
	for _, tag := range ruleTags {
		// Support wildcard matching
		if strings.Contains(pattern, "*") {
			matched, err := filepath.Match(pattern, tag)
			if err == nil && matched {
				return true
			}
		} else {
			// Exact match
			if tag == pattern {
				return true
			}
		}
	}
	return false
}

func (h *GitHandler) filterRulesBySeverity(rules []*sigma.SigmaRule, minSeverity string) []*sigma.SigmaRule {
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
