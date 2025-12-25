package feeds

import (
	"cerberus/core"
	"cerberus/sigma"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ProgressCallback is called during feed synchronization to report progress.
// TASK 158: Progress callback for real-time WebSocket event broadcasting.
// The callback receives:
// - eventType: "started", "progress", "completed", "failed"
// - message: human-readable progress message
// - progress: completion percentage (0-100), only for "progress" events
type ProgressCallback func(eventType, message string, progress int)

// RuleStorage defines the interface for storing detection rules
// This is defined locally to avoid import cycles with the storage package
type RuleStorage interface {
	CreateRule(ctx context.Context, rule *core.Rule) error
	GetRuleByID(ctx context.Context, id string) (*core.Rule, error)
	UpdateRule(ctx context.Context, rule *core.Rule) error
}

// Manager implements the FeedManager interface
type Manager struct {
	storage         FeedStorage
	ruleStorage     RuleStorage
	handlers        map[string]FeedHandler
	logger          *zap.SugaredLogger
	scheduler       *Scheduler
	templateManager *TemplateManager // Template manager for feed templates
	syncMutex       sync.Mutex       // Prevents concurrent syncs of the same feed
	syncLocks       map[string]*sync.Mutex
}

// NewManager creates a new feed manager.
// Returns error if template manager initialization fails - templates are a hard requirement.
func NewManager(
	feedStorage FeedStorage,
	ruleStorage RuleStorage,
	workingDir string,
	logger *zap.SugaredLogger,
) (*Manager, error) {
	handlers := make(map[string]FeedHandler)
	handlers[FeedTypeGit] = NewGitHandler(workingDir, logger)
	handlers[FeedTypeFilesystem] = NewFilesystemHandler(logger)

	// Initialize template manager with embedded templates
	// BLOCKER-2 FIX: Template initialization is now a hard requirement
	templateManager, err := NewTemplateManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize template manager: %w", err)
	}

	return &Manager{
		storage:         feedStorage,
		ruleStorage:     ruleStorage,
		handlers:        handlers,
		logger:          logger,
		templateManager: templateManager,
		syncLocks:       make(map[string]*sync.Mutex),
	}, nil
}

// CreateFeed creates a new feed
func (m *Manager) CreateFeed(ctx context.Context, feed *RuleFeed) error {
	if err := feed.Validate(); err != nil {
		return err
	}

	// Set timestamps
	now := time.Now()
	if feed.CreatedAt.IsZero() {
		feed.CreatedAt = now
	}
	feed.UpdatedAt = now

	// Set default status
	if feed.Status == "" {
		feed.Status = FeedStatusActive
	}

	// Validate feed with appropriate handler
	handler, err := m.getHandler(feed.Type)
	if err != nil {
		return err
	}

	if err := handler.Validate(feed); err != nil {
		return fmt.Errorf("feed validation failed: %w", err)
	}

	// Create feed in storage
	if err := m.storage.CreateFeed(ctx, feed); err != nil {
		return err
	}

	m.logger.Infof("Created feed: %s (ID: %s)", feed.Name, feed.ID)
	return nil
}

// GetFeed retrieves a feed by ID
func (m *Manager) GetFeed(ctx context.Context, id string) (*RuleFeed, error) {
	return m.storage.GetFeed(ctx, id)
}

// ListFeeds retrieves all feeds
func (m *Manager) ListFeeds(ctx context.Context) ([]*RuleFeed, error) {
	return m.storage.GetAllFeeds(ctx)
}

// UpdateFeed updates an existing feed
func (m *Manager) UpdateFeed(ctx context.Context, id string, feed *RuleFeed) error {
	if err := feed.Validate(); err != nil {
		return err
	}

	// Validate with appropriate handler
	handler, err := m.getHandler(feed.Type)
	if err != nil {
		return err
	}

	if err := handler.Validate(feed); err != nil {
		return fmt.Errorf("feed validation failed: %w", err)
	}

	return m.storage.UpdateFeed(ctx, id, feed)
}

// DeleteFeed deletes a feed
func (m *Manager) DeleteFeed(ctx context.Context, id string) error {
	return m.storage.DeleteFeed(ctx, id)
}

// SyncFeed synchronizes a specific feed with optional progress callback.
// TASK 158: Now supports progress callback for real-time WebSocket notifications.
func (m *Manager) SyncFeed(ctx context.Context, id string) (*FeedSyncResult, error) {
	return m.SyncFeedWithProgress(ctx, id, nil)
}

// SyncFeedWithProgress synchronizes a specific feed with progress reporting.
// TASK 158: Progress callback enables real-time WebSocket event broadcasting.
// PRODUCTION: Callback is called at key sync milestones with proper error handling.
func (m *Manager) SyncFeedWithProgress(ctx context.Context, id string, progressCallback ProgressCallback) (*FeedSyncResult, error) {
	// Get feed from storage
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return nil, err
	}

	if !feed.Enabled {
		return nil, ErrFeedDisabled
	}

	// Acquire sync lock for this feed
	m.syncMutex.Lock()
	if _, exists := m.syncLocks[id]; !exists {
		m.syncLocks[id] = &sync.Mutex{}
	}
	feedLock := m.syncLocks[id]
	m.syncMutex.Unlock()

	// Try to acquire feed-specific lock
	if !feedLock.TryLock() {
		return nil, ErrFeedSyncing
	}
	defer feedLock.Unlock()

	// Update feed status to syncing
	m.storage.UpdateFeedStatus(ctx, id, FeedStatusSyncing)
	defer m.storage.UpdateFeedStatus(ctx, id, FeedStatusActive)

	// Perform sync
	startTime := time.Now()
	result := &FeedSyncResult{
		FeedID:    feed.ID,
		FeedName:  feed.Name,
		StartTime: startTime,
	}

	m.logger.Infof("Starting sync for feed: %s", feed.Name)

	// TASK 158: Notify sync started
	if progressCallback != nil {
		progressCallback("started", fmt.Sprintf("Starting synchronization of feed: %s", feed.Name), 0)
	}

	// Get appropriate handler
	handler, err := m.getHandler(feed.Type)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).Seconds()
		m.storage.SaveSyncResult(ctx, result)
		// TASK 158: Notify sync failed
		if progressCallback != nil {
			progressCallback("failed", fmt.Sprintf("Feed sync failed: %v", err), 0)
		}
		return result, err
	}

	// TASK 158: Notify fetching rules
	if progressCallback != nil {
		progressCallback("progress", "Fetching rules from feed source...", 10)
	}

	// Fetch rules from feed
	rules, err := handler.FetchRules(ctx, feed)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to fetch rules: %v", err))
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).Seconds()
		m.storage.SaveSyncResult(ctx, result)
		// TASK 158: Notify sync failed
		if progressCallback != nil {
			progressCallback("failed", fmt.Sprintf("Failed to fetch rules: %v", err), 0)
		}
		return result, err
	}

	result.Stats.TotalRules = len(rules)

	// TASK 158: Notify rules fetched
	if progressCallback != nil {
		progressCallback("progress", fmt.Sprintf("Fetched %d rules, starting import...", len(rules)), 30)
	}

	// Import rules
	m.logger.Infof("Importing %d rules from feed: %s", len(rules), feed.Name)
	ruleResults := m.importRules(ctx, feed, rules)
	result.RuleResults = ruleResults

	// TASK 158: Notify import completed
	if progressCallback != nil {
		progressCallback("progress", "Rule import completed, finalizing sync...", 80)
	}

	// Calculate statistics
	for _, rr := range ruleResults {
		switch rr.Action {
		case "imported":
			result.Stats.ImportedRules++
		case "updated":
			result.Stats.UpdatedRules++
		case "skipped":
			result.Stats.SkippedRules++
		case "failed":
			result.Stats.FailedRules++
			if rr.Error != "" {
				result.Errors = append(result.Errors, rr.Error)
			}
		}
	}

	result.Success = result.Stats.FailedRules < result.Stats.TotalRules/2 // Success if < 50% failed
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Seconds()

	// Update feed statistics
	feed.Stats.TotalRules = result.Stats.TotalRules
	feed.Stats.ImportedRules += result.Stats.ImportedRules
	feed.Stats.UpdatedRules += result.Stats.UpdatedRules
	feed.Stats.SkippedRules += result.Stats.SkippedRules
	feed.Stats.FailedRules += result.Stats.FailedRules
	feed.Stats.LastSyncDuration = result.Duration
	feed.Stats.SyncCount++

	if !result.Success && len(result.Errors) > 0 {
		feed.Stats.LastError = result.Errors[0]
	} else {
		feed.Stats.LastError = ""
	}

	m.storage.UpdateFeedStats(ctx, id, &feed.Stats)
	m.storage.UpdateLastSync(ctx, id, startTime)

	// Save sync result
	m.storage.SaveSyncResult(ctx, result)

	m.logger.Infof("Sync completed for feed: %s (Imported: %d, Updated: %d, Skipped: %d, Failed: %d)",
		feed.Name, result.Stats.ImportedRules, result.Stats.UpdatedRules,
		result.Stats.SkippedRules, result.Stats.FailedRules)

	// TASK 158: Notify sync completed
	if progressCallback != nil {
		if result.Success {
			progressCallback("completed", fmt.Sprintf("Feed sync completed successfully: %d imported, %d updated, %d failed",
				result.Stats.ImportedRules, result.Stats.UpdatedRules, result.Stats.FailedRules), 100)
		} else {
			progressCallback("failed", fmt.Sprintf("Feed sync completed with errors: %d failed rules", result.Stats.FailedRules), 0)
		}
	}

	return result, nil
}

// SyncAllFeeds synchronizes all enabled feeds
func (m *Manager) SyncAllFeeds(ctx context.Context) ([]*FeedSyncResult, error) {
	feeds, err := m.storage.GetAllFeeds(ctx)
	if err != nil {
		return nil, err
	}

	var results []*FeedSyncResult
	for _, feed := range feeds {
		if !feed.Enabled {
			continue
		}

		result, err := m.SyncFeed(ctx, feed.ID)
		if err != nil {
			m.logger.Warnf("Failed to sync feed %s: %v", feed.Name, err)
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// ValidateFeed validates a feed configuration
func (m *Manager) ValidateFeed(ctx context.Context, id string) error {
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return err
	}

	handler, err := m.getHandler(feed.Type)
	if err != nil {
		return err
	}

	return handler.Validate(feed)
}

// TestFeedConnection tests connection to a feed
func (m *Manager) TestFeedConnection(ctx context.Context, id string) error {
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return err
	}

	handler, err := m.getHandler(feed.Type)
	if err != nil {
		return err
	}

	return handler.Test(ctx, feed)
}

// StartScheduler starts the feed scheduler
func (m *Manager) StartScheduler() error {
	if m.scheduler != nil {
		return fmt.Errorf("scheduler already running")
	}

	m.scheduler = NewScheduler(m, m.logger)
	return m.scheduler.Start()
}

// StopScheduler stops the feed scheduler
func (m *Manager) StopScheduler() error {
	if m.scheduler == nil {
		return fmt.Errorf("scheduler not running")
	}

	m.scheduler.Stop()
	m.scheduler = nil
	return nil
}

// GetFeedStats retrieves feed statistics
func (m *Manager) GetFeedStats(ctx context.Context, id string) (*FeedStats, error) {
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return nil, err
	}

	return &feed.Stats, nil
}

// GetFeedHealth returns health status of all feeds
func (m *Manager) GetFeedHealth(ctx context.Context) (map[string]string, error) {
	feeds, err := m.storage.GetAllFeeds(ctx)
	if err != nil {
		return nil, err
	}

	health := make(map[string]string)
	for _, feed := range feeds {
		if !feed.Enabled {
			health[feed.ID] = "disabled"
			continue
		}

		if feed.Status == FeedStatusError {
			health[feed.ID] = "error"
		} else if feed.Status == FeedStatusSyncing {
			health[feed.ID] = "syncing"
		} else if feed.Stats.LastError != "" {
			health[feed.ID] = "warning"
		} else {
			health[feed.ID] = "healthy"
		}
	}

	return health, nil
}

// GetSyncHistory retrieves synchronization history for a feed
func (m *Manager) GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*FeedSyncResult, error) {
	// Verify feed exists first
	_, err := m.storage.GetFeed(ctx, feedID)
	if err != nil {
		return nil, err
	}

	// Retrieve history from storage
	return m.storage.GetSyncHistory(ctx, feedID, limit)
}

// Helper methods

func (m *Manager) getHandler(feedType string) (FeedHandler, error) {
	handler, exists := m.handlers[feedType]
	if !exists {
		return nil, ErrUnsupportedType
	}
	return handler, nil
}

func (m *Manager) importRules(ctx context.Context, feed *RuleFeed, sigmaRules []*sigma.SigmaRule) []RuleImportResult {
	var results []RuleImportResult

	// Convert SIGMA rules to internal format
	converter := sigma.NewConverter()

	for _, sigmaRule := range sigmaRules {
		result := RuleImportResult{
			RuleID:    sigmaRule.ID,
			RuleTitle: sigmaRule.Title,
			FilePath:  sigmaRule.FilePath,
		}

		// Convert to internal format
		rule, err := converter.Convert(sigmaRule)
		if err != nil {
			result.Action = "failed"
			result.Error = fmt.Sprintf("conversion failed: %v", err)
			results = append(results, result)
			continue
		}

		// Calculate content hash for deduplication
		contentHash := m.calculateContentHash(sigmaRule)
		rule.Metadata["feed_id"] = feed.ID
		rule.Metadata["feed_name"] = feed.Name
		rule.Metadata["content_hash"] = contentHash
		rule.Metadata["source_file"] = sigmaRule.FilePath

		// Set enabled status based on feed configuration
		rule.Enabled = feed.AutoEnableRules

		// Check if rule already exists
		existingRule, err := m.ruleStorage.GetRuleByID(ctx, rule.ID)
		if err == nil && existingRule != nil {
			// Rule exists, check if it needs updating
			existingHash, _ := existingRule.Metadata["content_hash"]
			if existingHash == contentHash {
				result.Action = "skipped"
				result.Reason = "rule unchanged"
				results = append(results, result)
				continue
			}

			// Update existing rule
			rule.Version = existingRule.Version + 1
			rule.CreatedAt = existingRule.CreatedAt
			rule.UpdatedAt = time.Now()

			if err := m.ruleStorage.UpdateRule(ctx, rule); err != nil {
				result.Action = "failed"
				result.Error = fmt.Sprintf("update failed: %v", err)
			} else {
				result.Action = "updated"
			}
		} else {
			// New rule, create it
			rule.Version = 1
			rule.CreatedAt = time.Now()
			rule.UpdatedAt = time.Now()

			// Generate unique ID if not present
			if rule.ID == "" {
				rule.ID = uuid.New().String()
			}

			if err := m.ruleStorage.CreateRule(ctx, rule); err != nil {
				result.Action = "failed"
				result.Error = fmt.Sprintf("create failed: %v", err)
			} else {
				result.Action = "imported"
			}
		}

		results = append(results, result)
	}

	return results
}

func (m *Manager) calculateContentHash(rule *sigma.SigmaRule) string {
	// Create a canonical representation
	// v2: Include RawYAML to ensure rules are re-imported with sigma_yaml populated
	data := fmt.Sprintf("v2|%s|%s|%v|%s|%s|%s",
		rule.Title, rule.Description, rule.Detection, rule.Level, rule.Status, rule.RawYAML)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GetTemplates returns all available feed templates.
// BLOCKER-1 FIX: Returns error instead of empty slice when template manager is nil.
// Thread-safe for concurrent access.
func (m *Manager) GetTemplates() ([]FeedTemplate, error) {
	if m.templateManager == nil {
		return nil, fmt.Errorf("template manager not initialized")
	}
	return m.templateManager.ListTemplates(), nil
}

// GetTemplate retrieves a specific template by ID.
// Returns nil if template not found or template manager not initialized.
// Thread-safe for concurrent access.
func (m *Manager) GetTemplate(id string) *FeedTemplate {
	if m.templateManager == nil {
		m.logger.Warn("Template manager not initialized")
		return nil
	}
	return m.templateManager.GetTemplate(id)
}

// CreateFeedFromTemplate creates a new feed from a template with optional overrides.
//
// The overrides map supports the following keys:
//   - "id": string - Custom feed ID (auto-generated if not provided)
//   - "name": string - Feed name (required, overrides template name)
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
//   - "url": string - Override URL
//   - "path": string - Override path
//
// Security: All overrides are validated by TemplateManager.ApplyTemplate().
// The created feed is validated before being stored.
//
// Example:
//
//	overrides := map[string]interface{}{
//	    "name": "My Custom Feed",
//	    "enabled": true,
//	    "priority": 150,
//	    "update_strategy": "scheduled",
//	    "update_schedule": "0 */6 * * *",
//	}
//	err := manager.CreateFeedFromTemplate(ctx, "sigmahq-windows", overrides)
//
// Thread-safe for concurrent access.
func (m *Manager) CreateFeedFromTemplate(ctx context.Context, templateID string, overrides map[string]interface{}) error {
	// Validate template manager is available
	if m.templateManager == nil {
		return fmt.Errorf("template manager not initialized")
	}

	// Validate template exists
	template := m.templateManager.GetTemplate(templateID)
	if template == nil {
		return fmt.Errorf("template not found: %s", templateID)
	}

	// Apply template with overrides to create feed
	feed, err := m.templateManager.ApplyTemplate(templateID, overrides)
	if err != nil {
		return fmt.Errorf("failed to apply template: %w", err)
	}

	// Validate the created feed
	if err := feed.Validate(); err != nil {
		return fmt.Errorf("feed validation failed: %w", err)
	}

	// Create the feed using existing CreateFeed method
	if err := m.CreateFeed(ctx, feed); err != nil {
		return fmt.Errorf("failed to create feed: %w", err)
	}

	m.logger.Infow("Feed created from template",
		"template_id", templateID,
		"feed_id", feed.ID,
		"feed_name", feed.Name,
		"feed_type", feed.Type)

	return nil
}
