package feeds

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"cerberus/core"

	"github.com/google/uuid"
)

// =============================================================================
// IOC Feed Manager Implementation
// =============================================================================

// Manager implements IOCFeedManager interface
type Manager struct {
	config     *IOCFeedConfig
	storage    IOCFeedStorage
	iocStorage core.IOCStorage
	handlers   map[IOCFeedType]IOCFeedHandler
	scheduler  *Scheduler

	// Sync tracking
	syncingMu    sync.RWMutex
	syncingFeeds map[string]bool

	// Expiration sweeper
	expirationTicker *time.Ticker
	expirationDone   chan struct{}

	// Shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// ManagerConfig holds manager initialization options
type ManagerConfig struct {
	Config     *IOCFeedConfig
	Storage    IOCFeedStorage
	IOCStorage core.IOCStorage
}

// NewManager creates a new IOC feed manager
func NewManager(cfg *ManagerConfig) (*Manager, error) {
	if cfg.Storage == nil {
		return nil, fmt.Errorf("feed storage is required")
	}
	if cfg.IOCStorage == nil {
		return nil, fmt.Errorf("IOC storage is required")
	}

	config := cfg.Config
	if config == nil {
		config = DefaultIOCFeedConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:         config,
		storage:        cfg.Storage,
		iocStorage:     cfg.IOCStorage,
		handlers:       make(map[IOCFeedType]IOCFeedHandler),
		syncingFeeds:   make(map[string]bool),
		expirationDone: make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Register default handlers
	m.RegisterHandler(NewCSVHandler())
	m.RegisterHandler(NewJSONHandler())
	m.RegisterHandler(NewOTXHandler())

	return m, nil
}

// RegisterHandler registers a feed handler for a specific type
func (m *Manager) RegisterHandler(handler IOCFeedHandler) {
	m.handlers[handler.Type()] = handler
}

// =============================================================================
// Feed CRUD Operations
// =============================================================================

// CreateFeed creates a new IOC feed
func (m *Manager) CreateFeed(ctx context.Context, feed *IOCFeed) error {
	// Validate feed configuration
	if err := m.validateFeed(feed); err != nil {
		return err
	}

	// Generate ID if not set
	if feed.ID == "" {
		feed.ID = uuid.New().String()
	}

	// Set defaults
	now := time.Now()
	feed.CreatedAt = now
	feed.UpdatedAt = now
	if feed.Status == "" {
		feed.Status = IOCFeedStatusActive
	}
	if feed.UpdateStrategy == "" {
		feed.UpdateStrategy = IOCFeedUpdateManual
	}

	// Validate with type-specific handler
	handler, ok := m.handlers[feed.Type]
	if !ok {
		return ErrUnsupportedType
	}
	if err := handler.Validate(feed); err != nil {
		return err
	}

	return m.storage.CreateFeed(ctx, feed)
}

// GetFeed retrieves a feed by ID
func (m *Manager) GetFeed(ctx context.Context, id string) (*IOCFeed, error) {
	if id == "" {
		return nil, ErrInvalidFeedID
	}
	return m.storage.GetFeed(ctx, id)
}

// ListFeeds retrieves all feeds
func (m *Manager) ListFeeds(ctx context.Context) ([]*IOCFeed, error) {
	return m.storage.GetAllFeeds(ctx)
}

// UpdateFeed updates an existing feed
func (m *Manager) UpdateFeed(ctx context.Context, id string, feed *IOCFeed) error {
	if id == "" {
		return ErrInvalidFeedID
	}

	// Check if syncing
	if m.isSyncing(id) {
		return ErrFeedSyncing
	}

	// Validate feed configuration
	if err := m.validateFeed(feed); err != nil {
		return err
	}

	// Validate with handler
	handler, ok := m.handlers[feed.Type]
	if !ok {
		return ErrUnsupportedType
	}
	if err := handler.Validate(feed); err != nil {
		return err
	}

	feed.UpdatedAt = time.Now()
	return m.storage.UpdateFeed(ctx, id, feed)
}

// DeleteFeed removes a feed and optionally its IOCs
func (m *Manager) DeleteFeed(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidFeedID
	}

	// Check if syncing
	if m.isSyncing(id) {
		return ErrFeedSyncing
	}

	return m.storage.DeleteFeed(ctx, id)
}

// =============================================================================
// Feed Operations
// =============================================================================

// EnableFeed enables a feed for syncing
func (m *Manager) EnableFeed(ctx context.Context, id string) error {
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return err
	}

	feed.Enabled = true
	feed.Status = IOCFeedStatusActive
	feed.UpdatedAt = time.Now()

	return m.storage.UpdateFeed(ctx, id, feed)
}

// DisableFeed disables a feed
func (m *Manager) DisableFeed(ctx context.Context, id string) error {
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return err
	}

	feed.Enabled = false
	feed.Status = IOCFeedStatusDisabled
	feed.UpdatedAt = time.Now()

	return m.storage.UpdateFeed(ctx, id, feed)
}

// TestFeed tests connectivity to a feed
func (m *Manager) TestFeed(ctx context.Context, id string) error {
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return err
	}

	handler, ok := m.handlers[feed.Type]
	if !ok {
		return ErrUnsupportedType
	}

	return handler.Test(ctx, feed)
}

// =============================================================================
// Sync Operations
// =============================================================================

// SyncFeed synchronizes a feed without progress callbacks
func (m *Manager) SyncFeed(ctx context.Context, id string) (*IOCFeedSyncResult, error) {
	return m.SyncFeedWithProgress(ctx, id, nil)
}

// SyncFeedWithProgress synchronizes a feed with progress callbacks
func (m *Manager) SyncFeedWithProgress(ctx context.Context, id string, callback ProgressCallback) (*IOCFeedSyncResult, error) {
	// Get feed
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check if enabled
	if !feed.Enabled {
		return nil, ErrFeedDisabled
	}

	// Check if already syncing
	if !m.startSync(id) {
		return nil, ErrFeedSyncing
	}
	defer m.endSync(id)

	// Update status
	if err := m.storage.UpdateFeedStatus(ctx, id, IOCFeedStatusSyncing); err != nil {
		log.Printf("Failed to update feed status: %v", err)
	}

	// Create sync result
	result := &IOCFeedSyncResult{
		ID:        uuid.New().String(),
		FeedID:    feed.ID,
		FeedName:  feed.Name,
		StartTime: time.Now(),
	}

	// Report progress
	if callback != nil {
		callback(ProgressEventStarted, fmt.Sprintf("Starting sync for feed: %s", feed.Name), 0)
	}

	// Get handler
	handler, ok := m.handlers[feed.Type]
	if !ok {
		result.Success = false
		result.Errors = append(result.Errors, ErrUnsupportedType.Error())
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).Seconds()
		m.finalizeSyncResult(ctx, feed, result, callback)
		return result, ErrUnsupportedType
	}

	// Fetch IOCs
	if callback != nil {
		callback(ProgressEventProgress, "Fetching IOCs from feed...", 10)
	}

	fetchedIOCs, err := handler.FetchIOCs(ctx, feed, feed.LastSync)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).Seconds()
		m.finalizeSyncResult(ctx, feed, result, callback)
		return result, err
	}

	result.Stats.TotalIOCs = int64(len(fetchedIOCs))

	// Process IOCs in batches
	if callback != nil {
		callback(ProgressEventProgress, fmt.Sprintf("Processing %d IOCs...", len(fetchedIOCs)), 30)
	}

	batchSize := m.config.ImportSettings.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}

	for i := 0; i < len(fetchedIOCs); i += batchSize {
		select {
		case <-ctx.Done():
			result.Success = false
			result.Errors = append(result.Errors, ctx.Err().Error())
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime).Seconds()
			m.finalizeSyncResult(ctx, feed, result, callback)
			return result, ctx.Err()
		default:
		}

		end := i + batchSize
		if end > len(fetchedIOCs) {
			end = len(fetchedIOCs)
		}

		batch := fetchedIOCs[i:end]
		m.processBatch(ctx, feed, batch, result)

		// Report progress
		if callback != nil {
			progress := 30 + int(float64(end)/float64(len(fetchedIOCs))*60)
			callback(ProgressEventProgress, fmt.Sprintf("Processed %d/%d IOCs", end, len(fetchedIOCs)), progress)
		}
	}

	result.Success = true
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).Seconds()

	m.finalizeSyncResult(ctx, feed, result, callback)

	return result, nil
}

// SyncAllFeeds synchronizes all enabled feeds
func (m *Manager) SyncAllFeeds(ctx context.Context) ([]*IOCFeedSyncResult, error) {
	feeds, err := m.storage.GetEnabledFeeds(ctx)
	if err != nil {
		return nil, err
	}

	var results []*IOCFeedSyncResult
	for _, feed := range feeds {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result, err := m.SyncFeed(ctx, feed.ID)
		if err != nil {
			log.Printf("Failed to sync feed %s: %v", feed.ID, err)
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// =============================================================================
// Query Operations
// =============================================================================

// GetFeedStats retrieves statistics for a feed
func (m *Manager) GetFeedStats(ctx context.Context, id string) (*IOCFeedStats, error) {
	feed, err := m.storage.GetFeed(ctx, id)
	if err != nil {
		return nil, err
	}
	return &feed.Stats, nil
}

// GetSyncHistory retrieves sync history for a feed
func (m *Manager) GetSyncHistory(ctx context.Context, id string, limit int) ([]*IOCFeedSyncResult, error) {
	if limit <= 0 {
		limit = 10
	}
	return m.storage.GetSyncHistory(ctx, id, limit)
}

// GetFeedsSummary retrieves aggregate statistics
func (m *Manager) GetFeedsSummary(ctx context.Context) (*IOCFeedsSummary, error) {
	return m.storage.GetFeedsSummary(ctx)
}

// GetTemplates returns available feed templates
func (m *Manager) GetTemplates() []*IOCFeedTemplate {
	return GetIOCFeedTemplates()
}

// =============================================================================
// Scheduler Operations
// =============================================================================

// StartScheduler starts the feed scheduler
func (m *Manager) StartScheduler() error {
	if !m.config.Scheduler.Enabled {
		return nil
	}

	if m.scheduler != nil {
		return nil // Already running
	}

	var err error
	m.scheduler, err = NewScheduler(&SchedulerConfig{
		Manager:            m,
		MaxConcurrentSyncs: m.config.Scheduler.MaxConcurrentSyncs,
		SyncTimeout:        time.Duration(m.config.Scheduler.SyncTimeout) * time.Second,
		Timezone:           m.config.Scheduler.Timezone,
	})
	if err != nil {
		return err
	}

	return m.scheduler.Start()
}

// StopScheduler stops the feed scheduler
func (m *Manager) StopScheduler() error {
	if m.scheduler == nil {
		return nil
	}
	return m.scheduler.Stop()
}

// IsSchedulerRunning returns true if scheduler is running
func (m *Manager) IsSchedulerRunning() bool {
	return m.scheduler != nil && m.scheduler.IsRunning()
}

// =============================================================================
// Expiration Sweeper
// =============================================================================

// ExpirationSweeperInterval defines how often to check for expired IOCs
const ExpirationSweeperInterval = 1 * time.Hour

// StartExpirationSweeper starts the background expiration sweeper
// The sweeper periodically checks for and archives expired IOCs
func (m *Manager) StartExpirationSweeper() {
	if m.expirationTicker != nil {
		return // Already running
	}

	m.expirationTicker = time.NewTicker(ExpirationSweeperInterval)

	go func() {
		log.Printf("IOC expiration sweeper started (interval: %v)", ExpirationSweeperInterval)

		// Run immediately on start
		m.runExpirationSweep()

		for {
			select {
			case <-m.expirationTicker.C:
				m.runExpirationSweep()
			case <-m.ctx.Done():
				log.Println("IOC expiration sweeper stopping due to context cancellation")
				return
			case <-m.expirationDone:
				log.Println("IOC expiration sweeper stopped")
				return
			}
		}
	}()
}

// StopExpirationSweeper stops the background expiration sweeper
func (m *Manager) StopExpirationSweeper() {
	if m.expirationTicker != nil {
		m.expirationTicker.Stop()
		m.expirationTicker = nil
	}

	// Signal the goroutine to stop
	select {
	case m.expirationDone <- struct{}{}:
	default:
	}
}

// runExpirationSweep performs a single expiration sweep
func (m *Manager) runExpirationSweep() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	archived, err := m.iocStorage.ArchiveExpiredIOCs(ctx)
	if err != nil {
		log.Printf("Error during IOC expiration sweep: %v", err)
		return
	}

	if archived > 0 {
		log.Printf("IOC expiration sweep completed: %d IOCs archived", archived)
	}
}

// =============================================================================
// Lifecycle
// =============================================================================

// Close releases all resources
func (m *Manager) Close() error {
	m.cancel()

	// Stop expiration sweeper
	m.StopExpirationSweeper()

	// Stop scheduler
	if err := m.StopScheduler(); err != nil {
		log.Printf("Error stopping scheduler: %v", err)
	}

	// Close handlers
	for _, handler := range m.handlers {
		if err := handler.Close(); err != nil {
			log.Printf("Error closing handler: %v", err)
		}
	}

	return nil
}

// =============================================================================
// Internal Methods
// =============================================================================

// validateFeed validates basic feed configuration
func (m *Manager) validateFeed(feed *IOCFeed) error {
	if feed.Name == "" {
		return ErrInvalidFeedName
	}
	if !feed.Type.IsValid() {
		return ErrInvalidFeedType
	}
	if feed.UpdateStrategy != "" && !feed.UpdateStrategy.IsValid() {
		return fmt.Errorf("%w: invalid update strategy", ErrInvalidConfig)
	}
	return nil
}

// startSync marks a feed as syncing (returns false if already syncing)
func (m *Manager) startSync(feedID string) bool {
	m.syncingMu.Lock()
	defer m.syncingMu.Unlock()

	if m.syncingFeeds[feedID] {
		return false
	}
	m.syncingFeeds[feedID] = true
	return true
}

// endSync marks a feed as not syncing
func (m *Manager) endSync(feedID string) {
	m.syncingMu.Lock()
	defer m.syncingMu.Unlock()
	delete(m.syncingFeeds, feedID)
}

// isSyncing checks if a feed is currently syncing
func (m *Manager) isSyncing(feedID string) bool {
	m.syncingMu.RLock()
	defer m.syncingMu.RUnlock()
	return m.syncingFeeds[feedID]
}

// processBatch processes a batch of fetched IOCs
func (m *Manager) processBatch(ctx context.Context, feed *IOCFeed, batch []*FetchedIOC, result *IOCFeedSyncResult) {
	for _, fetched := range batch {
		importResult := m.processIOC(ctx, feed, fetched)

		// Track result
		switch importResult.Action {
		case IOCImportActionImported:
			result.Stats.ImportedIOCs++
		case IOCImportActionUpdated:
			result.Stats.UpdatedIOCs++
		case IOCImportActionSkipped:
			result.Stats.SkippedIOCs++
		case IOCImportActionFailed:
			result.Stats.FailedIOCs++
		}

		// Store sample results (limit to avoid bloat)
		if len(result.IOCResults) < 100 {
			result.IOCResults = append(result.IOCResults, *importResult)
		}
	}
}

// processIOC processes a single fetched IOC
func (m *Manager) processIOC(ctx context.Context, feed *IOCFeed, fetched *FetchedIOC) *IOCImportResult {
	result := &IOCImportResult{
		IOCValue: fetched.Value,
		IOCType:  string(fetched.Type),
	}

	// Apply confidence filter
	if feed.MinConfidence > 0 && fetched.Confidence != nil {
		if *fetched.Confidence < feed.MinConfidence {
			result.Action = IOCImportActionSkipped
			result.Reason = fmt.Sprintf("confidence %.1f below threshold %.1f", *fetched.Confidence, feed.MinConfidence)
			return result
		}
	}

	// Check for existing IOC by external ID
	if fetched.ExternalID != "" && m.config.ImportSettings.SkipDuplicates {
		existing, err := m.iocStorage.FindByFeedExternalID(ctx, feed.ID, fetched.ExternalID)
		if err == nil && existing != nil {
			// Update existing IOC if feed has higher or equal priority
			if m.shouldUpdate(existing, feed) {
				if err := m.updateIOC(ctx, existing, fetched, feed); err != nil {
					result.Action = IOCImportActionFailed
					result.Reason = err.Error()
					return result
				}
				result.Action = IOCImportActionUpdated
				return result
			}
			result.Action = IOCImportActionSkipped
			result.Reason = "existing IOC from higher priority feed"
			return result
		}
	}

	// Check for existing IOC by value using FindByValue
	if m.config.ImportSettings.DeduplicationKey == "value" && m.config.ImportSettings.SkipDuplicates {
		normalizedValue := core.NormalizeIOCValue(fetched.Type, fetched.Value)
		existing, err := m.iocStorage.FindByValue(ctx, fetched.Type, normalizedValue)
		if err == nil && existing != nil {
			if m.shouldUpdate(existing, feed) {
				if err := m.updateIOC(ctx, existing, fetched, feed); err != nil {
					result.Action = IOCImportActionFailed
					result.Reason = err.Error()
					return result
				}
				result.Action = IOCImportActionUpdated
				return result
			}
			result.Action = IOCImportActionSkipped
			result.Reason = "duplicate value from higher priority feed"
			return result
		}
	}

	// Create new IOC
	ioc := m.convertToIOC(fetched, feed)
	if err := m.iocStorage.CreateIOC(ctx, ioc); err != nil {
		result.Action = IOCImportActionFailed
		result.Reason = err.Error()
		return result
	}

	result.Action = IOCImportActionImported
	return result
}

// shouldUpdate determines if existing IOC should be updated
func (m *Manager) shouldUpdate(existing *core.IOC, newFeed *IOCFeed) bool {
	// Manual IOCs should not be overwritten
	if existing.IsManual() {
		return false
	}

	// Always update if from same feed
	if existing.FeedID == newFeed.ID {
		return true
	}

	// Compare priorities (higher wins)
	// In a real implementation, we'd look up the existing feed's priority
	// For now, assume new feed can update
	return newFeed.Priority > 0
}

// updateIOC updates an existing IOC with fetched data
func (m *Manager) updateIOC(ctx context.Context, existing *core.IOC, fetched *FetchedIOC, feed *IOCFeed) error {
	// Update fields from fetched
	if fetched.Description != "" {
		existing.Description = fetched.Description
	}
	if fetched.Severity != "" {
		existing.Severity = fetched.Severity
	}
	if fetched.Confidence != nil {
		existing.Confidence = *fetched.Confidence
	}
	if len(fetched.Tags) > 0 {
		// Merge tags
		tagSet := make(map[string]bool)
		for _, t := range existing.Tags {
			tagSet[t] = true
		}
		for _, t := range fetched.Tags {
			tagSet[t] = true
		}
		for _, t := range feed.Tags {
			tagSet[t] = true
		}
		existing.Tags = make([]string, 0, len(tagSet))
		for t := range tagSet {
			existing.Tags = append(existing.Tags, t)
		}
	}
	if len(fetched.References) > 0 {
		existing.References = append(existing.References, fetched.References...)
	}
	if fetched.LastSeen != nil {
		existing.LastSeen = fetched.LastSeen
	}
	if fetched.ExpiresAt != nil {
		existing.ExpiresAt = fetched.ExpiresAt
	}

	// Update feed attribution
	existing.FeedID = feed.ID
	existing.FeedName = feed.Name
	existing.ExternalID = fetched.ExternalID
	now := time.Now()
	existing.ImportedAt = &now
	existing.UpdatedAt = now

	return m.iocStorage.UpdateIOC(ctx, existing)
}

// convertToIOC converts a FetchedIOC to core.IOC
func (m *Manager) convertToIOC(fetched *FetchedIOC, feed *IOCFeed) *core.IOC {
	now := time.Now()

	ioc := &core.IOC{
		ID:          uuid.New().String(),
		Type:        fetched.Type,
		Value:       fetched.Value,
		Description: fetched.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
		Status:      core.IOCStatusActive,

		// Feed attribution
		FeedID:     feed.ID,
		FeedName:   feed.Name,
		ExternalID: fetched.ExternalID,
		ImportedAt: &now,
	}

	// Set severity (prefer fetched, then feed default, then medium)
	if fetched.Severity != "" {
		ioc.Severity = fetched.Severity
	} else if feed.DefaultSeverity != "" {
		ioc.Severity = feed.DefaultSeverity
	} else {
		ioc.Severity = core.IOCSeverityMedium
	}

	// Set confidence
	if fetched.Confidence != nil {
		ioc.Confidence = *fetched.Confidence
	}

	// Set status
	if feed.DefaultStatus != "" {
		ioc.Status = feed.DefaultStatus
	}

	// Set timestamps
	if fetched.FirstSeen != nil {
		ioc.FirstSeen = fetched.FirstSeen
	} else {
		ioc.FirstSeen = &now
	}
	if fetched.LastSeen != nil {
		ioc.LastSeen = fetched.LastSeen
	}

	// Set expiration
	// Priority: 1) fetched value, 2) feed-specific setting, 3) type-specific default
	if fetched.ExpiresAt != nil {
		// Use expiration from feed source if provided
		ioc.ExpiresAt = fetched.ExpiresAt
	} else if feed.AutoExpireDays == core.IOCExpirationNever {
		// Feed explicitly configured for "never expire"
		ioc.ExpiresAt = nil
	} else if feed.AutoExpireDays > 0 {
		// Feed has specific expiration days configured
		expires := now.Add(time.Duration(feed.AutoExpireDays) * 24 * time.Hour)
		ioc.ExpiresAt = &expires
	} else {
		// Use type-specific default expiration (e.g., IPs=30 days, hashes=730 days)
		defaultDays := core.GetDefaultExpirationDays(fetched.Type)
		if defaultDays > 0 {
			expires := now.Add(time.Duration(defaultDays) * 24 * time.Hour)
			ioc.ExpiresAt = &expires
		}
		// If defaultDays <= 0, leave ExpiresAt nil (never expire)
	}

	// Merge tags
	ioc.Tags = append(ioc.Tags, fetched.Tags...)
	ioc.Tags = append(ioc.Tags, feed.Tags...)

	// Set references
	ioc.References = fetched.References

	// Set source
	ioc.Source = fmt.Sprintf("feed:%s", feed.Name)

	return ioc
}

// finalizeSyncResult updates storage with sync result
func (m *Manager) finalizeSyncResult(ctx context.Context, feed *IOCFeed, result *IOCFeedSyncResult, callback ProgressCallback) {
	// Update feed stats
	feed.Stats = result.Stats
	feed.Stats.SyncCount++
	feed.Stats.LastSyncDuration = result.Duration
	feed.Stats.LastSyncTime = result.EndTime.Format(time.RFC3339)
	if !result.Success && len(result.Errors) > 0 {
		feed.Stats.LastError = result.Errors[len(result.Errors)-1]
	} else {
		feed.Stats.LastError = ""
	}

	// Update status
	status := IOCFeedStatusActive
	if !result.Success {
		status = IOCFeedStatusError
	}
	if err := m.storage.UpdateFeedStatus(ctx, feed.ID, status); err != nil {
		log.Printf("Failed to update feed status: %v", err)
	}

	// Update stats
	if err := m.storage.UpdateFeedStats(ctx, feed.ID, feed.Stats); err != nil {
		log.Printf("Failed to update feed stats: %v", err)
	}

	// Update last sync time
	if result.Success {
		if err := m.storage.UpdateLastSync(ctx, feed.ID, result.EndTime); err != nil {
			log.Printf("Failed to update last sync: %v", err)
		}
	}

	// Save sync result
	if err := m.storage.SaveSyncResult(ctx, result); err != nil {
		log.Printf("Failed to save sync result: %v", err)
	}

	// Report completion
	if callback != nil {
		if result.Success {
			callback(ProgressEventCompleted, fmt.Sprintf("Sync completed: %d imported, %d updated, %d skipped",
				result.Stats.ImportedIOCs, result.Stats.UpdatedIOCs, result.Stats.SkippedIOCs), 100)
		} else {
			errMsg := "Sync failed"
			if len(result.Errors) > 0 {
				errMsg = result.Errors[0]
			}
			callback(ProgressEventFailed, errMsg, 100)
		}
	}
}

// Ensure Manager satisfies interface at compile time
var _ IOCFeedManager = (*Manager)(nil)
