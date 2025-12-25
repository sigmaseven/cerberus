package feeds

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// =============================================================================
// IOC Feed Scheduler
// =============================================================================

// Scheduler handles automatic feed synchronization
type Scheduler struct {
	manager            IOCFeedManager
	cron               *cron.Cron
	maxConcurrentSyncs int
	syncTimeout        time.Duration
	timezone           *time.Location

	// Sync tracking
	syncingSem chan struct{}

	// State
	mu       sync.RWMutex
	running  bool
	feedJobs map[string]cron.EntryID // feedID -> cron entry ID

	// Shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// SchedulerConfig holds scheduler configuration
type SchedulerConfig struct {
	Manager            IOCFeedManager
	MaxConcurrentSyncs int
	SyncTimeout        time.Duration
	Timezone           string
}

// NewScheduler creates a new feed scheduler
func NewScheduler(cfg *SchedulerConfig) (*Scheduler, error) {
	if cfg.Manager == nil {
		return nil, ErrInvalidConfig
	}

	// Parse timezone
	tz := time.UTC
	if cfg.Timezone != "" {
		loc, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			log.Printf("Invalid timezone %s, using UTC: %v", cfg.Timezone, err)
		} else {
			tz = loc
		}
	}

	maxConcurrent := cfg.MaxConcurrentSyncs
	if maxConcurrent <= 0 {
		maxConcurrent = 3
	}

	syncTimeout := cfg.SyncTimeout
	if syncTimeout <= 0 {
		syncTimeout = 30 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Scheduler{
		manager:            cfg.Manager,
		maxConcurrentSyncs: maxConcurrent,
		syncTimeout:        syncTimeout,
		timezone:           tz,
		syncingSem:         make(chan struct{}, maxConcurrent),
		feedJobs:           make(map[string]cron.EntryID),
		ctx:                ctx,
		cancel:             cancel,
	}

	// Create cron scheduler with timezone
	s.cron = cron.New(
		cron.WithLocation(tz),
		cron.WithSeconds(), // Support second-level precision
		cron.WithLogger(cron.VerbosePrintfLogger(log.Default())),
	)

	return s, nil
}

// Start starts the scheduler
func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	// Load scheduled feeds
	if err := s.loadScheduledFeeds(); err != nil {
		return err
	}

	// Start cron
	s.cron.Start()
	s.running = true

	log.Printf("IOC feed scheduler started with %d max concurrent syncs", s.maxConcurrentSyncs)
	return nil
}

// Stop stops the scheduler
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.cancel()
	ctx := s.cron.Stop()
	<-ctx.Done() // Wait for running jobs to complete

	s.running = false
	log.Printf("IOC feed scheduler stopped")
	return nil
}

// IsRunning returns true if scheduler is running
func (s *Scheduler) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// RefreshFeed refreshes a single feed's schedule
func (s *Scheduler) RefreshFeed(feedID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove existing job if present
	if entryID, exists := s.feedJobs[feedID]; exists {
		s.cron.Remove(entryID)
		delete(s.feedJobs, feedID)
	}

	// Get feed
	feed, err := s.manager.GetFeed(context.Background(), feedID)
	if err != nil {
		return err
	}

	// Schedule if applicable
	return s.scheduleFeedLocked(feed)
}

// RemoveFeed removes a feed from the schedule
func (s *Scheduler) RemoveFeed(feedID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entryID, exists := s.feedJobs[feedID]; exists {
		s.cron.Remove(entryID)
		delete(s.feedJobs, feedID)
	}
}

// =============================================================================
// Internal Methods
// =============================================================================

// loadScheduledFeeds loads and schedules all enabled feeds with scheduled update strategy
func (s *Scheduler) loadScheduledFeeds() error {
	feeds, err := s.manager.ListFeeds(context.Background())
	if err != nil {
		return err
	}

	for _, feed := range feeds {
		if err := s.scheduleFeedLocked(feed); err != nil {
			log.Printf("Failed to schedule feed %s: %v", feed.ID, err)
		}
	}

	// Also handle startup syncs
	go s.handleStartupSyncs(feeds)

	return nil
}

// scheduleFeedLocked schedules a feed (must hold lock)
func (s *Scheduler) scheduleFeedLocked(feed *IOCFeed) error {
	// Only schedule enabled feeds with scheduled update strategy
	if !feed.Enabled || feed.UpdateStrategy != IOCFeedUpdateScheduled {
		return nil
	}

	// Validate cron expression
	if feed.UpdateSchedule == "" {
		return nil
	}

	// Create sync job
	entryID, err := s.cron.AddFunc(feed.UpdateSchedule, func() {
		s.syncFeed(feed.ID)
	})
	if err != nil {
		return err
	}

	s.feedJobs[feed.ID] = entryID
	log.Printf("Scheduled feed %s (%s) with schedule: %s", feed.Name, feed.ID, feed.UpdateSchedule)

	return nil
}

// handleStartupSyncs handles feeds that should sync at startup
func (s *Scheduler) handleStartupSyncs(feeds []*IOCFeed) {
	for _, feed := range feeds {
		if !feed.Enabled {
			continue
		}

		shouldSync := false
		switch feed.UpdateStrategy {
		case IOCFeedUpdateStartup:
			shouldSync = true
		case IOCFeedUpdateScheduled:
			// Check if last sync was too long ago
			if feed.LastSync == nil || time.Since(*feed.LastSync) > 24*time.Hour {
				shouldSync = true
			}
		}

		if shouldSync {
			go s.syncFeed(feed.ID)
		}
	}
}

// syncFeed performs a feed sync with concurrency limiting
func (s *Scheduler) syncFeed(feedID string) {
	// Acquire semaphore
	select {
	case s.syncingSem <- struct{}{}:
	case <-s.ctx.Done():
		return
	}
	defer func() { <-s.syncingSem }()

	// Create timeout context
	ctx, cancel := context.WithTimeout(s.ctx, s.syncTimeout)
	defer cancel()

	log.Printf("Scheduled sync starting for feed: %s", feedID)

	result, err := s.manager.SyncFeed(ctx, feedID)
	if err != nil {
		log.Printf("Scheduled sync failed for feed %s: %v", feedID, err)
		return
	}

	if result.Success {
		log.Printf("Scheduled sync completed for feed %s: %d imported, %d updated",
			feedID, result.Stats.ImportedIOCs, result.Stats.UpdatedIOCs)
	} else {
		log.Printf("Scheduled sync had errors for feed %s: %v", feedID, result.Errors)
	}
}

// GetNextSyncTime returns the next scheduled sync time for a feed
func (s *Scheduler) GetNextSyncTime(feedID string) *time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entryID, exists := s.feedJobs[feedID]
	if !exists {
		return nil
	}

	entry := s.cron.Entry(entryID)
	if entry.Valid() {
		next := entry.Next
		return &next
	}
	return nil
}

// GetAllNextSyncTimes returns next sync times for all scheduled feeds
func (s *Scheduler) GetAllNextSyncTimes() map[string]time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]time.Time)
	for feedID, entryID := range s.feedJobs {
		entry := s.cron.Entry(entryID)
		if entry.Valid() {
			result[feedID] = entry.Next
		}
	}
	return result
}

// TriggerSync manually triggers a sync for a feed (bypasses schedule)
func (s *Scheduler) TriggerSync(feedID string) {
	go s.syncFeed(feedID)
}
