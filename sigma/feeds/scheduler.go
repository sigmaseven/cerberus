package feeds

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Scheduler handles automated feed synchronization
type Scheduler struct {
	manager    *Manager
	logger     *zap.SugaredLogger
	stopCh     chan struct{}
	wg         sync.WaitGroup
	running    bool
	runningMux sync.Mutex
}

// NewScheduler creates a new feed scheduler
func NewScheduler(manager *Manager, logger *zap.SugaredLogger) *Scheduler {
	return &Scheduler{
		manager: manager,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

// Start starts the scheduler
func (s *Scheduler) Start() error {
	s.runningMux.Lock()
	defer s.runningMux.Unlock()

	if s.running {
		return nil
	}

	s.running = true
	s.stopCh = make(chan struct{})

	s.wg.Add(1)
	go s.run()

	s.logger.Info("Feed scheduler started")
	return nil
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.runningMux.Lock()
	defer s.runningMux.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.wg.Wait()
	s.running = false

	s.logger.Info("Feed scheduler stopped")
}

// run is the main scheduler loop
func (s *Scheduler) run() {
	defer s.wg.Done()

	// Check every minute for feeds that need syncing
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkAndSyncFeeds()
		}
	}
}

// checkAndSyncFeeds checks all feeds and syncs those that are due.
// Uses a context with timeout that also respects the shutdown signal.
func (s *Scheduler) checkAndSyncFeeds() {
	// Create context with timeout that also respects shutdown signal
	// 30 minute timeout allows for long-running sync operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Make the context cancellable via stopCh for graceful shutdown
	go func() {
		select {
		case <-s.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	feeds, err := s.manager.ListFeeds(ctx)
	if err != nil {
		if ctx.Err() == context.Canceled {
			s.logger.Info("Feed listing cancelled during shutdown")
			return
		}
		s.logger.Errorf("Failed to list feeds: %v", err)
		return
	}

	now := time.Now()

	for _, feed := range feeds {
		// Check for cancellation before processing each feed
		select {
		case <-ctx.Done():
			s.logger.Info("Feed sync check cancelled during shutdown")
			return
		default:
		}

		if !feed.Enabled {
			continue
		}

		// Check if feed needs syncing
		shouldSync := false

		switch feed.UpdateStrategy {
		case UpdateStartup:
			// Already synced at startup, skip
			continue

		case UpdateScheduled:
			// Check if it's time to sync based on schedule
			if !feed.NextSync.IsZero() && now.After(feed.NextSync) {
				shouldSync = true
			} else if feed.NextSync.IsZero() {
				// First run, calculate next sync
				shouldSync = true
			}

		case UpdateManual:
			// Manual updates only, skip
			continue
		}

		if shouldSync {
			s.logger.Infof("Triggering scheduled sync for feed: %s", feed.Name)

			_, err := s.manager.SyncFeed(ctx, feed.ID)
			if err != nil {
				if ctx.Err() == context.Canceled {
					s.logger.Infof("Feed sync for %s cancelled during shutdown", feed.Name)
					return
				}
				s.logger.Errorf("Failed to sync feed %s: %v", feed.Name, err)
			}

			// Update next sync time (simple: sync every 24 hours)
			// In future, implement proper cron parsing
			nextSync := now.Add(24 * time.Hour)
			feed.NextSync = nextSync
			s.manager.storage.UpdateFeed(ctx, feed.ID, feed)
		}
	}
}
