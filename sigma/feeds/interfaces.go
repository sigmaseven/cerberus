package feeds

import (
	"cerberus/sigma"
	"context"
	"time"
)

// FeedManager orchestrates rule feed operations
type FeedManager interface {
	// Feed CRUD
	CreateFeed(ctx context.Context, feed *RuleFeed) error
	GetFeed(ctx context.Context, id string) (*RuleFeed, error)
	ListFeeds(ctx context.Context) ([]*RuleFeed, error)
	UpdateFeed(ctx context.Context, id string, feed *RuleFeed) error
	DeleteFeed(ctx context.Context, id string) error

	// Feed operations
	SyncFeed(ctx context.Context, id string) (*FeedSyncResult, error)
	SyncAllFeeds(ctx context.Context) ([]*FeedSyncResult, error)
	ValidateFeed(ctx context.Context, id string) error
	TestFeedConnection(ctx context.Context, id string) error

	// Scheduling
	StartScheduler() error
	StopScheduler() error

	// Monitoring
	GetFeedStats(ctx context.Context, id string) (*FeedStats, error)
	GetFeedHealth(ctx context.Context) (map[string]string, error)
}

// FeedHandler handles specific feed types
type FeedHandler interface {
	// Connect to the feed source
	Connect(ctx context.Context, feed *RuleFeed) error

	// Fetch rules from the feed
	FetchRules(ctx context.Context, feed *RuleFeed) ([]*sigma.SigmaRule, error)

	// Validate feed configuration
	Validate(feed *RuleFeed) error

	// Test connection
	Test(ctx context.Context, feed *RuleFeed) error

	// Get feed metadata
	GetMetadata(ctx context.Context, feed *RuleFeed) (map[string]interface{}, error)

	// Clean up resources
	Close() error
}

// FeedStorage handles persistent storage of feed metadata
type FeedStorage interface {
	// Feed CRUD
	CreateFeed(ctx context.Context, feed *RuleFeed) error
	GetFeed(ctx context.Context, id string) (*RuleFeed, error)
	GetAllFeeds(ctx context.Context) ([]*RuleFeed, error)
	UpdateFeed(ctx context.Context, id string, feed *RuleFeed) error
	DeleteFeed(ctx context.Context, id string) error

	// Feed operations
	UpdateFeedStatus(ctx context.Context, id string, status string) error
	UpdateFeedStats(ctx context.Context, id string, stats *FeedStats) error
	UpdateLastSync(ctx context.Context, id string, syncTime time.Time) error

	// Sync history
	SaveSyncResult(ctx context.Context, result *FeedSyncResult) error
	GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*FeedSyncResult, error)
	GetSyncResult(ctx context.Context, syncID string) (*FeedSyncResult, error)

	// Cleanup
	Close() error
}
