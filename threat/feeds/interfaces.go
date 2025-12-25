package feeds

import (
	"context"
	"errors"
	"time"

	"cerberus/core"
)

// =============================================================================
// Feed Storage Interface
// =============================================================================

// IOCFeedStorage defines the interface for IOC feed persistence
type IOCFeedStorage interface {
	// Feed CRUD
	CreateFeed(ctx context.Context, feed *IOCFeed) error
	GetFeed(ctx context.Context, id string) (*IOCFeed, error)
	GetAllFeeds(ctx context.Context) ([]*IOCFeed, error)
	UpdateFeed(ctx context.Context, id string, feed *IOCFeed) error
	DeleteFeed(ctx context.Context, id string) error

	// Status and Stats
	UpdateFeedStatus(ctx context.Context, id string, status IOCFeedStatus) error
	UpdateFeedStats(ctx context.Context, id string, stats IOCFeedStats) error
	UpdateLastSync(ctx context.Context, id string, syncTime time.Time) error

	// Sync History
	SaveSyncResult(ctx context.Context, result *IOCFeedSyncResult) error
	GetSyncHistory(ctx context.Context, feedID string, limit int) ([]*IOCFeedSyncResult, error)

	// Queries
	GetEnabledFeeds(ctx context.Context) ([]*IOCFeed, error)
	GetFeedsSummary(ctx context.Context) (*IOCFeedsSummary, error)

	Close() error
}

// =============================================================================
// Feed Handler Interface
// =============================================================================

// IOCFeedHandler defines the interface for type-specific feed implementations
type IOCFeedHandler interface {
	// Type returns the feed type this handler supports
	Type() IOCFeedType

	// Validate checks if the feed configuration is valid
	Validate(feed *IOCFeed) error

	// Test verifies connectivity to the feed source without full sync
	Test(ctx context.Context, feed *IOCFeed) error

	// FetchIOCs retrieves IOCs from the feed
	// If since is provided, only fetch IOCs modified after that time (if supported)
	FetchIOCs(ctx context.Context, feed *IOCFeed, since *time.Time) ([]*FetchedIOC, error)

	// Close releases any resources held by the handler
	Close() error
}

// FetchedIOC represents an IOC fetched from a feed before processing
type FetchedIOC struct {
	// Required fields
	Type  core.IOCType `json:"type"`
	Value string       `json:"value"`

	// Optional fields from feed
	ExternalID  string           `json:"external_id,omitempty"`  // ID in source system
	Severity    core.IOCSeverity `json:"severity,omitempty"`
	Confidence  *float64         `json:"confidence,omitempty"`   // 0-100
	Description string           `json:"description,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	References  []string         `json:"references,omitempty"`
	FirstSeen   *time.Time       `json:"first_seen,omitempty"`
	LastSeen    *time.Time       `json:"last_seen,omitempty"`
	ExpiresAt   *time.Time       `json:"expires_at,omitempty"`

	// Source metadata
	RawData map[string]interface{} `json:"raw_data,omitempty"` // Original data from feed
}

// =============================================================================
// Feed Manager Interface
// =============================================================================

// IOCFeedManager defines the interface for feed management operations
type IOCFeedManager interface {
	// Feed CRUD
	CreateFeed(ctx context.Context, feed *IOCFeed) error
	GetFeed(ctx context.Context, id string) (*IOCFeed, error)
	ListFeeds(ctx context.Context) ([]*IOCFeed, error)
	UpdateFeed(ctx context.Context, id string, feed *IOCFeed) error
	DeleteFeed(ctx context.Context, id string) error

	// Feed Operations
	EnableFeed(ctx context.Context, id string) error
	DisableFeed(ctx context.Context, id string) error
	TestFeed(ctx context.Context, id string) error

	// Sync Operations
	SyncFeed(ctx context.Context, id string) (*IOCFeedSyncResult, error)
	SyncFeedWithProgress(ctx context.Context, id string, callback ProgressCallback) (*IOCFeedSyncResult, error)
	SyncAllFeeds(ctx context.Context) ([]*IOCFeedSyncResult, error)

	// Queries
	GetFeedStats(ctx context.Context, id string) (*IOCFeedStats, error)
	GetSyncHistory(ctx context.Context, id string, limit int) ([]*IOCFeedSyncResult, error)
	GetFeedsSummary(ctx context.Context) (*IOCFeedsSummary, error)
	GetTemplates() []*IOCFeedTemplate

	// Scheduler
	StartScheduler() error
	StopScheduler() error
	IsSchedulerRunning() bool

	// Lifecycle
	Close() error
}

// =============================================================================
// Errors
// =============================================================================

var (
	// Feed errors
	ErrFeedNotFound      = errors.New("feed not found")
	ErrFeedDisabled      = errors.New("feed is disabled")
	ErrFeedSyncing       = errors.New("feed is already syncing")
	ErrInvalidFeedID     = errors.New("invalid feed ID")
	ErrInvalidFeedName   = errors.New("invalid feed name")
	ErrInvalidFeedType   = errors.New("invalid feed type")
	ErrDuplicateFeedID   = errors.New("feed with this ID already exists")
	ErrUnsupportedType   = errors.New("unsupported feed type")

	// Connection errors
	ErrConnectionFailed  = errors.New("connection to feed failed")
	ErrAuthFailed        = errors.New("authentication failed")
	ErrTimeout           = errors.New("operation timed out")

	// Sync errors
	ErrSyncFailed        = errors.New("sync failed")
	ErrNoIOCsFound       = errors.New("no IOCs found in feed")

	// Configuration errors
	ErrMissingURL        = errors.New("URL is required for this feed type")
	ErrMissingPath       = errors.New("path is required for this feed type")
	ErrMissingAuth       = errors.New("authentication credentials are required")
	ErrInvalidConfig     = errors.New("invalid feed configuration")
)
