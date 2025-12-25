package feeds

import "errors"

// Feed validation errors
var (
	ErrInvalidFeedID   = errors.New("invalid feed ID")
	ErrInvalidFeedName = errors.New("invalid feed name")
	ErrInvalidFeedType = errors.New("invalid feed type")
	ErrMissingURL      = errors.New("missing URL for feed")
	ErrMissingPath     = errors.New("missing path for feed")
	ErrFeedNotFound    = errors.New("feed not found")
	ErrFeedDisabled    = errors.New("feed is disabled")
	ErrFeedSyncing     = errors.New("feed is already syncing")
)

// Feed operation errors
var (
	ErrConnectionFailed = errors.New("failed to connect to feed")
	ErrAuthFailed       = errors.New("authentication failed")
	ErrSyncFailed       = errors.New("feed synchronization failed")
	ErrInvalidConfig    = errors.New("invalid feed configuration")
	ErrUnsupportedType  = errors.New("unsupported feed type")
)

// Storage errors
var (
	ErrStorageNotAvailable = errors.New("feed storage not available")
	ErrDuplicateFeedID     = errors.New("feed with this ID already exists")
)
