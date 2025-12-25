package feeds

import (
	"time"

	"cerberus/core"
)

// =============================================================================
// IOC Feed Types and Constants
// =============================================================================

// IOCFeedType represents supported feed source types
type IOCFeedType string

const (
	IOCFeedTypeSTIX       IOCFeedType = "stix"       // STIX/TAXII 2.x
	IOCFeedTypeMISP       IOCFeedType = "misp"       // MISP platform
	IOCFeedTypeOTX        IOCFeedType = "otx"        // AlienVault OTX
	IOCFeedTypeCSV        IOCFeedType = "csv"        // CSV file/URL
	IOCFeedTypeJSON       IOCFeedType = "json"       // JSON file/URL
	IOCFeedTypeHTTP       IOCFeedType = "http"       // Generic HTTP API
	IOCFeedTypeFilesystem IOCFeedType = "filesystem" // Local files
)

// AllIOCFeedTypes returns all valid feed types
var AllIOCFeedTypes = []IOCFeedType{
	IOCFeedTypeSTIX, IOCFeedTypeMISP, IOCFeedTypeOTX,
	IOCFeedTypeCSV, IOCFeedTypeJSON, IOCFeedTypeHTTP, IOCFeedTypeFilesystem,
}

// IsValid checks if the feed type is valid
func (t IOCFeedType) IsValid() bool {
	for _, valid := range AllIOCFeedTypes {
		if t == valid {
			return true
		}
	}
	return false
}

// IOCFeedStatus represents feed operational status
type IOCFeedStatus string

const (
	IOCFeedStatusActive   IOCFeedStatus = "active"
	IOCFeedStatusDisabled IOCFeedStatus = "disabled"
	IOCFeedStatusError    IOCFeedStatus = "error"
	IOCFeedStatusSyncing  IOCFeedStatus = "syncing"
)

// AllIOCFeedStatuses returns all valid feed statuses
var AllIOCFeedStatuses = []IOCFeedStatus{
	IOCFeedStatusActive, IOCFeedStatusDisabled, IOCFeedStatusError, IOCFeedStatusSyncing,
}

// IsValid checks if the feed status is valid
func (s IOCFeedStatus) IsValid() bool {
	for _, valid := range AllIOCFeedStatuses {
		if s == valid {
			return true
		}
	}
	return false
}

// IOCFeedUpdateStrategy represents how feeds are updated
type IOCFeedUpdateStrategy string

const (
	IOCFeedUpdateManual    IOCFeedUpdateStrategy = "manual"    // Manual sync only
	IOCFeedUpdateStartup   IOCFeedUpdateStrategy = "startup"   // Sync at startup
	IOCFeedUpdateScheduled IOCFeedUpdateStrategy = "scheduled" // Cron-based sync
)

// IsValid checks if the update strategy is valid
func (s IOCFeedUpdateStrategy) IsValid() bool {
	return s == IOCFeedUpdateManual || s == IOCFeedUpdateStartup || s == IOCFeedUpdateScheduled
}

// =============================================================================
// IOC Feed Configuration
// =============================================================================

// IOCFeed represents a threat intelligence feed configuration
type IOCFeed struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Type        IOCFeedType   `json:"type"`
	Status      IOCFeedStatus `json:"status"`
	Enabled     bool          `json:"enabled"`

	// Connection
	URL        string                 `json:"url,omitempty"`
	AuthConfig map[string]interface{} `json:"auth_config,omitempty"`

	// STIX/TAXII specific
	CollectionID string `json:"collection_id,omitempty"`
	APIRoot      string `json:"api_root,omitempty"`

	// MISP specific
	OrgID        string `json:"org_id,omitempty"`
	EventFilters string `json:"event_filters,omitempty"` // JSON filter criteria

	// OTX specific
	PulseIDs []string `json:"pulse_ids,omitempty"` // Specific pulses or empty for subscribed

	// CSV/JSON specific
	FieldMapping map[string]string `json:"field_mapping,omitempty"` // Map source fields to IOC fields
	Delimiter    string            `json:"delimiter,omitempty"`     // CSV delimiter (default: ,)
	SkipHeader   bool              `json:"skip_header,omitempty"`   // Skip CSV header row
	CommentChar  string            `json:"comment_char,omitempty"`  // Skip lines starting with this char (e.g., "#")
	ValueColumn  int               `json:"value_column,omitempty"`  // Column index for IOC value (0-based)
	TypeColumn   int               `json:"type_column,omitempty"`   // Column index for IOC type (-1 = use default)

	// Filesystem specific
	Path         string   `json:"path,omitempty"`          // Local path
	FilePatterns []string `json:"file_patterns,omitempty"` // Glob patterns (e.g., *.csv)

	// Import Configuration
	IncludeTypes    []core.IOCType     `json:"include_types,omitempty"`    // Filter by IOC type
	ExcludeTypes    []core.IOCType     `json:"exclude_types,omitempty"`    // Exclude IOC types
	DefaultType     core.IOCType       `json:"default_type,omitempty"`     // Default type if not in data
	MinConfidence   float64            `json:"min_confidence,omitempty"`   // 0-100
	DefaultSeverity core.IOCSeverity   `json:"default_severity,omitempty"` // If not provided by feed
	DefaultStatus   core.IOCStatus     `json:"default_status,omitempty"`   // Usually "active"
	AutoExpireDays  int                `json:"auto_expire_days,omitempty"` // Auto-set expires_at
	Tags            []string           `json:"tags,omitempty"`             // Auto-apply tags
	Priority        int                `json:"priority"`                   // Conflict resolution (higher wins)

	// Update Configuration
	UpdateStrategy IOCFeedUpdateStrategy `json:"update_strategy"`
	UpdateSchedule string                `json:"update_schedule,omitempty"` // Cron expression
	LastSync       *time.Time            `json:"last_sync,omitempty"`
	NextSync       *time.Time            `json:"next_sync,omitempty"`

	// Statistics
	Stats IOCFeedStats `json:"stats"`

	// Metadata
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	CreatedBy string            `json:"created_by"`
}

// =============================================================================
// IOC Feed Statistics
// =============================================================================

// IOCFeedStats tracks import statistics
type IOCFeedStats struct {
	TotalIOCs        int64   `json:"total_iocs"`                   // IOCs in feed
	ImportedIOCs     int64   `json:"imported_iocs"`                // Successfully imported
	UpdatedIOCs      int64   `json:"updated_iocs"`                 // Updated existing
	SkippedIOCs      int64   `json:"skipped_iocs"`                 // Duplicates/filtered
	FailedIOCs       int64   `json:"failed_iocs"`                  // Validation failures
	LastSyncDuration float64 `json:"last_sync_duration"`           // Seconds
	LastError        string  `json:"last_error,omitempty"`         // Last error message
	SyncCount        int     `json:"sync_count"`                   // Total syncs performed
	LastSyncTime     string  `json:"last_sync_time,omitempty"`     // ISO 8601 timestamp
}

// =============================================================================
// IOC Feed Sync Results
// =============================================================================

// IOCFeedSyncResult captures sync operation results
type IOCFeedSyncResult struct {
	ID         string           `json:"id"`
	FeedID     string           `json:"feed_id"`
	FeedName   string           `json:"feed_name"`
	StartTime  time.Time        `json:"start_time"`
	EndTime    time.Time        `json:"end_time"`
	Duration   float64          `json:"duration"` // Seconds
	Success    bool             `json:"success"`
	Stats      IOCFeedStats     `json:"stats"`
	Errors     []string         `json:"errors,omitempty"`
	IOCResults []IOCImportResult `json:"ioc_results,omitempty"` // Limited sample
}

// IOCImportResult tracks individual IOC import outcome
type IOCImportResult struct {
	IOCValue string `json:"ioc_value"`
	IOCType  string `json:"ioc_type"`
	Action   string `json:"action"` // imported, updated, skipped, failed
	Reason   string `json:"reason,omitempty"`
}

// Import action constants
const (
	IOCImportActionImported = "imported"
	IOCImportActionUpdated  = "updated"
	IOCImportActionSkipped  = "skipped"
	IOCImportActionFailed   = "failed"
)

// =============================================================================
// IOC Feed Templates
// =============================================================================

// IOCFeedTemplate provides pre-configured feed setups
type IOCFeedTemplate struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Type                IOCFeedType            `json:"type"`
	URL                 string                 `json:"url,omitempty"`
	RequiresAuth        bool                   `json:"requires_auth"`
	AuthFields          []string               `json:"auth_fields,omitempty"` // Required auth fields
	DefaultConfig       map[string]interface{} `json:"default_config,omitempty"`
	FieldMapping        map[string]string      `json:"field_mapping,omitempty"`
	RecommendedPriority int                    `json:"recommended_priority"`
	EstimatedIOCCount   int                    `json:"estimated_ioc_count"`
	Tags                []string               `json:"tags"`
}

// =============================================================================
// IOC Feeds Summary
// =============================================================================

// IOCFeedsSummary provides aggregate feed statistics
type IOCFeedsSummary struct {
	TotalFeeds   int        `json:"total_feeds"`
	ActiveFeeds  int        `json:"active_feeds"`
	TotalIOCs    int64      `json:"total_iocs"`
	LastSync     *time.Time `json:"last_sync"`
	HealthStatus string     `json:"health_status"` // "healthy", "warning", "error"
	ErrorCount   int        `json:"error_count"`
}

// =============================================================================
// Configuration
// =============================================================================

// IOCFeedConfig holds global feed configuration
type IOCFeedConfig struct {
	Enabled        bool                    `json:"enabled"`
	WorkingDir     string                  `json:"working_dir"`
	ImportSettings IOCFeedImportSettings   `json:"import_settings"`
	Scheduler      IOCFeedSchedulerConfig  `json:"scheduler"`
}

// IOCFeedImportSettings configures import behavior
type IOCFeedImportSettings struct {
	BatchSize            int    `json:"batch_size"`              // IOCs per batch (default: 500)
	ValidateBeforeImport bool   `json:"validate_before_import"`  // Validate IOC values
	SkipDuplicates       bool   `json:"skip_duplicates"`         // Skip existing IOCs
	DefaultExpireDays    int    `json:"default_expire_days"`     // Default expiration
	MaxIOCsPerSync       int    `json:"max_iocs_per_sync"`       // Limit per sync (0 = unlimited)
	DeduplicationKey     string `json:"deduplication_key"`       // "value" or "external_id"
}

// IOCFeedSchedulerConfig configures the scheduler
type IOCFeedSchedulerConfig struct {
	Enabled            bool   `json:"enabled"`
	Timezone           string `json:"timezone"`              // Default: UTC
	MaxConcurrentSyncs int    `json:"max_concurrent_syncs"`  // Default: 3
	SyncTimeout        int    `json:"sync_timeout"`          // Seconds (default: 1800)
	RetryFailedSyncs   bool   `json:"retry_failed_syncs"`
	RetryDelay         int    `json:"retry_delay"`           // Seconds (default: 3600)
}

// DefaultIOCFeedConfig returns default configuration
func DefaultIOCFeedConfig() *IOCFeedConfig {
	return &IOCFeedConfig{
		Enabled:    true,
		WorkingDir: "./ioc_feeds",
		ImportSettings: IOCFeedImportSettings{
			BatchSize:            500,
			ValidateBeforeImport: true,
			SkipDuplicates:       true,
			DefaultExpireDays:    90,
			MaxIOCsPerSync:       100000,
			DeduplicationKey:     "value",
		},
		Scheduler: IOCFeedSchedulerConfig{
			Enabled:            true,
			Timezone:           "UTC",
			MaxConcurrentSyncs: 3,
			SyncTimeout:        1800,
			RetryFailedSyncs:   true,
			RetryDelay:         3600,
		},
	}
}

// =============================================================================
// Progress Callback
// =============================================================================

// ProgressCallback is called during sync to report progress
type ProgressCallback func(eventType string, message string, progress int)

// Progress event types
const (
	ProgressEventStarted   = "started"
	ProgressEventProgress  = "progress"
	ProgressEventCompleted = "completed"
	ProgressEventFailed    = "failed"
)
