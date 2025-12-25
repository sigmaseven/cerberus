package feeds

import (
	"time"
)

// Feed Types
const (
	FeedTypeGit        = "git"
	FeedTypeHTTP       = "http"
	FeedTypeFilesystem = "filesystem"
	FeedTypeAPI        = "api"
	FeedTypeS3         = "s3"
	FeedTypeWebhook    = "webhook"
)

// Feed Status
const (
	FeedStatusActive   = "active"
	FeedStatusDisabled = "disabled"
	FeedStatusError    = "error"
	FeedStatusSyncing  = "syncing"
)

// Update Strategies
const (
	UpdateManual    = "manual"
	UpdateStartup   = "startup"
	UpdateScheduled = "scheduled"
	UpdateWebhook   = "webhook"
)

// Deduplication Strategies
const (
	DedupeByContentHash = "content_hash"
	DedupeByID          = "id"
	DedupeByTitle       = "title"
)

// Conflict Resolution Strategies
const (
	ConflictResolutionPriority = "priority"
	ConflictResolutionNewest   = "newest"
	ConflictResolutionManual   = "manual"
)

// RuleFeed represents a source of detection rules
type RuleFeed struct {
	ID          string `json:"id" bson:"_id"`
	Name        string `json:"name" bson:"name"`
	Description string `json:"description" bson:"description"`
	Type        string `json:"type" bson:"type"` // git, http, filesystem, api
	Status      string `json:"status" bson:"status"`
	Enabled     bool   `json:"enabled" bson:"enabled"`

	// Connection details
	URL        string                 `json:"url,omitempty" bson:"url,omitempty"`
	Branch     string                 `json:"branch,omitempty" bson:"branch,omitempty"` // For git
	Path       string                 `json:"path,omitempty" bson:"path,omitempty"`     // For filesystem
	AuthConfig map[string]interface{} `json:"auth_config,omitempty" bson:"auth_config,omitempty"`

	// Import configuration
	IncludePaths    []string `json:"include_paths,omitempty" bson:"include_paths,omitempty"`
	ExcludePaths    []string `json:"exclude_paths,omitempty" bson:"exclude_paths,omitempty"`
	IncludeTags     []string `json:"include_tags,omitempty" bson:"include_tags,omitempty"`
	ExcludeTags     []string `json:"exclude_tags,omitempty" bson:"exclude_tags,omitempty"`
	MinSeverity     string   `json:"min_severity,omitempty" bson:"min_severity,omitempty"`
	AutoEnableRules bool     `json:"auto_enable_rules" bson:"auto_enable_rules"`
	Priority        int      `json:"priority" bson:"priority"` // Higher = takes precedence

	// Update strategy
	UpdateStrategy string    `json:"update_strategy" bson:"update_strategy"`
	UpdateSchedule string    `json:"update_schedule,omitempty" bson:"update_schedule,omitempty"` // Cron format
	LastSync       time.Time `json:"last_sync" bson:"last_sync"`
	NextSync       time.Time `json:"next_sync,omitempty" bson:"next_sync,omitempty"`

	// Statistics
	Stats FeedStats `json:"stats" bson:"stats"`

	// Metadata
	Tags      []string          `json:"tags,omitempty" bson:"tags,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty" bson:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time         `json:"updated_at" bson:"updated_at"`
	CreatedBy string            `json:"created_by,omitempty" bson:"created_by,omitempty"`
}

// FeedStats tracks feed synchronization statistics
type FeedStats struct {
	TotalRules       int     `json:"total_rules" bson:"total_rules"`
	ImportedRules    int     `json:"imported_rules" bson:"imported_rules"`
	UpdatedRules     int     `json:"updated_rules" bson:"updated_rules"`
	SkippedRules     int     `json:"skipped_rules" bson:"skipped_rules"`
	FailedRules      int     `json:"failed_rules" bson:"failed_rules"`
	LastSyncDuration float64 `json:"last_sync_duration" bson:"last_sync_duration"` // seconds
	LastError        string  `json:"last_error,omitempty" bson:"last_error,omitempty"`
	SyncCount        int     `json:"sync_count" bson:"sync_count"`
}

// FeedSyncResult tracks the result of a feed synchronization
type FeedSyncResult struct {
	FeedID      string             `json:"feed_id"`
	FeedName    string             `json:"feed_name"`
	StartTime   time.Time          `json:"start_time"`
	EndTime     time.Time          `json:"end_time"`
	Duration    float64            `json:"duration"`
	Success     bool               `json:"success"`
	Stats       FeedStats          `json:"stats"`
	Errors      []string           `json:"errors,omitempty"`
	RuleResults []RuleImportResult `json:"rule_results,omitempty"`
}

// RuleImportResult tracks individual rule import result
type RuleImportResult struct {
	RuleID    string `json:"rule_id"`
	RuleTitle string `json:"rule_title"`
	FilePath  string `json:"file_path"`
	Action    string `json:"action"` // imported, updated, skipped, failed
	Error     string `json:"error,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// FeedTemplate represents a pre-configured feed template
type FeedTemplate struct {
	ID                  string   `json:"id" yaml:"id"`
	Name                string   `json:"name" yaml:"name"`
	Description         string   `json:"description" yaml:"description"`
	Type                string   `json:"type" yaml:"type"`
	URL                 string   `json:"url" yaml:"url"`
	Branch              string   `json:"branch,omitempty" yaml:"branch,omitempty"`
	IncludePaths        []string `json:"include_paths,omitempty" yaml:"include_paths,omitempty"`
	ExcludePaths        []string `json:"exclude_paths,omitempty" yaml:"exclude_paths,omitempty"`
	RecommendedPriority int      `json:"recommended_priority" yaml:"recommended_priority"`
	EstimatedRuleCount  int      `json:"estimated_rule_count" yaml:"estimated_rule_count"`
	Tags                []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// FeedConfig represents the complete feed configuration
type FeedConfig struct {
	Feeds          []RuleFeed      `yaml:"feeds"`
	ImportSettings ImportSettings  `yaml:"import_settings"`
	Scheduler      SchedulerConfig `yaml:"scheduler"`
}

// ImportSettings defines global import configuration
type ImportSettings struct {
	ParallelWorkers       int                `yaml:"parallel_workers"`
	BatchSize             int                `yaml:"batch_size"`
	ValidateBeforeImport  bool               `yaml:"validate_before_import"`
	SkipDuplicates        bool               `yaml:"skip_duplicates"`
	DeduplicationStrategy string             `yaml:"deduplication_strategy"`
	QualityFilters        QualityFilters     `yaml:"quality_filters"`
	ConflictResolution    ConflictResolution `yaml:"conflict_resolution"`
}

// QualityFilters defines rule quality filtering criteria
type QualityFilters struct {
	MinStatus           string `yaml:"min_status"`
	ExcludeExperimental bool   `yaml:"exclude_experimental"`
	ExcludeDeprecated   bool   `yaml:"exclude_deprecated"`
	RequireDetection    bool   `yaml:"require_detection"`
	RequireLogsource    bool   `yaml:"require_logsource"`
	RequireMitreMapping bool   `yaml:"require_mitre_mapping"`
}

// ConflictResolution defines how to handle rule conflicts
type ConflictResolution struct {
	Strategy        string `yaml:"strategy"`
	AllowOverwrites bool   `yaml:"allow_overwrites"`
}

// SchedulerConfig defines scheduler configuration
type SchedulerConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Timezone           string `yaml:"timezone"`
	MaxConcurrentSyncs int    `yaml:"max_concurrent_syncs"`
	SyncTimeout        int    `yaml:"sync_timeout"` // seconds
	RetryFailedSyncs   bool   `yaml:"retry_failed_syncs"`
	RetryDelay         int    `yaml:"retry_delay"` // seconds
}

// Validate checks if a feed configuration is valid
func (f *RuleFeed) Validate() error {
	if f.ID == "" {
		return ErrInvalidFeedID
	}
	if f.Name == "" {
		return ErrInvalidFeedName
	}
	if f.Type == "" {
		return ErrInvalidFeedType
	}

	// Validate feed type
	validTypes := map[string]bool{
		FeedTypeGit:        true,
		FeedTypeHTTP:       true,
		FeedTypeFilesystem: true,
		FeedTypeAPI:        true,
		FeedTypeS3:         true,
		FeedTypeWebhook:    true,
	}
	if !validTypes[f.Type] {
		return ErrInvalidFeedType
	}

	// Type-specific validation
	switch f.Type {
	case FeedTypeGit:
		if f.URL == "" {
			return ErrMissingURL
		}
	case FeedTypeFilesystem:
		if f.Path == "" {
			return ErrMissingPath
		}
	case FeedTypeHTTP, FeedTypeAPI:
		if f.URL == "" {
			return ErrMissingURL
		}
	}

	return nil
}
