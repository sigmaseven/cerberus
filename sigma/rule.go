package sigma

import (
	"errors"
	"time"
)

// SigmaRule represents a SIGMA detection rule in YAML format
type SigmaRule struct {
	// Core identification
	ID          string `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description,omitempty" bson:"description,omitempty"`
	Author      string `json:"author,omitempty" bson:"author,omitempty"`
	Date        string `json:"date,omitempty" bson:"date,omitempty"`
	Modified    string `json:"modified,omitempty" bson:"modified,omitempty"`

	// Status and severity
	Status string `json:"status,omitempty" bson:"status,omitempty"` // experimental, test, stable, deprecated
	Level  string `json:"level,omitempty" bson:"level,omitempty"`   // informational, low, medium, high, critical

	// References and categorization
	References     []string               `json:"references,omitempty" bson:"references,omitempty"`
	Tags           []string               `json:"tags,omitempty" bson:"tags,omitempty"`
	Logsource      map[string]interface{} `json:"logsource,omitempty" bson:"logsource,omitempty"`
	FalsePositives []string               `json:"falsepositives,omitempty" bson:"falsepositives,omitempty"`

	// Detection logic (raw YAML structure)
	Detection map[string]interface{} `json:"detection" bson:"detection"`

	// RawYAML contains the original YAML content for the rule (used during import)
	RawYAML string `json:"-" bson:"-"` // Not serialized - only used during conversion

	// Source information
	Source      string `json:"source,omitempty" bson:"source,omitempty"`             // Repository/source name
	ContentHash string `json:"content_hash,omitempty" bson:"content_hash,omitempty"` // SHA-256 of rule content
	FilePath    string `json:"file_path,omitempty" bson:"file_path,omitempty"`       // Original file path

	// Import metadata
	ImportedAt time.Time `json:"imported_at,omitempty" bson:"imported_at,omitempty"`
	Enabled    bool      `json:"enabled" bson:"enabled"`

	// Standard timestamps
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// Validate checks if a SIGMA rule has all required fields
func (r *SigmaRule) Validate() error {
	if r.ID == "" {
		return errors.New("rule ID is required")
	}
	if r.Title == "" {
		return errors.New("rule title is required")
	}
	if r.Detection == nil || len(r.Detection) == 0 {
		return errors.New("rule detection logic is required")
	}

	// Validate status if provided
	if r.Status != "" {
		validStatuses := map[string]bool{
			"experimental": true,
			"test":         true,
			"stable":       true,
			"deprecated":   true,
		}
		if !validStatuses[r.Status] {
			return errors.New("invalid status: must be experimental, test, stable, or deprecated")
		}
	}

	// Validate level if provided
	if r.Level != "" {
		validLevels := map[string]bool{
			"informational": true,
			"low":           true,
			"medium":        true,
			"high":          true,
			"critical":      true,
		}
		if !validLevels[r.Level] {
			return errors.New("invalid level: must be informational, low, medium, high, or critical")
		}
	}

	return nil
}

// RuleSource represents a source repository or location for SIGMA rules
type RuleSource struct {
	Name            string    `json:"name" yaml:"name"`
	Enabled         bool      `json:"enabled" yaml:"enabled"`
	Type            string    `json:"type" yaml:"type"` // "git", "filesystem", "url"
	URL             string    `json:"url,omitempty" yaml:"url,omitempty"`
	Path            string    `json:"path,omitempty" yaml:"path,omitempty"`
	Branch          string    `json:"branch,omitempty" yaml:"branch,omitempty"`
	IncludePaths    []string  `json:"include_paths,omitempty" yaml:"include_paths,omitempty"`
	ExcludePaths    []string  `json:"exclude_paths,omitempty" yaml:"exclude_paths,omitempty"`
	UpdateOnStartup bool      `json:"update_on_startup" yaml:"update_on_startup"`
	AutoEnableRules bool      `json:"auto_enable_rules" yaml:"auto_enable_rules"`
	Priority        int       `json:"priority" yaml:"priority"`
	LastUpdate      time.Time `json:"last_update,omitempty" yaml:"last_update,omitempty"`
}

// ImportedRule represents a rule during the import process
type ImportedRule struct {
	Title       string
	ID          string
	Description string
	Detection   map[string]interface{}
	Level       string
	Status      string
	Tags        []string
	References  []string
	Author      string
	Date        string
	Modified    string
	Logsource   map[string]interface{}
	ContentHash string
	Source      string
	FilePath    string
	Enabled     bool
}

// ImportAction represents the action to take for an imported rule
type ImportAction int

const (
	// ActionSkip indicates the rule should be skipped (already exists, up-to-date)
	ActionSkip ImportAction = iota
	// ActionImport indicates the rule should be imported as new
	ActionImport
	// ActionUpdate indicates the rule should update an existing rule
	ActionUpdate
	// ActionReview indicates the rule needs manual review before import
	ActionReview
)

// ImportResult tracks the result of importing a single rule
type ImportResult struct {
	RuleID     string
	Title      string
	Action     ImportAction
	Error      error
	SourceFile string
}

// ImportStats tracks overall import statistics
type ImportStats struct {
	TotalScanned   int
	Imported       int
	Updated        int
	Skipped        int
	Failed         int
	ReviewRequired int
	Duration       time.Duration
	StartTime      time.Time
	EndTime        time.Time
}
