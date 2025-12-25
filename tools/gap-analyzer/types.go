package main

import (
	"time"
)

// Requirement represents a single requirement extracted from a requirement document.
// Requirements can be functional (FR-XXX-NNN), non-functional (NFR-XXX-NNN), or generic (REQ-XXX).
type Requirement struct {
	ID          string   `json:"id"`          // FR-API-001, NFR-PERF-001, etc.
	Category    string   `json:"category"`    // API Design, Performance, Security, etc.
	Title       string   `json:"title"`       // Short requirement title
	Description string   `json:"description"` // Full requirement statement
	Priority    string   `json:"priority"`    // P0/P1/P2/P3 or CRITICAL/HIGH/MEDIUM/LOW
	Type        string   `json:"type"`        // MUST/SHOULD/MAY/SHALL
	Keywords    []string `json:"keywords"`    // For matching with tests
	SourceFile  string   `json:"source_file"` // docs/requirements/api-design-requirements.md
	SourceLine  int      `json:"source_line"` // Line number in source file
	Section     string   `json:"section"`     // Section heading from markdown
}

// Test represents a single test function extracted from a *_test.go file.
type Test struct {
	Name        string   `json:"name"`        // TestAPIVersioning
	Package     string   `json:"package"`     // api, core, storage, etc.
	File        string   `json:"file"`        // api/handlers_test.go
	Line        int      `json:"line"`        // Line number where test starts
	Description string   `json:"description"` // From godoc comments
	Covers      []string `json:"covers"`      // Explicit requirement IDs from comments
	Keywords    []string `json:"keywords"`    // Extracted from test name and body
	Disabled    bool     `json:"disabled"`    // true if .go.disabled
}

// Coverage represents the test coverage status for a single requirement.
type Coverage struct {
	Requirement  Requirement `json:"requirement"`
	Tests        []Test      `json:"tests"`         // Tests that cover this requirement
	Status       string      `json:"status"`        // COVERED/PARTIAL/MISSING
	CoverageRate float64     `json:"coverage_rate"` // 0.0-1.0
	Confidence   string      `json:"confidence"`    // HIGH/MEDIUM/LOW (how certain is the mapping)
}

// CoverageStatus constants
const (
	StatusCovered = "COVERED" // Requirement has comprehensive test coverage
	StatusPartial = "PARTIAL" // Requirement has some test coverage but incomplete
	StatusMissing = "MISSING" // Requirement has no test coverage
)

// ConfidenceLevel constants - how certain are we about the mapping
const (
	ConfidenceHigh   = "HIGH"   // Explicit coverage comment in test
	ConfidenceMedium = "MEDIUM" // Strong keyword match + file correlation
	ConfidenceLow    = "LOW"    // Weak keyword match only
)

// Priority constants
const (
	PriorityP0 = "P0" // Critical - production blocker
	PriorityP1 = "P1" // High - important feature
	PriorityP2 = "P2" // Medium - nice to have
	PriorityP3 = "P3" // Low - optional
)

// RequirementType constants
const (
	TypeMust   = "MUST"   // RFC 2119 - absolute requirement
	TypeShall  = "SHALL"  // RFC 2119 - absolute requirement (synonym)
	TypeShould = "SHOULD" // RFC 2119 - recommended
	TypeMay    = "MAY"    // RFC 2119 - optional
)

// AnalysisReport represents the complete gap analysis report.
type AnalysisReport struct {
	Metadata        ReportMetadata `json:"metadata"`
	Summary         Summary        `json:"summary"`
	CategoryStats   []CategoryStat `json:"category_stats"`
	Coverages       []Coverage     `json:"coverages"`
	CriticalGaps    []Coverage     `json:"critical_gaps"` // P0 gaps only
	Recommendations []string       `json:"recommendations"`
}

// ReportMetadata contains metadata about the analysis run.
type ReportMetadata struct {
	GeneratedAt       time.Time `json:"generated_at"`
	ToolVersion       string    `json:"tool_version"`
	RequirementsPath  string    `json:"requirements_path"`
	TestsPath         string    `json:"tests_path"`
	TotalRequirements int       `json:"total_requirements"`
	TotalTests        int       `json:"total_tests"`
	TotalTestFiles    int       `json:"total_test_files"`
}

// Summary provides high-level coverage statistics.
type Summary struct {
	TotalRequirements int     `json:"total_requirements"`
	Covered           int     `json:"covered"`
	Partial           int     `json:"partial"`
	Missing           int     `json:"missing"`
	CoveragePercent   float64 `json:"coverage_percent"`
	P0Gaps            int     `json:"p0_gaps"`
	P1Gaps            int     `json:"p1_gaps"`
	P2Gaps            int     `json:"p2_gaps"`
	P3Gaps            int     `json:"p3_gaps"`
}

// CategoryStat provides coverage statistics for a requirement category.
type CategoryStat struct {
	Category        string  `json:"category"`
	Total           int     `json:"total"`
	Covered         int     `json:"covered"`
	Partial         int     `json:"partial"`
	Missing         int     `json:"missing"`
	CoveragePercent float64 `json:"coverage_percent"`
}

// Config represents the tool configuration.
type Config struct {
	Requirements RequirementsConfig `yaml:"requirements"`
	Tests        TestsConfig        `yaml:"tests"`
	Coverage     CoverageConfig     `yaml:"coverage"`
	Output       OutputConfig       `yaml:"output"`
}

// RequirementsConfig configures requirement discovery and parsing.
type RequirementsConfig struct {
	Directory        string              `yaml:"directory"`
	Patterns         []string            `yaml:"patterns"`
	IDPatterns       []string            `yaml:"id_patterns"`
	PriorityKeywords map[string][]string `yaml:"priority_keywords"`
}

// TestsConfig configures test discovery and parsing.
type TestsConfig struct {
	Directories             []string `yaml:"directories"`
	Patterns                []string `yaml:"patterns"`
	CoverageCommentPatterns []string `yaml:"coverage_comment_patterns"`
}

// CoverageConfig configures coverage thresholds and validation.
type CoverageConfig struct {
	MinimumPercentage int  `yaml:"minimum_percentage"`
	FailOnP0Gaps      bool `yaml:"fail_on_p0_gaps"`
	FailOnNewGaps     bool `yaml:"fail_on_new_gaps"`
}

// OutputConfig configures output formats and destinations.
type OutputConfig struct {
	Markdown string `yaml:"markdown"`
	JSON     string `yaml:"json"`
	YAML     string `yaml:"yaml"`
	Badge    string `yaml:"badge"`
	History  string `yaml:"history"`
}
