package core

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// IOC Types and Constants
// =============================================================================

// IOCType represents the type of indicator of compromise
type IOCType string

const (
	IOCTypeIP        IOCType = "ip"
	IOCTypeCIDR      IOCType = "cidr"
	IOCTypeDomain    IOCType = "domain"
	IOCTypeHash      IOCType = "hash" // MD5, SHA1, SHA256, SHA512
	IOCTypeURL       IOCType = "url"
	IOCTypeEmail     IOCType = "email"
	IOCTypeFilename  IOCType = "filename"
	IOCTypeRegKey    IOCType = "registry_key"
	IOCTypeRegistry  IOCType = "registry_key" // Alias for RegKey
	IOCTypeCVE       IOCType = "cve"
	IOCTypeJA3       IOCType = "ja3"        // TLS fingerprint
	IOCTypeUserAgent IOCType = "user_agent" // User-Agent strings
)

// AllIOCTypes returns all valid IOC types for validation
var AllIOCTypes = []IOCType{
	IOCTypeIP, IOCTypeCIDR, IOCTypeDomain, IOCTypeHash,
	IOCTypeURL, IOCTypeEmail, IOCTypeFilename, IOCTypeRegKey,
	IOCTypeCVE, IOCTypeJA3, IOCTypeUserAgent,
}

// IsValid checks if the IOC type is valid
func (t IOCType) IsValid() bool {
	for _, valid := range AllIOCTypes {
		if t == valid {
			return true
		}
	}
	return false
}

// IOCStatus represents the lifecycle status of an IOC
type IOCStatus string

const (
	IOCStatusActive     IOCStatus = "active"     // Actively monitored
	IOCStatusDeprecated IOCStatus = "deprecated" // Still matched but flagged as old
	IOCStatusArchived   IOCStatus = "archived"   // No longer matched
	IOCStatusWhitelist  IOCStatus = "whitelist"  // Known-good, suppress alerts
)

// AllIOCStatuses returns all valid IOC statuses
var AllIOCStatuses = []IOCStatus{
	IOCStatusActive, IOCStatusDeprecated, IOCStatusArchived, IOCStatusWhitelist,
}

// IsValid checks if the IOC status is valid
func (s IOCStatus) IsValid() bool {
	for _, valid := range AllIOCStatuses {
		if s == valid {
			return true
		}
	}
	return false
}

// IOCSeverity represents threat severity level
type IOCSeverity string

const (
	IOCSeverityCritical      IOCSeverity = "critical"
	IOCSeverityHigh          IOCSeverity = "high"
	IOCSeverityMedium        IOCSeverity = "medium"
	IOCSeverityLow           IOCSeverity = "low"
	IOCSeverityInfo          IOCSeverity = "info"
	IOCSeverityInformational IOCSeverity = "info" // Alias for Info
)

// AllIOCSeverities returns all valid IOC severities
var AllIOCSeverities = []IOCSeverity{
	IOCSeverityCritical, IOCSeverityHigh, IOCSeverityMedium, IOCSeverityLow, IOCSeverityInfo,
}

// IsValid checks if the IOC severity is valid
func (s IOCSeverity) IsValid() bool {
	for _, valid := range AllIOCSeverities {
		if s == valid {
			return true
		}
	}
	return false
}

// =============================================================================
// IOC Value Validation
// =============================================================================

// Validation patterns - compiled once at package init for performance
var (
	// Domain pattern - ReDoS-safe
	domainPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	// Hash pattern - MD5(32), SHA1(40), SHA256(64), SHA512(128)
	hashPattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$`)
	// JA3 fingerprint - MD5 hash
	ja3Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	// CVE pattern - CVE-YYYY-NNNNN
	cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	// Filename pattern - basic safety check
	filenamePattern = regexp.MustCompile(`^[^<>:"/\\|?*\x00-\x1f]+$`)
)

// Maximum lengths for IOC fields
const (
	MaxIOCValueLength       = 4096
	MaxIOCDescriptionLength = 2000
	MaxIOCTagLength         = 100
	MaxIOCTagCount          = 50
	MaxIOCReferenceLength   = 2048
	MaxIOCReferenceCount    = 20
)

// IOC Expiration Constants
// Different IOC types have different "burn rates" - ephemeral indicators like IPs
// and domains change frequently, while file hashes remain valid for longer.
const (
	// IOCExpirationNever indicates the IOC should never expire (use -1 for this special value)
	IOCExpirationNever = -1

	// Default expiration periods by IOC type (in days)
	// These reflect typical indicator lifespans in threat intelligence

	// Ephemeral indicators (change frequently)
	DefaultExpirationIP        = 30  // IPs are often rotated/reassigned
	DefaultExpirationCIDR      = 30  // CIDR ranges same as IPs
	DefaultExpirationDomain    = 60  // Domains burn slightly slower than IPs
	DefaultExpirationURL       = 30  // URLs are very ephemeral
	DefaultExpirationUserAgent = 90  // User agents change with software updates

	// Semi-persistent indicators
	DefaultExpirationEmail    = 180 // Email addresses last longer
	DefaultExpirationCVE      = 365 // CVEs remain relevant until patched
	DefaultExpirationFilename = 180 // Filenames vary

	// Persistent indicators (rarely change)
	DefaultExpirationHash    = 730 // 2 years - file hashes don't change
	DefaultExpirationRegKey  = 365 // Registry keys are fairly stable
	DefaultExpirationJA3     = 365 // TLS fingerprints are version-specific

	// Fallback default
	DefaultExpirationDefault = 90
)

// GetDefaultExpirationDays returns the default expiration period for an IOC type.
// Returns IOCExpirationNever (-1) if no expiration should be applied.
func GetDefaultExpirationDays(iocType IOCType) int {
	switch iocType {
	case IOCTypeIP:
		return DefaultExpirationIP
	case IOCTypeCIDR:
		return DefaultExpirationCIDR
	case IOCTypeDomain:
		return DefaultExpirationDomain
	case IOCTypeURL:
		return DefaultExpirationURL
	case IOCTypeHash:
		return DefaultExpirationHash
	case IOCTypeEmail:
		return DefaultExpirationEmail
	case IOCTypeFilename:
		return DefaultExpirationFilename
	case IOCTypeRegKey:
		return DefaultExpirationRegKey
	case IOCTypeCVE:
		return DefaultExpirationCVE
	case IOCTypeJA3:
		return DefaultExpirationJA3
	case IOCTypeUserAgent:
		return DefaultExpirationUserAgent
	default:
		return DefaultExpirationDefault
	}
}

// IsExpired checks if an IOC has expired based on its ExpiresAt field.
// Returns false if ExpiresAt is nil (never expires).
func (ioc *IOC) IsExpired() bool {
	if ioc.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*ioc.ExpiresAt)
}

// SetExpirationFromDays sets the ExpiresAt field based on days from now.
// If days is IOCExpirationNever (-1) or 0, ExpiresAt is set to nil (never expires).
// If days is positive, ExpiresAt is set to now + days.
func (ioc *IOC) SetExpirationFromDays(days int) {
	if days <= 0 {
		ioc.ExpiresAt = nil
		return
	}
	expires := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	ioc.ExpiresAt = &expires
}

// SetDefaultExpiration sets the ExpiresAt field based on the IOC's type defaults.
func (ioc *IOC) SetDefaultExpiration() {
	days := GetDefaultExpirationDays(ioc.Type)
	ioc.SetExpirationFromDays(days)
}

// ValidateIOCValue validates an IOC value based on its type
func ValidateIOCValue(iocType IOCType, value string) error {
	if value == "" {
		return fmt.Errorf("IOC value cannot be empty")
	}
	if len(value) > MaxIOCValueLength {
		return fmt.Errorf("IOC value exceeds maximum length of %d characters", MaxIOCValueLength)
	}

	// Normalize for validation
	normalizedValue := strings.TrimSpace(value)

	switch iocType {
	case IOCTypeIP:
		if net.ParseIP(normalizedValue) == nil {
			return fmt.Errorf("invalid IP address format")
		}
	case IOCTypeCIDR:
		if _, _, err := net.ParseCIDR(normalizedValue); err != nil {
			return fmt.Errorf("invalid CIDR notation: %w", err)
		}
	case IOCTypeDomain:
		lowered := strings.ToLower(normalizedValue)
		if !domainPattern.MatchString(lowered) {
			return fmt.Errorf("invalid domain format")
		}
	case IOCTypeHash:
		if !hashPattern.MatchString(normalizedValue) {
			return fmt.Errorf("invalid hash format (must be MD5/SHA1/SHA256/SHA512)")
		}
	case IOCTypeURL:
		parsed, err := url.ParseRequestURI(normalizedValue)
		if err != nil {
			return fmt.Errorf("invalid URL format: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("URL must use http or https scheme")
		}
	case IOCTypeEmail:
		if _, err := mail.ParseAddress(normalizedValue); err != nil {
			return fmt.Errorf("invalid email format: %w", err)
		}
	case IOCTypeFilename:
		if !filenamePattern.MatchString(normalizedValue) {
			return fmt.Errorf("invalid filename format")
		}
	case IOCTypeRegKey:
		// Registry keys should start with a valid hive
		validHives := []string{"HKEY_", "HKLM\\", "HKCU\\", "HKU\\", "HKCR\\", "HKCC\\"}
		hasValidHive := false
		upper := strings.ToUpper(normalizedValue)
		for _, hive := range validHives {
			if strings.HasPrefix(upper, hive) {
				hasValidHive = true
				break
			}
		}
		if !hasValidHive {
			return fmt.Errorf("invalid registry key format (must start with valid hive)")
		}
	case IOCTypeCVE:
		upper := strings.ToUpper(normalizedValue)
		if !cvePattern.MatchString(upper) {
			return fmt.Errorf("invalid CVE format (must be CVE-YYYY-NNNNN)")
		}
	case IOCTypeJA3:
		if !ja3Pattern.MatchString(normalizedValue) {
			return fmt.Errorf("invalid JA3 fingerprint format (must be 32-char hex)")
		}
	default:
		return fmt.Errorf("unknown IOC type: %s", iocType)
	}

	return nil
}

// NormalizeIOCValue normalizes an IOC value for consistent storage and matching
func NormalizeIOCValue(iocType IOCType, value string) string {
	normalized := strings.TrimSpace(value)

	switch iocType {
	case IOCTypeIP, IOCTypeCIDR:
		// IPs are case-insensitive (IPv6 hex)
		return strings.ToLower(normalized)
	case IOCTypeDomain:
		// Domains are case-insensitive
		return strings.ToLower(normalized)
	case IOCTypeHash, IOCTypeJA3:
		// Hashes are hex, normalize to lowercase
		return strings.ToLower(normalized)
	case IOCTypeURL:
		// Normalize URL: lowercase scheme and host
		if parsed, err := url.Parse(normalized); err == nil {
			parsed.Scheme = strings.ToLower(parsed.Scheme)
			parsed.Host = strings.ToLower(parsed.Host)
			return parsed.String()
		}
		return normalized
	case IOCTypeEmail:
		// Email local part is case-sensitive, domain is not
		if at := strings.LastIndex(normalized, "@"); at > 0 {
			local := normalized[:at]
			domain := strings.ToLower(normalized[at:])
			return local + domain
		}
		return normalized
	case IOCTypeCVE:
		// CVEs are uppercase
		return strings.ToUpper(normalized)
	default:
		return normalized
	}
}

// DetectIOCType attempts to detect the IOC type based on the value format
// Returns empty string if type cannot be determined
func DetectIOCType(value string) IOCType {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	// Check for CVE pattern: CVE-YYYY-NNNNN (case-insensitive)
	if strings.HasPrefix(strings.ToUpper(value), "CVE-") && cvePattern.MatchString(strings.ToUpper(value)) {
		return IOCTypeCVE
	}

	// Check for IP address (IPv4 or IPv6)
	if ip := net.ParseIP(value); ip != nil {
		return IOCTypeIP
	}

	// Check for CIDR notation
	if _, _, err := net.ParseCIDR(value); err == nil {
		return IOCTypeCIDR
	}

	// Check for URL
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err == nil {
			return IOCTypeURL
		}
	}

	// Check for email
	if strings.Contains(value, "@") {
		if _, err := mail.ParseAddress(value); err == nil {
			return IOCTypeEmail
		}
	}

	// Check for hash (MD5: 32, SHA1: 40, SHA256: 64, SHA512: 128)
	if hashPattern.MatchString(value) {
		return IOCTypeHash
	}

	// Check for domain (simple heuristic)
	if domainPattern.MatchString(strings.ToLower(value)) && !strings.Contains(value, "/") {
		return IOCTypeDomain
	}

	// Check for registry key
	upperValue := strings.ToUpper(value)
	if strings.HasPrefix(upperValue, "HKEY_") || strings.HasPrefix(upperValue, "HKLM\\") ||
		strings.HasPrefix(upperValue, "HKCU\\") || strings.HasPrefix(upperValue, "HKU\\") {
		return IOCTypeRegKey
	}

	// Check for filename (has file extension pattern)
	if detectFilenamePattern.MatchString(value) && !strings.Contains(value, "/") && !strings.Contains(value, "\\") {
		return IOCTypeFilename
	}

	return ""
}

// Additional regex pattern for filename detection in DetectIOCType
var detectFilenamePattern = regexp.MustCompile(`\.[a-zA-Z0-9]{1,10}$`)

// =============================================================================
// IOC Struct
// =============================================================================

// IOC represents a persistent indicator of compromise
type IOC struct {
	ID         string      `json:"id"`
	Type       IOCType     `json:"type"`
	Value      string      `json:"value"`
	Normalized string      `json:"normalized"` // Normalized value for matching
	Status     IOCStatus   `json:"status"`
	Severity   IOCSeverity `json:"severity"`
	Confidence float64     `json:"confidence"` // 0-100%

	// Metadata
	Description     string   `json:"description,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Source          string   `json:"source,omitempty"`           // Feed name, analyst, etc.
	References      []string `json:"references,omitempty"`       // URLs to reports
	MitreTechniques []string `json:"mitre_techniques,omitempty"` // T1xxx IDs

	// Threat intel enrichment (cached from providers)
	ThreatIntel map[string]interface{} `json:"threat_intel,omitempty"`

	// Tracking
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	FirstSeen *time.Time `json:"first_seen,omitempty"` // First detected in logs
	LastSeen  *time.Time `json:"last_seen,omitempty"`  // Last detected in logs
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // Auto-archive date
	HitCount  int64      `json:"hit_count"`            // Detection counter

	// Relationships (populated on demand, not stored in IOC table)
	InvestigationIDs []string `json:"investigation_ids,omitempty"`
	AlertIDs         []string `json:"alert_ids,omitempty"`

	// Feed Attribution (for IOCs imported from threat intelligence feeds)
	FeedID     string     `json:"feed_id,omitempty"`     // Source feed ID (empty = manual)
	FeedName   string     `json:"feed_name,omitempty"`   // Denormalized for display
	ExternalID string     `json:"external_id,omitempty"` // ID in source system
	ImportedAt *time.Time `json:"imported_at,omitempty"` // When imported from feed
}

// IsManual returns true if the IOC was manually created (not from a feed)
func (ioc *IOC) IsManual() bool {
	return ioc.FeedID == ""
}

// NewIOC creates a new IOC with generated ID and validation
func NewIOC(iocType IOCType, value, source, createdBy string) (*IOC, error) {
	// Validate type
	if !iocType.IsValid() {
		return nil, fmt.Errorf("invalid IOC type: %s", iocType)
	}

	// Validate value
	if err := ValidateIOCValue(iocType, value); err != nil {
		return nil, fmt.Errorf("invalid IOC value: %w", err)
	}

	now := time.Now().UTC()
	return &IOC{
		ID:         uuid.New().String(),
		Type:       iocType,
		Value:      strings.TrimSpace(value),
		Normalized: NormalizeIOCValue(iocType, value),
		Status:     IOCStatusActive,
		Severity:   IOCSeverityMedium,
		Confidence: 50.0, // Default confidence
		Source:     source,
		CreatedBy:  createdBy,
		CreatedAt:  now,
		UpdatedAt:  now,
		Tags:       []string{},
	}, nil
}

// Validate performs full validation on an IOC
func (ioc *IOC) Validate() error {
	// Required fields
	if ioc.ID == "" {
		return fmt.Errorf("IOC ID is required")
	}
	if !ioc.Type.IsValid() {
		return fmt.Errorf("invalid IOC type: %s", ioc.Type)
	}
	if err := ValidateIOCValue(ioc.Type, ioc.Value); err != nil {
		return err
	}
	if !ioc.Status.IsValid() {
		return fmt.Errorf("invalid IOC status: %s", ioc.Status)
	}
	if !ioc.Severity.IsValid() {
		return fmt.Errorf("invalid IOC severity: %s", ioc.Severity)
	}

	// Confidence bounds
	if ioc.Confidence < 0 || ioc.Confidence > 100 {
		return fmt.Errorf("confidence must be between 0 and 100")
	}

	// Description length
	if len(ioc.Description) > MaxIOCDescriptionLength {
		return fmt.Errorf("description exceeds maximum length of %d characters", MaxIOCDescriptionLength)
	}

	// Tags validation
	if len(ioc.Tags) > MaxIOCTagCount {
		return fmt.Errorf("too many tags (max %d)", MaxIOCTagCount)
	}
	for _, tag := range ioc.Tags {
		if len(tag) > MaxIOCTagLength {
			return fmt.Errorf("tag exceeds maximum length of %d characters", MaxIOCTagLength)
		}
	}

	// References validation
	if len(ioc.References) > MaxIOCReferenceCount {
		return fmt.Errorf("too many references (max %d)", MaxIOCReferenceCount)
	}
	for _, ref := range ioc.References {
		if len(ref) > MaxIOCReferenceLength {
			return fmt.Errorf("reference URL exceeds maximum length of %d characters", MaxIOCReferenceLength)
		}
	}

	return nil
}

// =============================================================================
// IOC Hunt Types
// =============================================================================

// HuntStatus represents the status of a threat hunt job
type HuntStatus string

const (
	HuntStatusPending   HuntStatus = "pending"
	HuntStatusRunning   HuntStatus = "running"
	HuntStatusCompleted HuntStatus = "completed"
	HuntStatusFailed    HuntStatus = "failed"
	HuntStatusCancelled HuntStatus = "cancelled"
)

// IsValid checks if the hunt status is valid
func (s HuntStatus) IsValid() bool {
	switch s {
	case HuntStatusPending, HuntStatusRunning, HuntStatusCompleted, HuntStatusFailed, HuntStatusCancelled:
		return true
	}
	return false
}

// IsTerminal returns true if the hunt is in a final state
func (s HuntStatus) IsTerminal() bool {
	return s == HuntStatusCompleted || s == HuntStatusFailed || s == HuntStatusCancelled
}

// Maximum hunt time range (90 days)
const MaxHuntTimeRangeDays = 90

// IOCHunt represents a threat hunting job searching for IOCs in historical logs
type IOCHunt struct {
	ID             string     `json:"id"`
	Status         HuntStatus `json:"status"`
	IOCIDs         []string   `json:"ioc_ids"`          // IOCs to hunt for
	TimeRangeStart time.Time  `json:"time_range_start"` // Start of search window
	TimeRangeEnd   time.Time  `json:"time_range_end"`   // End of search window
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	Progress       float64    `json:"progress"`      // 0-100%
	TotalEvents    int64      `json:"total_events"`  // Events scanned
	MatchCount     int64      `json:"match_count"`   // IOC hits found
	Error          string     `json:"error,omitempty"`
}

// NewIOCHunt creates a new hunt job with validation
func NewIOCHunt(iocIDs []string, timeRangeStart, timeRangeEnd time.Time, createdBy string) (*IOCHunt, error) {
	if len(iocIDs) == 0 {
		return nil, fmt.Errorf("at least one IOC ID is required")
	}

	// Validate time range
	if timeRangeEnd.Before(timeRangeStart) {
		return nil, fmt.Errorf("end time must be after start time")
	}

	duration := timeRangeEnd.Sub(timeRangeStart)
	maxDuration := time.Duration(MaxHuntTimeRangeDays) * 24 * time.Hour
	if duration > maxDuration {
		return nil, fmt.Errorf("time range exceeds maximum of %d days", MaxHuntTimeRangeDays)
	}

	// Don't allow future end times
	if timeRangeEnd.After(time.Now().UTC()) {
		return nil, fmt.Errorf("end time cannot be in the future")
	}

	now := time.Now().UTC()
	return &IOCHunt{
		ID:             uuid.New().String(),
		Status:         HuntStatusPending,
		IOCIDs:         iocIDs,
		TimeRangeStart: timeRangeStart,
		TimeRangeEnd:   timeRangeEnd,
		CreatedBy:      createdBy,
		CreatedAt:      now,
		Progress:       0,
		TotalEvents:    0,
		MatchCount:     0,
	}, nil
}

// IOCMatch represents a single IOC detection in logs
type IOCMatch struct {
	ID             string    `json:"id"`
	IOCID          string    `json:"ioc_id"`
	HuntID         string    `json:"hunt_id,omitempty"` // If from a hunt job
	EventID        string    `json:"event_id"`
	MatchedField   string    `json:"matched_field"` // e.g., "source_ip", "domain"
	MatchedValue   string    `json:"matched_value"`
	EventTimestamp time.Time `json:"event_timestamp"`
	DetectedAt     time.Time `json:"detected_at"`
}

// NewIOCMatch creates a new match record
func NewIOCMatch(iocID, huntID, eventID, matchedField, matchedValue string, eventTimestamp time.Time) *IOCMatch {
	return &IOCMatch{
		ID:             uuid.New().String(),
		IOCID:          iocID,
		HuntID:         huntID,
		EventID:        eventID,
		MatchedField:   matchedField,
		MatchedValue:   matchedValue,
		EventTimestamp: eventTimestamp,
		DetectedAt:     time.Now().UTC(),
	}
}

// =============================================================================
// IOC Storage Interface
// =============================================================================

// IOCFilters defines filters for listing IOCs
type IOCFilters struct {
	Types         []IOCType
	Statuses      []IOCStatus
	Severities    []IOCSeverity
	Tags          []string
	Source        string
	Search        string  // Value search (partial match)
	MinConfidence float64 // Minimum confidence threshold
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	Limit         int
	Offset        int
	SortBy        string // Must be validated against allowlist
	SortOrder     string // "asc" or "desc"

	// Feed filtering
	FeedID     string // Filter by specific feed ID
	FeedName   string // Filter by feed name (partial match)
	SourceType string // "manual", "feed", or "" for all
}

// IOCStatistics contains aggregated IOC metrics
type IOCStatistics struct {
	TotalCount       int64            `json:"total_count"`
	ByType           map[string]int64 `json:"by_type"`
	ByStatus         map[string]int64 `json:"by_status"`
	BySeverity       map[string]int64 `json:"by_severity"`
	ActiveCount      int64            `json:"active_count"`
	WhitelistCount   int64            `json:"whitelist_count"`
	RecentMatches24h int64            `json:"recent_matches_24h"`
}

// IOCStorage defines the interface for IOC persistence
type IOCStorage interface {
	// CRUD operations
	CreateIOC(ctx context.Context, ioc *IOC) error
	GetIOC(ctx context.Context, id string) (*IOC, error)
	UpdateIOC(ctx context.Context, ioc *IOC) error
	DeleteIOC(ctx context.Context, id string) error

	// Listing and search
	ListIOCs(ctx context.Context, filters *IOCFilters) ([]*IOC, int64, error)
	FindByValue(ctx context.Context, iocType IOCType, normalizedValue string) (*IOC, error)
	SearchIOCs(ctx context.Context, query string, limit int) ([]*IOC, error)

	// Bulk operations (must use transactions)
	BulkCreateIOCs(ctx context.Context, iocs []*IOC) (created int, skipped int, err error)
	BulkUpdateStatus(ctx context.Context, ids []string, status IOCStatus) error

	// Statistics
	GetIOCStats(ctx context.Context) (*IOCStatistics, error)

	// Relationship management
	LinkToInvestigation(ctx context.Context, iocID, investigationID, linkedBy string) error
	UnlinkFromInvestigation(ctx context.Context, iocID, investigationID string) error
	GetLinkedInvestigations(ctx context.Context, iocID string) ([]string, error)
	LinkToAlert(ctx context.Context, iocID, alertID string) error
	GetLinkedAlerts(ctx context.Context, iocID string) ([]string, error)

	// Hunt management
	CreateHunt(ctx context.Context, hunt *IOCHunt) error
	GetHunt(ctx context.Context, id string) (*IOCHunt, error)
	UpdateHuntStatus(ctx context.Context, id string, status HuntStatus) error
	UpdateHuntProgress(ctx context.Context, id string, progress float64, matchCount, totalEvents int64) error
	CompleteHunt(ctx context.Context, id string, matchCount, totalEvents int64, err error) error
	ListHunts(ctx context.Context, limit, offset int) ([]*IOCHunt, int64, error)

	// Match recording
	RecordMatch(ctx context.Context, match *IOCMatch) error
	BulkRecordMatches(ctx context.Context, matches []*IOCMatch) (int, error) // Returns count of recorded matches
	GetMatchesByHunt(ctx context.Context, huntID string, limit, offset int) ([]*IOCMatch, int64, error)
	GetMatchesByIOC(ctx context.Context, iocID string, limit, offset int) ([]*IOCMatch, int64, error)

	// Maintenance
	ArchiveExpiredIOCs(ctx context.Context) (int64, error)
	IncrementHitCount(ctx context.Context, iocID string, lastSeen time.Time) error

	// Feed-specific IOC operations
	FindByFeedExternalID(ctx context.Context, feedID, externalID string) (*IOC, error)
	GetIOCsByFeed(ctx context.Context, feedID string, limit, offset int) ([]*IOC, int64, error)
	DeleteIOCsByFeed(ctx context.Context, feedID string) (int64, error)
	CountIOCsByFeed(ctx context.Context, feedID string) (int64, error)
}
