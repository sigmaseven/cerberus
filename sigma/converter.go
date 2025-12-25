package sigma

import (
	"cerberus/core"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Converter handles converting SIGMA rules to Cerberus internal format
type Converter struct {
	// Future: Add configuration options here
}

// NewConverter creates a new SIGMA converter
func NewConverter() *Converter {
	return &Converter{}
}

// ConvertBatch converts multiple SIGMA rules to internal format
func (c *Converter) ConvertBatch(sigmaRules []*SigmaRule) ([]*core.Rule, []error) {
	var rules []*core.Rule
	var errors []error

	for _, sigmaRule := range sigmaRules {
		rule, err := c.Convert(sigmaRule)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to convert rule %s: %w", sigmaRule.ID, err))
			continue
		}
		rules = append(rules, rule)
	}

	return rules, errors
}

// Convert converts a single SIGMA rule to internal format
func (c *Converter) Convert(sigmaRule *SigmaRule) (*core.Rule, error) {
	if sigmaRule == nil {
		return nil, fmt.Errorf("sigma rule is nil")
	}

	// Validate the SIGMA rule
	if err := sigmaRule.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SIGMA rule: %w", err)
	}

	// Generate ID if not present
	id := sigmaRule.ID
	if id == "" {
		id = uuid.New().String()
	}

	// Calculate content hash for deduplication
	contentHash := c.calculateContentHash(sigmaRule)

	// Map SIGMA severity to Cerberus severity
	severity := c.mapSeverity(sigmaRule.Level)

	// Extract MITRE ATT&CK tags
	mitreTactics, mitreTechniques := c.extractMITRETags(sigmaRule.Tags)

	// Determine if rule should be enabled
	// Default to true (enable all rules on import) unless explicitly disabled
	enabled := true

	// Create internal rule with SIGMA detection stored directly as structured data
	// TASK #184: Conditions field removed - SIGMA rules use SigmaYAML exclusively
	rule := &core.Rule{
		ID:          id,
		Name:        sigmaRule.Title,
		Description: sigmaRule.Description,
		Type:        "sigma",
		SigmaYAML:   sigmaRule.RawYAML, // Store original YAML content
		Severity:    severity,
		Enabled:         enabled,
		Tags:            sigmaRule.Tags,
		MitreTactics:    mitreTactics,
		MitreTechniques: mitreTechniques,
		Author:          sigmaRule.Author,
		References:      sigmaRule.References,
		FalsePositives:  sigmaRule.FalsePositives,
		LogsourceCategory: extractLogsourceField(sigmaRule.Logsource, "category"),
		LogsourceProduct:  extractLogsourceField(sigmaRule.Logsource, "product"),
		LogsourceService:  extractLogsourceField(sigmaRule.Logsource, "service"),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Metadata:        make(map[string]interface{}),
	}

	// Store SIGMA-specific metadata
	rule.Metadata["sigma_status"] = sigmaRule.Status
	rule.Metadata["sigma_level"] = sigmaRule.Level
	rule.Metadata["sigma_date"] = sigmaRule.Date
	rule.Metadata["sigma_modified"] = sigmaRule.Modified
	rule.Metadata["sigma_source"] = sigmaRule.Source
	rule.Metadata["sigma_file_path"] = sigmaRule.FilePath
	rule.Metadata["sigma_content_hash"] = contentHash

	return rule, nil
}

// calculateContentHash computes a SHA-256 hash of the rule's content for deduplication
func (c *Converter) calculateContentHash(rule *SigmaRule) string {
	// Create a canonical representation of the rule
	data := fmt.Sprintf("%s|%s|%v", rule.Title, rule.Description, rule.Detection)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// mapSeverity maps SIGMA severity levels to Cerberus severity levels
func (c *Converter) mapSeverity(sigmaLevel string) string {
	switch sigmaLevel {
	case "informational":
		return "low"
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	default:
		return "medium" // Default to medium if not specified
	}
}

// extractMITRETags extracts MITRE ATT&CK tactics and techniques from rule tags
func (c *Converter) extractMITRETags(tags []string) ([]string, []string) {
	var tactics []string
	var techniques []string

	for _, tag := range tags {
		// SIGMA rules typically use "attack.t####" for techniques
		// and "attack.tactic_name" for tactics
		if len(tag) > 7 && tag[:7] == "attack." {
			rest := tag[7:]

			// Check if it's a technique (starts with 't' followed by digits)
			if len(rest) > 0 && rest[0] == 't' && len(rest) >= 5 {
				// This is a technique like "attack.t1078"
				techniques = append(techniques, "T"+rest[1:]) // Convert to "T1078" format
			} else {
				// This is a tactic like "attack.credential_access"
				tactics = append(tactics, rest)
			}
		}
	}

	return tactics, techniques
}

// TASK #184: Legacy condition conversion functions deleted
// The following functions were removed because core.Condition struct was deleted:
// - convertDetectionToConditions
// - parseDetectionBlock
// - parseFieldExpression
// - splitByPipe
// Detection rules now use SigmaYAML field exclusively with native SIGMA engine evaluation.

// extractLogsourceField safely extracts a string field from the logsource map
func extractLogsourceField(logsource map[string]interface{}, field string) string {
	if logsource == nil {
		return ""
	}
	if v, ok := logsource[field]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
