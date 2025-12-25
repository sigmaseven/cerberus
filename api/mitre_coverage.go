package api

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TacticAnalytics represents coverage statistics for a tactic
type TacticAnalytics struct {
	TacticID          string  `json:"tactic_id"`
	TacticName        string  `json:"tactic_name"`
	TotalTechniques   int     `json:"total_techniques"`
	CoveredTechniques int     `json:"covered_techniques"`
	GapCount          int     `json:"gap_count"`
	RuleCount         int     `json:"rule_count"`
	AlertCount30d     int     `json:"alert_count_30d"`
	CoveragePercent   float64 `json:"coverage_percent"`
}

// CoverageGap represents an uncovered technique
type CoverageGap struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	Tactics       []string `json:"tactics"`
}

// CoverageReport represents the overall coverage report
type CoverageReport struct {
	TotalTechniques   int               `json:"total_techniques"`
	CoveredTechniques int               `json:"covered_techniques"`
	CoveragePercent   float64           `json:"coverage_percent"`
	TotalUniqueRules  int               `json:"total_unique_rules"`
	TacticCoverage    []TacticAnalytics `json:"tactic_coverage"`
	CoverageGaps      []CoverageGap     `json:"coverage_gaps"`
	LastUpdated       string            `json:"last_updated"`
}

// RuleReference represents a rule that covers a technique
type RuleReference struct {
	RuleID       string `json:"rule_id"`
	RuleName     string `json:"rule_name"`
	RuleSeverity string `json:"rule_severity,omitempty"`
	Source       string `json:"source"` // "mongodb" or "sigma_feed"
}

// CoverageMatrixTechnique represents a technique in the matrix
type CoverageMatrixTechnique struct {
	TechniqueID   string          `json:"technique_id"`
	TechniqueName string          `json:"technique_name"`
	IsCovered     bool            `json:"is_covered"`
	RuleCount     int             `json:"rule_count"`
	Rules         []RuleReference `json:"rules,omitempty"`
}

// CoverageMatrixTactic represents a tactic with its techniques
type CoverageMatrixTactic struct {
	TacticID   string                    `json:"tactic_id"`
	TacticName string                    `json:"tactic_name"`
	Techniques []CoverageMatrixTechnique `json:"techniques"`
}

// CoverageMatrix represents the full coverage matrix
type CoverageMatrix struct {
	Tactics []CoverageMatrixTactic `json:"tactics"`
}

// Predefined MITRE ATT&CK tactics with their techniques
var mitreTactics = map[string]struct {
	Name       string
	Techniques []struct {
		ID   string
		Name string
	}
}{
	"TA0001": {
		Name: "Initial Access",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1190", "Exploit Public-Facing Application"},
			{"T1133", "External Remote Services"},
			{"T1566", "Phishing"},
			{"T1078", "Valid Accounts"},
			{"T1189", "Drive-by Compromise"},
		},
	},
	"TA0002": {
		Name: "Execution",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1059", "Command and Scripting Interpreter"},
			{"T1053", "Scheduled Task/Job"},
			{"T1204", "User Execution"},
			{"T1047", "Windows Management Instrumentation"},
			{"T1106", "Native API"},
		},
	},
	"TA0003": {
		Name: "Persistence",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1053", "Scheduled Task/Job"},
			{"T1098", "Account Manipulation"},
			{"T1136", "Create Account"},
			{"T1543", "Create or Modify System Process"},
			{"T1078", "Valid Accounts"},
		},
	},
	"TA0004": {
		Name: "Privilege Escalation",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1548", "Abuse Elevation Control Mechanism"},
			{"T1134", "Access Token Manipulation"},
			{"T1068", "Exploitation for Privilege Escalation"},
			{"T1055", "Process Injection"},
			{"T1053", "Scheduled Task/Job"},
		},
	},
	"TA0005": {
		Name: "Defense Evasion",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1562", "Impair Defenses"},
			{"T1070", "Indicator Removal"},
			{"T1112", "Modify Registry"},
			{"T1036", "Masquerading"},
			{"T1027", "Obfuscated Files or Information"},
		},
	},
	"TA0006": {
		Name: "Credential Access",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1003", "OS Credential Dumping"},
			{"T1110", "Brute Force"},
			{"T1555", "Credentials from Password Stores"},
			{"T1056", "Input Capture"},
			{"T1558", "Steal or Forge Kerberos Tickets"},
		},
	},
	"TA0007": {
		Name: "Discovery",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1087", "Account Discovery"},
			{"T1069", "Permission Groups Discovery"},
			{"T1083", "File and Directory Discovery"},
			{"T1046", "Network Service Discovery"},
			{"T1057", "Process Discovery"},
		},
	},
	"TA0008": {
		Name: "Lateral Movement",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1021", "Remote Services"},
			{"T1080", "Taint Shared Content"},
			{"T1091", "Replication Through Removable Media"},
			{"T1563", "Remote Service Session Hijacking"},
			{"T1550", "Use Alternate Authentication Material"},
		},
	},
	"TA0009": {
		Name: "Collection",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1560", "Archive Collected Data"},
			{"T1123", "Audio Capture"},
			{"T1119", "Automated Collection"},
			{"T1005", "Data from Local System"},
			{"T1074", "Data Staged"},
		},
	},
	"TA0011": {
		Name: "Command and Control",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1071", "Application Layer Protocol"},
			{"T1132", "Data Encoding"},
			{"T1001", "Data Obfuscation"},
			{"T1568", "Dynamic Resolution"},
			{"T1573", "Encrypted Channel"},
		},
	},
	"TA0010": {
		Name: "Exfiltration",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1020", "Automated Exfiltration"},
			{"T1030", "Data Transfer Size Limits"},
			{"T1048", "Exfiltration Over Alternative Protocol"},
			{"T1041", "Exfiltration Over C2 Channel"},
			{"T1011", "Exfiltration Over Other Network Medium"},
		},
	},
	"TA0040": {
		Name: "Impact",
		Techniques: []struct {
			ID   string
			Name string
		}{
			{"T1485", "Data Destruction"},
			{"T1486", "Data Encrypted for Impact"},
			{"T1491", "Defacement"},
			{"T1561", "Disk Wipe"},
			{"T1489", "Service Stop"},
		},
	},
}

// SigmaRule represents a minimal Sigma rule structure for parsing
type SigmaRule struct {
	ID     string   `yaml:"id"`
	Title  string   `yaml:"title"`
	Status string   `yaml:"status"`
	Level  string   `yaml:"level"`
	Tags   []string `yaml:"tags"`
}

// TechniqueRuleMap maps technique IDs to the rules that cover them
type TechniqueRuleMap map[string][]RuleReference

// scanSigmaFeedRules scans Sigma rule files from feeds directory
func scanSigmaFeedRules(feedsDir string) (map[string]int, TechniqueRuleMap, int) {
	coveredTechniques := make(map[string]int)
	techniqueRules := make(TechniqueRuleMap)
	uniqueRuleCount := 0
	techniquePattern := regexp.MustCompile(`(?i)attack\.t(\d{4})(?:\.(\d{3}))?`)

	// SECURITY FIX: Get absolute path of feeds directory to prevent path traversal
	absBase, err := filepath.Abs(filepath.Clean(feedsDir))
	if err != nil {
		return coveredTechniques, techniqueRules, uniqueRuleCount
	}

	// Walk through all YAML files in feeds directory
	filepath.Walk(feedsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		// Only process .yml and .yaml files
		if info.IsDir() || (!strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml")) {
			return nil
		}

		// Skip non-rule files (like FUNDING.yml, README.yml, etc.)
		if !strings.Contains(path, "/rules/") && !strings.Contains(path, "\\rules\\") {
			return nil
		}

		// SECURITY FIX: Validate that resolved path is within allowed directory
		absPath, err := filepath.Abs(filepath.Clean(path))
		if err != nil || !strings.HasPrefix(absPath, absBase) {
			return nil // Skip potentially malicious paths
		}

		// Read and parse YAML file - use os.ReadFile instead of deprecated ioutil
		data, err := os.ReadFile(absPath)
		if err != nil {
			return nil // Skip errors
		}

		var sigmaRule SigmaRule
		if err := yaml.Unmarshal(data, &sigmaRule); err != nil {
			return nil // Skip invalid YAML
		}

		// Count this as a unique rule
		uniqueRuleCount++

		// Extract MITRE technique IDs from tags
		var ruleTechniques []string
		for _, tag := range sigmaRule.Tags {
			matches := techniquePattern.FindStringSubmatch(tag)
			if len(matches) > 0 {
				techID := "T" + matches[1]
				if len(matches) > 2 && matches[2] != "" {
					techID += "." + matches[2]
				}
				ruleTechniques = append(ruleTechniques, techID)
				coveredTechniques[techID]++
			}
		}

		// Add rule reference for each technique it covers
		if len(ruleTechniques) > 0 && sigmaRule.Title != "" {
			ruleRef := RuleReference{
				RuleID:       sigmaRule.ID,
				RuleName:     sigmaRule.Title,
				RuleSeverity: sigmaRule.Level,
				Source:       "sigma_feed",
			}
			for _, techID := range ruleTechniques {
				techniqueRules[techID] = append(techniqueRules[techID], ruleRef)
			}
		}

		return nil
	})

	return coveredTechniques, techniqueRules, uniqueRuleCount
}

// getMITRECoverage godoc
//
//	@Summary		Get MITRE ATT&CK coverage report
//	@Description	Returns comprehensive coverage statistics across all tactics and techniques
//	@Tags			mitre
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	CoverageReport
//	@Failure		500	{string}	string	"Failed to generate coverage report"
//	@Router			/api/v1/mitre/coverage [get]
func (a *API) getMITRECoverage(w http.ResponseWriter, r *http.Request) {
	// Get all rules from storage
	rules, err := a.ruleStorage.GetAllRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get rules", err, a.logger)
		return
	}

	// Build a map of covered techniques from MongoDB rules
	coveredTechniques := make(map[string]int) // technique_id -> rule_count
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, techID := range rule.MitreTechniques {
			techID = strings.ToUpper(strings.TrimSpace(techID))
			if techID != "" {
				coveredTechniques[techID]++
			}
		}
	}

	// Also scan Sigma feed rules from data/feeds directory
	feedsDir := "./data/feeds"
	sigmaRuleCount := 0
	if _, err := os.Stat(feedsDir); err == nil {
		sigmaRuleCoverage, _, count := scanSigmaFeedRules(feedsDir)
		sigmaRuleCount = count
		// Merge Sigma rules into coverage map
		for techID, count := range sigmaRuleCoverage {
			coveredTechniques[techID] += count
		}
	}

	// Calculate coverage by tactic
	tacticCoverage := []TacticAnalytics{}
	allGaps := []CoverageGap{}
	totalTechniques := 0
	totalCovered := 0

	for tacticID, tacticData := range mitreTactics {
		tacticTotal := len(tacticData.Techniques)
		tacticCovered := 0
		tacticRuleCount := 0

		for _, tech := range tacticData.Techniques {
			totalTechniques++
			ruleCount := coveredTechniques[tech.ID]
			if ruleCount > 0 {
				tacticCovered++
				totalCovered++
				tacticRuleCount += ruleCount
			} else {
				// This is a gap
				allGaps = append(allGaps, CoverageGap{
					TechniqueID:   tech.ID,
					TechniqueName: tech.Name,
					Tactics:       []string{tacticData.Name},
				})
			}
		}

		gapCount := tacticTotal - tacticCovered
		coveragePercent := 0.0
		if tacticTotal > 0 {
			coveragePercent = (float64(tacticCovered) / float64(tacticTotal)) * 100
		}

		tacticCoverage = append(tacticCoverage, TacticAnalytics{
			TacticID:          tacticID,
			TacticName:        tacticData.Name,
			TotalTechniques:   tacticTotal,
			CoveredTechniques: tacticCovered,
			GapCount:          gapCount,
			RuleCount:         tacticRuleCount,
			AlertCount30d:     0, // TODO: Query alert storage
			CoveragePercent:   coveragePercent,
		})
	}

	// Calculate overall coverage
	overallCoveragePercent := 0.0
	if totalTechniques > 0 {
		overallCoveragePercent = (float64(totalCovered) / float64(totalTechniques)) * 100
	}

	// Calculate total unique rules (MongoDB rules + Sigma rules + CQL rules)
	totalUniqueRules := len(rules) + sigmaRuleCount

	report := CoverageReport{
		TotalTechniques:   totalTechniques,
		CoveredTechniques: totalCovered,
		CoveragePercent:   overallCoveragePercent,
		TotalUniqueRules:  totalUniqueRules,
		TacticCoverage:    tacticCoverage,
		CoverageGaps:      allGaps,
		LastUpdated:       time.Now().UTC().Format(time.RFC3339),
	}

	a.respondJSON(w, report, http.StatusOK)
}

// getMITRECoverageMatrix godoc
//
//	@Summary		Get MITRE ATT&CK coverage matrix
//	@Description	Returns detailed coverage matrix with all tactics and techniques
//	@Tags			mitre
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	CoverageMatrix
//	@Failure		500	{string}	string	"Failed to generate coverage matrix"
//	@Router			/api/v1/mitre/coverage/matrix [get]
func (a *API) getMITRECoverageMatrix(w http.ResponseWriter, r *http.Request) {
	// Get all rules from storage
	rules, err := a.ruleStorage.GetAllRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get rules", err, a.logger)
		return
	}

	// Build a map of covered techniques from MongoDB rules with rule details
	coveredTechniques := make(map[string]int) // technique_id -> rule_count
	techniqueRules := make(TechniqueRuleMap)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, techID := range rule.MitreTechniques {
			techID = strings.ToUpper(strings.TrimSpace(techID))
			if techID != "" {
				coveredTechniques[techID]++
				// Add MongoDB rule reference
				techniqueRules[techID] = append(techniqueRules[techID], RuleReference{
					RuleID:       rule.ID,
					RuleName:     rule.Name,
					RuleSeverity: rule.Severity,
					Source:       "mongodb",
				})
			}
		}
	}

	// Also scan Sigma feed rules from data/feeds directory
	feedsDir := "./data/feeds"
	if _, err := os.Stat(feedsDir); err == nil {
		sigmaRuleCoverage, sigmaRuleMap, _ := scanSigmaFeedRules(feedsDir)
		// Merge Sigma rules into coverage map
		for techID, count := range sigmaRuleCoverage {
			coveredTechniques[techID] += count
		}
		// Merge Sigma rule details
		for techID, sigmaRules := range sigmaRuleMap {
			techniqueRules[techID] = append(techniqueRules[techID], sigmaRules...)
		}
	}

	// Build matrix
	matrix := CoverageMatrix{
		Tactics: []CoverageMatrixTactic{},
	}

	for tacticID, tacticData := range mitreTactics {
		tacticMatrix := CoverageMatrixTactic{
			TacticID:   tacticID,
			TacticName: tacticData.Name,
			Techniques: []CoverageMatrixTechnique{},
		}

		for _, tech := range tacticData.Techniques {
			ruleCount := coveredTechniques[tech.ID]
			rules := techniqueRules[tech.ID]

			tacticMatrix.Techniques = append(tacticMatrix.Techniques, CoverageMatrixTechnique{
				TechniqueID:   tech.ID,
				TechniqueName: tech.Name,
				IsCovered:     ruleCount > 0,
				RuleCount:     ruleCount,
				Rules:         rules,
			})
		}

		matrix.Tactics = append(matrix.Tactics, tacticMatrix)
	}

	a.respondJSON(w, matrix, http.StatusOK)
}
