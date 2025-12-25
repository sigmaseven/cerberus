package parser

import (
	"strings"
)

// Coverage represents test coverage for a requirement
type Coverage struct {
	Requirement  Requirement
	Tests        []Test
	Status       string
	CoverageRate float64
	Confidence   string
}

// CoverageMatcher matches requirements to tests.
type CoverageMatcher struct {
	requirements []Requirement
	tests        []Test
}

// NewCoverageMatcher creates a new coverage matcher.
func NewCoverageMatcher(requirements []Requirement, tests []Test) *CoverageMatcher {
	return &CoverageMatcher{
		requirements: requirements,
		tests:        tests,
	}
}

// Match performs the requirements-to-tests matching.
func (m *CoverageMatcher) Match() []Coverage {
	coverages := make([]Coverage, 0, len(m.requirements))

	for _, req := range m.requirements {
		coverage := m.matchRequirement(req)
		coverages = append(coverages, coverage)
	}

	return coverages
}

// matchRequirement finds all tests that cover a specific requirement.
func (m *CoverageMatcher) matchRequirement(req Requirement) Coverage {
	var matchedTests []Test
	maxConfidence := ""

	for _, test := range m.tests {
		confidence := m.calculateMatchConfidence(req, test)

		if confidence != "" {
			matchedTests = append(matchedTests, test)

			// Track highest confidence level
			if maxConfidence == "" || confidenceRank(confidence) > confidenceRank(maxConfidence) {
				maxConfidence = confidence
			}
		}
	}

	// Calculate coverage status and rate
	status, coverageRate := m.calculateCoverage(req, matchedTests, maxConfidence)

	return Coverage{
		Requirement:  req,
		Tests:        matchedTests,
		Status:       status,
		CoverageRate: coverageRate,
		Confidence:   maxConfidence,
	}
}

// calculateMatchConfidence determines if a test covers a requirement and with what confidence.
func (m *CoverageMatcher) calculateMatchConfidence(req Requirement, test Test) string {
	// HIGHEST CONFIDENCE: Explicit coverage comment
	for _, coveredID := range test.Covers {
		if coveredID == req.ID {
			return "HIGH"
		}
	}

	// MEDIUM CONFIDENCE: Strong keyword match + file correlation
	// Check if test file is in the same package/area as the requirement
	fileCorrelation := m.checkFileCorrelation(req, test)
	keywordMatches := m.countKeywordMatches(req.Keywords, test.Keywords)

	if fileCorrelation && keywordMatches >= 2 {
		return "MEDIUM"
	}

	// LOW CONFIDENCE: Some keyword matches
	if keywordMatches >= 1 {
		return "LOW"
	}

	// NO MATCH
	return ""
}

// checkFileCorrelation checks if the test file correlates with the requirement category.
func (m *CoverageMatcher) checkFileCorrelation(req Requirement, test Test) bool {
	// Extract key parts from requirement category
	categoryLower := strings.ToLower(req.Category)
	categoryWords := strings.Fields(categoryLower)

	// Check package and file path
	testPackage := strings.ToLower(test.Package)
	testFile := strings.ToLower(test.File)

	for _, word := range categoryWords {
		if len(word) < 3 {
			continue
		}

		// Check if category word appears in package or file path
		if strings.Contains(testPackage, word) || strings.Contains(testFile, word) {
			return true
		}
	}

	// Special cases for common mappings
	correlations := map[string][]string{
		"api design":       {"api", "handlers"},
		"alert":            {"alert", "core"},
		"circuit breaker":  {"circuit", "breaker", "core"},
		"correlation":      {"correlation", "detect"},
		"data ingestion":   {"ingest", "parser"},
		"error handling":   {"error", "util"},
		"mitre":            {"mitre"},
		"machine learning": {"ml"},
		"performance":      {"performance", "benchmark"},
		"search":           {"search", "query", "cql"},
		"security":         {"security", "auth", "csrf", "xss", "sql"},
		"sigma":            {"sigma"},
		"soar":             {"soar", "playbook"},
		"storage":          {"storage", "sqlite", "clickhouse"},
		"user management":  {"user", "auth"},
		"authentication":   {"auth", "jwt"},
	}

	for category, keywords := range correlations {
		if strings.Contains(categoryLower, category) {
			for _, keyword := range keywords {
				if strings.Contains(testPackage, keyword) || strings.Contains(testFile, keyword) {
					return true
				}
			}
		}
	}

	return false
}

// countKeywordMatches counts how many keywords overlap between requirement and test.
func (m *CoverageMatcher) countKeywordMatches(reqKeywords, testKeywords []string) int {
	matches := 0

	for _, reqKW := range reqKeywords {
		for _, testKW := range testKeywords {
			// Exact match
			if reqKW == testKW {
				matches++
				break
			}

			// Partial match (one contains the other)
			if len(reqKW) >= 4 && len(testKW) >= 4 {
				if strings.Contains(reqKW, testKW) || strings.Contains(testKW, reqKW) {
					matches++
					break
				}
			}
		}
	}

	return matches
}

// calculateCoverage determines the coverage status and rate for a requirement.
func (m *CoverageMatcher) calculateCoverage(req Requirement, tests []Test, confidence string) (string, float64) {
	if len(tests) == 0 {
		return "MISSING", 0.0
	}

	// Count non-disabled tests
	activeTests := 0
	for _, test := range tests {
		if !test.Disabled {
			activeTests++
		}
	}

	// If all tests are disabled, consider it missing
	if activeTests == 0 {
		return "MISSING", 0.0
	}

	// Determine status based on confidence and number of tests
	switch confidence {
	case "HIGH":
		// Explicit coverage comment - trust it
		if activeTests >= 2 {
			return "COVERED", 1.0
		}
		return "PARTIAL", 0.7

	case "MEDIUM":
		// Good correlation and keywords
		if activeTests >= 3 {
			return "COVERED", 0.8
		}
		if activeTests >= 1 {
			return "PARTIAL", 0.5
		}

	case "LOW":
		// Weak match - consider it partial at best
		if activeTests >= 5 {
			return "PARTIAL", 0.4
		}
		return "PARTIAL", 0.2
	}

	return "MISSING", 0.0
}

// confidenceRank returns a numeric rank for confidence levels (higher is better).
func confidenceRank(confidence string) int {
	switch confidence {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
