package analyzer

import (
	"fmt"
	"sort"
	"time"
)

// Requirement, Test, Coverage types (duplicated for package independence)
type Requirement struct {
	ID          string
	Category    string
	Title       string
	Description string
	Priority    string
	Type        string
	Keywords    []string
	SourceFile  string
	SourceLine  int
	Section     string
}

type Test struct {
	Name        string
	Package     string
	File        string
	Line        int
	Description string
	Covers      []string
	Keywords    []string
	Disabled    bool
}

type Coverage struct {
	Requirement  Requirement
	Tests        []Test
	Status       string
	CoverageRate float64
	Confidence   string
}

type AnalysisReport struct {
	Metadata        ReportMetadata
	Summary         Summary
	CategoryStats   []CategoryStat
	Coverages       []Coverage
	CriticalGaps    []Coverage
	Recommendations []string
}

type ReportMetadata struct {
	GeneratedAt       time.Time
	ToolVersion       string
	RequirementsPath  string
	TestsPath         string
	TotalRequirements int
	TotalTests        int
	TotalTestFiles    int
}

type Summary struct {
	TotalRequirements int
	Covered           int
	Partial           int
	Missing           int
	CoveragePercent   float64
	P0Gaps            int
	P1Gaps            int
	P2Gaps            int
	P3Gaps            int
}

type CategoryStat struct {
	Category        string
	Total           int
	Covered         int
	Partial         int
	Missing         int
	CoveragePercent float64
}

// Analyzer performs gap analysis on coverage data.
type Analyzer struct {
	coverages []Coverage
	tests     []Test
}

// NewAnalyzer creates a new analyzer.
func NewAnalyzer(coverages []Coverage, tests []Test) *Analyzer {
	return &Analyzer{
		coverages: coverages,
		tests:     tests,
	}
}

// Analyze performs comprehensive gap analysis and generates a report.
func (a *Analyzer) Analyze(reqPath, testPath, version string) AnalysisReport {
	summary := a.calculateSummary()
	categoryStats := a.calculateCategoryStats()
	criticalGaps := a.identifyCriticalGaps()
	recommendations := a.generateRecommendations(summary, categoryStats, criticalGaps)

	// Count unique test files
	testFiles := make(map[string]bool)
	for _, test := range a.tests {
		testFiles[test.File] = true
	}

	return AnalysisReport{
		Metadata: ReportMetadata{
			GeneratedAt:       time.Now(),
			ToolVersion:       version,
			RequirementsPath:  reqPath,
			TestsPath:         testPath,
			TotalRequirements: len(a.coverages),
			TotalTests:        len(a.tests),
			TotalTestFiles:    len(testFiles),
		},
		Summary:         summary,
		CategoryStats:   categoryStats,
		Coverages:       a.coverages,
		CriticalGaps:    criticalGaps,
		Recommendations: recommendations,
	}
}

// calculateSummary calculates overall coverage summary statistics.
func (a *Analyzer) calculateSummary() Summary {
	summary := Summary{
		TotalRequirements: len(a.coverages),
	}

	for _, coverage := range a.coverages {
		switch coverage.Status {
		case "COVERED":
			summary.Covered++
		case "PARTIAL":
			summary.Partial++
		case "MISSING":
			summary.Missing++
		}

		// Count priority gaps (only for MISSING or weak PARTIAL)
		if coverage.Status == "MISSING" || (coverage.Status == "PARTIAL" && coverage.CoverageRate < 0.5) {
			switch coverage.Requirement.Priority {
			case "P0":
				summary.P0Gaps++
			case "P1":
				summary.P1Gaps++
			case "P2":
				summary.P2Gaps++
			case "P3":
				summary.P3Gaps++
			}
		}
	}

	// Calculate overall coverage percentage
	if summary.TotalRequirements > 0 {
		// Weighted: COVERED=1.0, PARTIAL=0.5, MISSING=0.0
		weightedCoverage := float64(summary.Covered) + (float64(summary.Partial) * 0.5)
		summary.CoveragePercent = (weightedCoverage / float64(summary.TotalRequirements)) * 100.0
	}

	return summary
}

// calculateCategoryStats calculates coverage statistics per requirement category.
func (a *Analyzer) calculateCategoryStats() []CategoryStat {
	// Group coverages by category
	categoryMap := make(map[string]*CategoryStat)

	for _, coverage := range a.coverages {
		category := coverage.Requirement.Category
		if category == "" {
			category = "Uncategorized"
		}

		stat, exists := categoryMap[category]
		if !exists {
			stat = &CategoryStat{Category: category}
			categoryMap[category] = stat
		}

		stat.Total++
		switch coverage.Status {
		case "COVERED":
			stat.Covered++
		case "PARTIAL":
			stat.Partial++
		case "MISSING":
			stat.Missing++
		}
	}

	// Convert map to slice and calculate percentages
	stats := make([]CategoryStat, 0, len(categoryMap))
	for _, stat := range categoryMap {
		if stat.Total > 0 {
			weightedCoverage := float64(stat.Covered) + (float64(stat.Partial) * 0.5)
			stat.CoveragePercent = (weightedCoverage / float64(stat.Total)) * 100.0
		}
		stats = append(stats, *stat)
	}

	// Sort by coverage percentage (ascending) to highlight problem areas
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].CoveragePercent < stats[j].CoveragePercent
	})

	return stats
}

// identifyCriticalGaps identifies P0 and P1 gaps that need immediate attention.
func (a *Analyzer) identifyCriticalGaps() []Coverage {
	var criticalGaps []Coverage

	for _, coverage := range a.coverages {
		// P0 gaps are always critical
		if coverage.Requirement.Priority == "P0" && coverage.Status == "MISSING" {
			criticalGaps = append(criticalGaps, coverage)
			continue
		}

		// P1 MUST requirements with missing or weak coverage
		if coverage.Requirement.Priority == "P1" &&
			coverage.Requirement.Type == "MUST" &&
			(coverage.Status == "MISSING" || coverage.CoverageRate < 0.5) {
			criticalGaps = append(criticalGaps, coverage)
			continue
		}
	}

	// Sort by priority then by requirement ID
	sort.Slice(criticalGaps, func(i, j int) bool {
		if criticalGaps[i].Requirement.Priority != criticalGaps[j].Requirement.Priority {
			return priorityRank(criticalGaps[i].Requirement.Priority) > priorityRank(criticalGaps[j].Requirement.Priority)
		}
		return criticalGaps[i].Requirement.ID < criticalGaps[j].Requirement.ID
	})

	return criticalGaps
}

// generateRecommendations generates actionable recommendations based on the analysis.
func (a *Analyzer) generateRecommendations(summary Summary, categoryStats []CategoryStat, criticalGaps []Coverage) []string {
	var recommendations []string

	// Overall coverage recommendation
	if summary.CoveragePercent < 70 {
		recommendations = append(recommendations,
			fmt.Sprintf("Overall coverage is %.1f%%, which is below the recommended 70%% threshold. Prioritize adding tests for P0 and P1 requirements.", summary.CoveragePercent))
	}

	// P0 gaps
	if summary.P0Gaps > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("CRITICAL: %d P0 requirements have insufficient test coverage. These are production blockers and must be addressed immediately.", summary.P0Gaps))
	}

	// Category-specific recommendations (bottom 3 categories)
	if len(categoryStats) > 0 {
		bottomCategories := categoryStats
		if len(bottomCategories) > 3 {
			bottomCategories = categoryStats[:3]
		}

		for _, stat := range bottomCategories {
			if stat.CoveragePercent < 50 {
				recommendations = append(recommendations,
					fmt.Sprintf("Category '%s' has only %.1f%% coverage (%d/%d requirements). Focus on improving test coverage in this area.",
						stat.Category, stat.CoveragePercent, stat.Covered, stat.Total))
			}
		}
	}

	// Disabled test files
	disabledTests := 0
	for _, test := range a.tests {
		if test.Disabled {
			disabledTests++
		}
	}
	if disabledTests > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Found %d disabled tests. Review and re-enable these tests or document why they are disabled.", disabledTests))
	}

	// Missing explicit coverage comments
	explicitCoverage := 0
	for _, coverage := range a.coverages {
		if coverage.Confidence == "HIGH" {
			explicitCoverage++
		}
	}
	implicitCoverage := len(a.coverages) - explicitCoverage - summary.Missing
	if implicitCoverage > len(a.coverages)/2 {
		recommendations = append(recommendations,
			"Many test-to-requirement mappings are based on keyword matching. Add explicit coverage comments (// Covers: FR-XXX-NNN) to improve traceability.")
	}

	// No recommendations is good news
	if len(recommendations) == 0 {
		recommendations = append(recommendations,
			"Excellent! Test coverage meets quality standards. Continue maintaining coverage as new requirements are added.")
	}

	return recommendations
}

// priorityRank returns numeric rank for priority (higher is more important).
func priorityRank(priority string) int {
	switch priority {
	case "P0":
		return 4
	case "P1":
		return 3
	case "P2":
		return 2
	case "P3":
		return 1
	default:
		return 0
	}
}
