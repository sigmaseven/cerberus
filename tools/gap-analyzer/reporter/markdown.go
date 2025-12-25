package reporter

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Types (duplicated for package independence)
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

// MarkdownReporter generates markdown-formatted gap analysis reports.
type MarkdownReporter struct{}

// NewMarkdownReporter creates a new markdown reporter.
func NewMarkdownReporter() *MarkdownReporter {
	return &MarkdownReporter{}
}

// Generate generates a comprehensive markdown report.
func (r *MarkdownReporter) Generate(report AnalysisReport, outputPath string) error {
	var sb strings.Builder

	// Header
	r.writeHeader(&sb, report)

	// Executive Summary
	r.writeSummary(&sb, report)

	// Category Statistics
	r.writeCategoryStats(&sb, report)

	// Critical Gaps
	r.writeCriticalGaps(&sb, report)

	// Detailed Coverage by Category
	r.writeDetailedCoverage(&sb, report)

	// Recommendations
	r.writeRecommendations(&sb, report)

	// Traceability Matrix
	r.writeTraceabilityMatrix(&sb, report)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write markdown report: %w", err)
	}

	return nil
}

func (r *MarkdownReporter) writeHeader(sb *strings.Builder, report AnalysisReport) {
	sb.WriteString("# Requirements-to-Test-Coverage Gap Analysis\n")
	sb.WriteString("## Automated Analysis Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated**: %s\n", report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Tool Version**: %s\n", report.Metadata.ToolVersion))
	sb.WriteString(fmt.Sprintf("**Requirements Path**: %s\n", report.Metadata.RequirementsPath))
	sb.WriteString(fmt.Sprintf("**Tests Path**: %s\n", report.Metadata.TestsPath))
	sb.WriteString(fmt.Sprintf("**Total Requirements**: %d\n", report.Metadata.TotalRequirements))
	sb.WriteString(fmt.Sprintf("**Total Test Files**: %d\n", report.Metadata.TotalTestFiles))
	sb.WriteString(fmt.Sprintf("**Total Test Functions**: %d\n\n", report.Metadata.TotalTests))
	sb.WriteString("---\n\n")
}

func (r *MarkdownReporter) writeSummary(sb *strings.Builder, report AnalysisReport) {
	sb.WriteString("## Executive Summary\n\n")

	sum := report.Summary

	sb.WriteString("### Coverage Overview\n\n")
	sb.WriteString(fmt.Sprintf("**Overall Coverage**: %.1f%%\n\n", sum.CoveragePercent))

	sb.WriteString("| Metric | Count | Percentage |\n")
	sb.WriteString("|--------|-------|------------|\n")
	sb.WriteString(fmt.Sprintf("| Total Requirements | %d | 100%% |\n", sum.TotalRequirements))
	sb.WriteString(fmt.Sprintf("| Covered | %d | %.1f%% |\n", sum.Covered, percentage(sum.Covered, sum.TotalRequirements)))
	sb.WriteString(fmt.Sprintf("| Partial | %d | %.1f%% |\n", sum.Partial, percentage(sum.Partial, sum.TotalRequirements)))
	sb.WriteString(fmt.Sprintf("| Missing | %d | %.1f%% |\n\n", sum.Missing, percentage(sum.Missing, sum.TotalRequirements)))

	sb.WriteString("### Priority Distribution of Gaps\n\n")
	sb.WriteString("| Priority | Gaps | Status |\n")
	sb.WriteString("|----------|------|--------|\n")
	sb.WriteString(fmt.Sprintf("| P0 (Critical) | %d | %s |\n", sum.P0Gaps, gapStatus(sum.P0Gaps)))
	sb.WriteString(fmt.Sprintf("| P1 (High) | %d | %s |\n", sum.P1Gaps, gapStatus(sum.P1Gaps)))
	sb.WriteString(fmt.Sprintf("| P2 (Medium) | %d | %s |\n", sum.P2Gaps, gapStatus(sum.P2Gaps)))
	sb.WriteString(fmt.Sprintf("| P3 (Low) | %d | %s |\n\n", sum.P3Gaps, gapStatus(sum.P3Gaps)))

	sb.WriteString("---\n\n")
}

func (r *MarkdownReporter) writeCategoryStats(sb *strings.Builder, report AnalysisReport) {
	sb.WriteString("## Coverage by Category\n\n")

	sb.WriteString("| Category | Total | Covered | Partial | Missing | Coverage % | Status |\n")
	sb.WriteString("|----------|-------|---------|---------|---------|------------|--------|\n")

	for _, stat := range report.CategoryStats {
		status := coverageStatus(stat.CoveragePercent)
		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %.1f%% | %s |\n",
			stat.Category, stat.Total, stat.Covered, stat.Partial, stat.Missing,
			stat.CoveragePercent, status))
	}

	sb.WriteString("\n---\n\n")
}

func (r *MarkdownReporter) writeCriticalGaps(sb *strings.Builder, report AnalysisReport) {
	if len(report.CriticalGaps) == 0 {
		sb.WriteString("## Critical Gaps\n\n")
		sb.WriteString("**No critical gaps found!** All P0 requirements have test coverage.\n\n")
		sb.WriteString("---\n\n")
		return
	}

	sb.WriteString("## Critical Gaps Requiring Immediate Attention\n\n")
	sb.WriteString(fmt.Sprintf("Found **%d critical gaps** that must be addressed:\n\n", len(report.CriticalGaps)))

	// Group by priority
	p0Gaps := []Coverage{}
	p1Gaps := []Coverage{}

	for _, gap := range report.CriticalGaps {
		if gap.Requirement.Priority == "P0" {
			p0Gaps = append(p0Gaps, gap)
		} else {
			p1Gaps = append(p1Gaps, gap)
		}
	}

	if len(p0Gaps) > 0 {
		sb.WriteString("### P0 (Critical) Gaps\n\n")
		for _, gap := range p0Gaps {
			sb.WriteString(fmt.Sprintf("**%s**: %s\n", gap.Requirement.ID, gap.Requirement.Title))
			sb.WriteString(fmt.Sprintf("- **Source**: `%s:%d`\n", gap.Requirement.SourceFile, gap.Requirement.SourceLine))
			sb.WriteString(fmt.Sprintf("- **Type**: %s\n", gap.Requirement.Type))
			sb.WriteString(fmt.Sprintf("- **Status**: %s\n", gap.Status))
			if gap.Requirement.Description != "" {
				sb.WriteString(fmt.Sprintf("- **Description**: %s\n", truncate(gap.Requirement.Description, 200)))
			}
			sb.WriteString("\n")
		}
	}

	if len(p1Gaps) > 0 {
		sb.WriteString("### P1 (High Priority) Gaps\n\n")
		for i, gap := range p1Gaps {
			if i >= 10 { // Limit to first 10 to keep report concise
				sb.WriteString(fmt.Sprintf("... and %d more P1 gaps (see detailed coverage section)\n\n", len(p1Gaps)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("**%s**: %s\n", gap.Requirement.ID, gap.Requirement.Title))
			sb.WriteString(fmt.Sprintf("- **Source**: `%s:%d`\n", gap.Requirement.SourceFile, gap.Requirement.SourceLine))
			sb.WriteString(fmt.Sprintf("- **Status**: %s (Coverage: %.0f%%)\n\n", gap.Status, gap.CoverageRate*100))
		}
	}

	sb.WriteString("---\n\n")
}

func (r *MarkdownReporter) writeDetailedCoverage(sb *strings.Builder, report AnalysisReport) {
	sb.WriteString("## Detailed Coverage by Category\n\n")

	// Group coverages by category
	categoryMap := make(map[string][]Coverage)
	for _, coverage := range report.Coverages {
		category := coverage.Requirement.Category
		if category == "" {
			category = "Uncategorized"
		}
		categoryMap[category] = append(categoryMap[category], coverage)
	}

	// Sort categories alphabetically
	categories := make([]string, 0, len(categoryMap))
	for category := range categoryMap {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	// Write each category
	for _, category := range categories {
		coverages := categoryMap[category]

		// Calculate category stats
		covered := 0
		partial := 0
		missing := 0
		for _, c := range coverages {
			switch c.Status {
			case "COVERED":
				covered++
			case "PARTIAL":
				partial++
			case "MISSING":
				missing++
			}
		}

		sb.WriteString(fmt.Sprintf("### %s\n\n", category))
		sb.WriteString(fmt.Sprintf("**Coverage**: %d covered, %d partial, %d missing (Total: %d)\n\n", covered, partial, missing, len(coverages)))

		// Write requirements
		for _, coverage := range coverages {
			icon := statusIcon(coverage.Status)
			sb.WriteString(fmt.Sprintf("%s **%s**: %s\n", icon, coverage.Requirement.ID, coverage.Requirement.Title))

			if len(coverage.Tests) > 0 {
				sb.WriteString(fmt.Sprintf("  - **Tests** (%d):\n", len(coverage.Tests)))
				for _, test := range coverage.Tests {
					disabledMark := ""
					if test.Disabled {
						disabledMark = " [DISABLED]"
					}
					sb.WriteString(fmt.Sprintf("    - `%s` (%s)%s\n", test.Name, test.File, disabledMark))
				}
				sb.WriteString(fmt.Sprintf("  - **Confidence**: %s\n", coverage.Confidence))
			} else {
				sb.WriteString("  - **No tests found**\n")
			}

			sb.WriteString("\n")
		}

		sb.WriteString("---\n\n")
	}
}

func (r *MarkdownReporter) writeRecommendations(sb *strings.Builder, report AnalysisReport) {
	sb.WriteString("## Recommendations\n\n")

	for i, recommendation := range report.Recommendations {
		sb.WriteString(fmt.Sprintf("%d. %s\n\n", i+1, recommendation))
	}

	sb.WriteString("---\n\n")
}

func (r *MarkdownReporter) writeTraceabilityMatrix(sb *strings.Builder, report AnalysisReport) {
	sb.WriteString("## Traceability Matrix\n\n")
	sb.WriteString("Complete requirements-to-tests mapping:\n\n")

	sb.WriteString("| Requirement ID | Title | Status | Tests | Files |\n")
	sb.WriteString("|----------------|-------|--------|-------|-------|\n")

	for _, coverage := range report.Coverages {
		testCount := len(coverage.Tests)

		// Get unique test files
		fileSet := make(map[string]bool)
		for _, test := range coverage.Tests {
			fileSet[test.File] = true
		}
		fileCount := len(fileSet)

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %d |\n",
			coverage.Requirement.ID,
			truncate(coverage.Requirement.Title, 50),
			coverage.Status,
			testCount,
			fileCount))
	}

	sb.WriteString("\n---\n\n")
	sb.WriteString("**End of Report**\n")
}

// Helper functions

func percentage(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return (float64(part) / float64(total)) * 100.0
}

func gapStatus(gaps int) string {
	if gaps == 0 {
		return "✅ OK"
	}
	if gaps <= 3 {
		return "⚠️ Warning"
	}
	return "❌ Critical"
}

func coverageStatus(percent float64) string {
	if percent >= 80 {
		return "✅ Excellent"
	}
	if percent >= 60 {
		return "🟢 Good"
	}
	if percent >= 40 {
		return "⚠️ Fair"
	}
	if percent >= 20 {
		return "🟠 Poor"
	}
	return "❌ Critical"
}

func statusIcon(status string) string {
	switch status {
	case "COVERED":
		return "✅"
	case "PARTIAL":
		return "⚠️"
	case "MISSING":
		return "❌"
	default:
		return "❓"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
