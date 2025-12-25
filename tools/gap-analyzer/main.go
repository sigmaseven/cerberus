package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cerberus/tools/gap-analyzer/analyzer"
	"cerberus/tools/gap-analyzer/parser"
	"cerberus/tools/gap-analyzer/reporter"

	"gopkg.in/yaml.v3"
)

const version = "1.0.0"

// cliFlags holds command-line flag values
type cliFlags struct {
	configPath string
	format     string
	outputPath string
	check      bool
	threshold  int
	verbose    bool
	summary    bool
}

func main() {
	startTime := time.Now()

	// Parse command-line flags
	flags := parseFlags()

	// Load configuration
	config := loadConfiguration(flags.configPath, flags.verbose)

	// Run analysis pipeline
	report := runAnalysis(config, flags.verbose, flags.summary)

	// Print summary to stdout
	printSummary(report)

	// Generate output reports
	generateOutputReports(report, config, flags)

	// Check coverage threshold if requested
	if flags.check {
		checkThreshold(report, config, flags.threshold)
	}

	// Report execution time
	if flags.verbose {
		fmt.Printf("\nExecution time: %.2fs\n", time.Since(startTime).Seconds())
	}

	os.Exit(0)
}

// parseFlags parses and validates command-line flags.
func parseFlags() cliFlags {
	configPath := flag.String("config", "tools/gap-analyzer/config.yaml", "Path to configuration file")
	format := flag.String("format", "all", "Output format: markdown, json, yaml, badge, all")
	outputPath := flag.String("output", "", "Output file path (overrides config)")
	check := flag.Bool("check", false, "Check mode: exit with error if coverage below threshold")
	threshold := flag.Int("threshold", 0, "Coverage threshold percentage (0 = use config)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	summary := flag.Bool("summary", false, "Summary mode: generate compact reports (< 5MB)")
	showVersion := flag.Bool("version", false, "Show version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("gap-analyzer version %s\n", version)
		os.Exit(0)
	}

	return cliFlags{
		configPath: *configPath,
		format:     *format,
		outputPath: *outputPath,
		check:      *check,
		threshold:  *threshold,
		verbose:    *verbose,
		summary:    *summary,
	}
}

// loadConfiguration loads and validates the configuration file.
func loadConfiguration(configPath string, verbose bool) *Config {
	config, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Gap Analyzer v%s\n", version)
		fmt.Printf("Config: %s\n", configPath)
		fmt.Printf("Requirements path: %s\n", config.Requirements.Directory)
		fmt.Println("---")
	}

	return config
}

// runAnalysis executes the complete analysis pipeline.
func runAnalysis(config *Config, verbose bool, summaryMode bool) analyzer.AnalysisReport {
	// Parse requirements
	if verbose {
		fmt.Println("Parsing requirements...")
	}

	reqParser, err := parser.NewRequirementsParser(
		config.Requirements.IDPatterns,
		config.Requirements.PriorityKeywords,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating requirements parser: %v\n", err)
		os.Exit(1)
	}

	requirements, err := reqParser.ParseDirectory(
		config.Requirements.Directory,
		config.Requirements.Patterns,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing requirements: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Found %d requirements\n", len(requirements))
	}

	// Parse tests
	if verbose {
		fmt.Println("Parsing test files...")
	}

	testParser, err := parser.NewTestsParser(
		config.Tests.CoverageCommentPatterns,
		config.Requirements.IDPatterns,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating test parser: %v\n", err)
		os.Exit(1)
	}

	tests, err := testParser.ParseDirectories(
		config.Tests.Directories,
		config.Tests.Patterns,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing tests: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Found %d test functions\n", len(tests))
	}

	// Match requirements to tests
	if verbose {
		fmt.Println("Matching requirements to tests...")
	}

	matcher := parser.NewCoverageMatcher(requirements, tests)
	coverages := matcher.Match()

	if verbose {
		fmt.Printf("Matched %d requirements to tests\n", len(coverages))
	}

	// Analyze coverage
	if verbose {
		fmt.Println("Analyzing coverage gaps...")
	}

	analyzerCoverages := convertCoverages(coverages)
	analyzerTests := convertTests(tests)
	gapAnalyzer := analyzer.NewAnalyzer(analyzerCoverages, analyzerTests)
	report := gapAnalyzer.Analyze(
		config.Requirements.Directory,
		config.Tests.Directories[0],
		version,
	)

	// Apply summary mode filter if enabled
	if summaryMode {
		report = filterReportForSummary(report)
		if verbose {
			fmt.Println("Summary mode: filtered to critical gaps only")
		}
	}

	return report
}

// printSummary prints the analysis summary to stdout.
func printSummary(report analyzer.AnalysisReport) {
	fmt.Println("===== Gap Analysis Summary =====")
	fmt.Printf("Total Requirements: %d\n", report.Summary.TotalRequirements)
	fmt.Printf("Covered: %d (%.1f%%)\n", report.Summary.Covered, percentage(report.Summary.Covered, report.Summary.TotalRequirements))
	fmt.Printf("Partial: %d (%.1f%%)\n", report.Summary.Partial, percentage(report.Summary.Partial, report.Summary.TotalRequirements))
	fmt.Printf("Missing: %d (%.1f%%)\n", report.Summary.Missing, percentage(report.Summary.Missing, report.Summary.TotalRequirements))
	fmt.Printf("Overall Coverage: %.1f%%\n", report.Summary.CoveragePercent)
	fmt.Println("---")
	fmt.Printf("P0 Gaps: %d\n", report.Summary.P0Gaps)
	fmt.Printf("P1 Gaps: %d\n", report.Summary.P1Gaps)
	fmt.Printf("P2 Gaps: %d\n", report.Summary.P2Gaps)
	fmt.Printf("P3 Gaps: %d\n", report.Summary.P3Gaps)
	fmt.Println("================================")
}

// generateOutputReports generates all requested output reports.
func generateOutputReports(report analyzer.AnalysisReport, config *Config, flags cliFlags) {
	reporterReport := convertToReporterReport(report)

	// Generate markdown report
	if flags.format == "all" || flags.format == "markdown" {
		mdPath := config.Output.Markdown
		if flags.outputPath != "" && flags.format == "markdown" {
			mdPath = flags.outputPath
		}

		if flags.verbose {
			fmt.Printf("Generating markdown report: %s\n", mdPath)
		}

		mdReporter := reporter.NewMarkdownReporter()
		if err := mdReporter.Generate(reporterReport, mdPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating markdown report: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ Markdown report: %s\n", mdPath)
	}

	// Generate JSON report
	if flags.format == "all" || flags.format == "json" {
		jsonPath := config.Output.JSON
		if flags.outputPath != "" && flags.format == "json" {
			jsonPath = flags.outputPath
		}

		if flags.verbose {
			fmt.Printf("Generating JSON report: %s\n", jsonPath)
		}

		jsonReporter := reporter.NewJSONReporter()
		if err := jsonReporter.Generate(reporterReport, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JSON report: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ JSON report: %s\n", jsonPath)
	}

	// Generate YAML report
	if flags.format == "all" || flags.format == "yaml" {
		yamlPath := config.Output.YAML
		if flags.outputPath != "" && flags.format == "yaml" {
			yamlPath = flags.outputPath
		}

		if flags.verbose {
			fmt.Printf("Generating YAML report: %s\n", yamlPath)
		}

		yamlReporter := reporter.NewYAMLReporter()
		if err := yamlReporter.Generate(reporterReport, yamlPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating YAML report: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ YAML report: %s\n", yamlPath)
	}

	// Generate coverage badge
	if flags.format == "all" || flags.format == "badge" {
		badgePath := config.Output.Badge
		if flags.outputPath != "" && flags.format == "badge" {
			badgePath = flags.outputPath
		}

		if flags.verbose {
			fmt.Printf("Generating coverage badge: %s\n", badgePath)
		}

		badgeReporter := reporter.NewBadgeReporter()
		if err := badgeReporter.Generate(reporterReport, badgePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating badge: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ Coverage badge: %s\n", badgePath)
	}

	// Save to history if configured
	if config.Output.History != "" {
		historyPath := filepath.Join(config.Output.History, fmt.Sprintf("%s.json", time.Now().Format("2006-01-02")))

		if err := os.MkdirAll(config.Output.History, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create history directory: %v\n", err)
		} else {
			jsonReporter := reporter.NewJSONReporter()
			if err := jsonReporter.Generate(reporterReport, historyPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save history: %v\n", err)
			} else {
				if flags.verbose {
					fmt.Printf("✓ History saved: %s\n", historyPath)
				}
			}
		}
	}
}

// checkThreshold validates coverage meets minimum threshold in check mode.
func checkThreshold(report analyzer.AnalysisReport, config *Config, customThreshold int) {
	minCoverage := config.Coverage.MinimumPercentage
	if customThreshold > 0 {
		minCoverage = customThreshold
	}

	if report.Summary.CoveragePercent < float64(minCoverage) {
		fmt.Fprintf(os.Stderr, "\n❌ FAILED: Coverage %.1f%% is below threshold %d%%\n",
			report.Summary.CoveragePercent, minCoverage)
		os.Exit(1)
	}

	if config.Coverage.FailOnP0Gaps && report.Summary.P0Gaps > 0 {
		fmt.Fprintf(os.Stderr, "\n❌ FAILED: Found %d P0 gaps\n", report.Summary.P0Gaps)
		os.Exit(1)
	}

	fmt.Printf("\n✓ PASSED: Coverage %.1f%% meets threshold %d%%\n",
		report.Summary.CoveragePercent, minCoverage)
}

// loadConfig loads the configuration file.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func percentage(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return (float64(part) / float64(total)) * 100.0
}

// Type conversion functions (to handle package-local type duplications)

func convertTests(tests []parser.Test) []analyzer.Test {
	result := make([]analyzer.Test, len(tests))
	for i, t := range tests {
		result[i] = analyzer.Test{
			Name:        t.Name,
			Package:     t.Package,
			File:        t.File,
			Line:        t.Line,
			Description: t.Description,
			Covers:      t.Covers,
			Keywords:    t.Keywords,
			Disabled:    t.Disabled,
		}
	}
	return result
}

func convertCoverages(coverages []parser.Coverage) []analyzer.Coverage {
	result := make([]analyzer.Coverage, len(coverages))
	for i, c := range coverages {
		result[i] = analyzer.Coverage{
			Requirement:  convertRequirement(c.Requirement),
			Tests:        convertTestsSlice(c.Tests),
			Status:       c.Status,
			CoverageRate: c.CoverageRate,
			Confidence:   c.Confidence,
		}
	}
	return result
}

func convertRequirement(r parser.Requirement) analyzer.Requirement {
	return analyzer.Requirement{
		ID:          r.ID,
		Category:    r.Category,
		Title:       r.Title,
		Description: r.Description,
		Priority:    r.Priority,
		Type:        r.Type,
		Keywords:    r.Keywords,
		SourceFile:  r.SourceFile,
		SourceLine:  r.SourceLine,
		Section:     r.Section,
	}
}

func convertTestsSlice(tests []parser.Test) []analyzer.Test {
	result := make([]analyzer.Test, len(tests))
	for i, t := range tests {
		result[i] = analyzer.Test{
			Name:        t.Name,
			Package:     t.Package,
			File:        t.File,
			Line:        t.Line,
			Description: t.Description,
			Covers:      t.Covers,
			Keywords:    t.Keywords,
			Disabled:    t.Disabled,
		}
	}
	return result
}

func convertToReporterReport(report analyzer.AnalysisReport) reporter.AnalysisReport {
	return reporter.AnalysisReport{
		Metadata:        convertMetadata(report.Metadata),
		Summary:         convertSummary(report.Summary),
		CategoryStats:   convertCategoryStats(report.CategoryStats),
		Coverages:       convertCoveragesToReporter(report.Coverages),
		CriticalGaps:    convertCoveragesToReporter(report.CriticalGaps),
		Recommendations: report.Recommendations,
	}
}

func convertMetadata(m analyzer.ReportMetadata) reporter.ReportMetadata {
	return reporter.ReportMetadata{
		GeneratedAt:       m.GeneratedAt,
		ToolVersion:       m.ToolVersion,
		RequirementsPath:  m.RequirementsPath,
		TestsPath:         m.TestsPath,
		TotalRequirements: m.TotalRequirements,
		TotalTests:        m.TotalTests,
		TotalTestFiles:    m.TotalTestFiles,
	}
}

func convertSummary(s analyzer.Summary) reporter.Summary {
	return reporter.Summary{
		TotalRequirements: s.TotalRequirements,
		Covered:           s.Covered,
		Partial:           s.Partial,
		Missing:           s.Missing,
		CoveragePercent:   s.CoveragePercent,
		P0Gaps:            s.P0Gaps,
		P1Gaps:            s.P1Gaps,
		P2Gaps:            s.P2Gaps,
		P3Gaps:            s.P3Gaps,
	}
}

func convertCategoryStats(stats []analyzer.CategoryStat) []reporter.CategoryStat {
	result := make([]reporter.CategoryStat, len(stats))
	for i, s := range stats {
		result[i] = reporter.CategoryStat{
			Category:        s.Category,
			Total:           s.Total,
			Covered:         s.Covered,
			Partial:         s.Partial,
			Missing:         s.Missing,
			CoveragePercent: s.CoveragePercent,
		}
	}
	return result
}

func convertCoveragesToReporter(coverages []analyzer.Coverage) []reporter.Coverage {
	result := make([]reporter.Coverage, len(coverages))
	for i, c := range coverages {
		result[i] = reporter.Coverage{
			Requirement:  convertRequirementToReporter(c.Requirement),
			Tests:        convertTestsToReporter(c.Tests),
			Status:       c.Status,
			CoverageRate: c.CoverageRate,
			Confidence:   c.Confidence,
		}
	}
	return result
}

func convertRequirementToReporter(r analyzer.Requirement) reporter.Requirement {
	return reporter.Requirement{
		ID:          r.ID,
		Category:    r.Category,
		Title:       r.Title,
		Description: r.Description,
		Priority:    r.Priority,
		Type:        r.Type,
		Keywords:    r.Keywords,
		SourceFile:  r.SourceFile,
		SourceLine:  r.SourceLine,
		Section:     r.Section,
	}
}

func convertTestsToReporter(tests []analyzer.Test) []reporter.Test {
	result := make([]reporter.Test, len(tests))
	for i, t := range tests {
		result[i] = reporter.Test{
			Name:        t.Name,
			Package:     t.Package,
			File:        t.File,
			Line:        t.Line,
			Description: t.Description,
			Covers:      t.Covers,
			Keywords:    t.Keywords,
			Disabled:    t.Disabled,
		}
	}
	return result
}

// filterReportForSummary filters the report to include only critical information
// for summary mode, reducing file size significantly.
func filterReportForSummary(report analyzer.AnalysisReport) analyzer.AnalysisReport {
	// Keep only P0 and P1 gaps (critical requirements)
	criticalGaps := make([]analyzer.Coverage, 0)
	for _, cov := range report.Coverages {
		req := cov.Requirement
		if (req.Priority == "P0" || req.Priority == "P1") && cov.Status != "COVERED" {
			// Strip detailed test information to reduce size
			cov.Tests = []analyzer.Test{} // Remove test details
			criticalGaps = append(criticalGaps, cov)
		}
	}

	// Return filtered report with only critical gaps and summary statistics
	return analyzer.AnalysisReport{
		Metadata:        report.Metadata,
		Summary:         report.Summary,
		CategoryStats:   report.CategoryStats,
		Coverages:       criticalGaps,           // Only P0/P1 gaps
		CriticalGaps:    report.CriticalGaps,    // Keep critical gaps
		Recommendations: report.Recommendations, // Keep recommendations
	}
}
