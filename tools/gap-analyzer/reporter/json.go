package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// JSONReporter generates JSON-formatted gap analysis reports.
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// Generate generates a JSON report.
func (r *JSONReporter) Generate(report AnalysisReport, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// YAMLReporter generates YAML-formatted gap analysis reports.
type YAMLReporter struct{}

// NewYAMLReporter creates a new YAML reporter.
func NewYAMLReporter() *YAMLReporter {
	return &YAMLReporter{}
}

// Generate generates a YAML report.
func (r *YAMLReporter) Generate(report AnalysisReport, outputPath string) error {
	data, err := yaml.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML report: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write YAML report: %w", err)
	}

	return nil
}

// BadgeReporter generates coverage badge in shields.io JSON format.
type BadgeReporter struct{}

// NewBadgeReporter creates a new badge reporter.
func NewBadgeReporter() *BadgeReporter {
	return &BadgeReporter{}
}

// Badge represents a shields.io badge JSON schema.
type Badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

// Generate generates a coverage badge JSON file compatible with shields.io.
func (r *BadgeReporter) Generate(report AnalysisReport, outputPath string) error {
	// Determine badge color based on coverage percentage
	color := r.getBadgeColor(report.Summary.CoveragePercent)

	badge := Badge{
		SchemaVersion: 1,
		Label:         "test coverage",
		Message:       fmt.Sprintf("%.1f%%", report.Summary.CoveragePercent),
		Color:         color,
	}

	data, err := json.MarshalIndent(badge, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal badge JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write badge JSON: %w", err)
	}

	return nil
}

func (r *BadgeReporter) getBadgeColor(percent float64) string {
	if percent >= 80 {
		return "brightgreen"
	}
	if percent >= 60 {
		return "green"
	}
	if percent >= 40 {
		return "yellow"
	}
	if percent >= 20 {
		return "orange"
	}
	return "red"
}
