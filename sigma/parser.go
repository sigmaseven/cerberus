package sigma

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Parser handles parsing SIGMA YAML files
type Parser struct {
	// Future: Add configuration options here
}

// NewParser creates a new SIGMA parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseDirectory parses all SIGMA YAML files in a directory
func (p *Parser) ParseDirectory(directory string) ([]*SigmaRule, error) {
	var rules []*SigmaRule

	// Walk the directory looking for .yml and .yaml files
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check for YAML extensions
		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		// Parse the file
		rule, err := p.ParseFile(path)
		if err != nil {
			// Log error but continue processing other files
			return nil // Don't stop on individual file errors
		}

		if rule != nil {
			rules = append(rules, rule)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return rules, nil
}

// ParseFile parses a single SIGMA YAML file
func (p *Parser) ParseFile(filePath string) (*SigmaRule, error) {
	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse YAML
	var rule SigmaRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Store the file path
	rule.FilePath = filePath
	rule.RawYAML = string(data)

	// Validate the rule
	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SIGMA rule: %w", err)
	}

	return &rule, nil
}

// ParseYAML parses SIGMA rule from YAML bytes
func (p *Parser) ParseYAML(data []byte) (*SigmaRule, error) {
	var rule SigmaRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	rule.RawYAML = string(data)

	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SIGMA rule: %w", err)
	}

	return &rule, nil
}
