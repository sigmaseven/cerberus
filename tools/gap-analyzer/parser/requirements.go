package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Requirement represents a single requirement (imported from parent package)
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

// RequirementsParser parses requirement documents and extracts structured requirements.
type RequirementsParser struct {
	idPatterns       []*regexp.Regexp
	priorityKeywords map[string][]string
}

// NewRequirementsParser creates a new requirements parser with the given configuration.
func NewRequirementsParser(idPatterns []string, priorityKeywords map[string][]string) (*RequirementsParser, error) {
	compiledPatterns := make([]*regexp.Regexp, 0, len(idPatterns))
	for _, pattern := range idPatterns {
		// Add negative lookbehind to prevent "FR-API-001" matching inside "NFR-API-001"
		// Use (?:^|[^A-Z]) to ensure pattern starts at word boundary or after non-letter
		// This prevents substring matches while allowing pattern to match in various contexts
		// Wrap pattern in capturing group so we extract just the ID, not the prefix
		boundedPattern := `(?:^|[^A-Z-])(` + pattern + `)\b`
		re, err := regexp.Compile(boundedPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid requirement ID pattern %q: %w", pattern, err)
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	return &RequirementsParser{
		idPatterns:       compiledPatterns,
		priorityKeywords: priorityKeywords,
	}, nil
}

// ParseDirectory recursively parses all requirement documents in the given directory.
func (p *RequirementsParser) ParseDirectory(dir string, patterns []string) ([]Requirement, error) {
	var requirements []Requirement

	// Walk the directory tree
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file matches any pattern
		matched := false
		for _, pattern := range patterns {
			match, err := filepath.Match(pattern, filepath.Base(path))
			if err != nil {
				return fmt.Errorf("invalid file pattern %q: %w", pattern, err)
			}
			if match {
				matched = true
				break
			}
		}

		if !matched {
			return nil
		}

		// Parse the file
		reqs, err := p.ParseFile(path)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		requirements = append(requirements, reqs...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk requirements directory: %w", err)
	}

	return requirements, nil
}

// ParseFile parses a single requirement document.
func (p *RequirementsParser) ParseFile(filePath string) ([]Requirement, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var requirements []Requirement
	var currentSection string
	var currentReq *Requirement
	var descriptionLines []string

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Derive category from filename
	category := deriveCategoryFromFilename(filePath)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Track markdown sections (headings) and check for requirement IDs in them
		if strings.HasPrefix(trimmed, "#") {
			currentSection = strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			// Don't continue - check if heading contains a requirement ID
		}

		// Look for requirement IDs
		reqID := p.extractRequirementID(trimmed)
		if reqID != "" {
			// Save previous requirement if any
			if currentReq != nil {
				currentReq.Description = strings.TrimSpace(strings.Join(descriptionLines, " "))
				currentReq.Keywords = extractKeywords(currentReq.Description)
				requirements = append(requirements, *currentReq)
			}

			// Start new requirement
			currentReq = &Requirement{
				ID:         reqID,
				Category:   category,
				SourceFile: filePath,
				SourceLine: lineNum,
				Section:    currentSection,
				Title:      extractTitle(trimmed, reqID),
			}
			descriptionLines = []string{}
			continue
		}

		// Look for requirement type (MUST/SHOULD/MAY)
		if currentReq != nil && currentReq.Type == "" {
			reqType := extractRequirementType(trimmed)
			if reqType != "" {
				currentReq.Type = reqType
			}
		}

		// Accumulate description lines
		if currentReq != nil && trimmed != "" && !strings.HasPrefix(trimmed, "```") {
			// Extract priority if present in this line
			if currentReq.Priority == "" {
				priority := p.extractPriority(trimmed)
				if priority != "" {
					currentReq.Priority = priority
				}
			}
			descriptionLines = append(descriptionLines, trimmed)
		}
	}

	// Save last requirement
	if currentReq != nil {
		currentReq.Description = strings.TrimSpace(strings.Join(descriptionLines, " "))
		currentReq.Keywords = extractKeywords(currentReq.Description)
		requirements = append(requirements, *currentReq)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Post-process: infer priority for requirements that don't have explicit priority
	for i := range requirements {
		if requirements[i].Priority == "" {
			requirements[i].Priority = inferPriority(&requirements[i])
		}
	}

	return requirements, nil
}

// extractRequirementID extracts requirement IDs from a line (e.g., FR-API-001, NFR-PERF-005).
func (p *RequirementsParser) extractRequirementID(line string) string {
	for _, pattern := range p.idPatterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			// Return capture group 1 (the actual ID), not the full match
			return matches[1]
		}
	}
	return ""
}

// extractTitle extracts a title from the line containing the requirement ID.
func extractTitle(line, reqID string) string {
	// Remove markdown heading markers first
	title := strings.TrimLeft(line, "#")
	title = strings.TrimSpace(title)
	// Remove the requirement ID from the line
	title = strings.ReplaceAll(title, reqID, "")
	// Remove common prefixes
	title = strings.TrimPrefix(title, ":")
	title = strings.TrimPrefix(title, "-")
	title = strings.TrimSpace(title)
	return title
}

// extractRequirementType extracts MUST/SHOULD/MAY/SHALL from requirement text.
func extractRequirementType(line string) string {
	upperLine := strings.ToUpper(line)

	// Look for RFC 2119 keywords in ALL CAPS (which is the standard)
	if strings.Contains(upperLine, " MUST ") || strings.Contains(upperLine, " SHALL ") {
		return "MUST"
	}
	if strings.Contains(upperLine, " SHOULD ") {
		return "SHOULD"
	}
	if strings.Contains(upperLine, " MAY ") {
		return "MAY"
	}

	return ""
}

// extractPriority extracts priority indicators from a line.
func (p *RequirementsParser) extractPriority(line string) string {
	upperLine := strings.ToUpper(line)

	// Check for explicit priority markers
	priorityOrder := []string{"P0", "P1", "P2", "P3"}
	for _, priority := range priorityOrder {
		if strings.Contains(upperLine, priority) {
			return priority
		}
	}

	// Check for keyword-based priority
	for priority, keywords := range p.priorityKeywords {
		for _, keyword := range keywords {
			if strings.Contains(upperLine, strings.ToUpper(keyword)) {
				return priority
			}
		}
	}

	return ""
}

// extractKeywords extracts relevant keywords from requirement description for matching.
func extractKeywords(description string) []string {
	// Split on common delimiters
	words := strings.FieldsFunc(strings.ToLower(description), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_')
	})

	// Remove common stop words and keep relevant keywords
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true, "but": true,
		"is": true, "are": true, "was": true, "were": true, "be": true, "been": true,
		"have": true, "has": true, "had": true, "do": true, "does": true, "did": true,
		"will": true, "would": true, "should": true, "could": true, "may": true, "might": true,
		"must": true, "shall": true, "can": true, "this": true, "that": true, "these": true,
		"those": true, "to": true, "of": true, "in": true, "for": true, "on": true, "at": true,
		"by": true, "with": true, "from": true, "as": true, "into": true, "through": true,
	}

	keywords := make([]string, 0)
	seen := make(map[string]bool)

	for _, word := range words {
		// Skip stop words, short words, and duplicates
		if len(word) < 3 || stopWords[word] || seen[word] {
			continue
		}
		keywords = append(keywords, word)
		seen[word] = true
	}

	return keywords
}

// deriveCategoryFromFilename derives the requirement category from the filename.
func deriveCategoryFromFilename(filePath string) string {
	filename := filepath.Base(filePath)

	// Remove file extension
	name := strings.TrimSuffix(filename, filepath.Ext(filename))

	// Remove "-requirements" suffix if present
	name = strings.TrimSuffix(name, "-requirements")

	// Convert to title case
	parts := strings.Split(name, "-")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}

	return strings.Join(parts, " ")
}

// inferPriority infers priority based on requirement type and keywords when not explicitly stated.
func inferPriority(req *Requirement) string {
	// MUST requirements are at least P1 by default
	if req.Type == "MUST" || req.Type == "SHALL" {
		// Check for security/critical keywords
		desc := strings.ToLower(req.Description)
		criticalKeywords := []string{
			"security", "authentication", "authorization", "injection", "xss", "csrf",
			"critical", "compliance", "audit", "encryption", "sensitive", "privacy",
		}

		for _, keyword := range criticalKeywords {
			if strings.Contains(desc, keyword) {
				return "P0"
			}
		}

		return "P1"
	}

	// SHOULD requirements are typically P2
	if req.Type == "SHOULD" {
		return "P2"
	}

	// MAY requirements are typically P3
	if req.Type == "MAY" {
		return "P3"
	}

	// Default to P2 if we can't determine
	return "P2"
}
