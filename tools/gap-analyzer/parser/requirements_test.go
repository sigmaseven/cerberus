package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirementsParser_extractRequirementID(t *testing.T) {
	parser, err := NewRequirementsParser(
		[]string{`FR-[A-Z]+-[0-9]+`, `NFR-[A-Z]+-[0-9]+`, `[A-Z]+-[0-9]+`},
		nil,
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "Functional requirement",
			line:     "### FR-API-001: Resource-Oriented URLs",
			expected: "FR-API-001",
		},
		{
			name:     "Non-functional requirement",
			line:     "NFR-PERF-005: System must handle 10,000 events per second",
			expected: "NFR-PERF-005",
		},
		{
			name:     "Simple pattern",
			line:     "ALERT-003: Alert Deduplication",
			expected: "ALERT-003",
		},
		{
			name:     "No requirement ID",
			line:     "This is just a regular line of text",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.extractRequirementID(tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequirementsParser_extractRequirementType(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "MUST requirement",
			line:     "The API MUST support JSON requests",
			expected: "MUST",
		},
		{
			name:     "SHALL requirement",
			line:     "The system SHALL validate all inputs",
			expected: "MUST", // SHALL maps to MUST
		},
		{
			name:     "SHOULD requirement",
			line:     "The system SHOULD log all errors",
			expected: "SHOULD",
		},
		{
			name:     "MAY requirement",
			line:     "The system MAY cache responses",
			expected: "MAY",
		},
		{
			name:     "No requirement type",
			line:     "This is a description without keywords",
			expected: "",
		},
		{
			name:     "Case insensitive",
			line:     "must be lowercase must",
			expected: "", // Must be uppercase per RFC 2119
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRequirementType(tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequirementsParser_extractKeywords(t *testing.T) {
	description := "The API must support JSON request and response validation with schema enforcement"
	keywords := extractKeywords(description)

	// Should extract meaningful keywords
	assert.Contains(t, keywords, "api")
	assert.Contains(t, keywords, "json")
	assert.Contains(t, keywords, "request")
	assert.Contains(t, keywords, "response")
	assert.Contains(t, keywords, "validation")
	assert.Contains(t, keywords, "schema")
	assert.Contains(t, keywords, "enforcement")

	// Should not contain stop words
	assert.NotContains(t, keywords, "the")
	assert.NotContains(t, keywords, "and")
	assert.NotContains(t, keywords, "with")
	assert.NotContains(t, keywords, "must")
}

func TestRequirementsParser_deriveCategoryFromFilename(t *testing.T) {
	tests := []struct {
		name     string
		filepath string
		expected string
	}{
		{
			name:     "API design requirements",
			filepath: "/path/to/api-design-requirements.md",
			expected: "Api Design",
		},
		{
			name:     "Single word",
			filepath: "/path/to/security-requirements.md",
			expected: "Security",
		},
		{
			name:     "Multiple hyphens",
			filepath: "/path/to/user-management-authentication-requirements.md",
			expected: "User Management Authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveCategoryFromFilename(tt.filepath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequirementsParser_inferPriority(t *testing.T) {
	tests := []struct {
		name     string
		req      Requirement
		expected string
	}{
		{
			name: "MUST with security keyword",
			req: Requirement{
				Type:        "MUST",
				Description: "The system must validate authentication credentials",
			},
			expected: "P0",
		},
		{
			name: "MUST without critical keyword",
			req: Requirement{
				Type:        "MUST",
				Description: "The API must return JSON responses",
			},
			expected: "P1",
		},
		{
			name: "SHOULD requirement",
			req: Requirement{
				Type:        "SHOULD",
				Description: "The system should cache frequently accessed data",
			},
			expected: "P2",
		},
		{
			name: "MAY requirement",
			req: Requirement{
				Type:        "MAY",
				Description: "The system may support multiple themes",
			},
			expected: "P3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferPriority(&tt.req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequirementsParser_ParseFile_Integration(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-requirements.md")

	content := `# Test Requirements

## Section 1: Authentication

### FR-AUTH-001: User Login
**Requirement**: The system MUST support user authentication.

This is a critical security requirement that ensures only authorized users can access the system.

### FR-AUTH-002: Password Complexity
**Requirement**: Passwords SHOULD meet complexity requirements.

P2 priority - recommended but not required.

## Section 2: Performance

### NFR-PERF-001: Response Time
The system MUST respond to requests within 200ms (P0 requirement).
`

	err := os.WriteFile(testFile, []byte(content), 0644)
	require.NoError(t, err)

	// Parse the file
	parser, err := NewRequirementsParser(
		[]string{`FR-[A-Z]+-[0-9]+`, `NFR-[A-Z]+-[0-9]+`},
		map[string][]string{
			"P0": {"CRITICAL", "SECURITY"},
			"P1": {"HIGH"},
			"P2": {"MEDIUM"},
		},
	)
	require.NoError(t, err)

	requirements, err := parser.ParseFile(testFile)
	require.NoError(t, err)

	// Verify parsed requirements
	assert.Len(t, requirements, 3)

	// Check FR-AUTH-001
	authReq := findRequirement(requirements, "FR-AUTH-001")
	require.NotNil(t, authReq)
	assert.Equal(t, "FR-AUTH-001", authReq.ID)
	assert.Equal(t, "Test", authReq.Category)
	assert.Equal(t, "User Login", authReq.Title)
	assert.Equal(t, "MUST", authReq.Type)
	assert.Equal(t, "P0", authReq.Priority) // Inferred from "MUST" + "security"
	assert.Contains(t, authReq.Keywords, "authentication")

	// Check FR-AUTH-002
	passReq := findRequirement(requirements, "FR-AUTH-002")
	require.NotNil(t, passReq)
	assert.Equal(t, "SHOULD", passReq.Type)
	assert.Equal(t, "P2", passReq.Priority)

	// Check NFR-PERF-001
	perfReq := findRequirement(requirements, "NFR-PERF-001")
	require.NotNil(t, perfReq)
	assert.Equal(t, "MUST", perfReq.Type)
	assert.Equal(t, "P0", perfReq.Priority)
}

func findRequirement(requirements []Requirement, id string) *Requirement {
	for i := range requirements {
		if requirements[i].ID == id {
			return &requirements[i]
		}
	}
	return nil
}
