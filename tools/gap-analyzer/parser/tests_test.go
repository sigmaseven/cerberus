package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestsParser_extractTestName(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "Standard test function",
			line:     "func TestAPIVersioning(t *testing.T) {",
			expected: "TestAPIVersioning",
		},
		{
			name:     "Benchmark function",
			line:     "func BenchmarkEventProcessing(b *testing.B) {",
			expected: "BenchmarkEventProcessing",
		},
		{
			name:     "Test with underscores",
			line:     "func TestAPI_SQLInjection_OWASPVectors(t *testing.T) {",
			expected: "TestAPI_SQLInjection_OWASPVectors",
		},
		{
			name:     "Not a test function",
			line:     "func processEvent(e Event) error {",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTestName(tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTestsParser_extractTestKeywords(t *testing.T) {
	tests := []struct {
		name     string
		testName string
		expected []string
	}{
		{
			name:     "CamelCase test name",
			testName: "TestAPIVersioning",
			expected: []string{"api", "versioning"},
		},
		{
			name:     "Underscore separated",
			testName: "TestAPI_SQLInjection_OWASPVectors",
			expected: []string{"api", "sql", "injection", "owasp", "vectors"},
		},
		{
			name:     "Mixed case with numbers",
			testName: "TestHTTP2Protocol",
			expected: []string{"http2", "protocol"}, // Numbers kept with adjacent letters, consecutive capitals split
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTestKeywords(tt.testName)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestTestsParser_splitCamelCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Simple camelCase",
			input:    "camelCase",
			expected: []string{"camel", "Case"},
		},
		{
			name:     "PascalCase",
			input:    "PascalCase",
			expected: []string{"Pascal", "Case"},
		},
		{
			name:     "All caps",
			input:    "API",
			expected: []string{"API"},
		},
		{
			name:     "Mixed",
			input:    "HTTPSConnection",
			expected: []string{"HTTPS", "Connection"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitCamelCase(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTestsParser_processComments(t *testing.T) {
	parser, err := NewTestsParser(
		[]string{"// Covers: ", "// Tests: ", "// REQUIREMENT: "},
		[]string{`FR-[A-Z]+-[0-9]+`, `NFR-[A-Z]+-[0-9]+`},
	)
	require.NoError(t, err)

	tests := []struct {
		name           string
		comments       []string
		expectedDesc   string
		expectedCovers []string
	}{
		{
			name: "Explicit coverage comment",
			comments: []string{
				"// Covers: FR-API-001, FR-API-002",
				"// This test validates API versioning",
			},
			expectedDesc:   "This test validates API versioning",
			expectedCovers: []string{"FR-API-001", "FR-API-002"},
		},
		{
			name: "REQUIREMENT prefix",
			comments: []string{
				"// REQUIREMENT: FR-AUTH-001 - User authentication",
				"// Tests login functionality",
			},
			expectedDesc:   "Tests login functionality",
			expectedCovers: []string{"FR-AUTH-001"},
		},
		{
			name: "Multiple coverage comments",
			comments: []string{
				"// Covers: FR-API-001",
				"// Tests: NFR-PERF-001",
				"// Description of the test",
			},
			expectedDesc:   "Description of the test",
			expectedCovers: []string{"FR-API-001", "NFR-PERF-001"},
		},
		{
			name: "No coverage comments",
			comments: []string{
				"// This is just a test description",
				"// It has no explicit requirement IDs",
			},
			expectedDesc:   "This is just a test description It has no explicit requirement IDs",
			expectedCovers: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc, covers := parser.processComments(tt.comments)
			assert.Equal(t, tt.expectedDesc, desc)
			assert.ElementsMatch(t, tt.expectedCovers, covers)
		})
	}
}

func TestTestsParser_ParseFile_Integration(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "sample_test.go")

	content := `package sample

import "testing"

// REQUIREMENT: FR-API-001
// This test validates API request handling
func TestAPIRequest(t *testing.T) {
	// test implementation
}

// Covers: FR-AUTH-001, FR-AUTH-002
// Tests authentication and authorization
func TestUserAuthentication(t *testing.T) {
	// test implementation
}

// No explicit coverage
func TestHelperFunction(t *testing.T) {
	// test implementation
}

// BenchmarkEventProcessing benchmarks event processing
func BenchmarkEventProcessing(b *testing.B) {
	// benchmark implementation
}
`

	err := os.WriteFile(testFile, []byte(content), 0644)
	require.NoError(t, err)

	// Parse the file
	parser, err := NewTestsParser(
		[]string{"// Covers: ", "// Tests: ", "// REQUIREMENT: "},
		[]string{`FR-[A-Z]+-[0-9]+`, `NFR-[A-Z]+-[0-9]+`},
	)
	require.NoError(t, err)

	tests, err := parser.ParseFile(testFile)
	require.NoError(t, err)

	// Verify parsed tests
	assert.Len(t, tests, 4)

	// Check TestAPIRequest
	apiTest := findTest(tests, "TestAPIRequest")
	require.NotNil(t, apiTest)
	assert.Equal(t, "TestAPIRequest", apiTest.Name)
	assert.Contains(t, apiTest.Covers, "FR-API-001")
	assert.Contains(t, apiTest.Description, "validates API request handling")
	assert.False(t, apiTest.Disabled)

	// Check TestUserAuthentication
	authTest := findTest(tests, "TestUserAuthentication")
	require.NotNil(t, authTest)
	assert.ElementsMatch(t, []string{"FR-AUTH-001", "FR-AUTH-002"}, authTest.Covers)

	// Check TestHelperFunction
	helperTest := findTest(tests, "TestHelperFunction")
	require.NotNil(t, helperTest)
	assert.Empty(t, helperTest.Covers)

	// Check BenchmarkEventProcessing
	benchTest := findTest(tests, "BenchmarkEventProcessing")
	require.NotNil(t, benchTest)
	assert.Equal(t, "BenchmarkEventProcessing", benchTest.Name)
}

func TestTestsParser_ParseFile_DisabledTests(t *testing.T) {
	// Create a temporary disabled test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "sample_test.go.disabled")

	content := `package sample

import "testing"

func TestDisabledTest(t *testing.T) {
	// test implementation
}
`

	err := os.WriteFile(testFile, []byte(content), 0644)
	require.NoError(t, err)

	// Parse the file
	parser, err := NewTestsParser(
		[]string{"// Covers: "},
		[]string{`FR-[A-Z]+-[0-9]+`},
	)
	require.NoError(t, err)

	tests, err := parser.ParseFile(testFile)
	require.NoError(t, err)

	// Verify test is marked as disabled
	assert.Len(t, tests, 1)
	assert.True(t, tests[0].Disabled)
}

func findTest(tests []Test, name string) *Test {
	for i := range tests {
		if tests[i].Name == name {
			return &tests[i]
		}
	}
	return nil
}
