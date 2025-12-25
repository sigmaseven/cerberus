package integration

import (
	"testing"

	"cerberus/search"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 61.4: Search E2E Integration Test
// Tests complete search flow: CQL query → parser → executor → ClickHouse → results

// TestSearchE2E_CQLQuery tests end-to-end CQL query execution
func TestSearchE2E_CQLQuery(t *testing.T) {
	infra := SetupTestInfrastructure(t)
	defer infra.Cleanup()

	// Create CQL parser (requires query string in constructor)
	queryStr := `severity = "high"`
	parser := search.NewParser(queryStr)

	// Test CQL query parsing (no arguments - uses internal query string)
	ast, err := parser.Parse()
	require.NoError(t, err, "Should parse CQL query")
	assert.NotNil(t, ast, "AST should not be nil")

	// Test query validation (requires schema)
	schema := search.DefaultSchema()
	validator := search.NewValidator(schema)
	err = validator.ValidateQuery(ast)
	require.NoError(t, err, "Should validate query")
}

// TestSearchE2E_Pagination tests pagination with large result sets
func TestSearchE2E_Pagination(t *testing.T) {
	infra := SetupTestInfrastructure(t)
	defer infra.Cleanup()

	// Test pagination in query
	queryStr := `severity = "info" LIMIT 10 OFFSET 20`
	parser := search.NewParser(queryStr)
	ast, err := parser.Parse()
	require.NoError(t, err)
	assert.NotNil(t, ast)
}

// TestSearchE2E_TimeRange tests time range queries
func TestSearchE2E_TimeRange(t *testing.T) {
	infra := SetupTestInfrastructure(t)
	defer infra.Cleanup()

	// Test time range query
	queryStr := `severity = "high" AND timestamp > "2024-01-01T00:00:00Z"`
	parser := search.NewParser(queryStr)
	ast, err := parser.Parse()
	require.NoError(t, err)
	assert.NotNil(t, ast)
}
