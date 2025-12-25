package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSQLBuilder_BasicQuery tests basic SELECT query construction
func TestSQLBuilder_BasicQuery(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.Select("*").From("events").Build()

	expected := "SELECT * FROM events"
	assert.Equal(t, expected, query)
	assert.Empty(t, params, "Basic query should have no parameters")
}

// TestSQLBuilder_SelectFields tests SELECT with specific fields
func TestSQLBuilder_SelectFields(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.Select("id", "timestamp", "source_ip").From("events").Build()

	expected := "SELECT id, timestamp, source_ip FROM events"
	assert.Equal(t, expected, query)
	assert.Empty(t, params)
}

// TestSQLBuilder_WhereClause tests WHERE clause with parameters
func TestSQLBuilder_WhereClause(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Where("source_ip = ?", "192.168.1.100").
		Build()

	expected := "SELECT * FROM events WHERE source_ip = ?"
	assert.Equal(t, expected, query)
	require.Len(t, params, 1)
	assert.Equal(t, "192.168.1.100", params[0])
}

// TestSQLBuilder_MultipleWhereClauses tests multiple WHERE conditions
func TestSQLBuilder_MultipleWhereClauses(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Where("source_ip = ?", "192.168.1.100").
		Where("port > ?", 1024).
		Where("severity = ?", "High").
		Build()

	expected := "SELECT * FROM events WHERE source_ip = ? AND port > ? AND severity = ?"
	assert.Equal(t, expected, query)
	require.Len(t, params, 3)
	assert.Equal(t, "192.168.1.100", params[0])
	assert.Equal(t, 1024, params[1])
	assert.Equal(t, "High", params[2])
}

// TestSQLBuilder_AndClause tests AND clause (equivalent to Where)
func TestSQLBuilder_AndClause(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Where("source_ip = ?", "192.168.1.100").
		And("port > ?", 1024).
		Build()

	expected := "SELECT * FROM events WHERE source_ip = ? AND port > ?"
	assert.Equal(t, expected, query)
	require.Len(t, params, 2)
}

// TestSQLBuilder_OrClause tests OR clause
func TestSQLBuilder_OrClause(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Where("source_ip = ?", "192.168.1.100").
		Or("source_ip = ?", "10.0.0.1").
		Build()

	expected := "SELECT * FROM events WHERE (source_ip = ?) OR (source_ip = ?)"
	assert.Equal(t, expected, query)
	require.Len(t, params, 2)
	assert.Equal(t, "192.168.1.100", params[0])
	assert.Equal(t, "10.0.0.1", params[1])
}

// TestSQLBuilder_NotClause tests NOT clause
func TestSQLBuilder_NotClause(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Where("source_ip = ?", "192.168.1.100").
		Not().
		Build()

	expected := "SELECT * FROM events WHERE NOT (source_ip = ?)"
	assert.Equal(t, expected, query)
	require.Len(t, params, 1)
}

// TestSQLBuilder_Limit tests LIMIT clause
func TestSQLBuilder_Limit(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Limit(100).
		Build()

	expected := "SELECT * FROM events LIMIT 100"
	assert.Equal(t, expected, query)
	assert.Empty(t, params)
}

// TestSQLBuilder_Offset tests OFFSET clause
func TestSQLBuilder_Offset(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Offset(50).
		Build()

	expected := "SELECT * FROM events OFFSET 50"
	assert.Equal(t, expected, query)
	assert.Empty(t, params)
}

// TestSQLBuilder_LimitOffset tests LIMIT and OFFSET together
func TestSQLBuilder_LimitOffset(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Limit(100).
		Offset(50).
		Build()

	expected := "SELECT * FROM events LIMIT 100 OFFSET 50"
	assert.Equal(t, expected, query)
	assert.Empty(t, params)
}

// TestSQLBuilder_OrderBy tests ORDER BY clause
func TestSQLBuilder_OrderBy(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		OrderBy("timestamp", "DESC").
		Build()

	expected := "SELECT * FROM events ORDER BY timestamp DESC"
	assert.Equal(t, expected, query)
	assert.Empty(t, params)
}

// TestSQLBuilder_ComplexQuery tests a complex query with all clauses
func TestSQLBuilder_ComplexQuery(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("id", "timestamp", "source_ip", "severity").
		From("events").
		Where("source_ip = ?", "192.168.1.100").
		Where("port > ?", 1024).
		OrderBy("timestamp", "DESC").
		Limit(100).
		Offset(50).
		Build()

	expected := "SELECT id, timestamp, source_ip, severity FROM events WHERE source_ip = ? AND port > ? ORDER BY timestamp DESC LIMIT 100 OFFSET 50"
	assert.Equal(t, expected, query)
	require.Len(t, params, 2)
	assert.Equal(t, "192.168.1.100", params[0])
	assert.Equal(t, 1024, params[1])
}

// TestSQLBuilder_ParameterOrdering tests that parameters are in correct order
func TestSQLBuilder_ParameterOrdering(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.
		Select("*").
		From("events").
		Where("source_ip = ?", "192.168.1.100").
		Where("port > ?", 1024).
		Where("severity = ?", "High").
		Where("event_type = ?", "auth_failure").
		Build()

	// Verify SQL has correct number of placeholders
	assert.Contains(t, query, "source_ip = ?")
	assert.Contains(t, query, "port > ?")
	assert.Contains(t, query, "severity = ?")
	assert.Contains(t, query, "event_type = ?")

	// Verify parameter order matches WHERE clause order
	require.Len(t, params, 4)
	assert.Equal(t, "192.168.1.100", params[0])
	assert.Equal(t, 1024, params[1])
	assert.Equal(t, "High", params[2])
	assert.Equal(t, "auth_failure", params[3])
}

// TestSQLBuilder_EscapeIdentifier tests identifier escaping
func TestSQLBuilder_EscapeIdentifier(t *testing.T) {
	builder := NewSQLBuilder()

	// Test normal identifier (no escaping needed)
	query, _ := builder.Select("normal_field").From("events").Build()
	assert.Contains(t, query, "normal_field")

	// Test identifier with dot (nested field)
	query, _ = builder.Reset().Select("user.name").From("events").Build()
	assert.Contains(t, query, "user.name")

	// Test identifier with backtick (should be escaped)
	builder2 := NewSQLBuilder()
	query2, _ := builder2.Select("`test`").From("events").Build()
	// Should escape backticks in identifier
	assert.Contains(t, query2, "`")
}

// TestSQLBuilder_AggregateFunctions tests that SQL aggregate functions are not escaped
func TestSQLBuilder_AggregateFunctions(t *testing.T) {
	tests := []struct {
		name     string
		selectFn string
		expected string
	}{
		{"count()", "count()", "SELECT count() FROM events"},
		{"count(*)", "count(*)", "SELECT count(*) FROM events"},
		{"COUNT() uppercase", "COUNT()", "SELECT COUNT() FROM events"},
		{"sum(field)", "sum(amount)", "SELECT sum(amount) FROM events"},
		{"avg(field)", "avg(value)", "SELECT avg(value) FROM events"},
		{"min(field)", "min(timestamp)", "SELECT min(timestamp) FROM events"},
		{"max(field)", "max(timestamp)", "SELECT max(timestamp) FROM events"},
		{"uniq(field)", "uniq(user_id)", "SELECT uniq(user_id) FROM events"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewSQLBuilder()
			query, _ := builder.Select(tt.selectFn).From("events").Build()
			assert.Equal(t, tt.expected, query, "Aggregate function should not be escaped with backticks")
		})
	}
}

// TestSQLBuilder_Reset tests builder reset
func TestSQLBuilder_Reset(t *testing.T) {
	builder := NewSQLBuilder()
	builder.Select("id").From("events").Where("source_ip = ?", "192.168.1.100").Limit(100)

	// Reset and build new query
	query, params := builder.Reset().Select("*").From("events").Build()

	expected := "SELECT * FROM events"
	assert.Equal(t, expected, query)
	assert.Empty(t, params, "Reset builder should have no parameters")
}

// TestSQLBuilder_SQLInjectionPrevention tests that parameterization prevents SQL injection
func TestSQLBuilder_SQLInjectionPrevention(t *testing.T) {
	builder := NewSQLBuilder()

	// Attempt SQL injection via parameter
	maliciousInput := "'; DROP TABLE events; --"
	query, params := builder.
		Select("*").
		From("events").
		Where("source_ip = ?", maliciousInput).
		Build()

	// Query should still have parameterized placeholder
	expected := "SELECT * FROM events WHERE source_ip = ?"
	assert.Equal(t, expected, query, "Query should use parameterized placeholder")

	// Malicious input should be in params, not in query string
	require.Len(t, params, 1)
	assert.Equal(t, maliciousInput, params[0], "Malicious input should be in parameters, not query string")

	// Query string should NOT contain the malicious SQL
	assert.NotContains(t, query, "DROP TABLE", "Query string should not contain injected SQL")
}

// TestSQLBuilder_EmptyBuilder tests empty builder
func TestSQLBuilder_EmptyBuilder(t *testing.T) {
	builder := NewSQLBuilder()
	query, params := builder.Build()

	expected := "SELECT *"
	assert.Equal(t, expected, query)
	assert.Empty(t, params)
}
