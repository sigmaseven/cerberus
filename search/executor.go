package search

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/util/goroutine"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

// QueryExecutor executes CQL queries against ClickHouse
// TASK 4.5: Query executor with pagination and total count
// TASK 4.6: Query optimization and safety limits
type QueryExecutor struct {
	conn          driver.Conn
	registry      *FieldTypeRegistry
	logger        *zap.SugaredLogger
	maxResultRows int           // Maximum result rows (default: 10000)
	queryTimeout  time.Duration // Query timeout (default: 5 seconds)
}

// QueryStats contains query execution statistics
// TASK 4.6: Query statistics for monitoring and optimization
type QueryStats struct {
	ExecutionTime time.Duration
	RowsScanned   int64
	BytesRead     int64
	Query         string
}

// NewQueryExecutor creates a new query executor
func NewQueryExecutor(conn driver.Conn, logger *zap.SugaredLogger) *QueryExecutor {
	return &QueryExecutor{
		conn:          conn,
		registry:      NewFieldTypeRegistry(),
		logger:        logger,
		maxResultRows: 10000,           // TASK 4.6: Max result limit
		queryTimeout:  5 * time.Second, // TASK 4.6: Query timeout
	}
}

// SetMaxResultRows sets the maximum number of result rows
// TASK 4.6: Configurable safety limit
func (e *QueryExecutor) SetMaxResultRows(maxRows int) {
	if maxRows > 0 && maxRows <= 100000 {
		e.maxResultRows = maxRows
	}
}

// SetQueryTimeout sets the query timeout
// TASK 4.6: Configurable query timeout
func (e *QueryExecutor) SetQueryTimeout(timeout time.Duration) {
	if timeout > 0 && timeout <= 60*time.Second {
		e.queryTimeout = timeout
	}
}

// QueryResult contains query execution results with pagination metadata
// TASK 4.5: Pagination support with total count and hasMore flag
// TASK 4.6: Query statistics for monitoring
type QueryResult struct {
	Events   []*core.Event
	Total    int64
	Limit    int
	Offset   int
	HasMore  bool
	Duration time.Duration
	Stats    *QueryStats // TASK 4.6: Query execution statistics
}

// Execute executes a CQL query and returns results with pagination
// TASK 4.5: Execute query with limit/offset and calculate total count
// TASK 4.6: Query optimization and safety limits with timeout
func (e *QueryExecutor) Execute(ctx context.Context, query string, opts QueryOptions) (*QueryResult, error) {
	start := time.Now()

	// TASK 4.6: Add query timeout to context
	ctx, cancel := context.WithTimeout(ctx, e.queryTimeout)
	defer cancel()

	// Parse CQL query
	parser := NewParser(query)
	ast, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse query: %w", err)
	}

	// Validate AST
	if err := ast.Validate(); err != nil {
		return nil, fmt.Errorf("invalid query: %w", err)
	}

	// TASK 4.6: Analyze query for expensive operations
	e.analyzeQuery(ast, query)

	// Translate AST to SQL
	translator := NewTranslator()
	sqlQuery, params, err := translator.TranslateAST(ast, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to translate query: %w", err)
	}

	// TASK 4.6: Optimize query (add PREWHERE, ensure ORDER BY)
	sqlQuery = e.optimizeQuery(sqlQuery, ast)

	// Validate query options
	if opts.Limit <= 0 {
		opts.Limit = 100 // Default limit
	}
	// TASK 4.6: Enforce max result limit
	if opts.Limit > e.maxResultRows {
		opts.Limit = e.maxResultRows
		e.logger.Warnf("Query limit (%d) exceeds maximum (%d), using maximum", opts.Limit, e.maxResultRows)
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	// Execute count and data queries in parallel
	var wg sync.WaitGroup
	var total int64
	var countErr error
	var events []*core.Event
	var dataErr error

	// Count query
	// TASK 147: Added panic recovery to parallel query execution
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer goroutine.Recover("cql-count-query", e.logger)
		total, countErr = e.executeCountQuery(ctx, ast, opts)
	}()

	// Data query
	// TASK 147: Added panic recovery to parallel query execution
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer goroutine.Recover("cql-data-query", e.logger)
		events, dataErr = e.executeDataQuery(ctx, sqlQuery, params)
	}()

	wg.Wait()

	if countErr != nil {
		return nil, fmt.Errorf("failed to count results: %w", countErr)
	}
	if dataErr != nil {
		return nil, fmt.Errorf("failed to execute query: %w", dataErr)
	}

	// Calculate hasMore
	hasMore := opts.Offset+opts.Limit < int(total)

	duration := time.Since(start)

	// TASK 4.6: Create query stats
	stats := &QueryStats{
		ExecutionTime: duration,
		RowsScanned:   total, // Approximate - actual rows scanned may differ
		BytesRead:     0,     // Would need EXPLAIN query to get actual bytes
		Query:         sqlQuery,
	}

	return &QueryResult{
		Events:   events,
		Total:    total,
		Limit:    opts.Limit,
		Offset:   opts.Offset,
		HasMore:  hasMore,
		Duration: duration,
		Stats:    stats,
	}, nil
}

// executeCountQuery executes a COUNT query to get total matching events
// TASK 4.5: Separate count query for total result count
func (e *QueryExecutor) executeCountQuery(ctx context.Context, ast *ASTNode, opts QueryOptions) (int64, error) {
	// Build count query using translator (same WHERE clause, but SELECT count(*))
	builder := NewSQLBuilder()
	builder.Select("count()").From("events")

	// Translate AST to get WHERE clause and params (without LIMIT/OFFSET)
	translator := NewTranslator()
	sqlQuery, params, err := translator.TranslateAST(ast, QueryOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to translate count query: %w", err)
	}

	// Extract WHERE clause from SQL query
	// SQL format: SELECT * FROM events WHERE ... ORDER BY ... LIMIT ...
	whereIdx := strings.Index(sqlQuery, " WHERE ")
	var paramCount int
	var whereClause string
	if whereIdx > 0 {
		// Find end of WHERE clause (ORDER BY or LIMIT or end)
		whereClause = sqlQuery[whereIdx+7:] // Skip " WHERE "

		// Remove ORDER BY if present
		orderIdx := strings.Index(whereClause, " ORDER BY ")
		if orderIdx > 0 {
			whereClause = whereClause[:orderIdx]
		}

		// Remove LIMIT if present
		limitIdx := strings.Index(whereClause, " LIMIT ")
		if limitIdx > 0 {
			whereClause = whereClause[:limitIdx]
		}

		// Count parameters needed for WHERE clause
		paramCount = strings.Count(whereClause, "?")

		// Add WHERE clause to count query
		if len(params) >= paramCount {
			// Only use params needed for WHERE clause (exclude time range params if any)
			builder.Where(whereClause, params[:paramCount]...)
		} else {
			builder.Where(whereClause, params...)
		}
	}

	// Add time range filtering
	if opts.StartTime != nil {
		if startTime, ok := opts.StartTime.(time.Time); ok && !startTime.IsZero() {
			builder.Where("timestamp >= ?", startTime)
		}
	}
	if opts.EndTime != nil {
		if endTime, ok := opts.EndTime.(time.Time); ok && !endTime.IsZero() {
			builder.Where("timestamp <= ?", endTime)
		}
	}

	countQuery, countParams := builder.Build()

	var count uint64
	err = e.conn.QueryRow(ctx, countQuery, countParams...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	return int64(count), nil
}

// executeDataQuery executes the data query and returns events
// TASK 4.5: Execute data query with LIMIT/OFFSET
func (e *QueryExecutor) executeDataQuery(ctx context.Context, sqlQuery string, params []interface{}) ([]*core.Event, error) {
	rows, err := e.conn.Query(ctx, sqlQuery, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	events := make([]*core.Event, 0)
	for rows.Next() {
		var event core.Event
		var fieldsData string
		var rawDataStr string // Scan into string, then convert to json.RawMessage

		err := rows.Scan(
			&event.EventID,
			&event.Timestamp,
			&event.IngestedAt,
			&event.ListenerID,
			&event.ListenerName,
			&event.Source,
			&event.SourceFormat,
			&rawDataStr,
			&fieldsData,
		)
		if err != nil {
			e.logger.Warnf("Failed to scan event: %v", err)
			continue
		}

		// Convert raw_data string to json.RawMessage
		event.RawData = json.RawMessage(rawDataStr)

		// Parse Fields JSON
		if fieldsData != "" {
			var fields map[string]interface{}
			if err := json.Unmarshal([]byte(fieldsData), &fields); err == nil {
				event.Fields = fields
			} else {
				e.logger.Warnf("Failed to parse fields JSON: %v", err)
			}
		}

		events = append(events, &event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return events, nil
}

// analyzeQuery analyzes query for expensive operations and logs warnings
// TASK 4.6: Detect expensive operations (regex on unindexed fields)
func (e *QueryExecutor) analyzeQuery(ast *ASTNode, query string) {
	if ast == nil {
		return
	}

	e.analyzeNode(ast)
}

// analyzeNode recursively analyzes AST node for expensive operations
func (e *QueryExecutor) analyzeNode(node *ASTNode) {
	if node == nil {
		return
	}

	switch node.Type {
	case NodeCondition:
		// Check for expensive operators on unindexed fields
		if node.Operator == "matches" || node.Operator == "~=" {
			// Regex operation detected
			fieldType := e.registry.DetectFieldType(node.Field)

			// Check if field is indexed
			indexedFields := []string{"timestamp", "source", "listener_id", "listener_name", "source_format"}
			isIndexed := false
			for _, indexed := range indexedFields {
				if node.Field == indexed {
					isIndexed = true
					break
				}
			}

			if !isIndexed && fieldType == FieldTypeUnknown {
				e.logger.Warnf("Query uses regex operator on potentially unindexed field '%s' - this may be slow", node.Field)
			}
		}

	case NodeLogical:
		if node.Left != nil {
			e.analyzeNode(node.Left)
		}
		if node.Right != nil {
			e.analyzeNode(node.Right)
		}

	case NodeGroup:
		for _, child := range node.Children {
			e.analyzeNode(child)
		}
	}
}

// optimizeQuery optimizes SQL query for ClickHouse
// TASK 4.6: Query optimization (PREWHERE, ORDER BY, etc.)
func (e *QueryExecutor) optimizeQuery(sqlQuery string, ast *ASTNode) string {
	// For now, ensure ORDER BY timestamp DESC is present for time-based queries
	// This is already handled by translator, but we can verify/enhance here

	// In the future, we could:
	// - Add PREWHERE clauses for high-cardinality filters
	// - Reorder WHERE conditions to put indexed fields first
	// - Add index hints

	return sqlQuery
}

// IndexedFields contains list of indexed fields in ClickHouse events table
// TASK 4.6: Indexed fields for query optimization
var IndexedFields = []string{
	"timestamp",
	"source",
	"listener_id",
	"listener_name",
	"source_format",
}

//lint:ignore U1000 Reserved for future query optimization - checks if field has ClickHouse index
func (e *QueryExecutor) isIndexedField(field string) bool {
	for _, indexed := range IndexedFields {
		if field == indexed {
			return true
		}
	}
	return false
}
