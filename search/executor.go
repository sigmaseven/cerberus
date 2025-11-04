package search

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Executor executes parsed queries against the database
type Executor struct {
	db *mongo.Database
}

// NewExecutor creates a new query executor
func NewExecutor(db *mongo.Database) *Executor {
	return &Executor{db: db}
}

// SearchRequest represents a search query request
type SearchRequest struct {
	Query     string                 `json:"query"`
	TimeRange *TimeRange             `json:"time_range,omitempty"`
	Page      int                    `json:"page"`
	Limit     int                    `json:"limit"`
	SortBy    string                 `json:"sort_by"`
	SortOrder string                 `json:"sort_order"`
	Fields    []string               `json:"fields,omitempty"`
	Params    map[string]interface{} `json:"params,omitempty"`
}

// TimeRange represents a time range filter
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// SearchResponse represents search results
type SearchResponse struct {
	Events        []bson.M   `json:"events"`
	Total         int64      `json:"total"`
	Page          int        `json:"page"`
	Limit         int        `json:"limit"`
	ExecutionTime float64    `json:"execution_time_ms"`
	Query         string     `json:"query"`
	TimeRange     *TimeRange `json:"time_range,omitempty"`
}

// Execute executes a search query
func (e *Executor) Execute(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	startTime := time.Now()

	// Parse query
	parser := NewParser(req.Query)
	ast, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// Validate AST
	if err := ast.Validate(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// Convert AST to MongoDB filter
	filter, err := e.astToMongoFilter(ast)
	if err != nil {
		return nil, fmt.Errorf("filter conversion error: %w", err)
	}

	// Apply time range filter
	if req.TimeRange != nil {
		timeFilter := bson.M{
			"timestamp": bson.M{
				"$gte": primitive.NewDateTimeFromTime(req.TimeRange.Start),
				"$lte": primitive.NewDateTimeFromTime(req.TimeRange.End),
			},
		}
		// Combine with existing filter
		if len(filter) > 0 {
			filter = bson.M{"$and": []bson.M{filter, timeFilter}}
		} else {
			filter = timeFilter
		}
	}

	// Count total results
	collection := e.db.Collection("events")
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("count error: %w", err)
	}

	// Build query options
	findOptions := options.Find()
	findOptions.SetSkip(int64((req.Page - 1) * req.Limit))
	findOptions.SetLimit(int64(req.Limit))

	// Sort
	sortField := "timestamp"
	sortOrder := -1 // descending by default
	if req.SortBy != "" {
		sortField = req.SortBy
	}
	if req.SortOrder == "asc" {
		sortOrder = 1
	}
	findOptions.SetSort(bson.D{{Key: sortField, Value: sortOrder}})

	// Project specific fields if requested
	if len(req.Fields) > 0 {
		projection := bson.M{}
		for _, field := range req.Fields {
			projection[field] = 1
		}
		findOptions.SetProjection(projection)
	}

	// Execute query
	cursor, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, fmt.Errorf("query execution error: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	var events []bson.M
	if err := cursor.All(ctx, &events); err != nil {
		return nil, fmt.Errorf("result decoding error: %w", err)
	}

	// Convert MongoDB dates to ISO strings for JSON serialization
	for i := range events {
		if ts, ok := events[i]["timestamp"].(primitive.DateTime); ok {
			events[i]["timestamp"] = ts.Time().Format(time.RFC3339)
		}
	}

	executionTime := time.Since(startTime).Seconds() * 1000 // ms

	return &SearchResponse{
		Events:        events,
		Total:         total,
		Page:          req.Page,
		Limit:         req.Limit,
		ExecutionTime: executionTime,
		Query:         req.Query,
		TimeRange:     req.TimeRange,
	}, nil
}

// astToMongoFilter converts an AST to a MongoDB filter
func (e *Executor) astToMongoFilter(node *ASTNode) (bson.M, error) {
	if node == nil {
		return bson.M{}, nil
	}

	switch node.Type {
	case NodeCondition:
		return e.conditionToFilter(node)
	case NodeLogical:
		return e.logicalToFilter(node)
	case NodeGroup:
		if len(node.Children) > 0 {
			return e.astToMongoFilter(node.Children[0])
		}
		return bson.M{}, nil
	default:
		return nil, fmt.Errorf("unknown node type")
	}
}

// conditionToFilter converts a condition node to MongoDB filter
func (e *Executor) conditionToFilter(node *ASTNode) (bson.M, error) {
	field := node.Field
	operator := node.Operator
	value := node.Value

	// Special handling for @timestamp field
	if field == "@timestamp" {
		field = "timestamp"

		// If value is a time.Time, convert to primitive.DateTime
		if t, ok := value.(time.Time); ok {
			value = primitive.NewDateTimeFromTime(t)
		}
	}

	switch operator {
	case "=", "equals":
		return bson.M{field: value}, nil
	case "!=", "not_equals":
		return bson.M{field: bson.M{"$ne": value}}, nil
	case ">", "gt":
		return bson.M{field: bson.M{"$gt": value}}, nil
	case "<", "lt":
		return bson.M{field: bson.M{"$lt": value}}, nil
	case ">=", "gte":
		return bson.M{field: bson.M{"$gte": value}}, nil
	case "<=", "lte":
		return bson.M{field: bson.M{"$lte": value}}, nil
	case "contains":
		// Case-insensitive substring search
		return bson.M{field: bson.M{"$regex": primitive.Regex{Pattern: fmt.Sprintf("%v", value), Options: "i"}}}, nil
	case "startswith":
		return bson.M{field: bson.M{"$regex": primitive.Regex{Pattern: fmt.Sprintf("^%v", value), Options: "i"}}}, nil
	case "endswith":
		return bson.M{field: bson.M{"$regex": primitive.Regex{Pattern: fmt.Sprintf("%v$", value), Options: "i"}}}, nil
	case "matches", "~=":
		return bson.M{field: bson.M{"$regex": primitive.Regex{Pattern: fmt.Sprintf("%v", value), Options: ""}}}, nil
	case "in":
		return bson.M{field: bson.M{"$in": value}}, nil
	case "not in":
		return bson.M{field: bson.M{"$nin": value}}, nil
	case "exists":
		return bson.M{field: bson.M{"$exists": true}}, nil
	case "not exists":
		return bson.M{field: bson.M{"$exists": false}}, nil
	default:
		return nil, fmt.Errorf("unsupported operator: %s", operator)
	}
}

// logicalToFilter converts a logical node to MongoDB filter
func (e *Executor) logicalToFilter(node *ASTNode) (bson.M, error) {
	switch node.Logic {
	case "AND":
		left, err := e.astToMongoFilter(node.Left)
		if err != nil {
			return nil, err
		}
		right, err := e.astToMongoFilter(node.Right)
		if err != nil {
			return nil, err
		}
		return bson.M{"$and": []bson.M{left, right}}, nil

	case "OR":
		left, err := e.astToMongoFilter(node.Left)
		if err != nil {
			return nil, err
		}
		right, err := e.astToMongoFilter(node.Right)
		if err != nil {
			return nil, err
		}
		return bson.M{"$or": []bson.M{left, right}}, nil

	case "NOT":
		left, err := e.astToMongoFilter(node.Left)
		if err != nil {
			return nil, err
		}
		return bson.M{"$nor": []bson.M{left}}, nil

	default:
		return nil, fmt.Errorf("unsupported logical operator: %s", node.Logic)
	}
}
