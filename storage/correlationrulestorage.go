package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cerberus/core"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var ErrCorrelationRuleNotFound = errors.New("correlation rule not found")

// CorrelationRuleCursor interface for mocking
type CorrelationRuleCursor interface {
	All(ctx context.Context, results interface{}) error
	Close(ctx context.Context) error
	Err() error
	Next(ctx context.Context) bool
	Decode(v interface{}) error
}

// CorrelationRuleSingleResult interface for mocking
type CorrelationRuleSingleResult interface {
	Decode(v interface{}) error
}

// CorrelationRuleCollection interface for mocking
type CorrelationRuleCollection interface {
	Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (CorrelationRuleCursor, error)
	FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) CorrelationRuleSingleResult
	InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error)
	UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error)
	DeleteOne(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error)
}

// mongoCorrelationRuleCursor adapts *mongo.Cursor to CorrelationRuleCursor
type mongoCorrelationRuleCursor struct {
	*mongo.Cursor
}

func (m *mongoCorrelationRuleCursor) All(ctx context.Context, results interface{}) error {
	return m.Cursor.All(ctx, results)
}

func (m *mongoCorrelationRuleCursor) Close(ctx context.Context) error {
	return m.Cursor.Close(ctx)
}

func (m *mongoCorrelationRuleCursor) Err() error {
	return m.Cursor.Err()
}

func (m *mongoCorrelationRuleCursor) Next(ctx context.Context) bool {
	return m.Cursor.Next(ctx)
}

func (m *mongoCorrelationRuleCursor) Decode(v interface{}) error {
	return m.Cursor.Decode(v)
}

// mongoCorrelationRuleSingleResult adapts *mongo.SingleResult to CorrelationRuleSingleResult
type mongoCorrelationRuleSingleResult struct {
	*mongo.SingleResult
}

func (m *mongoCorrelationRuleSingleResult) Decode(v interface{}) error {
	return m.SingleResult.Decode(v)
}

// mongoCorrelationRuleCollection adapts *mongo.Collection to CorrelationRuleCollection
type mongoCorrelationRuleCollection struct {
	*mongo.Collection
}

func (m *mongoCorrelationRuleCollection) Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (CorrelationRuleCursor, error) {
	cursor, err := m.Collection.Find(ctx, filter, opts...)
	if err != nil {
		return nil, err
	}
	return &mongoCorrelationRuleCursor{Cursor: cursor}, nil
}

func (m *mongoCorrelationRuleCollection) FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) CorrelationRuleSingleResult {
	return &mongoCorrelationRuleSingleResult{SingleResult: m.Collection.FindOne(ctx, filter, opts...)}
}

// CorrelationRuleStorage handles correlation rule persistence and retrieval
type CorrelationRuleStorage struct {
	mongoDB              *MongoDB
	correlationRulesColl CorrelationRuleCollection
}

// NewCorrelationRuleStorage creates a new correlation rule storage handler
func NewCorrelationRuleStorage(mongoDB *MongoDB) *CorrelationRuleStorage {
	return &CorrelationRuleStorage{
		mongoDB:              mongoDB,
		correlationRulesColl: &mongoCorrelationRuleCollection{Collection: mongoDB.Database.Collection("correlation_rules")},
	}
}

// GetCorrelationRules retrieves all correlation rules from the database
func (crs *CorrelationRuleStorage) GetCorrelationRules() ([]core.CorrelationRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := crs.correlationRulesColl.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to find correlation rules: %w", err)
	}
	defer cursor.Close(ctx)

	rules := make([]core.CorrelationRule, 0)
	if err = cursor.All(ctx, &rules); err != nil {
		return nil, fmt.Errorf("failed to decode correlation rules: %w", err)
	}

	return rules, nil
}

// GetCorrelationRule retrieves a single correlation rule by ID
func (crs *CorrelationRuleStorage) GetCorrelationRule(id string) (*core.CorrelationRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var rule core.CorrelationRule
	err := crs.correlationRulesColl.FindOne(ctx, bson.M{"_id": id}).Decode(&rule)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrCorrelationRuleNotFound
		}
		return nil, fmt.Errorf("failed to find correlation rule: %w", err)
	}

	return &rule, nil
}

// CreateCorrelationRule inserts a new correlation rule
func (crs *CorrelationRuleStorage) CreateCorrelationRule(rule *core.CorrelationRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if rule with same ID exists
	existing, _ := crs.GetCorrelationRule(rule.ID)
	if existing != nil {
		return fmt.Errorf("correlation rule with ID %s already exists", rule.ID)
	}

	_, err := crs.correlationRulesColl.InsertOne(ctx, rule)
	if err != nil {
		return fmt.Errorf("failed to insert correlation rule: %w", err)
	}

	return nil
}

// UpdateCorrelationRule updates an existing correlation rule
func (crs *CorrelationRuleStorage) UpdateCorrelationRule(id string, rule *core.CorrelationRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get current rule to increment version
	current, err := crs.GetCorrelationRule(id)
	if err != nil {
		return err
	}

	rule.Version = current.Version + 1

	filter := bson.M{"_id": id}
	update := bson.M{"$set": rule}

	result, err := crs.correlationRulesColl.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update correlation rule: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrCorrelationRuleNotFound
	}

	return nil
}

// DeleteCorrelationRule deletes a correlation rule by ID
func (crs *CorrelationRuleStorage) DeleteCorrelationRule(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := crs.correlationRulesColl.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete correlation rule: %w", err)
	}

	if result.DeletedCount == 0 {
		return ErrCorrelationRuleNotFound
	}

	return nil
}

// EnsureIndexes creates necessary indexes for correlation rules collection
func (crs *CorrelationRuleStorage) EnsureIndexes() error {
	// _id is automatically indexed, no need for additional index
	return nil
}
