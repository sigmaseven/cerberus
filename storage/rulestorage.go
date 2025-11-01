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

var ErrRuleNotFound = errors.New("rule not found")

// RuleCursor interface for mocking
type RuleCursor interface {
	All(ctx context.Context, results interface{}) error
	Close(ctx context.Context) error
	Err() error
}

// RuleSingleResult interface for mocking
type RuleSingleResult interface {
	Decode(v interface{}) error
}

// RuleCollection interface for mocking
type RuleCollection interface {
	Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (RuleCursor, error)
	FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) RuleSingleResult
	InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error)
	UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error)
	DeleteOne(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error)
}

// mongoRuleCursor adapts *mongo.Cursor to RuleCursor
type mongoRuleCursor struct {
	*mongo.Cursor
}

func (m *mongoRuleCursor) All(ctx context.Context, results interface{}) error {
	return m.Cursor.All(ctx, results)
}

func (m *mongoRuleCursor) Close(ctx context.Context) error {
	return m.Cursor.Close(ctx)
}

func (m *mongoRuleCursor) Err() error {
	return m.Cursor.Err()
}

// mongoRuleSingleResult adapts *mongo.SingleResult to RuleSingleResult
type mongoRuleSingleResult struct {
	*mongo.SingleResult
}

func (m *mongoRuleSingleResult) Decode(v interface{}) error {
	return m.SingleResult.Decode(v)
}

// mongoRuleCollection adapts *mongo.Collection to RuleCollection
type mongoRuleCollection struct {
	*mongo.Collection
}

func (m *mongoRuleCollection) Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (RuleCursor, error) {
	cursor, err := m.Collection.Find(ctx, filter, opts...)
	if err != nil {
		return nil, err
	}
	return &mongoRuleCursor{Cursor: cursor}, nil
}

func (m *mongoRuleCollection) FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) RuleSingleResult {
	return &mongoRuleSingleResult{SingleResult: m.Collection.FindOne(ctx, filter, opts...)}
}

// RuleStorage handles rule persistence and retrieval
type RuleStorage struct {
	mongoDB   *MongoDB
	rulesColl RuleCollection
}

// NewRuleStorage creates a new rule storage handler
func NewRuleStorage(mongoDB *MongoDB) *RuleStorage {
	return &RuleStorage{
		mongoDB:   mongoDB,
		rulesColl: &mongoRuleCollection{Collection: mongoDB.Database.Collection("rules")},
	}
}

// GetRules retrieves all rules from the database
func (rs *RuleStorage) GetRules() ([]core.Rule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := rs.rulesColl.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to find rules: %w", err)
	}
	defer cursor.Close(ctx)

	rules := make([]core.Rule, 0)
	if err = cursor.All(ctx, &rules); err != nil {
		return nil, fmt.Errorf("failed to decode rules: %w", err)
	}

	return rules, nil
}

// GetRule retrieves a single rule by ID
func (rs *RuleStorage) GetRule(id string) (*core.Rule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var rule core.Rule
	err := rs.rulesColl.FindOne(ctx, bson.M{"_id": id}).Decode(&rule)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrRuleNotFound
		}
		return nil, fmt.Errorf("failed to find rule: %w", err)
	}

	return &rule, nil
}

// CreateRule inserts a new rule
func (rs *RuleStorage) CreateRule(rule *core.Rule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if rule with same ID exists
	existing, err := rs.GetRule(rule.ID)
	if err != nil && err != ErrRuleNotFound {
		return fmt.Errorf("failed to check existing rule: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("rule with ID %s already exists", rule.ID)
	}

	_, err = rs.rulesColl.InsertOne(ctx, rule)
	if err != nil {
		return fmt.Errorf("failed to insert rule: %w", err)
	}

	return nil
}

// UpdateRule updates an existing rule
func (rs *RuleStorage) UpdateRule(id string, rule *core.Rule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get current rule to increment version
	current, err := rs.GetRule(id)
	if err != nil {
		return err
	}

	rule.Version = current.Version + 1

	filter := bson.M{"_id": id}
	update := bson.M{"$set": rule}

	result, err := rs.rulesColl.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrRuleNotFound
	}

	return nil
}

// DeleteRule deletes a rule by ID
func (rs *RuleStorage) DeleteRule(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := rs.rulesColl.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	if result.DeletedCount == 0 {
		return ErrRuleNotFound
	}

	return nil
}

// EnsureIndexes creates necessary indexes for rules collection
func (rs *RuleStorage) EnsureIndexes() error {
	// _id is automatically indexed, no need for additional index
	return nil
}
