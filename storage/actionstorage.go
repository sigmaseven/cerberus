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

// ErrActionNotFound is returned when an action is not found
var ErrActionNotFound = errors.New("action not found")

// ActionCursor interface for mocking
type ActionCursor interface {
	All(ctx context.Context, results interface{}) error
	Close(ctx context.Context) error
	Err() error
	Next(ctx context.Context) bool
	Decode(v interface{}) error
}

// ActionSingleResult interface for mocking
type ActionSingleResult interface {
	Decode(v interface{}) error
}

// ActionCollection interface for mocking
type ActionCollection interface {
	Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (ActionCursor, error)
	FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) ActionSingleResult
	InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error)
	UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error)
	DeleteOne(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error)
	Indexes() mongo.IndexView
}

// mongoActionCursor adapts *mongo.Cursor to ActionCursor
type mongoActionCursor struct {
	*mongo.Cursor
}

func (m *mongoActionCursor) All(ctx context.Context, results interface{}) error {
	return m.Cursor.All(ctx, results)
}

func (m *mongoActionCursor) Close(ctx context.Context) error {
	return m.Cursor.Close(ctx)
}

func (m *mongoActionCursor) Err() error {
	return m.Cursor.Err()
}

func (m *mongoActionCursor) Next(ctx context.Context) bool {
	return m.Cursor.Next(ctx)
}

func (m *mongoActionCursor) Decode(v interface{}) error {
	return m.Cursor.Decode(v)
}

// mongoActionSingleResult adapts *mongo.SingleResult to ActionSingleResult
type mongoActionSingleResult struct {
	*mongo.SingleResult
}

func (m *mongoActionSingleResult) Decode(v interface{}) error {
	return m.SingleResult.Decode(v)
}

// mongoActionCollection adapts *mongo.Collection to ActionCollection
type mongoActionCollection struct {
	*mongo.Collection
}

func (m *mongoActionCollection) Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (ActionCursor, error) {
	cursor, err := m.Collection.Find(ctx, filter, opts...)
	if err != nil {
		return nil, err
	}
	return &mongoActionCursor{Cursor: cursor}, nil
}

func (m *mongoActionCollection) FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) ActionSingleResult {
	return &mongoActionSingleResult{SingleResult: m.Collection.FindOne(ctx, filter, opts...)}
}

func (m *mongoActionCollection) Indexes() mongo.IndexView {
	return m.Collection.Indexes()
}

// ActionStorage handles action persistence and retrieval
type ActionStorage struct {
	mongoDB     *MongoDB
	actionsColl ActionCollection
}

// NewActionStorage creates a new action storage handler
func NewActionStorage(mongoDB *MongoDB) *ActionStorage {
	return &ActionStorage{
		mongoDB:     mongoDB,
		actionsColl: &mongoActionCollection{Collection: mongoDB.Database.Collection("actions")},
	}
}

// GetActions retrieves all actions from the database
func (as *ActionStorage) GetActions() ([]core.Action, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := as.actionsColl.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to find actions: %w", err)
	}
	defer cursor.Close(ctx)

	actions := make([]core.Action, 0)
	if err = cursor.All(ctx, &actions); err != nil {
		return nil, fmt.Errorf("failed to decode actions: %w", err)
	}

	return actions, nil
}

// GetAction retrieves a single action by ID
func (as *ActionStorage) GetAction(id string) (*core.Action, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var action core.Action
	err := as.actionsColl.FindOne(ctx, bson.M{"_id": id}).Decode(&action)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrActionNotFound
		}
		return nil, fmt.Errorf("failed to find action: %w", err)
	}

	return &action, nil
}

// CreateAction inserts a new action
func (as *ActionStorage) CreateAction(action *core.Action) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if action with same ID exists
	existing, _ := as.GetAction(action.ID)
	if existing != nil {
		return fmt.Errorf("action with ID %s already exists", action.ID)
	}

	_, err := as.actionsColl.InsertOne(ctx, action)
	if err != nil {
		return fmt.Errorf("failed to insert action: %w", err)
	}

	return nil
}

// UpdateAction updates an existing action
func (as *ActionStorage) UpdateAction(id string, action *core.Action) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": id}
	update := bson.M{"$set": action}

	result, err := as.actionsColl.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update action: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrActionNotFound
	}

	return nil
}

// DeleteAction deletes an action by ID
func (as *ActionStorage) DeleteAction(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := as.actionsColl.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete action: %w", err)
	}

	if result.DeletedCount == 0 {
		return ErrActionNotFound
	}

	return nil
}

// EnsureIndexes creates necessary indexes for actions collection
func (as *ActionStorage) EnsureIndexes() error {
	// _id is automatically indexed, no need for additional index
	return nil
}
