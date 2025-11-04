package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// SavedSearch represents a saved search query
type SavedSearch struct {
	ID          string                 `json:"id" bson:"_id,omitempty"`
	UserID      string                 `json:"user_id" bson:"user_id"`
	Name        string                 `json:"name" bson:"name"`
	Description string                 `json:"description" bson:"description"`
	Query       string                 `json:"query" bson:"query"`
	TimeRange   *TimeRange             `json:"time_range,omitempty" bson:"time_range,omitempty"`
	Tags        []string               `json:"tags" bson:"tags"`
	IsDefault   bool                   `json:"is_default" bson:"is_default"`
	IsShared    bool                   `json:"is_shared" bson:"is_shared"`
	SharedWith  []string               `json:"shared_with" bson:"shared_with"`
	CreatedAt   time.Time              `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" bson:"updated_at"`
	LastUsed    *time.Time             `json:"last_used,omitempty" bson:"last_used,omitempty"`
	UseCount    int                    `json:"use_count" bson:"use_count"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// TimeRange represents a time range for queries
type TimeRange struct {
	Start time.Time `json:"start" bson:"start"`
	End   time.Time `json:"end" bson:"end"`
}

// SavedSearchStorage handles saved search persistence
type SavedSearchStorage struct {
	collection *mongo.Collection
}

// NewSavedSearchStorage creates a new saved search storage
func NewSavedSearchStorage(db *mongo.Database) *SavedSearchStorage {
	collection := db.Collection("saved_searches")

	// Create indexes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Index on user_id
	collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "user_id", Value: 1}},
	})

	// Unique index on user_id + name
	collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
			{Key: "name", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	})

	// Index on last_used for sorting
	collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "last_used", Value: -1}},
	})

	// Index on tags
	collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "tags", Value: 1}},
	})

	return &SavedSearchStorage{
		collection: collection,
	}
}

// Create creates a new saved search
func (s *SavedSearchStorage) Create(ctx context.Context, search *SavedSearch) error {
	// Generate ID if not provided
	if search.ID == "" {
		search.ID = primitive.NewObjectID().Hex()
	}

	// Set timestamps
	now := time.Now()
	search.CreatedAt = now
	search.UpdatedAt = now
	search.UseCount = 0

	// Insert
	_, err := s.collection.InsertOne(ctx, search)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("saved search with name '%s' already exists", search.Name)
		}
		return fmt.Errorf("failed to create saved search: %w", err)
	}

	return nil
}

// GetByID retrieves a saved search by ID
func (s *SavedSearchStorage) GetByID(ctx context.Context, id string) (*SavedSearch, error) {
	var search SavedSearch
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&search)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("saved search not found")
		}
		return nil, fmt.Errorf("failed to get saved search: %w", err)
	}

	return &search, nil
}

// GetByUser retrieves all saved searches for a user
func (s *SavedSearchStorage) GetByUser(ctx context.Context, userID string) ([]*SavedSearch, error) {
	filter := bson.M{
		"$or": []bson.M{
			{"user_id": userID},
			{"is_shared": true, "shared_with": userID},
		},
	}

	// Sort by last_used descending (most recently used first)
	opts := options.Find().SetSort(bson.D{{Key: "last_used", Value: -1}})

	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get saved searches: %w", err)
	}
	defer cursor.Close(ctx)

	var searches []*SavedSearch
	if err := cursor.All(ctx, &searches); err != nil {
		return nil, fmt.Errorf("failed to decode saved searches: %w", err)
	}

	return searches, nil
}

// GetByTags retrieves saved searches by tags
func (s *SavedSearchStorage) GetByTags(ctx context.Context, userID string, tags []string) ([]*SavedSearch, error) {
	filter := bson.M{
		"user_id": userID,
		"tags":    bson.M{"$in": tags},
	}

	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get saved searches by tags: %w", err)
	}
	defer cursor.Close(ctx)

	var searches []*SavedSearch
	if err := cursor.All(ctx, &searches); err != nil {
		return nil, fmt.Errorf("failed to decode saved searches: %w", err)
	}

	return searches, nil
}

// Update updates an existing saved search
func (s *SavedSearchStorage) Update(ctx context.Context, search *SavedSearch) error {
	search.UpdatedAt = time.Now()

	update := bson.M{
		"$set": bson.M{
			"name":        search.Name,
			"description": search.Description,
			"query":       search.Query,
			"time_range":  search.TimeRange,
			"tags":        search.Tags,
			"is_default":  search.IsDefault,
			"is_shared":   search.IsShared,
			"shared_with": search.SharedWith,
			"updated_at":  search.UpdatedAt,
			"metadata":    search.Metadata,
		},
	}

	result, err := s.collection.UpdateOne(
		ctx,
		bson.M{"_id": search.ID},
		update,
	)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("saved search with name '%s' already exists", search.Name)
		}
		return fmt.Errorf("failed to update saved search: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("saved search not found")
	}

	return nil
}

// Delete deletes a saved search
func (s *SavedSearchStorage) Delete(ctx context.Context, id string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete saved search: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("saved search not found")
	}

	return nil
}

// RecordUsage records that a saved search was used
func (s *SavedSearchStorage) RecordUsage(ctx context.Context, id string) error {
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"last_used": now,
		},
		"$inc": bson.M{
			"use_count": 1,
		},
	}

	_, err := s.collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		update,
	)
	if err != nil {
		return fmt.Errorf("failed to record usage: %w", err)
	}

	return nil
}

// GetDefault retrieves the default saved search for a user
func (s *SavedSearchStorage) GetDefault(ctx context.Context, userID string) (*SavedSearch, error) {
	var search SavedSearch
	err := s.collection.FindOne(ctx, bson.M{
		"user_id":    userID,
		"is_default": true,
	}).Decode(&search)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // No default search
		}
		return nil, fmt.Errorf("failed to get default saved search: %w", err)
	}

	return &search, nil
}

// SetDefault sets a saved search as the default
func (s *SavedSearchStorage) SetDefault(ctx context.Context, userID string, id string) error {
	// First, unset any existing default
	_, err := s.collection.UpdateMany(
		ctx,
		bson.M{
			"user_id":    userID,
			"is_default": true,
		},
		bson.M{
			"$set": bson.M{
				"is_default": false,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to unset existing default: %w", err)
	}

	// Set the new default
	result, err := s.collection.UpdateOne(
		ctx,
		bson.M{
			"_id":     id,
			"user_id": userID,
		},
		bson.M{
			"$set": bson.M{
				"is_default": true,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to set default: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("saved search not found or not owned by user")
	}

	return nil
}
