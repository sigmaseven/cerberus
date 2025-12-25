package storage

import (
	"cerberus/core"
	"context"
)

// FeedRuleStorageAdapter adapts SQLiteRuleStorage to the interface expected by feeds.Manager
// The feeds manager expects a simpler interface with context-aware methods
type FeedRuleStorageAdapter struct {
	storage *SQLiteRuleStorage
}

// NewFeedRuleStorageAdapter creates an adapter for the feed manager
func NewFeedRuleStorageAdapter(storage *SQLiteRuleStorage) *FeedRuleStorageAdapter {
	return &FeedRuleStorageAdapter{storage: storage}
}

// CreateRule creates a rule (context is accepted but not used by underlying storage)
func (a *FeedRuleStorageAdapter) CreateRule(ctx context.Context, rule *core.Rule) error {
	return a.storage.CreateRule(rule)
}

// GetRuleByID retrieves a rule by ID
func (a *FeedRuleStorageAdapter) GetRuleByID(ctx context.Context, id string) (*core.Rule, error) {
	return a.storage.GetRule(id)
}

// UpdateRule updates an existing rule
func (a *FeedRuleStorageAdapter) UpdateRule(ctx context.Context, rule *core.Rule) error {
	return a.storage.UpdateRule(rule.ID, rule)
}
