package storage

import (
	"context"
	"errors"
	"testing"

	"cerberus/core"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestCorrelationRuleStorage_GetCorrelationRules(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	expectedRules := []core.CorrelationRule{{ID: "1", Name: "test"}}

	mockCursor := NewMockCorrelationRuleCursor(ctrl)
	mockColl.EXPECT().Find(gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().All(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, results interface{}) error {
		rules := results.(*[]core.CorrelationRule)
		*rules = expectedRules
		return nil
	})
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	rules, err := crs.GetCorrelationRules()

	assert.NoError(t, err)
	assert.Equal(t, expectedRules, rules)
}

func TestCorrelationRuleStorage_GetCorrelationRules_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	mockColl.EXPECT().Find(gomock.Any(), gomock.Any()).Return(nil, errors.New("find error"))

	_, err := crs.GetCorrelationRules()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find correlation rules")
}

func TestCorrelationRuleStorage_GetCorrelationRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	expectedRule := &core.CorrelationRule{ID: "1", Name: "test"}

	mockSingleResult := NewMockCorrelationRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		rule := v.(*core.CorrelationRule)
		*rule = *expectedRule
		return nil
	})

	rule, err := crs.GetCorrelationRule("1")

	assert.NoError(t, err)
	assert.Equal(t, expectedRule, rule)
}

func TestCorrelationRuleStorage_GetCorrelationRule_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	mockSingleResult := NewMockCorrelationRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	_, err := crs.GetCorrelationRule("1")

	assert.Error(t, err)
	assert.Equal(t, ErrCorrelationRuleNotFound, err)
}

func TestCorrelationRuleStorage_CreateCorrelationRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	rule := &core.CorrelationRule{ID: "1", Name: "test"}

	// No existing rule
	mockSingleResult := NewMockCorrelationRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	mockColl.EXPECT().InsertOne(gomock.Any(), rule).Return(&mongo.InsertOneResult{}, nil)

	err := crs.CreateCorrelationRule(rule)

	assert.NoError(t, err)
}

func TestCorrelationRuleStorage_CreateCorrelationRule_AlreadyExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	rule := &core.CorrelationRule{ID: "1", Name: "test"}

	mockSingleResult := NewMockCorrelationRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		r := v.(*core.CorrelationRule)
		*r = *rule
		return nil
	})

	err := crs.CreateCorrelationRule(rule)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestCorrelationRuleStorage_UpdateCorrelationRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	currentRule := &core.CorrelationRule{ID: "1", Name: "old", Version: 1}
	updatedRule := &core.CorrelationRule{ID: "1", Name: "new"}

	mockSingleResult := NewMockCorrelationRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		r := v.(*core.CorrelationRule)
		*r = *currentRule
		return nil
	})

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 1}, nil)

	err := crs.UpdateCorrelationRule("1", updatedRule)

	assert.NoError(t, err)
	assert.Equal(t, 2, updatedRule.Version) // Version incremented
}

func TestCorrelationRuleStorage_UpdateCorrelationRule_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	mockSingleResult := NewMockCorrelationRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	err := crs.UpdateCorrelationRule("1", &core.CorrelationRule{})

	assert.Error(t, err)
	assert.Equal(t, ErrCorrelationRuleNotFound, err)
}

func TestCorrelationRuleStorage_DeleteCorrelationRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	mockColl.EXPECT().DeleteOne(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 1}, nil)

	err := crs.DeleteCorrelationRule("1")

	assert.NoError(t, err)
}

func TestCorrelationRuleStorage_DeleteCorrelationRule_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockCorrelationRuleCollection(ctrl)
	crs := &CorrelationRuleStorage{correlationRulesColl: mockColl}

	mockColl.EXPECT().DeleteOne(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 0}, nil)

	err := crs.DeleteCorrelationRule("1")

	assert.Error(t, err)
	assert.Equal(t, ErrCorrelationRuleNotFound, err)
}

func TestCorrelationRuleStorage_EnsureIndexes(t *testing.T) {
	crs := &CorrelationRuleStorage{}

	err := crs.EnsureIndexes()

	assert.NoError(t, err)
}
