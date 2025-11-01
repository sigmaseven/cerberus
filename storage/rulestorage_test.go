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

func TestRuleStorage_EnsureIndexes(t *testing.T) {
	rs := &RuleStorage{}

	err := rs.EnsureIndexes()

	assert.NoError(t, err)
}

func TestRuleStorage_GetRules(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	expectedRules := []core.Rule{{ID: "1", Name: "test"}}

	mockCursor := NewMockRuleCursor(ctrl)
	mockColl.EXPECT().Find(gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().All(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, results interface{}) error {
		rules := results.(*[]core.Rule)
		*rules = expectedRules
		return nil
	})
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	rules, err := rs.GetRules()

	assert.NoError(t, err)
	assert.Equal(t, expectedRules, rules)
}

func TestRuleStorage_GetRules_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	mockColl.EXPECT().Find(gomock.Any(), gomock.Any()).Return(nil, errors.New("find error"))

	_, err := rs.GetRules()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find rules")
}

func TestRuleStorage_GetRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	expectedRule := &core.Rule{ID: "1", Name: "test"}

	mockSingleResult := NewMockRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		rule := v.(*core.Rule)
		*rule = *expectedRule
		return nil
	})

	rule, err := rs.GetRule("1")

	assert.NoError(t, err)
	assert.Equal(t, expectedRule, rule)
}

func TestRuleStorage_GetRule_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	mockSingleResult := NewMockRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	_, err := rs.GetRule("1")

	assert.Error(t, err)
	assert.Equal(t, ErrRuleNotFound, err)
}

func TestRuleStorage_CreateRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	rule := &core.Rule{ID: "1", Name: "test"}

	// No existing rule
	mockSingleResult := NewMockRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	mockColl.EXPECT().InsertOne(gomock.Any(), rule).Return(&mongo.InsertOneResult{}, nil)

	err := rs.CreateRule(rule)

	assert.NoError(t, err)
}

func TestRuleStorage_CreateRule_AlreadyExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	rule := &core.Rule{ID: "1", Name: "test"}

	mockSingleResult := NewMockRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		r := v.(*core.Rule)
		*r = *rule
		return nil
	})

	err := rs.CreateRule(rule)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestRuleStorage_UpdateRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	currentRule := &core.Rule{ID: "1", Name: "old", Version: 1}
	updatedRule := &core.Rule{ID: "1", Name: "new"}

	mockSingleResult := NewMockRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		r := v.(*core.Rule)
		*r = *currentRule
		return nil
	})

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 1}, nil)

	err := rs.UpdateRule("1", updatedRule)

	assert.NoError(t, err)
	assert.Equal(t, 2, updatedRule.Version) // Version incremented
}

func TestRuleStorage_UpdateRule_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	mockSingleResult := NewMockRuleSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	err := rs.UpdateRule("1", &core.Rule{})

	assert.Error(t, err)
	assert.Equal(t, ErrRuleNotFound, err)
}

func TestRuleStorage_DeleteRule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	mockColl.EXPECT().DeleteOne(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 1}, nil)

	err := rs.DeleteRule("1")

	assert.NoError(t, err)
}

func TestRuleStorage_DeleteRule_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockRuleCollection(ctrl)
	rs := &RuleStorage{rulesColl: mockColl}

	mockColl.EXPECT().DeleteOne(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 0}, nil)

	err := rs.DeleteRule("1")

	assert.Error(t, err)
	assert.Equal(t, ErrRuleNotFound, err)
}
