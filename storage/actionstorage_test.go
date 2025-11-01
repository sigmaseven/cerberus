package storage

import (
	"context"
	"testing"

	"cerberus/core"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestActionStorage_GetActions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	expectedActions := []core.Action{{ID: "1", Type: "test"}}

	mockCursor := NewMockActionCursor(ctrl)
	mockColl.EXPECT().Find(gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().All(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, results interface{}) error {
		actions := results.(*[]core.Action)
		*actions = expectedActions
		return nil
	})
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	actions, err := as.GetActions()

	assert.NoError(t, err)
	assert.Equal(t, expectedActions, actions)
}

func TestActionStorage_GetAction(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	expectedAction := &core.Action{ID: "1", Type: "test"}

	mockSingleResult := NewMockActionSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		action := v.(*core.Action)
		*action = *expectedAction
		return nil
	})

	action, err := as.GetAction("1")

	assert.NoError(t, err)
	assert.Equal(t, expectedAction, action)
}

func TestActionStorage_GetAction_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockSingleResult := NewMockActionSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	_, err := as.GetAction("1")

	assert.Error(t, err)
	assert.Equal(t, ErrActionNotFound, err)
}

func TestActionStorage_CreateAction(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	action := &core.Action{ID: "1", Type: "test"}

	// No existing action
	mockSingleResult := NewMockActionSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	mockColl.EXPECT().InsertOne(gomock.Any(), action).Return(&mongo.InsertOneResult{}, nil)

	err := as.CreateAction(action)

	assert.NoError(t, err)
}

func TestActionStorage_CreateAction_AlreadyExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	action := &core.Action{ID: "1", Type: "test"}

	// Existing action found
	mockSingleResult := NewMockActionSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		action := v.(*core.Action)
		*action = core.Action{ID: "1", Type: "existing"}
		return nil
	})

	err := as.CreateAction(action)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestActionStorage_UpdateAction(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	action := &core.Action{ID: "1", Type: "new"}

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 1}, nil)

	err := as.UpdateAction("1", action)

	assert.NoError(t, err)
}

func TestActionStorage_UpdateAction_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 0}, nil)

	err := as.UpdateAction("1", &core.Action{})

	assert.Error(t, err)
	assert.Equal(t, ErrActionNotFound, err)
}

func TestActionStorage_DeleteAction(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockColl.EXPECT().DeleteOne(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 1}, nil)

	err := as.DeleteAction("1")

	assert.NoError(t, err)
}

func TestActionStorage_DeleteAction_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockColl.EXPECT().DeleteOne(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 0}, nil)

	err := as.DeleteAction("1")

	assert.Error(t, err)
	assert.Equal(t, ErrActionNotFound, err)
}

func TestActionStorage_GetActions_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockColl.EXPECT().Find(gomock.Any(), gomock.Any()).Return(nil, mongo.ErrClientDisconnected)

	_, err := as.GetActions()

	assert.Error(t, err)
}

func TestActionStorage_GetAction_DecodeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockSingleResult := NewMockActionSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	_, err := as.GetAction("1")

	assert.Error(t, err)
	assert.Equal(t, ErrActionNotFound, err)
}

func TestActionStorage_CreateAction_InsertError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	action := &core.Action{ID: "1", Type: "test"}

	// No existing action
	mockSingleResult := NewMockActionSingleResult(ctrl)
	mockColl.EXPECT().FindOne(gomock.Any(), gomock.Any()).Return(mockSingleResult)
	mockSingleResult.EXPECT().Decode(gomock.Any()).Return(mongo.ErrNoDocuments)

	mockColl.EXPECT().InsertOne(gomock.Any(), action).Return(nil, mongo.ErrClientDisconnected)

	err := as.CreateAction(action)

	assert.Error(t, err)
}

func TestActionStorage_UpdateAction_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, mongo.ErrClientDisconnected)

	err := as.UpdateAction("1", &core.Action{})

	assert.Error(t, err)
}

func TestActionStorage_DeleteAction_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockActionCollection(ctrl)
	as := &ActionStorage{actionsColl: mockColl}

	mockColl.EXPECT().DeleteOne(gomock.Any(), gomock.Any()).Return(nil, mongo.ErrClientDisconnected)

	err := as.DeleteAction("1")

	assert.Error(t, err)
}
