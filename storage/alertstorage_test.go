package storage

import (
	"context"
	"testing"

	"cerberus/core"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func TestAlertStorage_hashAlert(t *testing.T) {
	as := &AlertStorage{}

	alert := &core.Alert{
		RuleID:  "rule1",
		EventID: "event1",
	}

	hash := as.hashAlert(alert)
	assert.NotEmpty(t, hash)

	// Same alert should have same hash
	hash2 := as.hashAlert(alert)
	assert.Equal(t, hash, hash2)

	// Different alert should have different hash
	alert2 := *alert
	alert2.RuleID = "rule2"
	hash3 := as.hashAlert(&alert2)
	assert.NotEqual(t, hash, hash3)
}

func TestAlertStorage_GetAlerts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	as := &AlertStorage{alertsColl: mockColl}

	expectedAlert := core.Alert{AlertID: "1"}

	mockCursor := NewMockAlertCursor(ctrl)
	mockColl.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().Next(gomock.Any()).Return(true)
	mockCursor.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		alert := v.(*core.Alert)
		*alert = expectedAlert
		return nil
	})
	mockCursor.EXPECT().Next(gomock.Any()).Return(false)
	mockCursor.EXPECT().Err().Return(nil)
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	alerts, err := as.GetAlerts(10)

	assert.NoError(t, err)
	assert.Len(t, alerts, 1)
	assert.Equal(t, expectedAlert, alerts[0])
}

func TestAlertStorage_GetAlertCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	as := &AlertStorage{alertsColl: mockColl}

	mockColl.EXPECT().CountDocuments(gomock.Any(), gomock.Any()).Return(int64(5), nil)

	count, err := as.GetAlertCount()

	assert.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestAlertStorage_AcknowledgeAlert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	as := &AlertStorage{alertsColl: mockColl}

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 1}, nil)

	err := as.AcknowledgeAlert("1")

	assert.NoError(t, err)
}

func TestAlertStorage_AcknowledgeAlert_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	as := &AlertStorage{alertsColl: mockColl}

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 0}, nil)

	err := as.AcknowledgeAlert("1")

	assert.Error(t, err)
	assert.Equal(t, ErrAlertNotFound, err)
}

func TestAlertStorage_DismissAlert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	as := &AlertStorage{alertsColl: mockColl}

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 1}, nil)

	err := as.DismissAlert("1")

	assert.NoError(t, err)
}

func TestAlertStorage_DismissAlert_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	as := &AlertStorage{alertsColl: mockColl}

	mockColl.EXPECT().UpdateOne(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.UpdateResult{MatchedCount: 0}, nil)

	err := as.DismissAlert("1")

	assert.Error(t, err)
	assert.Equal(t, ErrAlertNotFound, err)
}

func TestAlertStorage_CleanupOldAlerts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	logger := zap.NewNop().Sugar()
	as := &AlertStorage{alertsColl: mockColl, logger: logger}

	mockColl.EXPECT().DeleteMany(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 10}, nil)

	err := as.CleanupOldAlerts(30)

	assert.NoError(t, err)
}

func TestAlertStorage_GetAlertCountsByMonth(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockAlertCollection(ctrl)
	as := &AlertStorage{alertsColl: mockColl}

	results := []bson.M{
		{"_id": "2025-05", "count": int32(5)},
	}

	mockCursor := NewMockAlertCursor(ctrl)
	mockColl.EXPECT().Aggregate(gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().All(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, resultsPtr interface{}) error {
		res := resultsPtr.(*[]bson.M)
		*res = results
		return nil
	})
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	data, err := as.GetAlertCountsByMonth()

	assert.NoError(t, err)
	assert.Len(t, data, 6)
	// Check the first one, which is May
	assert.Equal(t, "May", data[0]["name"])
	assert.Equal(t, 5, data[0]["alerts"])
}
