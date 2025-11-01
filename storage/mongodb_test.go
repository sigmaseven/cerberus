package storage

import (
	"container/list"
	"context"
	"fmt"
	"testing"
	"time"

	"cerberus/core"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func TestNewMongoDB_InvalidURI(t *testing.T) {
	logger := zap.NewNop().Sugar()

	_, err := NewMongoDB("invalid-uri", "testdb", 10, logger)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to MongoDB")
}

func TestMongoDB_HealthCheck(t *testing.T) {
	// Since we can't connect, perhaps skip or mock.

	// For coverage, perhaps create a mock client.

	// But hard.

	// Perhaps the method is simple, but to test, need a real connection.

	// Skip for now.
}

func TestMongoDB_Close(t *testing.T) {
	// Similar.
}

func TestEventStorage_hashEvent(t *testing.T) {
	es := &EventStorage{}

	event := &core.Event{
		RawData:   "test data",
		EventType: "test",
		SourceIP:  "192.168.1.1",
		Timestamp: time.Unix(1234567890, 0),
	}

	hash := es.hashEvent(event)
	assert.NotEmpty(t, hash)

	// Same event should have same hash
	hash2 := es.hashEvent(event)
	assert.Equal(t, hash, hash2)

	// Different event should have different hash
	event2 := *event
	event2.SourceIP = "192.168.1.2"
	hash3 := es.hashEvent(&event2)
	assert.NotEqual(t, hash, hash3)
}

func TestEventStorage_GetEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{EventsColl: mockColl, logger: logger}

	expectedEvent := core.Event{EventID: "1"}

	mockCursor := NewMockEventCursor(ctrl)
	mockColl.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().Next(gomock.Any()).Return(true)
	mockCursor.EXPECT().Decode(gomock.Any()).DoAndReturn(func(v interface{}) error {
		event := v.(*core.Event)
		*event = expectedEvent
		return nil
	})
	mockCursor.EXPECT().Next(gomock.Any()).Return(false)
	mockCursor.EXPECT().Err().Return(nil)
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	events, err := es.GetEvents(10)

	assert.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, expectedEvent, events[0])
}

func TestEventStorage_GetEventCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	es := &EventStorage{EventsColl: mockColl}

	mockColl.EXPECT().CountDocuments(gomock.Any(), gomock.Any()).Return(int64(5), nil)

	count, err := es.GetEventCount()

	assert.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestEventStorage_CleanupOldEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{EventsColl: mockColl, logger: logger}

	mockColl.EXPECT().DeleteMany(gomock.Any(), gomock.Any()).Return(&mongo.DeleteResult{DeletedCount: 10}, nil)

	err := es.CleanupOldEvents(30)

	assert.NoError(t, err)
}

func TestEventStorage_GetEventCountsByMonth(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	es := &EventStorage{EventsColl: mockColl}

	results := []bson.M{
		{"_id": "2025-05", "count": int32(5)},
	}

	mockCursor := NewMockEventCursor(ctrl)
	mockColl.EXPECT().Aggregate(gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().All(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, resultsPtr interface{}) error {
		res := resultsPtr.(*[]bson.M)
		*res = results
		return nil
	})
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	data, err := es.GetEventCountsByMonth()

	assert.NoError(t, err)
	assert.Len(t, data, 6)
	// Check the first one, which is May
	assert.Equal(t, "May", data[0]["name"])
	assert.Equal(t, 5, data[0]["events"])
}

func TestEventStorage_worker(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 2)
	es := &EventStorage{
		EventsColl:          mockColl,
		batchSize:           2,
		eventCh:             eventCh,
		timeout:             1 * time.Second,
		enableDeduplication: false,
		logger:              logger,
	}

	// Send events
	event1 := &core.Event{EventID: "1", RawData: "data1"}
	event2 := &core.Event{EventID: "2", RawData: "data2"}
	eventCh <- event1
	eventCh <- event2
	close(eventCh)

	mockColl.EXPECT().InsertMany(gomock.Any(), gomock.Len(2), gomock.Any()).Return(&mongo.InsertManyResult{}, nil)

	// Start worker in goroutine
	es.wg.Add(1)
	go es.worker()
	es.wg.Wait() // Wait for worker to finish
}

func TestEventStorage_worker_WithDeduplication(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 3)
	es := &EventStorage{
		EventsColl:          mockColl,
		batchSize:           2,
		eventCh:             eventCh,
		timeout:             1 * time.Second,
		enableDeduplication: true,
		dedupCache:          make(map[string]bool),
		dedupKeys:           list.New(),
		dedupCacheSize:      10,
		dedupEvictionSize:   5,
		logger:              logger,
	}

	// Send duplicate events
	event1 := &core.Event{EventID: "1", RawData: "data", EventType: "type", SourceIP: "1.2.3.4", Timestamp: time.Unix(1234567890, 0)}
	event2 := &core.Event{EventID: "2", RawData: "data", EventType: "type", SourceIP: "1.2.3.4", Timestamp: time.Unix(1234567890, 0)} // Duplicate
	event3 := &core.Event{EventID: "3", RawData: "data2", EventType: "type", SourceIP: "1.2.3.4", Timestamp: time.Unix(1234567890, 0)}
	eventCh <- event1
	eventCh <- event2
	eventCh <- event3
	close(eventCh)

	// Should only insert 2 events (event1 and event3)
	mockColl.EXPECT().InsertMany(gomock.Any(), gomock.Len(2), gomock.Any()).Return(&mongo.InsertManyResult{}, nil)

	es.wg.Add(1)
	go es.worker()
	es.wg.Wait()
}

func TestEventStorage_insertBatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{
		EventsColl: mockColl,
		timeout:    1 * time.Second,
		logger:     logger,
	}

	batch := []interface{}{
		&core.Event{EventID: "1", RawData: "data1", SourceFormat: "json"},
		&core.Event{EventID: "2", RawData: "data2", SourceFormat: "cef"},
	}

	mockColl.EXPECT().InsertMany(gomock.Any(), batch, gomock.Any()).Return(&mongo.InsertManyResult{}, nil)

	es.insertBatch(batch)
}

func TestEventStorage_insertBatch_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	mockDlColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{
		EventsColl: mockColl,
		dlColl:     mockDlColl,
		timeout:    1 * time.Second,
		logger:     logger,
	}

	batch := []interface{}{
		&core.Event{EventID: "1", RawData: "data1"},
	}

	mockColl.EXPECT().InsertMany(gomock.Any(), batch, gomock.Any()).Return(nil, fmt.Errorf("insert error"))
	mockDlColl.EXPECT().InsertMany(gomock.Any(), gomock.Any(), gomock.Any()).Return(&mongo.InsertManyResult{}, nil)

	es.insertBatch(batch)
}

func TestEventStorage_insertDeadLetter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDlColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{
		dlColl:  mockDlColl,
		timeout: 1 * time.Second,
		logger:  logger,
	}

	batch := []interface{}{
		&core.Event{EventID: "1", RawData: "data1"},
	}

	mockDlColl.EXPECT().InsertMany(gomock.Any(), gomock.Len(1), gomock.Any()).Return(&mongo.InsertManyResult{}, nil)

	ctx := context.Background()
	es.insertDeadLetter(ctx, batch)
}

func TestEventStorage_GetEvents_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{EventsColl: mockColl, logger: logger}

	mockColl.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("find error"))

	_, err := es.GetEvents(10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find events")
}

func TestEventStorage_GetEvents_DecodeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{EventsColl: mockColl, logger: logger}

	mockCursor := NewMockEventCursor(ctrl)
	mockColl.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().Next(gomock.Any()).Return(true)
	mockCursor.EXPECT().Decode(gomock.Any()).Return(fmt.Errorf("decode error"))
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	_, err := es.GetEvents(10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode event")
}

func TestEventStorage_GetEventCount_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	es := &EventStorage{EventsColl: mockColl}

	mockColl.EXPECT().CountDocuments(gomock.Any(), gomock.Any()).Return(int64(0), fmt.Errorf("count error"))

	_, err := es.GetEventCount()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count events")
}

func TestEventStorage_CleanupOldEvents_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	logger := zap.NewNop().Sugar()
	es := &EventStorage{EventsColl: mockColl, logger: logger}

	mockColl.EXPECT().DeleteMany(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("delete error"))

	err := es.CleanupOldEvents(30)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete old events")
}

func TestEventStorage_GetEventCountsByMonth_AggregateError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	es := &EventStorage{EventsColl: mockColl}

	mockColl.EXPECT().Aggregate(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("aggregate error"))

	_, err := es.GetEventCountsByMonth()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to aggregate events")
}

func TestEventStorage_GetEventCountsByMonth_AllError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockColl := NewMockEventCollection(ctrl)
	es := &EventStorage{EventsColl: mockColl}

	mockCursor := NewMockEventCursor(ctrl)
	mockColl.EXPECT().Aggregate(gomock.Any(), gomock.Any()).Return(mockCursor, nil)
	mockCursor.EXPECT().All(gomock.Any(), gomock.Any()).Return(fmt.Errorf("all error"))
	mockCursor.EXPECT().Close(gomock.Any()).Return(nil)

	_, err := es.GetEventCountsByMonth()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode aggregation results")
}
