package storage

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/metrics"
	"github.com/cespare/xxhash/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const defaultChartMonths = 6

// EventCursor interface for mocking
type EventCursor interface {
	All(ctx context.Context, results interface{}) error
	Close(ctx context.Context) error
	Err() error
	Next(ctx context.Context) bool
	Decode(v interface{}) error
}

// EventSingleResult interface for mocking
type EventSingleResult interface {
	Decode(v interface{}) error
}

// EventCollection interface for mocking
type EventCollection interface {
	Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (EventCursor, error)
	InsertMany(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error)
	Aggregate(ctx context.Context, pipeline interface{}, opts ...*options.AggregateOptions) (EventCursor, error)
	DeleteMany(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error)
	CountDocuments(ctx context.Context, filter interface{}, opts ...*options.CountOptions) (int64, error)
}

// mongoEventCursor adapts *mongo.Cursor to EventCursor
type mongoEventCursor struct {
	*mongo.Cursor
}

func (m *mongoEventCursor) All(ctx context.Context, results interface{}) error {
	return m.Cursor.All(ctx, results)
}

func (m *mongoEventCursor) Close(ctx context.Context) error {
	return m.Cursor.Close(ctx)
}

func (m *mongoEventCursor) Err() error {
	return m.Cursor.Err()
}

func (m *mongoEventCursor) Next(ctx context.Context) bool {
	return m.Cursor.Next(ctx)
}

func (m *mongoEventCursor) Decode(v interface{}) error {
	return m.Cursor.Decode(v)
}

// mongoEventCollection adapts *mongo.Collection to EventCollection
type mongoEventCollection struct {
	*mongo.Collection
}

func (m *mongoEventCollection) Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (EventCursor, error) {
	cursor, err := m.Collection.Find(ctx, filter, opts...)
	if err != nil {
		return nil, err
	}
	return &mongoEventCursor{Cursor: cursor}, nil
}

func (m *mongoEventCollection) Aggregate(ctx context.Context, pipeline interface{}, opts ...*options.AggregateOptions) (EventCursor, error) {
	cursor, err := m.Collection.Aggregate(ctx, pipeline, opts...)
	if err != nil {
		return nil, err
	}
	return &mongoEventCursor{Cursor: cursor}, nil
}

// MongoDB holds the MongoDB client and database
type MongoDB struct {
	Client   *mongo.Client
	Database *mongo.Database
}

// NewMongoDB creates a new MongoDB connection
func NewMongoDB(uri, dbName string, maxPoolSize uint64, logger *zap.SugaredLogger) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(uri).SetMaxPoolSize(maxPoolSize)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	logger.Info("Connected to MongoDB successfully")

	return &MongoDB{
		Client:   client,
		Database: client.Database(dbName),
	}, nil
}

// HealthCheck performs a health check on the MongoDB connection
func (m *MongoDB) HealthCheck(ctx context.Context) error {
	return m.Client.Ping(ctx, nil)
}

// Close closes the MongoDB connection
func (m *MongoDB) Close(ctx context.Context) error {
	return m.Client.Disconnect(ctx)
}

// EventStorage handles event persistence
type EventStorage struct {
	mongoDB             *MongoDB
	EventsColl          EventCollection
	dlColl              EventCollection
	batchSize           int
	eventCh             <-chan *core.Event
	timeout             time.Duration
	wg                  sync.WaitGroup
	dedupCache          map[string]bool
	dedupKeys           *list.List
	dedupCacheSize      int
	dedupEvictionSize   int
	dedupMutex          sync.RWMutex
	enableDeduplication bool
	logger              *zap.SugaredLogger
}

// NewEventStorage creates a new event storage handler
func NewEventStorage(mongoDB *MongoDB, cfg *config.Config, eventCh <-chan *core.Event, logger *zap.SugaredLogger) *EventStorage {
	return &EventStorage{
		mongoDB:             mongoDB,
		EventsColl:          &mongoEventCollection{Collection: mongoDB.Database.Collection("events")},
		dlColl:              &mongoEventCollection{Collection: mongoDB.Database.Collection("dead_letter_events")},
		batchSize:           cfg.Storage.BufferSize,
		eventCh:             eventCh,
		timeout:             time.Duration(cfg.MongoDB.BatchInsertTimeout) * time.Second,
		dedupCache:          make(map[string]bool),
		dedupKeys:           list.New(),
		dedupCacheSize:      cfg.Storage.DedupCacheSize,
		dedupEvictionSize:   cfg.Storage.DedupEvictionSize,
		enableDeduplication: cfg.Storage.Deduplication,
		logger:              logger,
	}
}

// Start starts the event storage workers
func (es *EventStorage) Start(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		es.wg.Add(1)
		go es.worker()
	}
}

// worker processes events from the channel
func (es *EventStorage) worker() {
	defer es.wg.Done()
	batch := make([]interface{}, 0, es.batchSize)

	for event := range es.eventCh {
		if es.enableDeduplication {
			// Deduplication
			hash := es.hashEvent(event)
			es.dedupMutex.Lock()
			if es.dedupCache[hash] {
				es.dedupMutex.Unlock()
				continue
			}
			es.dedupCache[hash] = true
			es.dedupKeys.PushBack(hash)
			// LRU eviction: remove oldest entries if too large
			for es.dedupKeys.Len() > es.dedupCacheSize {
				front := es.dedupKeys.Front()
				if front != nil {
					delete(es.dedupCache, front.Value.(string))
					es.dedupKeys.Remove(front)
				}
			}
			es.dedupMutex.Unlock()
		}

		batch = append(batch, event)

		if len(batch) >= es.batchSize {
			es.insertBatch(batch)
			batch = batch[:0]
		}
	}

	// Insert remaining
	if len(batch) > 0 {
		es.insertBatch(batch)
	}
}

// hashEvent generates a fast xxHash for deduplication (non-cryptographic)
func (es *EventStorage) hashEvent(event *core.Event) string {
	sourceIP := event.SourceIP
	if sourceIP == "" {
		sourceIP = "unknown"
	}
	data := fmt.Sprintf("%s|%s|%s|%d", event.RawData, event.EventType, sourceIP, event.Timestamp.Unix())
	hash := xxhash.Sum64String(data)
	return fmt.Sprintf("%016x", hash)
}

// insertBatch inserts a batch of events
func (es *EventStorage) insertBatch(batch []interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), es.timeout)
	defer cancel()

	_, err := es.EventsColl.InsertMany(ctx, batch)
	if err != nil {
		es.logger.Errorf("Failed to insert batch: %v", err)
		// Send to dead letter
		es.insertDeadLetter(ctx, batch)
	} else {
		// Increment metrics for each event
		for _, item := range batch {
			event := item.(*core.Event)
			metrics.EventsIngested.WithLabelValues(event.SourceFormat).Inc()
		}
	}
}

// insertDeadLetter inserts failed events to dead letter queue
func (es *EventStorage) insertDeadLetter(ctx context.Context, batch []interface{}) {
	dlDocs := make([]interface{}, len(batch))
	for i, doc := range batch {
		dlDocs[i] = bson.M{
			"failed_at": time.Now(),
			"document":  doc,
		}
	}
	_, err := es.dlColl.InsertMany(ctx, dlDocs)
	if err != nil {
		es.logger.Errorf("Failed to insert to dead letter: %v", err)
		metrics.DeadLetterInsertFailures.Inc()
	}
}

// Stop stops the storage workers
func (es *EventStorage) Stop() {
	es.wg.Wait()
}

// CleanupOldEvents deletes events older than the specified retention period
func (es *EventStorage) CleanupOldEvents(retentionDays int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	filter := bson.M{"timestamp": bson.M{"$lt": cutoff}}

	result, err := es.EventsColl.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete old events: %w", err)
	}

	es.logger.Infof("Deleted %d old events", result.DeletedCount)
	return nil
}

// GetEvents retrieves recent events from the database
func (es *EventStorage) GetEvents(limit int) ([]core.Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findOptions := options.Find()
	findOptions.SetSort(bson.M{"timestamp": -1})
	findOptions.SetLimit(int64(limit))

	cursor, err := es.EventsColl.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to find events: %w", err)
	}
	defer cursor.Close(ctx)

	events := make([]core.Event, 0)
	for cursor.Next(ctx) {
		var event core.Event
		if err := cursor.Decode(&event); err != nil {
			return nil, fmt.Errorf("failed to decode event: %w", err)
		}
		events = append(events, event)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return events, nil
}

// GetEventCount returns the total number of events
func (es *EventStorage) GetEventCount() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	count, err := es.EventsColl.CountDocuments(ctx, bson.M{})
	if err != nil {
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	return count, nil
}

// GetEventCountsByMonth returns event counts grouped by month for the last 6 months
func (es *EventStorage) GetEventCountsByMonth() ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get current time and months ago
	now := time.Now()
	monthsAgo := now.AddDate(0, -defaultChartMonths, 0)

	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{"timestamp": bson.M{"$gte": monthsAgo}}}},
		bson.D{{Key: "$group", Value: bson.M{
			"_id":   bson.M{"$dateToString": bson.M{"format": "%Y-%m", "date": "$timestamp"}},
			"count": bson.M{"$sum": 1},
		}}},
		bson.D{{Key: "$sort", Value: bson.M{"_id": 1}}},
	}

	cursor, err := es.EventsColl.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate events: %w", err)
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode aggregation results: %w", err)
	}

	// Map to the expected format, with month names
	chartData := make([]map[string]interface{}, 0, defaultChartMonths)

	for i := 0; i < defaultChartMonths; i++ {
		targetMonth := now.AddDate(0, -(defaultChartMonths-1)+i, 0)
		monthStr := fmt.Sprintf("%d-%02d", targetMonth.Year(), targetMonth.Month())
		name := targetMonth.Month().String()[:3]

		count := 0
		for _, result := range results {
			if id, ok := result["_id"].(string); ok && id == monthStr {
				if c, ok := result["count"].(int32); ok {
					count = int(c)
				}
				break
			}
		}

		chartData = append(chartData, map[string]interface{}{
			"name":   name,
			"events": count,
		})
	}

	return chartData, nil
}
