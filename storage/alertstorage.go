package storage

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"github.com/cespare/xxhash/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

var ErrAlertNotFound = errors.New("alert not found")

// AlertCursor interface for mocking
type AlertCursor interface {
	All(ctx context.Context, results interface{}) error
	Close(ctx context.Context) error
	Err() error
	Next(ctx context.Context) bool
	Decode(v interface{}) error
}

// AlertSingleResult interface for mocking
type AlertSingleResult interface {
	Decode(v interface{}) error
}

// AlertCollection interface for mocking
type AlertCollection interface {
	Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (AlertCursor, error)
	InsertMany(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error)
	UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error)
	CountDocuments(ctx context.Context, filter interface{}, opts ...*options.CountOptions) (int64, error)
	Aggregate(ctx context.Context, pipeline interface{}, opts ...*options.AggregateOptions) (AlertCursor, error)
	DeleteMany(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error)
}

// mongoAlertCursor adapts *mongo.Cursor to AlertCursor
type mongoAlertCursor struct {
	*mongo.Cursor
}

func (m *mongoAlertCursor) All(ctx context.Context, results interface{}) error {
	return m.Cursor.All(ctx, results)
}

func (m *mongoAlertCursor) Close(ctx context.Context) error {
	return m.Cursor.Close(ctx)
}

func (m *mongoAlertCursor) Err() error {
	return m.Cursor.Err()
}

func (m *mongoAlertCursor) Next(ctx context.Context) bool {
	return m.Cursor.Next(ctx)
}

func (m *mongoAlertCursor) Decode(v interface{}) error {
	return m.Cursor.Decode(v)
}

// mongoAlertSingleResult adapts *mongo.SingleResult to AlertSingleResult
type mongoAlertSingleResult struct {
	*mongo.SingleResult
}

func (m *mongoAlertSingleResult) Decode(v interface{}) error {
	return m.SingleResult.Decode(v)
}

// mongoAlertCollection adapts *mongo.Collection to AlertCollection
type mongoAlertCollection struct {
	*mongo.Collection
}

func (m *mongoAlertCollection) Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (AlertCursor, error) {
	cursor, err := m.Collection.Find(ctx, filter, opts...)
	if err != nil {
		return nil, err
	}
	return &mongoAlertCursor{Cursor: cursor}, nil
}

func (m *mongoAlertCollection) Aggregate(ctx context.Context, pipeline interface{}, opts ...*options.AggregateOptions) (AlertCursor, error) {
	cursor, err := m.Collection.Aggregate(ctx, pipeline, opts...)
	if err != nil {
		return nil, err
	}
	return &mongoAlertCursor{Cursor: cursor}, nil
}

// AlertStorage handles alert persistence
type AlertStorage struct {
	mongoDB        *MongoDB
	alertsColl     AlertCollection
	dlColl         AlertCollection
	batchSize      int
	alertCh        <-chan *core.Alert
	timeout        time.Duration
	wg             sync.WaitGroup
	dedupCache     map[string]bool
	dedupOrder     *list.List
	dedupOrderMap  map[string]*list.Element
	dedupCacheSize int
	dedupMutex     sync.RWMutex
	logger         *zap.SugaredLogger
}

// NewAlertStorage creates a new alert storage handler
func NewAlertStorage(mongoDB *MongoDB, cfg *config.Config, alertCh <-chan *core.Alert, logger *zap.SugaredLogger) *AlertStorage {
	return &AlertStorage{
		mongoDB:        mongoDB,
		alertsColl:     &mongoAlertCollection{Collection: mongoDB.Database.Collection("alerts")},
		dlColl:         &mongoAlertCollection{Collection: mongoDB.Database.Collection("dead_letter_alerts")},
		batchSize:      cfg.Storage.BufferSize,
		alertCh:        alertCh,
		timeout:        time.Duration(cfg.MongoDB.BatchInsertTimeout) * time.Second,
		dedupCache:     make(map[string]bool),
		dedupOrder:     list.New(),
		dedupOrderMap:  make(map[string]*list.Element),
		dedupCacheSize: cfg.Storage.DedupCacheSize,
		logger:         logger,
	}
}

// Start starts the alert storage workers
func (as *AlertStorage) Start(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		as.wg.Add(1)
		go as.worker()
	}
}

// worker processes alerts from the channel
func (as *AlertStorage) worker() {
	defer as.wg.Done()
	batch := make([]interface{}, 0, as.batchSize)

	for alert := range as.alertCh {
		// Deduplication based on rule ID and event ID
		hash := as.hashAlert(alert)
		as.dedupMutex.Lock()
		if _, exists := as.dedupOrderMap[hash]; exists {
			as.dedupMutex.Unlock()
			continue
		}
		as.dedupCache[hash] = true
		elem := as.dedupOrder.PushBack(hash)
		as.dedupOrderMap[hash] = elem
		// LRU eviction: remove oldest if too large
		if as.dedupOrder.Len() > as.dedupCacheSize {
			front := as.dedupOrder.Front()
			old := front.Value.(string)
			delete(as.dedupCache, old)
			delete(as.dedupOrderMap, old)
			as.dedupOrder.Remove(front)
		}
		as.dedupMutex.Unlock()

		batch = append(batch, alert)

		if len(batch) >= as.batchSize {
			as.insertBatch(batch)
			batch = batch[:0]
		}
	}

	// Insert remaining
	if len(batch) > 0 {
		as.insertBatch(batch)
	}
}

// hashAlert generates a fast xxHash for deduplication (non-cryptographic)
func (as *AlertStorage) hashAlert(alert *core.Alert) string {
	data := fmt.Sprintf("%s-%s-%d", alert.RuleID, alert.EventID, alert.Timestamp.Unix())
	hash := xxhash.Sum64String(data)
	return fmt.Sprintf("%016x", hash)
}

// insertBatch inserts a batch of alerts
func (as *AlertStorage) insertBatch(batch []interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), as.timeout)
	defer cancel()

	_, err := as.alertsColl.InsertMany(ctx, batch)
	if err != nil {
		as.logger.Errorf("Failed to insert alert batch: %v", err)
		// Send to dead letter
		as.insertDeadLetter(ctx, batch)
	}
}

// insertDeadLetter inserts failed alerts to dead letter queue
func (as *AlertStorage) insertDeadLetter(ctx context.Context, batch []interface{}) {
	dlDocs := make([]interface{}, len(batch))
	for i, doc := range batch {
		dlDocs[i] = bson.M{
			"failed_at": time.Now(),
			"document":  doc,
		}
	}
	_, err := as.dlColl.InsertMany(ctx, dlDocs)
	if err != nil {
		as.logger.Errorf("Failed to insert alert to dead letter: %v", err)
	}
}

// Stop stops the storage workers
func (as *AlertStorage) Stop() {
	as.wg.Wait()
}

// CleanupOldAlerts deletes alerts older than the specified retention period
func (as *AlertStorage) CleanupOldAlerts(retentionDays int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	filter := bson.M{"timestamp": bson.M{"$lt": cutoff}}

	result, err := as.alertsColl.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete old alerts: %w", err)
	}

	as.logger.Infof("Deleted %d old alerts", result.DeletedCount)
	return nil
}

// AcknowledgeAlert updates an alert status to acknowledged
func (as *AlertStorage) AcknowledgeAlert(alertID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"alert_id": alertID}
	update := bson.M{"$set": bson.M{"status": core.AlertStatusAcknowledged.String()}}

	result, err := as.alertsColl.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to acknowledge alert: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrAlertNotFound
	}

	return nil
}

// DismissAlert updates an alert status to dismissed
func (as *AlertStorage) DismissAlert(alertID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"alert_id": alertID}
	update := bson.M{"$set": bson.M{"status": core.AlertStatusDismissed.String()}}

	result, err := as.alertsColl.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to dismiss alert: %w", err)
	}

	if result.MatchedCount == 0 {
		return ErrAlertNotFound
	}

	return nil
}

// GetAlerts retrieves recent alerts from the database
func (as *AlertStorage) GetAlerts(limit int) ([]core.Alert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findOptions := options.Find()
	findOptions.SetSort(bson.M{"timestamp": -1})
	findOptions.SetLimit(int64(limit))

	cursor, err := as.alertsColl.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to find alerts: %w", err)
	}
	defer cursor.Close(ctx)

	alerts := make([]core.Alert, 0)
	for cursor.Next(ctx) {
		var alert core.Alert
		if err := cursor.Decode(&alert); err != nil {
			return nil, fmt.Errorf("failed to decode alert: %w", err)
		}
		alerts = append(alerts, alert)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return alerts, nil
}

// GetAlertCount returns the total number of alerts
func (as *AlertStorage) GetAlertCount() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	count, err := as.alertsColl.CountDocuments(ctx, bson.M{})
	if err != nil {
		return 0, fmt.Errorf("failed to count alerts: %w", err)
	}

	return count, nil
}

// GetAlertCountsByMonth returns alert counts grouped by month for the last defaultChartMonths months
func (as *AlertStorage) GetAlertCountsByMonth() ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get current time and defaultChartMonths months ago
	now := time.Now()
	sixMonthsAgo := now.AddDate(0, -defaultChartMonths, 0)

	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{"timestamp": bson.M{"$gte": sixMonthsAgo}}}},
		bson.D{{Key: "$group", Value: bson.M{
			"_id":   bson.M{"$dateToString": bson.M{"format": "%Y-%m", "date": "$timestamp"}},
			"count": bson.M{"$sum": 1},
		}}},
		bson.D{{Key: "$sort", Value: bson.M{"_id": 1}}},
	}

	cursor, err := as.alertsColl.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate alerts: %w", err)
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode aggregation results: %w", err)
	}

	// Map to the expected format, with month names
	alertData := make([]map[string]interface{}, 0, defaultChartMonths)

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

		alertData = append(alertData, map[string]interface{}{
			"name":   name,
			"alerts": count,
		})
	}

	return alertData, nil
}
