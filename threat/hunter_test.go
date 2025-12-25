package threat

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// =============================================================================
// Mock IOC Storage for Testing
// =============================================================================

type mockIOCStorage struct {
	iocs       map[string]*core.IOC
	hunts      map[string]*core.IOCHunt
	matches    []*core.IOCMatch
	hitCounts  map[string]int64
	mu         sync.RWMutex
	getIOCErr  error
	recordErr  error
	slowGetIOC time.Duration // Simulate slow IOC fetches
}

func newMockIOCStorage() *mockIOCStorage {
	return &mockIOCStorage{
		iocs:      make(map[string]*core.IOC),
		hunts:     make(map[string]*core.IOCHunt),
		matches:   make([]*core.IOCMatch, 0),
		hitCounts: make(map[string]int64),
	}
}

func (m *mockIOCStorage) CreateIOC(ctx context.Context, ioc *core.IOC) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.iocs[ioc.ID] = ioc
	return nil
}

func (m *mockIOCStorage) GetIOC(ctx context.Context, id string) (*core.IOC, error) {
	if m.slowGetIOC > 0 {
		time.Sleep(m.slowGetIOC)
	}
	if m.getIOCErr != nil {
		return nil, m.getIOCErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ioc, ok := m.iocs[id]; ok {
		return ioc, nil
	}
	return nil, nil
}

func (m *mockIOCStorage) UpdateIOC(ctx context.Context, ioc *core.IOC) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.iocs[ioc.ID] = ioc
	return nil
}

func (m *mockIOCStorage) DeleteIOC(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.iocs, id)
	return nil
}

func (m *mockIOCStorage) ListIOCs(ctx context.Context, filters *core.IOCFilters) ([]*core.IOC, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*core.IOC, 0, len(m.iocs))
	for _, ioc := range m.iocs {
		result = append(result, ioc)
	}
	return result, int64(len(result)), nil
}

func (m *mockIOCStorage) FindByValue(ctx context.Context, iocType core.IOCType, normalizedValue string) (*core.IOC, error) {
	return nil, nil
}

func (m *mockIOCStorage) SearchIOCs(ctx context.Context, query string, limit int) ([]*core.IOC, error) {
	return nil, nil
}

func (m *mockIOCStorage) BulkCreateIOCs(ctx context.Context, iocs []*core.IOC) (int, int, error) {
	return 0, 0, nil
}

func (m *mockIOCStorage) BulkUpdateStatus(ctx context.Context, ids []string, status core.IOCStatus) error {
	return nil
}

func (m *mockIOCStorage) GetIOCStats(ctx context.Context) (*core.IOCStatistics, error) {
	return &core.IOCStatistics{}, nil
}

func (m *mockIOCStorage) LinkToInvestigation(ctx context.Context, iocID, investigationID, linkedBy string) error {
	return nil
}

func (m *mockIOCStorage) UnlinkFromInvestigation(ctx context.Context, iocID, investigationID string) error {
	return nil
}

func (m *mockIOCStorage) GetLinkedInvestigations(ctx context.Context, iocID string) ([]string, error) {
	return nil, nil
}

func (m *mockIOCStorage) LinkToAlert(ctx context.Context, iocID, alertID string) error {
	return nil
}

func (m *mockIOCStorage) GetLinkedAlerts(ctx context.Context, iocID string) ([]string, error) {
	return nil, nil
}

func (m *mockIOCStorage) CreateHunt(ctx context.Context, hunt *core.IOCHunt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hunts[hunt.ID] = hunt
	return nil
}

func (m *mockIOCStorage) GetHunt(ctx context.Context, id string) (*core.IOCHunt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if hunt, ok := m.hunts[id]; ok {
		return hunt, nil
	}
	return nil, nil
}

func (m *mockIOCStorage) UpdateHuntStatus(ctx context.Context, id string, status core.HuntStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if hunt, ok := m.hunts[id]; ok {
		hunt.Status = status
	}
	return nil
}

func (m *mockIOCStorage) UpdateHuntProgress(ctx context.Context, id string, progress float64, matchCount, totalEvents int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if hunt, ok := m.hunts[id]; ok {
		hunt.Progress = progress
		hunt.MatchCount = matchCount
		hunt.TotalEvents = totalEvents
	}
	return nil
}

func (m *mockIOCStorage) CompleteHunt(ctx context.Context, id string, matchCount, totalEvents int64, err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if hunt, ok := m.hunts[id]; ok {
		if err != nil {
			hunt.Status = core.HuntStatusFailed
		} else {
			hunt.Status = core.HuntStatusCompleted
		}
		hunt.MatchCount = matchCount
		hunt.TotalEvents = totalEvents
	}
	return nil
}

func (m *mockIOCStorage) ListHunts(ctx context.Context, limit, offset int) ([]*core.IOCHunt, int64, error) {
	return nil, 0, nil
}

func (m *mockIOCStorage) RecordMatch(ctx context.Context, match *core.IOCMatch) error {
	if m.recordErr != nil {
		return m.recordErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.matches = append(m.matches, match)
	return nil
}

func (m *mockIOCStorage) BulkRecordMatches(ctx context.Context, matches []*core.IOCMatch) (int, error) {
	if m.recordErr != nil {
		return 0, m.recordErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.matches = append(m.matches, matches...)
	return len(matches), nil
}

func (m *mockIOCStorage) GetMatchesByHunt(ctx context.Context, huntID string, limit, offset int) ([]*core.IOCMatch, int64, error) {
	return nil, 0, nil
}

func (m *mockIOCStorage) GetMatchesByIOC(ctx context.Context, iocID string, limit, offset int) ([]*core.IOCMatch, int64, error) {
	return nil, 0, nil
}

func (m *mockIOCStorage) ArchiveExpiredIOCs(ctx context.Context) (int64, error) {
	return 0, nil
}

func (m *mockIOCStorage) IncrementHitCount(ctx context.Context, iocID string, lastSeen time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hitCounts[iocID]++
	return nil
}

// =============================================================================
// Mock Event Searcher for Testing
// =============================================================================

type testEventSearcher struct {
	matches      []IOCMatchResult
	totalEvents  int64
	searchDelay  time.Duration
	cancelDuring bool // Cancel context during search
}

func (t *testEventSearcher) SearchEventsForIOCs(ctx context.Context, iocs []*core.IOC, start, end time.Time, batchSize int,
	progressCh chan<- HuntProgress) ([]IOCMatchResult, error) {

	// Simulate search time
	if t.searchDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(t.searchDelay):
		}
	}

	// Send progress updates
	for i := 0; i <= 100; i += 25 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case progressCh <- HuntProgress{
			Progress:    float64(i),
			TotalEvents: t.totalEvents,
			MatchCount:  int64(len(t.matches) * i / 100),
		}:
		default:
		}
	}

	return t.matches, nil
}

// =============================================================================
// Tests
// =============================================================================

func TestHuntEngine_ProgressUpdater_RaceCondition(t *testing.T) {
	// This test verifies the mutex fix for the race condition in progressUpdater
	// Run with -race flag to detect race conditions

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	storage := newMockIOCStorage()
	searcher := &MockEventSearcher{}
	config := DefaultHuntConfig()
	config.ProgressInterval = 10 * time.Millisecond // Fast updates for testing

	engine := NewHuntEngine(storage, searcher, config, sugar)
	defer engine.Shutdown(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	progressCh := make(chan HuntProgress, 100)

	// Run progress updater in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		engine.progressUpdater(ctx, "test-hunt", progressCh)
	}()

	// Hammer the progress channel from multiple goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				select {
				case progressCh <- HuntProgress{
					HuntID:      "test-hunt",
					Progress:    float64(j),
					TotalEvents: int64(j * 100),
					MatchCount:  int64(j),
				}:
				default:
				}
			}
		}(i)
	}

	wg.Wait()
	close(progressCh)
	<-done

	// If we get here without race detector errors, the test passes
	t.Log("Progress updater race condition test passed")
}

func TestHuntEngine_ContextCancellation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	storage := newMockIOCStorage()

	// Add some IOCs with valid IP addresses
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/255, i%255+1)
		ioc, err := core.NewIOC(core.IOCTypeIP, ip, "test", "test-user")
		if err != nil {
			t.Fatalf("Failed to create IOC: %v", err)
		}
		storage.CreateIOC(context.Background(), ioc)
	}

	// Create hunt with slow IOC fetches
	storage.slowGetIOC = 10 * time.Millisecond

	searcher := &testEventSearcher{
		matches:     make([]IOCMatchResult, 0),
		totalEvents: 1000,
	}

	config := DefaultHuntConfig()
	config.IOCLoadCheckInterval = 5 // Check every 5 IOCs

	engine := NewHuntEngine(storage, searcher, config, sugar)

	// Create a hunt
	var iocIDs []string
	for id := range storage.iocs {
		iocIDs = append(iocIDs, id)
	}

	hunt, err := core.NewIOCHunt(iocIDs, time.Now().Add(-24*time.Hour), time.Now(), "test-user")
	if err != nil {
		t.Fatalf("Failed to create hunt: %v", err)
	}
	storage.CreateHunt(context.Background(), hunt)

	// Start the hunt
	err = engine.StartHunt(hunt.ID)
	if err != nil {
		t.Fatalf("Failed to start hunt: %v", err)
	}

	// Wait a bit then cancel
	time.Sleep(50 * time.Millisecond)
	err = engine.CancelHunt(hunt.ID)
	if err != nil {
		t.Fatalf("Failed to cancel hunt: %v", err)
	}

	// Wait for cleanup
	engine.Shutdown(5 * time.Second)

	// Verify hunt was cancelled
	savedHunt, _ := storage.GetHunt(context.Background(), hunt.ID)
	if savedHunt.Status != core.HuntStatusCancelled && savedHunt.Status != core.HuntStatusFailed {
		t.Errorf("Expected hunt status to be cancelled or failed, got %s", savedHunt.Status)
	}
}

func TestHuntEngine_BatchProcessing(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	storage := newMockIOCStorage()

	// Add an IOC
	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "test-user")
	storage.CreateIOC(context.Background(), ioc)

	// Create matches to be returned
	matches := make([]IOCMatchResult, 500)
	for i := 0; i < 500; i++ {
		matches[i] = IOCMatchResult{
			IOCID:          ioc.ID,
			EventID:        fmt.Sprintf("event-%d", i),
			MatchedField:   "src_ip",
			MatchedValue:   "10.0.0.1",
			EventTimestamp: time.Now(),
		}
	}

	searcher := &testEventSearcher{
		matches:     matches,
		totalEvents: 10000,
		searchDelay: 50 * time.Millisecond, // Small delay to simulate real search
	}

	config := DefaultHuntConfig()
	config.MatchBatchSize = 50 // Process in batches of 50
	config.MaxHuntDuration = 30 * time.Second

	engine := NewHuntEngine(storage, searcher, config, sugar)

	// Create hunt
	hunt, _ := core.NewIOCHunt([]string{ioc.ID}, time.Now().Add(-24*time.Hour), time.Now(), "test-user")
	storage.CreateHunt(context.Background(), hunt)

	// Start hunt
	err := engine.StartHunt(hunt.ID)
	if err != nil {
		t.Fatalf("Failed to start hunt: %v", err)
	}

	// Wait for hunt to complete by checking status
	timeout := time.After(10 * time.Second)
	for {
		savedHunt, _ := storage.GetHunt(context.Background(), hunt.ID)
		if savedHunt != nil && savedHunt.Status.IsTerminal() {
			break
		}
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for hunt to complete")
		case <-time.After(100 * time.Millisecond):
		}
	}

	engine.Shutdown(5 * time.Second)

	// Verify all matches were recorded
	storage.mu.RLock()
	matchCount := len(storage.matches)
	storage.mu.RUnlock()

	if matchCount != 500 {
		t.Errorf("Expected 500 matches to be recorded, got %d", matchCount)
	}

	// Verify hit count was incremented (should be 1 per unique IOC, not per match)
	storage.mu.RLock()
	hitCount := storage.hitCounts[ioc.ID]
	storage.mu.RUnlock()

	if hitCount != 1 {
		t.Errorf("Expected hit count of 1 (deduplicated), got %d", hitCount)
	}
}

func TestHuntEngine_Timeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	storage := newMockIOCStorage()

	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "test-user")
	storage.CreateIOC(context.Background(), ioc)

	// Create a slow searcher
	searcher := &testEventSearcher{
		matches:     []IOCMatchResult{},
		totalEvents: 1000,
		searchDelay: 10 * time.Second, // Very slow search
	}

	config := DefaultHuntConfig()
	config.MaxHuntDuration = 100 * time.Millisecond // Short timeout

	engine := NewHuntEngine(storage, searcher, config, sugar)

	hunt, _ := core.NewIOCHunt([]string{ioc.ID}, time.Now().Add(-24*time.Hour), time.Now(), "test-user")
	storage.CreateHunt(context.Background(), hunt)

	err := engine.StartHunt(hunt.ID)
	if err != nil {
		t.Fatalf("Failed to start hunt: %v", err)
	}

	// Wait for timeout
	time.Sleep(500 * time.Millisecond)
	engine.Shutdown(5 * time.Second)

	// Verify hunt was marked as failed due to timeout
	savedHunt, _ := storage.GetHunt(context.Background(), hunt.ID)
	if savedHunt.Status != core.HuntStatusFailed {
		t.Errorf("Expected hunt to fail due to timeout, got status %s", savedHunt.Status)
	}
}

func TestHuntConfig_Defaults(t *testing.T) {
	config := DefaultHuntConfig()

	if config.MaxConcurrentHunts != 3 {
		t.Errorf("Expected MaxConcurrentHunts=3, got %d", config.MaxConcurrentHunts)
	}
	if config.EventBatchSize != 1000 {
		t.Errorf("Expected EventBatchSize=1000, got %d", config.EventBatchSize)
	}
	if config.ProgressInterval != 5*time.Second {
		t.Errorf("Expected ProgressInterval=5s, got %v", config.ProgressInterval)
	}
	if config.MaxHuntDuration != 1*time.Hour {
		t.Errorf("Expected MaxHuntDuration=1h, got %v", config.MaxHuntDuration)
	}
	if config.IOCLoadCheckInterval != 10 {
		t.Errorf("Expected IOCLoadCheckInterval=10, got %d", config.IOCLoadCheckInterval)
	}
	if config.MatchBatchSize != 100 {
		t.Errorf("Expected MatchBatchSize=100, got %d", config.MatchBatchSize)
	}
}

func TestHuntEngine_MaxConcurrentHunts(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	storage := newMockIOCStorage()

	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "test-user")
	storage.CreateIOC(context.Background(), ioc)

	searcher := &testEventSearcher{
		matches:     []IOCMatchResult{},
		totalEvents: 1000,
		searchDelay: 2 * time.Second,
	}

	config := DefaultHuntConfig()
	config.MaxConcurrentHunts = 2 // Only allow 2 concurrent hunts

	engine := NewHuntEngine(storage, searcher, config, sugar)
	defer engine.Shutdown(5 * time.Second)

	// Create 3 hunts
	var hunts []*core.IOCHunt
	for i := 0; i < 3; i++ {
		hunt, _ := core.NewIOCHunt([]string{ioc.ID}, time.Now().Add(-24*time.Hour), time.Now(), "test-user")
		storage.CreateHunt(context.Background(), hunt)
		hunts = append(hunts, hunt)
	}

	// Start first 2 - should succeed
	var started int32
	for i := 0; i < 2; i++ {
		err := engine.StartHunt(hunts[i].ID)
		if err != nil {
			t.Errorf("Hunt %d should have started: %v", i, err)
		} else {
			atomic.AddInt32(&started, 1)
		}
	}

	// Third should fail with max concurrent error
	err := engine.StartHunt(hunts[2].ID)
	if err == nil {
		t.Error("Third hunt should have failed with max concurrent error")
	} else if err.Error() != "maximum concurrent hunts reached" {
		t.Errorf("Expected 'maximum concurrent hunts reached', got: %v", err)
	}
}

func TestHuntEngine_Shutdown(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	storage := newMockIOCStorage()

	ioc, _ := core.NewIOC(core.IOCTypeIP, "10.0.0.1", "test", "test-user")
	storage.CreateIOC(context.Background(), ioc)

	searcher := &testEventSearcher{
		matches:     []IOCMatchResult{},
		totalEvents: 1000,
		searchDelay: 5 * time.Second, // Long search
	}

	config := DefaultHuntConfig()
	engine := NewHuntEngine(storage, searcher, config, sugar)

	hunt, _ := core.NewIOCHunt([]string{ioc.ID}, time.Now().Add(-24*time.Hour), time.Now(), "test-user")
	storage.CreateHunt(context.Background(), hunt)

	// Start hunt
	engine.StartHunt(hunt.ID)

	// Immediate shutdown should timeout gracefully
	start := time.Now()
	err := engine.Shutdown(100 * time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Log("Shutdown completed gracefully (hunt finished quickly)")
	} else {
		if elapsed < 100*time.Millisecond {
			t.Error("Shutdown returned too quickly")
		}
		t.Logf("Shutdown timed out as expected: %v", err)
	}
}
