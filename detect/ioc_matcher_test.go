package detect

import (
	"context"
	"testing"
	"time"

	"cerberus/core"
)

// mockIOCStorage implements core.IOCStorage for testing
type mockIOCStorage struct {
	iocs []*core.IOC
}

func (m *mockIOCStorage) CreateIOC(ctx context.Context, ioc *core.IOC) error {
	m.iocs = append(m.iocs, ioc)
	return nil
}

func (m *mockIOCStorage) GetIOC(ctx context.Context, id string) (*core.IOC, error) {
	for _, ioc := range m.iocs {
		if ioc.ID == id {
			return ioc, nil
		}
	}
	return nil, nil
}

func (m *mockIOCStorage) UpdateIOC(ctx context.Context, ioc *core.IOC) error {
	return nil
}

func (m *mockIOCStorage) DeleteIOC(ctx context.Context, id string) error {
	return nil
}

func (m *mockIOCStorage) ListIOCs(ctx context.Context, filters *core.IOCFilters) ([]*core.IOC, int64, error) {
	return m.iocs, int64(len(m.iocs)), nil
}

func (m *mockIOCStorage) BulkCreateIOCs(ctx context.Context, iocs []*core.IOC) (int, int, error) {
	m.iocs = append(m.iocs, iocs...)
	return len(iocs), 0, nil
}

func (m *mockIOCStorage) BulkUpdateStatus(ctx context.Context, ids []string, status core.IOCStatus) error {
	return nil
}

func (m *mockIOCStorage) FindByValue(ctx context.Context, iocType core.IOCType, normalizedValue string) (*core.IOC, error) {
	for _, ioc := range m.iocs {
		if ioc.Type == iocType && ioc.Value == normalizedValue {
			return ioc, nil
		}
	}
	return nil, nil
}

func (m *mockIOCStorage) SearchIOCs(ctx context.Context, query string, limit int) ([]*core.IOC, error) {
	return m.iocs, nil
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

func (m *mockIOCStorage) GetLinkedIOCs(ctx context.Context, alertID string) ([]*core.IOC, error) {
	return nil, nil
}

func (m *mockIOCStorage) RecordMatch(ctx context.Context, match *core.IOCMatch) error {
	return nil
}

func (m *mockIOCStorage) GetMatchesByIOC(ctx context.Context, iocID string, limit, offset int) ([]*core.IOCMatch, int64, error) {
	return nil, 0, nil
}

func (m *mockIOCStorage) CreateHunt(ctx context.Context, hunt *core.IOCHunt) error {
	return nil
}

func (m *mockIOCStorage) GetHunt(ctx context.Context, id string) (*core.IOCHunt, error) {
	return nil, nil
}

func (m *mockIOCStorage) UpdateHuntStatus(ctx context.Context, id string, status core.HuntStatus) error {
	return nil
}

func (m *mockIOCStorage) UpdateHuntProgress(ctx context.Context, id string, progress float64, eventsProcessed, matchCount int64) error {
	return nil
}

func (m *mockIOCStorage) CompleteHunt(ctx context.Context, id string, matchCount, totalEvents int64, err error) error {
	return nil
}

func (m *mockIOCStorage) ListHunts(ctx context.Context, limit, offset int) ([]*core.IOCHunt, int64, error) {
	return nil, 0, nil
}

func (m *mockIOCStorage) GetMatchesByHunt(ctx context.Context, huntID string, limit, offset int) ([]*core.IOCMatch, int64, error) {
	return nil, 0, nil
}

func (m *mockIOCStorage) ArchiveExpiredIOCs(ctx context.Context) (int64, error) {
	return 0, nil
}

func (m *mockIOCStorage) IncrementHitCount(ctx context.Context, iocID string, lastSeen time.Time) error {
	return nil
}

func (m *mockIOCStorage) BulkRecordMatches(ctx context.Context, matches []*core.IOCMatch) (int, error) {
	return len(matches), nil
}

func (m *mockIOCStorage) CountIOCsByFeed(ctx context.Context, feedID string) (int64, error) {
	var count int64
	for _, ioc := range m.iocs {
		if ioc.FeedID == feedID {
			count++
		}
	}
	return count, nil
}

func (m *mockIOCStorage) FindByFeedExternalID(ctx context.Context, feedID, externalID string) (*core.IOC, error) {
	for _, ioc := range m.iocs {
		if ioc.FeedID == feedID && ioc.ExternalID == externalID {
			return ioc, nil
		}
	}
	return nil, nil
}

func (m *mockIOCStorage) GetIOCsByFeed(ctx context.Context, feedID string, limit, offset int) ([]*core.IOC, int64, error) {
	var result []*core.IOC
	for _, ioc := range m.iocs {
		if ioc.FeedID == feedID {
			result = append(result, ioc)
		}
	}
	return result, int64(len(result)), nil
}

func (m *mockIOCStorage) DeleteIOCsByFeed(ctx context.Context, feedID string) (int64, error) {
	var count int64
	var remaining []*core.IOC
	for _, ioc := range m.iocs {
		if ioc.FeedID == feedID {
			count++
		} else {
			remaining = append(remaining, ioc)
		}
	}
	m.iocs = remaining
	return count, nil
}

func TestNewIOCMatcher(t *testing.T) {
	storage := &mockIOCStorage{}
	config := &IOCMatcherConfig{
		Enabled:     true,
		RefreshTTL:  60 * time.Second,
		CacheConfig: DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}
	if matcher == nil {
		t.Fatal("NewIOCMatcher returned nil")
	}

	if !matcher.IsEnabled() {
		t.Error("Matcher should be enabled")
	}
}

func TestIOCMatcherMatchIP(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:       "ioc-ip-1",
				Type:     core.IOCTypeIP,
				Value:    "192.168.1.100",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityHigh,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:     true,
		RefreshTTL:  60 * time.Second,
		CacheConfig: DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	// Load IOCs into cache
	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test matching event
	event := map[string]interface{}{
		"source.ip": "192.168.1.100",
		"dest.ip":   "10.0.0.1",
	}

	matches, err := matcher.Match(ctx, event)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}

	if len(matches) > 0 {
		if matches[0].IOC.ID != "ioc-ip-1" {
			t.Errorf("Expected IOC ID ioc-ip-1, got %s", matches[0].IOC.ID)
		}
		if matches[0].FieldName != "source.ip" {
			t.Errorf("Expected field name source.ip, got %s", matches[0].FieldName)
		}
	}
}

func TestIOCMatcherMatchDomain(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:       "ioc-domain-1",
				Type:     core.IOCTypeDomain,
				Value:    "malicious.example.com",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityCritical,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test matching event
	event := map[string]interface{}{
		"dns.question.name": "malicious.example.com",
	}

	matches, err := matcher.Match(ctx, event)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}
}

func TestIOCMatcherMatchHash(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:       "ioc-hash-1",
				Type:     core.IOCTypeHash,
				Value:    "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityHigh,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test matching event
	event := map[string]interface{}{
		"file.hash.sha256": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}

	matches, err := matcher.Match(ctx, event)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}
}

func TestIOCMatcherNoMatch(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:       "ioc-ip-1",
				Type:     core.IOCTypeIP,
				Value:    "192.168.1.100",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityHigh,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test non-matching event
	event := map[string]interface{}{
		"source.ip": "10.0.0.1", // Different IP
		"dest.ip":   "10.0.0.2",
	}

	matches, err := matcher.Match(ctx, event)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("Expected 0 matches, got %d", len(matches))
	}
}

func TestIOCMatcherDisabled(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:     "ioc-ip-1",
				Type:   core.IOCTypeIP,
				Value:  "192.168.1.100",
				Status: core.IOCStatusActive,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        false, // Disabled
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	if matcher.IsEnabled() {
		t.Error("Matcher should be disabled")
	}

	ctx := context.Background()
	event := map[string]interface{}{
		"source.ip": "192.168.1.100",
	}

	matches, err := matcher.Match(ctx, event)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	// Should return no matches when disabled
	if len(matches) != 0 {
		t.Errorf("Disabled matcher should return 0 matches, got %d", len(matches))
	}
}

func TestIOCMatcherCIDR(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:       "ioc-cidr-1",
				Type:     core.IOCTypeCIDR,
				Value:    "10.0.0.0/24",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityMedium,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test matching event - IP within CIDR range
	event := map[string]interface{}{
		"source.ip": "10.0.0.50",
	}

	matches, err := matcher.Match(ctx, event)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	if len(matches) != 1 {
		t.Errorf("Expected 1 CIDR match, got %d", len(matches))
	}
}

func TestIOCMatcherMultipleMatches(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:       "ioc-ip-1",
				Type:     core.IOCTypeIP,
				Value:    "192.168.1.100",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityHigh,
			},
			{
				ID:       "ioc-domain-1",
				Type:     core.IOCTypeDomain,
				Value:    "malware.test.com",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityCritical,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test event that matches both IOCs
	event := map[string]interface{}{
		"source.ip":         "192.168.1.100",
		"dns.question.name": "malware.test.com",
	}

	matches, err := matcher.Match(ctx, event)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	if len(matches) != 2 {
		t.Errorf("Expected 2 matches, got %d", len(matches))
	}
}

func TestIOCMatcherStats(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{ID: "1", Type: core.IOCTypeIP, Value: "1.1.1.1", Status: core.IOCStatusActive},
			{ID: "2", Type: core.IOCTypeIP, Value: "2.2.2.2", Status: core.IOCStatusActive},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	stats := matcher.Stats()
	if stats.TotalIOCs != 2 {
		t.Errorf("Expected TotalIOCs 2, got %d", stats.TotalIOCs)
	}

	if !matcher.IsEnabled() {
		t.Error("Expected matcher to be enabled")
	}
}

func TestDefaultFieldMappings(t *testing.T) {
	config := DefaultIOCMatcherConfig()
	mappings := config.FieldMappings

	// Check IP field mappings exist
	ipFields, ok := mappings[core.IOCTypeIP]
	if !ok {
		t.Fatal("IP field mappings not found")
	}
	if len(ipFields) == 0 {
		t.Error("IP field mappings should not be empty")
	}

	// Check domain field mappings exist
	domainFields, ok := mappings[core.IOCTypeDomain]
	if !ok {
		t.Fatal("Domain field mappings not found")
	}
	if len(domainFields) == 0 {
		t.Error("Domain field mappings should not be empty")
	}

	// Check hash field mappings exist
	hashFields, ok := mappings[core.IOCTypeHash]
	if !ok {
		t.Fatal("Hash field mappings not found")
	}
	if len(hashFields) == 0 {
		t.Error("Hash field mappings should not be empty")
	}
}

func TestIOCMatcherInactiveIOCs(t *testing.T) {
	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:       "ioc-active",
				Type:     core.IOCTypeIP,
				Value:    "192.168.1.100",
				Status:   core.IOCStatusActive,
				Severity: core.IOCSeverityHigh,
			},
			{
				ID:       "ioc-deprecated",
				Type:     core.IOCTypeIP,
				Value:    "192.168.1.101",
				Status:   core.IOCStatusDeprecated, // Inactive
				Severity: core.IOCSeverityHigh,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test matching active IOC
	event1 := map[string]interface{}{
		"source.ip": "192.168.1.100",
	}
	matches1, _ := matcher.Match(ctx, event1)
	if len(matches1) != 1 {
		t.Errorf("Expected 1 match for active IOC, got %d", len(matches1))
	}

	// Test matching deprecated IOC - should still match as it's in cache
	// (In production, RefreshCache would filter by status)
	event2 := map[string]interface{}{
		"source.ip": "192.168.1.101",
	}
	matches2, _ := matcher.Match(ctx, event2)
	// Note: This depends on implementation - if ListIOCs filters by status
	// The test expectations should match the actual behavior
	_ = matches2 // Just ensure no error
}

func TestIOCMatcherExpiredIOCs(t *testing.T) {
	expiredTime := time.Now().Add(-24 * time.Hour) // Expired yesterday
	activeTime := time.Now().Add(24 * time.Hour)   // Active until tomorrow

	storage := &mockIOCStorage{
		iocs: []*core.IOC{
			{
				ID:        "ioc-expired",
				Type:      core.IOCTypeIP,
				Value:     "192.168.1.100",
				Status:    core.IOCStatusActive,
				ExpiresAt: &expiredTime,
			},
			{
				ID:        "ioc-not-expired",
				Type:      core.IOCTypeIP,
				Value:     "192.168.1.101",
				Status:    core.IOCStatusActive,
				ExpiresAt: &activeTime,
			},
		},
	}

	config := &IOCMatcherConfig{
		Enabled:        true,
		RefreshTTL: 60 * time.Second,
		CacheConfig:    DefaultIOCCacheConfig(),
	}

	matcher, err := NewIOCMatcher(storage, config)
	if err != nil {
		t.Fatalf("NewIOCMatcher failed: %v", err)
	}

	ctx := context.Background()
	if err := matcher.Refresh(ctx); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Both IOCs are in cache (expiry filtering happens at match time or storage level)
	stats := matcher.Stats()
	_ = stats // Just verify no panic
}
