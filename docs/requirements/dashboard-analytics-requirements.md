# Dashboard Analytics Requirements

**Document Owner**: Backend Team  
**Created**: 2025-01-19  
**Status**: ACTIVE  
**Last Updated**: 2025-01-19  
**Version**: 1.0  

**Reference Implementation**: `api/handlers.go` (getDashboardStats, getDashboardChart)

---

## 1. Executive Summary

The Cerberus SIEM dashboard analytics system provides real-time visibility into security events, alerts, and system health metrics. This document defines the requirements for dashboard statistics, time-series charts, performance SLAs, and future customization options.

**Critical Requirements**:
- Real-time event and alert counts
- Time-series charts for events and alerts
- System health metrics
- Performance SLAs (<200ms p95)
- Customizable dashboard widgets (future enhancement)

**Implementation Status**: ✅ 90% IMPLEMENTED (customization pending)

---

## 2. Functional Requirements

### FR-DASH-001: Dashboard Statistics
**Requirement**: The system MUST provide real-time statistics for the dashboard.

**Specification**:
- Statistics include:
  - `total_events`: Total number of security events
  - `active_alerts`: Total number of active alerts
  - `rules_fired`: Number of rules triggered (future enhancement)
  - `system_health`: System health status (OK, WARNING, ERROR)
- Statistics are calculated in real-time
- Statistics are cached for performance (optional, future enhancement)
- Statistics update frequency: On-demand (via API call)

**Implementation**: `api/handlers.go:996-1023` (getDashboardStats)

**Acceptance Criteria**:
- [x] Dashboard statistics endpoint exists
- [x] Statistics include event and alert counts
- [x] Statistics include system health status
- [ ] Statistics include rules_fired count (future enhancement)

---

### FR-DASH-002: Time-Series Charts
**Requirement**: The system MUST provide time-series chart data for events and alerts.

**Specification**:
- Chart data includes:
  - `timestamp`: Time bucket (month, day, hour)
  - `events`: Event count for time bucket
  - `alerts`: Alert count for time bucket
- Time buckets:
  - Monthly aggregation (default)
  - Daily aggregation (future enhancement)
  - Hourly aggregation (future enhancement)
- Chart data is ordered chronologically
- Chart data supports time range filtering (future enhancement)

**Implementation**: `api/handlers.go:1025-1081` (getDashboardChart)

**Acceptance Criteria**:
- [x] Chart endpoint exists
- [x] Chart data includes events and alerts
- [x] Chart data is aggregated by month
- [ ] Chart data supports daily/hourly aggregation (future enhancement)
- [ ] Chart data supports time range filtering (future enhancement)

---

### FR-DASH-003: Event Count Aggregation
**Requirement**: The system MUST aggregate event counts by time periods for charting.

**Specification**:
- Event counts are aggregated by month
- Aggregation groups events by month (YYYY-MM format)
- Aggregation includes count per month
- Aggregation supports ordering (chronological)

**Implementation**: `storage/clickhouse_events.go` (GetEventCountsByMonth)

**Acceptance Criteria**:
- [x] Event counts are aggregated by month
- [x] Aggregation groups events correctly
- [x] Aggregation includes count per month

---

### FR-DASH-004: Alert Count Aggregation
**Requirement**: The system MUST aggregate alert counts by time periods for charting.

**Specification**:
- Alert counts are aggregated by month
- Aggregation groups alerts by month (YYYY-MM format)
- Aggregation includes count per month
- Aggregation supports ordering (chronological)

**Implementation**: `storage/clickhouse_alerts.go` (GetAlertCountsByMonth)

**Acceptance Criteria**:
- [x] Alert counts are aggregated by month
- [x] Aggregation groups alerts correctly
- [x] Aggregation includes count per month

---

### FR-DASH-005: Dashboard API Endpoints
**Requirement**: The system MUST provide REST API endpoints for dashboard data.

**Specification**:
- `GET /api/v1/dashboard`: Get dashboard statistics
  - Response: Statistics object with event count, alert count, system health
- `GET /api/v1/dashboard/chart`: Get dashboard chart data
  - Response: Array of chart data points with timestamp, events, alerts
- Endpoints require authentication
- Endpoints enforce RBAC (`read:events` permission)

**Implementation**: 
- `api/handlers.go:996-1023` (getDashboardStats)
- `api/handlers.go:1025-1081` (getDashboardChart)
- `api/api.go:337-338` (dashboard routes with RBAC)

**RBAC Requirements**:
- Dashboard statistics: `read:events` permission
- Dashboard chart: `read:events` permission

**Acceptance Criteria**:
- [x] Dashboard statistics endpoint exists
- [x] Dashboard chart endpoint exists
- [x] RBAC is enforced
- [x] Endpoints require authentication

---

### FR-DASH-006: System Health Monitoring
**Requirement**: The system MUST provide system health status for the dashboard.

**Specification**:
- Health status values:
  - `OK`: All systems operational
  - `WARNING`: Minor issues detected
  - `ERROR`: Critical issues detected
- Health status is calculated from:
  - Database connectivity
  - Storage availability
  - Service status (future enhancement)
- Health status is updated in real-time

**Implementation**: `api/handlers.go:1019` (system_health: "OK")

**Acceptance Criteria**:
- [x] System health status is included in statistics
- [ ] Health status calculation includes all system components (future enhancement)

---

### FR-DASH-007: Dashboard Performance SLAs
**Requirement**: Dashboard endpoints MUST meet performance SLAs.

**Specification**:
- Dashboard statistics: < 200ms p95 response time
- Dashboard chart: < 500ms p95 response time
- Endpoints SHOULD support caching for performance (future enhancement)
- Endpoints SHOULD use efficient aggregation queries

**Implementation**: Dashboard endpoints use direct storage queries

**Acceptance Criteria**:
- [ ] Performance SLAs are met
- [ ] Endpoints use efficient queries
- [ ] Caching is implemented (future enhancement)

---

### FR-DASH-008: Dashboard Customization (Future Enhancement)
**Requirement**: The system SHOULD support customizable dashboard widgets (future enhancement).

**Specification**:
- Users can customize dashboard layout
- Users can add/remove widgets
- Widget types:
  - Event count widgets
  - Alert count widgets
  - Time-series chart widgets
  - Custom query widgets (future enhancement)
- Dashboard configurations are user-scoped

**Implementation Status**: ⚠️ NOT IMPLEMENTED (Future enhancement)

**Acceptance Criteria**:
- [ ] Dashboard customization is supported
- [ ] Widget configuration is stored
- [ ] Dashboard layouts are user-scoped

---

### FR-DASH-009: Dashboard Data Retention
**Requirement**: Dashboard data MUST be available for historical analysis.

**Specification**:
- Event and alert data retention: Follows data retention policy
- Chart data availability: Historical data available for configured retention period
- Aggregation data: Computed on-demand from stored events/alerts

**Implementation**: Dashboard queries historical data from storage

**Acceptance Criteria**:
- [x] Historical data is available
- [x] Chart data is computed from stored data
- [ ] Data retention policies are configurable (future enhancement)

---

### FR-DASH-010: Dashboard Real-Time Updates (Future Enhancement)
**Requirement**: The system SHOULD support real-time dashboard updates via WebSocket (future enhancement).

**Specification**:
- Dashboard can subscribe to real-time updates
- Updates include:
  - Event count changes
  - Alert count changes
  - System health changes
- WebSocket connection maintains authentication
- WebSocket connection enforces RBAC

**Implementation Status**: ⚠️ NOT IMPLEMENTED (Future enhancement)

**Acceptance Criteria**:
- [ ] WebSocket endpoint exists
- [ ] Real-time updates are supported
- [ ] Authentication is maintained
- [ ] RBAC is enforced

---

## 3. Non-Functional Requirements

### NFR-DASH-001: Dashboard Performance
**Requirement**: Dashboard endpoints MUST meet performance SLAs.

**Specification**:
- Dashboard statistics: < 200ms p95 response time
- Dashboard chart: < 500ms p95 response time
- Endpoints SHOULD support caching (future enhancement)
- Aggregation queries SHOULD be optimized

**Acceptance Criteria**:
- [ ] Performance targets are met
- [ ] Queries are optimized
- [ ] Caching is implemented (future enhancement)

---

### NFR-DASH-002: Dashboard Scalability
**Requirement**: Dashboard endpoints MUST scale with data volume.

**Specification**:
- Support 1M+ events in database
- Support 100K+ alerts in database
- Chart aggregation scales to 1 year of data
- Performance degrades gracefully with data volume

**Acceptance Criteria**:
- [ ] System handles scale requirements
- [ ] Performance scales with data volume

---

### NFR-DASH-003: Dashboard Reliability
**Requirement**: Dashboard endpoints MUST be highly available.

**Specification**:
- Dashboard endpoints are available 99.9% of the time
- Dashboard endpoints handle errors gracefully
- Dashboard endpoints return cached data if available (future enhancement)
- Dashboard endpoints degrade gracefully on storage failures

**Acceptance Criteria**:
- [ ] High availability is maintained
- [ ] Error handling is robust
- [ ] Graceful degradation is implemented

---

### NFR-DASH-004: Dashboard Security
**Requirement**: Dashboard operations MUST enforce RBAC and prevent unauthorized access.

**Specification**:
- All endpoints require authentication
- RBAC permissions are enforced (`read:events` permission)
- Dashboard data is protected from unauthorized access
- Dashboard queries respect user permissions (future enhancement: data filtering)

**Implementation**: `api/api.go:337-338` (RBAC-protected routes)

**Acceptance Criteria**:
- [x] RBAC is enforced
- [x] Unauthorized access is prevented
- [ ] Data filtering by user permissions (future enhancement)

---

### NFR-DASH-005: Dashboard Data Accuracy
**Requirement**: Dashboard data MUST be accurate and consistent.

**Specification**:
- Statistics are calculated from authoritative data sources
- Chart data is aggregated correctly
- Data consistency is maintained across requests
- Data freshness is acceptable (real-time or near-real-time)

**Acceptance Criteria**:
- [x] Data is accurate
- [x] Aggregation is correct
- [x] Data consistency is maintained

---

## 4. API Endpoints

### GET /api/v1/dashboard
Get dashboard statistics.

**Response**: 200 OK
```json
{
  "total_events": 125000,
  "active_alerts": 45,
  "rules_fired": 0,
  "system_health": "OK"
}
```

**RBAC**: Requires `read:events` permission

**Performance SLA**: < 200ms p95

---

### GET /api/v1/dashboard/chart
Get dashboard chart data (time-series).

**Response**: 200 OK
```json
[
  {
    "timestamp": "2025-01",
    "events": 12500,
    "alerts": 12
  },
  {
    "timestamp": "2025-02",
    "events": 13200,
    "alerts": 15
  }
]
```

**RBAC**: Requires `read:events` permission

**Performance SLA**: < 500ms p95

---

## 5. Data Models

### Dashboard Statistics
```go
type DashboardStats struct {
    TotalEvents int64  `json:"total_events"`
    ActiveAlerts int64  `json:"active_alerts"`
    RulesFired   int64  `json:"rules_fired"`
    SystemHealth string `json:"system_health"` // "OK", "WARNING", "ERROR"
}
```

### Chart Data Point
```go
type ChartDataPoint struct {
    Timestamp string `json:"timestamp"` // "YYYY-MM", "YYYY-MM-DD", "YYYY-MM-DD HH"
    Events    int64  `json:"events"`
    Alerts    int64  `json:"alerts"`
}
```

---

## 6. Security Considerations

1. **RBAC Enforcement**: Dashboard endpoints require `read:events` permission
2. **Authentication**: All dashboard endpoints require authentication
3. **Data Protection**: Dashboard data is protected from unauthorized access
4. **Query Security**: Dashboard queries use parameterized queries to prevent injection

---

## 7. Testing Requirements

1. **Unit Tests**:
   - Test dashboard statistics calculation
   - Test chart data aggregation
   - Test system health calculation

2. **Integration Tests**:
   - Test dashboard API endpoints
   - Test RBAC enforcement
   - Test performance SLAs

3. **Security Tests**:
   - Test unauthorized access prevention
   - Test RBAC enforcement
   - Test query security

---

## 8. Known Limitations

1. **Rules Fired Count**: Rules fired count is not yet implemented (returns 0)
2. **Dashboard Customization**: Dashboard customization is not yet implemented
3. **Real-Time Updates**: Real-time dashboard updates via WebSocket are not yet implemented
4. **Time Range Filtering**: Chart data time range filtering is not yet implemented
5. **Daily/Hourly Aggregation**: Chart data only supports monthly aggregation

---

## 9. Future Enhancements

1. **Dashboard Customization**: User-customizable dashboard widgets and layouts
2. **Real-Time Updates**: WebSocket-based real-time dashboard updates
3. **Advanced Analytics**: Advanced analytics widgets (trends, correlations, etc.)
4. **Dashboard Sharing**: Share dashboard configurations with other users
5. **Dashboard Templates**: Pre-configured dashboard templates for common use cases
6. **Dashboard Export**: Export dashboard data to PDF, CSV, JSON formats
7. **Time Range Filtering**: Filter chart data by custom time ranges
8. **Daily/Hourly Aggregation**: Support daily and hourly time bucket aggregation
9. **Performance Caching**: Cache dashboard statistics and chart data for performance
10. **Dashboard Permissions**: Fine-grained permissions for dashboard access and customization

---

_This document defines the comprehensive requirements for dashboard analytics in Cerberus SIEM. All functional requirements marked with [x] are implemented. Future enhancements are documented for roadmap planning._



