-- ============================================================
-- Cerberus SIEM - ClickHouse Schema
-- ============================================================
-- This schema is optimized for high-volume time-series data
-- Expected performance: 500k+ EPS, 50x compression, sub-100ms queries
-- ============================================================

-- ============================================================
-- EVENTS TABLE - High-volume time-series log data
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
    -- Identity
    event_id String,
    timestamp DateTime64(3, 'UTC'),  -- Millisecond precision

    -- Event classification
    event_type LowCardinality(String),  -- Automatic dictionary encoding for <10k unique values
    severity LowCardinality(String),    -- low, medium, high, critical
    source_format LowCardinality(String),  -- syslog, cef, json, windows_event

    -- Network information (using native types for efficiency)
    source_ip IPv4,      -- 4 bytes instead of 15+ for string
    source_port UInt16,
    dest_ip IPv4,
    dest_port UInt16,

    -- Data payloads
    raw_data String,
    parsed_data String,  -- JSON string for flexible data

    -- Context fields
    hostname LowCardinality(String),
    username String,
    process_name LowCardinality(String),

    -- Bloom filter indexes for fast lookups
    INDEX idx_event_type event_type TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_source_ip source_ip TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_severity severity TYPE set(0) GRANULARITY 1,
    INDEX idx_hostname hostname TYPE bloom_filter(0.01) GRANULARITY 1

) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)  -- Monthly partitions (can drop entire month instantly)
ORDER BY (timestamp, event_type, source_ip)  -- Primary key (data is sorted by this)
TTL timestamp + INTERVAL 30 DAY  -- Auto-delete events older than 30 days
SETTINGS
    index_granularity = 8192,  -- Default granularity (good for most workloads)
    min_bytes_for_wide_part = 10485760;  -- 10MB before using wide format

-- ============================================================
-- ALERTS TABLE - Medium-volume time-series alert data
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    -- Identity
    alert_id String,
    created_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC'),

    -- Rule information
    rule_id String,
    rule_name String,
    event_id String,

    -- Classification
    severity LowCardinality(String),  -- low, medium, high, critical
    status LowCardinality(String),    -- open, acknowledged, closed, false_positive

    -- Context
    source_ip IPv4,
    event_type LowCardinality(String),
    raw_event String,  -- Full event data for investigation

    -- Lifecycle tracking
    acknowledged_by String,
    acknowledged_at Nullable(DateTime64(3, 'UTC')),
    closed_at Nullable(DateTime64(3, 'UTC')),
    notes String,

    -- TASK 101: Disposition workflow fields
    disposition LowCardinality(String) DEFAULT 'undetermined',  -- undetermined, true_positive, false_positive, benign
    disposition_reason String DEFAULT '',  -- User-provided reason for disposition
    disposition_set_at Nullable(DateTime64(3, 'UTC')),  -- When disposition was set
    disposition_set_by String DEFAULT '',  -- Who set the disposition
    investigation_id String DEFAULT '',  -- Link to investigation if any

    -- Indexes for common queries
    INDEX idx_rule_id rule_id TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_status status TYPE set(0) GRANULARITY 1,
    INDEX idx_severity severity TYPE set(0) GRANULARITY 1,
    INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_disposition disposition TYPE set(0) GRANULARITY 1

) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)  -- Monthly partitions
ORDER BY (created_at, severity, status, rule_id)
TTL created_at + INTERVAL 90 DAY  -- Auto-delete alerts older than 90 days
SETTINGS index_granularity = 8192;

-- ============================================================
-- MATERIALIZED VIEWS - Pre-aggregated analytics for dashboards
-- ============================================================

-- Hourly event counts by type (for timeline charts)
CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, event_type)
AS SELECT
    toStartOfHour(timestamp) as hour,
    event_type,
    count() as event_count
FROM events
GROUP BY hour, event_type;

-- Daily alert counts by severity (for dashboard KPIs)
CREATE MATERIALIZED VIEW IF NOT EXISTS alerts_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, severity, status)
AS SELECT
    toDate(created_at) as day,
    severity,
    status,
    count() as alert_count
FROM alerts
GROUP BY day, severity, status;

-- Top source IPs by event count (for threat detection)
CREATE MATERIALIZED VIEW IF NOT EXISTS top_source_ips_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_ip)
AS SELECT
    toStartOfHour(timestamp) as hour,
    source_ip,
    event_type,
    count() as event_count
FROM events
WHERE source_ip != IPv4StringToNum('0.0.0.0')
GROUP BY hour, source_ip, event_type;

-- Event counts by severity over time (for trend analysis)
CREATE MATERIALIZED VIEW IF NOT EXISTS events_by_severity_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, severity)
AS SELECT
    toStartOfHour(timestamp) as hour,
    severity,
    count() as event_count
FROM events
GROUP BY hour, severity;

-- ============================================================
-- HELPER FUNCTIONS (use in queries)
-- ============================================================

-- Example queries using the schema:

-- Get recent events
-- SELECT event_id, timestamp, event_type, IPv4NumToString(source_ip) as source_ip, severity
-- FROM events
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Count events by type in last 24 hours
-- SELECT event_type, count() as count
-- FROM events
-- WHERE timestamp >= now() - INTERVAL 24 HOUR
-- GROUP BY event_type
-- ORDER BY count DESC;

-- Get top source IPs in last hour
-- SELECT IPv4NumToString(source_ip) as source_ip, count() as count
-- FROM events
-- WHERE timestamp >= now() - INTERVAL 1 HOUR
-- GROUP BY source_ip
-- ORDER BY count DESC
-- LIMIT 10;

-- Event timeline (1 hour buckets)
-- SELECT toStartOfHour(timestamp) as hour, count() as count
-- FROM events
-- WHERE timestamp >= now() - INTERVAL 24 HOUR
-- GROUP BY hour
-- ORDER BY hour ASC;

-- Alert statistics by status
-- SELECT status, count() as count
-- FROM alerts
-- WHERE created_at >= now() - INTERVAL 7 DAY
-- GROUP BY status;
