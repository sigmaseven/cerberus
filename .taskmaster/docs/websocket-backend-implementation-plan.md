# WebSocket Backend Implementation Plan for Cerberus SIEM

**Version:** 1.0
**Date:** 2025-12-01
**Status:** Planning
**Priority:** High
**Estimated Complexity:** Medium-High

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Implementation Phases](#3-implementation-phases)
4. [Detailed Component Specifications](#4-detailed-component-specifications)
5. [Integration Points](#5-integration-points)
6. [Security Requirements](#6-security-requirements)
7. [Testing Strategy](#7-testing-strategy)
8. [Performance & Scalability](#8-performance--scalability)
9. [Monitoring & Observability](#9-monitoring--observability)
10. [Deployment Considerations](#10-deployment-considerations)

---

## 1. Executive Summary

### 1.1 Purpose

Implement real-time bidirectional communication between the Cerberus backend and frontend clients (web and Electron) using WebSocket protocol. This enables instant delivery of security events, alerts, listener status updates, and dashboard metrics without polling.

### 1.2 Goals

- **Real-time Event Streaming**: Push new security events to connected clients as they're ingested
- **Alert Notifications**: Instant delivery of newly generated alerts
- **Dashboard Live Updates**: Real-time KPI updates (events/sec, active alerts, system health)
- **Listener Status**: Live monitoring of data source health and throughput
- **Investigation Updates**: Collaborative investigation features with live updates

### 1.3 Success Criteria

- ✅ WebSocket endpoint `/ws` accepts authenticated connections
- ✅ Clients receive events within 2 seconds of ingestion
- ✅ Support for 1000+ concurrent WebSocket connections
- ✅ Automatic reconnection handling with exponential backoff
- ✅ RBAC filtering - clients only receive data they're authorized to see
- ✅ Zero message loss during normal operation
- ✅ Graceful degradation when WebSocket unavailable (fallback to polling)

### 1.4 Non-Goals (Out of Scope)

- ❌ Client-to-server commands via WebSocket (use REST API instead)
- ❌ Binary protocol implementation (stick with JSON for simplicity)
- ❌ Multi-region WebSocket synchronization (single-region deployment)
- ❌ WebSocket compression (can be added later if needed)

---

## 2. Architecture Overview

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CERBERUS BACKEND                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────┐                                                     │
│  │  HTTP Request  │──────────────┐                                      │
│  │  GET /ws       │              │                                      │
│  │  + JWT Token   │              ▼                                      │
│  └────────────────┘     ┌──────────────────┐                           │
│                         │  WebSocket Hub   │                           │
│                         │  (Central Mgr)   │                           │
│                         └──────────────────┘                           │
│                                  │                                      │
│              ┌───────────────────┼───────────────────┐                 │
│              │                   │                   │                 │
│              ▼                   ▼                   ▼                 │
│     ┌─────────────┐     ┌─────────────┐    ┌─────────────┐            │
│     │  Client 1   │     │  Client 2   │    │  Client N   │            │
│     │  (Analyst)  │     │  (Manager)  │    │  (Admin)    │            │
│     │  Perms: R-E │     │  Perms: ALL │    │  Perms: R-A │            │
│     └─────────────┘     └─────────────┘    └─────────────┘            │
│              ▲                   ▲                   ▲                 │
│              │                   │                   │                 │
│              └───────────────────┴───────────────────┘                 │
│                                  │                                      │
│                         ┌────────┴────────┐                            │
│                         │  Broadcast Bus  │                            │
│                         │  (Channel)      │                            │
│                         └────────┬────────┘                            │
│                                  │                                      │
│              ┌───────────────────┼───────────────────┐                 │
│              │                   │                   │                 │
│              ▼                   ▼                   ▼                 │
│     ┌─────────────┐     ┌─────────────┐    ┌─────────────┐            │
│     │   Ingest    │     │   Detect    │    │  Dashboard  │            │
│     │  Manager    │     │   Engine    │    │  Updater    │            │
│     │  (Events)   │     │  (Alerts)   │    │  (Stats)    │            │
│     └─────────────┘     └─────────────┘    └─────────────┘            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

| Component | Responsibility | File Location |
|-----------|----------------|---------------|
| **WebSocketHub** | Manages all client connections, subscriptions, broadcasting | `api/websocket_hub.go` |
| **WebSocketClient** | Represents single client connection with send/receive channels | `api/websocket_client.go` |
| **WebSocketHandler** | HTTP upgrade handler, JWT authentication | `api/websocket_handlers.go` |
| **MessageBroadcaster** | Queues and distributes messages to appropriate clients | `api/websocket_broadcaster.go` |
| **SubscriptionManager** | Manages client subscriptions to message types | `api/websocket_subscriptions.go` |

### 2.3 Message Flow

```
INGEST FLOW:
Event Ingested → IngestManager → WebSocketHub.Broadcast(event) →
  → Clients with read:events permission receive message

ALERT FLOW:
Rule Match → DetectionEngine → WebSocketHub.Broadcast(alert) →
  → Clients with read:alerts permission receive message

DASHBOARD FLOW:
Background Ticker (5s) → Dashboard Calculator → WebSocketHub.Broadcast(stats) →
  → All authenticated clients receive message

LISTENER STATUS FLOW:
Listener Health Check → Listener Manager → WebSocketHub.Broadcast(status) →
  → Clients with read:listeners permission receive message
```

### 2.4 Data Flow Diagram

```
┌──────────────┐
│ Event Source │ (Syslog, CEF, JSON)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│IngestManager │ Parses & stores event in ClickHouse
└──────┬───────┘
       │
       ├─────────────────────────────────────────────┐
       │                                             │
       ▼                                             ▼
┌──────────────┐                              ┌──────────────┐
│DetectEngine  │ Evaluates rules              │WebSocketHub  │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │ (If rule matches)                           │
       │                                             │
       ▼                                             │
┌──────────────┐                                     │
│Create Alert  │                                     │
└──────┬───────┘                                     │
       │                                             │
       └──────────────┬──────────────────────────────┘
                      │
                      ▼
            ┌──────────────────┐
            │ Broadcast to ALL │
            │  WS Clients      │
            └────────┬─────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
         ▼           ▼           ▼
    ┌────────┐  ┌────────┐  ┌────────┐
    │Client 1│  │Client 2│  │Client N│
    └────────┘  └────────┘  └────────┘
    (Filtered   (Filtered   (Filtered
     by RBAC)    by RBAC)    by RBAC)
```

---

## 3. Implementation Phases

### Phase 1: Foundation (Week 1)
**Goal**: Basic WebSocket infrastructure with authentication

#### Tasks:
1. **Add gorilla/websocket dependency**
   - Run: `go get github.com/gorilla/websocket`
   - Update `go.mod` and `go.sum`

2. **Create WebSocket Hub skeleton**
   - File: `api/websocket_hub.go`
   - Implement connection registry (map of clientID → client)
   - Implement register/unregister channels
   - Create background goroutine for hub management

3. **Implement WebSocket client wrapper**
   - File: `api/websocket_client.go`
   - Wrap `*websocket.Conn` with send/receive channels
   - Add user context (username, permissions)
   - Implement read/write pumps

4. **Create HTTP upgrade handler**
   - File: `api/websocket_handlers.go`
   - Extract JWT token from query param or cookie
   - Validate authentication and extract user claims
   - Upgrade HTTP connection to WebSocket
   - Register client with hub

5. **Register `/ws` route**
   - File: `api/api.go` in `setupRoutes()`
   - Add route: `a.router.HandleFunc("/ws", a.handleWebSocket)`
   - Optional: Add to protected routes if auth required

6. **Basic ping/pong heartbeat**
   - Implement ping every 30 seconds
   - Close connection if no pong within 60 seconds

**Deliverables**:
- ✅ WebSocket endpoint accessible at `ws://localhost:8081/ws`
- ✅ Clients can connect with valid JWT token
- ✅ Connection stays alive with heartbeat
- ✅ Unit tests for hub register/unregister

**Testing**:
```bash
# Test WebSocket connection with wscat
npm install -g wscat
wscat -c "ws://localhost:8081/ws?token=YOUR_JWT_TOKEN"

# Should receive heartbeat pings
```

---

### Phase 2: Message Broadcasting (Week 2)
**Goal**: Broadcast messages to all connected clients

#### Tasks:
1. **Define message types**
   - File: `api/websocket_messages.go`
   - Create `WebSocketMessage` struct
   - Define message types: event, alert, dashboard_stats, listener_status
   - Implement JSON marshaling

2. **Implement broadcast channel**
   - Add broadcast channel to Hub: `broadcast chan *WebSocketMessage`
   - Create goroutine that reads from channel and distributes to clients
   - Handle client send buffer overflow (skip slow clients)

3. **Create broadcaster utility**
   - File: `api/websocket_broadcaster.go`
   - Helper function: `BroadcastEvent(event core.Event)`
   - Helper function: `BroadcastAlert(alert core.Alert)`
   - Helper function: `BroadcastDashboardStats(stats DashboardStats)`

4. **Integrate with IngestManager**
   - File: `ingest/manager.go`
   - After storing event, call `wsHub.BroadcastEvent(event)`
   - Add feature flag in config to enable/disable

5. **Integrate with DetectionEngine**
   - File: `detect/engine.go`
   - After creating alert, call `wsHub.BroadcastAlert(alert)`
   - Ensure no circular dependencies

6. **Create dashboard stats broadcaster**
   - Background goroutine that runs every 5 seconds
   - Calculates current stats (total_events, active_alerts, eps, etc.)
   - Broadcasts to all connected clients

**Deliverables**:
- ✅ Clients receive real-time events as they're ingested
- ✅ Clients receive alerts immediately when generated
- ✅ Clients receive dashboard stats every 5 seconds
- ✅ Integration tests for end-to-end flow

**Testing**:
```bash
# Connect with wscat and send test event via API
wscat -c "ws://localhost:8081/ws?token=TOKEN"

# In another terminal, ingest event
curl -X POST http://localhost:8081/api/v1/events \
  -H "Authorization: Bearer TOKEN" \
  -d '{"message": "test event"}'

# Should see event appear in wscat output
```

---

### Phase 3: RBAC & Filtering (Week 3)
**Goal**: Filter messages based on user permissions

#### Tasks:
1. **Store user permissions in WebSocketClient**
   - Extract permissions from JWT claims during upgrade
   - Store in `client.permissions` field
   - Types: read:events, read:alerts, read:listeners

2. **Implement permission checker**
   - File: `api/websocket_permissions.go`
   - Function: `canReceiveMessage(client *Client, msgType string) bool`
   - Check if user has required permission for message type

3. **Add filtering to broadcast**
   - Before sending message to client, check permissions
   - Skip clients without required permission
   - Log skipped clients (debug level)

4. **Create subscription system (optional)**
   - Allow clients to subscribe to specific message types
   - Default: subscribe to all types user has permission for
   - Message: `{"type": "subscribe", "topics": ["events", "alerts"]}`

5. **Implement message filtering by severity**
   - Allow clients to filter alerts by severity (e.g., only critical/high)
   - Store filter preferences in client context
   - Apply during broadcast

6. **Add investigation-specific broadcasts**
   - When investigation updated, broadcast to users assigned to it
   - Enables collaborative investigation features

**Deliverables**:
- ✅ Users only receive messages they're authorized to see
- ✅ Subscription system allows granular control
- ✅ Investigation updates go to relevant users only
- ✅ RBAC integration tests

**Testing**:
```go
// Test: User without read:alerts permission should not receive alerts
func TestRBACFiltering(t *testing.T) {
    // Create client with only read:events permission
    // Broadcast alert message
    // Assert client did NOT receive alert
    // Assert client DID receive event
}
```

---

### Phase 4: Security & Rate Limiting (Week 4)
**Goal**: Production-grade security and abuse prevention

#### Tasks:
1. **Implement connection limits**
   - File: `api/websocket_limits.go`
   - Max connections per user: 5 (configurable)
   - Max total connections: 1000 (configurable)
   - Reject new connections when limit reached

2. **Add rate limiting**
   - Reuse existing `MultiTierRateLimiter`
   - Limit WebSocket upgrade attempts (10/min per IP)
   - Limit message send rate (100 messages/min per client)
   - Implement backpressure for slow clients

3. **Implement message validation**
   - Validate all outbound messages match schema
   - Sanitize event data to prevent XSS
   - Truncate large messages (max 1MB per message)

4. **Add CORS validation**
   - Implement `CheckOrigin` function in upgrader
   - Allow origins from config file
   - Reject connections from unauthorized origins

5. **Implement graceful shutdown**
   - On server shutdown, send close message to all clients
   - Wait up to 10 seconds for clients to disconnect
   - Force-close remaining connections
   - File: `api/websocket_shutdown.go`

6. **Add connection metadata logging**
   - Log new connections (IP, user, timestamp)
   - Log disconnections (reason, duration)
   - Track connection statistics for monitoring

**Deliverables**:
- ✅ Connection limits prevent resource exhaustion
- ✅ Rate limiting prevents abuse
- ✅ CORS validation prevents unauthorized origins
- ✅ Graceful shutdown ensures clean disconnections
- ✅ Security tests for all protections

**Configuration** (`config.yaml`):
```yaml
api:
  websocket:
    enabled: true
    max_connections_per_user: 5
    max_total_connections: 1000
    upgrade_rate_limit: 10 # per minute per IP
    message_rate_limit: 100 # per minute per client
    ping_interval: 30s
    pong_wait: 60s
    write_wait: 10s
    max_message_size: 1048576 # 1MB
    allowed_origins:
      - "http://localhost:3000"
      - "https://cerberus.example.com"
```

---

### Phase 5: Scalability & Performance (Week 5)
**Goal**: Optimize for high-throughput scenarios

#### Tasks:
1. **Implement buffered channels**
   - Use buffered channels for client send (capacity: 256)
   - Drop messages if buffer full (slow client protection)
   - Emit metric when messages dropped

2. **Add Redis Pub/Sub for multi-server support**
   - File: `api/websocket_redis.go`
   - When broadcasting, publish to Redis channel
   - Each server subscribes and forwards to local clients
   - Enables horizontal scaling across multiple API servers

3. **Optimize message serialization**
   - Pre-serialize common messages (dashboard stats)
   - Cache serialized JSON to avoid repeated marshaling
   - Use `json.RawMessage` for pass-through data

4. **Implement connection pooling**
   - Reuse goroutines for read/write pumps
   - Use worker pools for message processing
   - Reduce goroutine churn

5. **Add message batching (optional)**
   - Batch multiple events into single WebSocket frame
   - Reduces protocol overhead
   - Configurable batch size (10 messages) and timeout (100ms)

6. **Performance benchmarking**
   - File: `api/websocket_benchmark_test.go`
   - Benchmark 1000 concurrent connections
   - Benchmark 10,000 messages/sec throughput
   - Measure memory usage and GC pressure

**Deliverables**:
- ✅ Support 1000+ concurrent connections
- ✅ Handle 10,000+ messages/sec throughput
- ✅ Multi-server support via Redis Pub/Sub
- ✅ Performance benchmarks
- ✅ Load testing results

**Redis Pub/Sub Architecture**:
```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  API Server 1│     │  API Server 2│     │  API Server 3│
│              │     │              │     │              │
│ ┌──────────┐ │     │ ┌──────────┐ │     │ ┌──────────┐ │
│ │WS Clients│ │     │ │WS Clients│ │     │ │WS Clients│ │
│ └────┬─────┘ │     │ └────┬─────┘ │     │ └────┬─────┘ │
│      │       │     │      │       │     │      │       │
│      ▼       │     │      ▼       │     │      ▼       │
│ ┌──────────┐ │     │ ┌──────────┐ │     │ ┌──────────┐ │
│ │WS Hub    │ │     │ │WS Hub    │ │     │ │WS Hub    │ │
│ └────┬─────┘ │     │ └────┬─────┘ │     │ └────┬─────┘ │
│      │       │     │      │       │     │      │       │
└──────┼───────┘     └──────┼───────┘     └──────┼───────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │  Redis Pub/Sub  │
                   │  Channel: "ws"  │
                   └─────────────────┘
```

---

### Phase 6: Monitoring & Observability (Week 6)
**Goal**: Full visibility into WebSocket operations

#### Tasks:
1. **Add Prometheus metrics**
   - File: `metrics/websocket_metrics.go`
   - Metrics:
     - `cerberus_websocket_connections_active` (gauge)
     - `cerberus_websocket_connections_total` (counter)
     - `cerberus_websocket_messages_sent_total` (counter by type)
     - `cerberus_websocket_messages_dropped_total` (counter)
     - `cerberus_websocket_errors_total` (counter)
     - `cerberus_websocket_latency_seconds` (histogram)

2. **Implement structured logging**
   - Use `zap.SugaredLogger` for all WebSocket logs
   - Log levels:
     - DEBUG: Connection events, message sends
     - INFO: Client connect/disconnect
     - WARN: Rate limit hits, slow clients
     - ERROR: Upgrade failures, broadcast errors
   - Include correlation IDs for request tracing

3. **Add health check endpoint**
   - Endpoint: `GET /api/v1/websocket/health`
   - Returns: active connections, hub status, uptime
   - Used by monitoring systems

4. **Create WebSocket dashboard**
   - Grafana dashboard JSON
   - Panels:
     - Active connections over time
     - Message throughput by type
     - Connection duration histogram
     - Error rate by type
     - Latency percentiles (p50, p95, p99)

5. **Implement alerting rules**
   - Alert if connection count > 900 (approaching limit)
   - Alert if error rate > 5%
   - Alert if message drop rate > 1%
   - Alert if Redis Pub/Sub disconnected

6. **Add distributed tracing (optional)**
   - OpenTelemetry integration
   - Trace WebSocket upgrade flow
   - Trace message broadcast path
   - Correlate with HTTP requests

**Deliverables**:
- ✅ Comprehensive Prometheus metrics
- ✅ Structured logging with correlation IDs
- ✅ Health check endpoint
- ✅ Grafana dashboard
- ✅ Alerting rules configured

**Example Metrics Query**:
```promql
# Active WebSocket connections
cerberus_websocket_connections_active

# Message throughput rate (last 5 minutes)
rate(cerberus_websocket_messages_sent_total[5m])

# 95th percentile latency
histogram_quantile(0.95, cerberus_websocket_latency_seconds_bucket)
```

---

### Phase 7: Testing & Quality Assurance (Week 7)
**Goal**: Comprehensive test coverage

#### Tasks:
1. **Unit tests**
   - File: `api/websocket_hub_test.go`
   - Test: Register/unregister clients
   - Test: Broadcast to all clients
   - Test: Permission filtering
   - Test: Subscription management
   - Coverage target: >80%

2. **Integration tests**
   - File: `api/websocket_integration_test.go`
   - Test: End-to-end message flow (event → WebSocket)
   - Test: Authentication with valid/invalid JWT
   - Test: Concurrent connections
   - Test: Graceful shutdown

3. **Performance tests**
   - File: `api/websocket_performance_test.go`
   - Test: 1000 concurrent connections
   - Test: 10,000 messages/sec throughput
   - Test: Memory usage under load
   - Test: GC pause times

4. **Security tests**
   - File: `api/websocket_security_test.go`
   - Test: RBAC enforcement
   - Test: Connection limits
   - Test: Rate limiting
   - Test: CORS validation
   - Test: XSS prevention in messages

5. **Chaos tests**
   - File: `api/websocket_chaos_test.go`
   - Test: Random client disconnections
   - Test: Network partitions
   - Test: Slow clients (backpressure)
   - Test: Message storms

6. **Manual testing scenarios**
   - Test: WebSocket with Chrome DevTools
   - Test: WebSocket with Electron app
   - Test: Reconnection behavior
   - Test: Multi-tab scenarios

**Deliverables**:
- ✅ >80% code coverage
- ✅ All integration tests passing
- ✅ Performance benchmarks documented
- ✅ Security tests all green
- ✅ Manual test plan executed

**Test Example**:
```go
func TestWebSocketBroadcast(t *testing.T) {
    // Setup test server with WebSocket hub
    server := setupTestServer(t)
    defer server.Close()

    // Connect 3 clients
    client1 := connectWebSocketClient(t, server.URL)
    client2 := connectWebSocketClient(t, server.URL)
    client3 := connectWebSocketClient(t, server.URL)

    // Broadcast test event
    testEvent := core.Event{Message: "test"}
    server.Hub.BroadcastEvent(testEvent)

    // Assert all clients received the event
    assertReceivedEvent(t, client1, testEvent)
    assertReceivedEvent(t, client2, testEvent)
    assertReceivedEvent(t, client3, testEvent)
}
```

---

## 4. Detailed Component Specifications

### 4.1 WebSocketHub

**File**: `api/websocket_hub.go`

**Responsibilities**:
- Maintain registry of all active WebSocket connections
- Handle client registration and unregistration
- Broadcast messages to appropriate clients
- Manage hub lifecycle (start, shutdown)

**Data Structures**:
```go
type WebSocketHub struct {
    // Client connections (protected by mutex)
    clients    map[string]*WebSocketClient
    clientsMu  sync.RWMutex

    // Channels for hub communication
    register   chan *WebSocketClient
    unregister chan *WebSocketClient
    broadcast  chan *WebSocketMessage

    // Configuration
    config     *config.Config
    logger     *zap.SugaredLogger

    // Metrics
    metrics    *WebSocketMetrics

    // Redis Pub/Sub (optional for multi-server)
    redisPubSub *redis.PubSub

    // Shutdown coordination
    done       chan struct{}
    wg         sync.WaitGroup
}
```

**Key Methods**:
```go
// NewWebSocketHub creates and starts the hub
func NewWebSocketHub(cfg *config.Config, logger *zap.SugaredLogger) *WebSocketHub

// Run starts the hub event loop (call as goroutine)
func (h *WebSocketHub) Run()

// RegisterClient adds a new client to the hub
func (h *WebSocketHub) RegisterClient(client *WebSocketClient)

// UnregisterClient removes a client from the hub
func (h *WebSocketHub) UnregisterClient(client *WebSocketClient)

// Broadcast sends message to all eligible clients
func (h *WebSocketHub) Broadcast(msg *WebSocketMessage)

// BroadcastToUser sends message to specific user's connections
func (h *WebSocketHub) BroadcastToUser(username string, msg *WebSocketMessage)

// GetConnectionCount returns number of active connections
func (h *WebSocketHub) GetConnectionCount() int

// Shutdown gracefully stops the hub
func (h *WebSocketHub) Shutdown(ctx context.Context) error
```

**Hub Event Loop**:
```go
func (h *WebSocketHub) Run() {
    defer h.wg.Done()

    for {
        select {
        case client := <-h.register:
            h.handleRegister(client)

        case client := <-h.unregister:
            h.handleUnregister(client)

        case message := <-h.broadcast:
            h.handleBroadcast(message)

        case <-h.done:
            return
        }
    }
}
```

---

### 4.2 WebSocketClient

**File**: `api/websocket_client.go`

**Responsibilities**:
- Wrap `*websocket.Conn` with buffered send channel
- Store client metadata (user, permissions, subscriptions)
- Implement read and write pumps
- Handle ping/pong heartbeat

**Data Structures**:
```go
type WebSocketClient struct {
    // Unique client identifier
    id       string

    // WebSocket connection
    conn     *websocket.Conn

    // Send channel (buffered)
    send     chan []byte

    // User context
    username    string
    permissions []string

    // Subscriptions (message types client wants)
    subscriptions map[string]bool

    // Filters (e.g., minimum alert severity)
    filters    *MessageFilters

    // Hub reference
    hub      *WebSocketHub

    // Metrics
    messagesSent    uint64
    messagesDropped uint64
    connectedAt     time.Time
}

type MessageFilters struct {
    MinAlertSeverity string   // "critical", "high", "medium", "low"
    EventTypes       []string // Filter events by type
}
```

**Key Methods**:
```go
// NewWebSocketClient creates a new client wrapper
func NewWebSocketClient(conn *websocket.Conn, hub *WebSocketHub, username string, permissions []string) *WebSocketClient

// ReadPump reads messages from WebSocket connection
func (c *WebSocketClient) ReadPump()

// WritePump sends messages from send channel to WebSocket
func (c *WebSocketClient) WritePump()

// Send queues message for sending (non-blocking)
func (c *WebSocketClient) Send(message []byte) error

// Close gracefully closes the connection
func (c *WebSocketClient) Close() error

// HasPermission checks if client has specific permission
func (c *WebSocketClient) HasPermission(perm string) bool

// IsSubscribed checks if client subscribed to message type
func (c *WebSocketClient) IsSubscribed(msgType string) bool

// ApplyFilters checks if message passes client filters
func (c *WebSocketClient) ApplyFilters(msg *WebSocketMessage) bool
```

**Read Pump** (handles incoming messages from client):
```go
func (c *WebSocketClient) ReadPump() {
    defer func() {
        c.hub.unregister <- c
        c.conn.Close()
    }()

    c.conn.SetReadDeadline(time.Now().Add(pongWait))
    c.conn.SetPongHandler(func(string) error {
        c.conn.SetReadDeadline(time.Now().Add(pongWait))
        return nil
    })

    for {
        _, message, err := c.conn.ReadMessage()
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                c.hub.logger.Warnf("WebSocket read error: %v", err)
            }
            break
        }

        // Handle client messages (subscription changes, etc.)
        c.handleClientMessage(message)
    }
}
```

**Write Pump** (sends messages to client):
```go
func (c *WebSocketClient) WritePump() {
    ticker := time.NewTicker(pingPeriod)
    defer func() {
        ticker.Stop()
        c.conn.Close()
    }()

    for {
        select {
        case message, ok := <-c.send:
            c.conn.SetWriteDeadline(time.Now().Add(writeWait))
            if !ok {
                // Hub closed the channel
                c.conn.WriteMessage(websocket.CloseMessage, []byte{})
                return
            }

            if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
                return
            }

            atomic.AddUint64(&c.messagesSent, 1)

        case <-ticker.C:
            c.conn.SetWriteDeadline(time.Now().Add(writeWait))
            if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
                return
            }
        }
    }
}
```

---

### 4.3 WebSocketHandler (HTTP Upgrade)

**File**: `api/websocket_handlers.go`

**Responsibilities**:
- Handle HTTP GET requests to `/ws`
- Extract and validate JWT token
- Perform WebSocket upgrade handshake
- Create client and register with hub

**Implementation**:
```go
var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
    CheckOrigin: func(r *http.Request) bool {
        // Check if origin is in allowed list
        origin := r.Header.Get("Origin")
        return isOriginAllowed(origin, a.config.API.WebSocket.AllowedOrigins)
    },
}

// handleWebSocket handles WebSocket upgrade requests
// @Summary WebSocket endpoint for real-time updates
// @Description Upgrades HTTP connection to WebSocket for real-time event/alert streaming
// @Tags WebSocket
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param token query string false "JWT token (alternative to Authorization header)"
// @Success 101 "Switching Protocols"
// @Failure 400 {object} ErrorResponse "Bad Request"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Failure 429 {object} ErrorResponse "Too Many Requests"
// @Router /ws [get]
func (a *API) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Check connection limits
    if a.wsHub.GetConnectionCount() >= a.config.API.WebSocket.MaxTotalConnections {
        http.Error(w, "Maximum connections reached", http.StatusServiceUnavailable)
        return
    }

    // Extract JWT token from query param or Authorization header
    token := r.URL.Query().Get("token")
    if token == "" {
        token = extractBearerToken(r)
    }

    if token == "" {
        http.Error(w, "Missing authentication token", http.StatusUnauthorized)
        return
    }

    // Validate JWT and extract claims
    claims, err := a.validateJWT(token)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    username := claims.Username
    permissions := claims.Permissions

    // Check per-user connection limit
    if a.wsHub.GetUserConnectionCount(username) >= a.config.API.WebSocket.MaxConnectionsPerUser {
        http.Error(w, "Maximum connections per user reached", http.StatusTooManyRequests)
        return
    }

    // Upgrade HTTP connection to WebSocket
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        a.logger.Errorf("WebSocket upgrade failed: %v", err)
        return
    }

    // Create client wrapper
    client := NewWebSocketClient(conn, a.wsHub, username, permissions)

    // Register with hub
    a.wsHub.RegisterClient(client)

    // Start read and write pumps
    go client.WritePump()
    go client.ReadPump()

    a.logger.Infof("WebSocket client connected: user=%s, id=%s", username, client.id)
}
```

---

### 4.4 WebSocketMessage

**File**: `api/websocket_messages.go`

**Responsibilities**:
- Define message structure
- Provide serialization/deserialization
- Type-safe message construction

**Data Structures**:
```go
// WebSocketMessage represents a message sent to clients
type WebSocketMessage struct {
    Type      string          `json:"type"`      // "event", "alert", "dashboard_stats", "listener_status"
    Data      json.RawMessage `json:"data"`      // Actual payload (Event, Alert, etc.)
    Timestamp time.Time       `json:"timestamp"` // Message generation time
}

// Message types
const (
    MessageTypeEvent          = "event"
    MessageTypeAlert          = "alert"
    MessageTypeDashboardStats = "dashboard_stats"
    MessageTypeListenerStatus = "listener_status"
    MessageTypeInvestigation  = "investigation"
    MessageTypeHeartbeat      = "heartbeat"
)
```

**Helper Functions**:
```go
// NewEventMessage creates a WebSocket message for an event
func NewEventMessage(event *core.Event) (*WebSocketMessage, error) {
    data, err := json.Marshal(event)
    if err != nil {
        return nil, err
    }

    return &WebSocketMessage{
        Type:      MessageTypeEvent,
        Data:      data,
        Timestamp: time.Now(),
    }, nil
}

// NewAlertMessage creates a WebSocket message for an alert
func NewAlertMessage(alert *core.Alert) (*WebSocketMessage, error) {
    data, err := json.Marshal(alert)
    if err != nil {
        return nil, err
    }

    return &WebSocketMessage{
        Type:      MessageTypeAlert,
        Data:      data,
        Timestamp: time.Now(),
    }, nil
}

// NewDashboardStatsMessage creates a WebSocket message for dashboard stats
func NewDashboardStatsMessage(stats *DashboardStats) (*WebSocketMessage, error) {
    data, err := json.Marshal(stats)
    if err != nil {
        return nil, err
    }

    return &WebSocketMessage{
        Type:      MessageTypeDashboardStats,
        Data:      data,
        Timestamp: time.Now(),
    }, nil
}

// Serialize converts message to JSON bytes
func (m *WebSocketMessage) Serialize() ([]byte, error) {
    return json.Marshal(m)
}
```

---

## 5. Integration Points

### 5.1 Ingest Manager Integration

**File**: `ingest/manager.go`

**Integration Point**: After successful event storage

```go
// After storing event in ClickHouse
func (m *Manager) processEvent(event *core.Event) error {
    // Store event in ClickHouse
    if err := m.clickhouseStorage.StoreEvent(event); err != nil {
        return err
    }

    // Broadcast to WebSocket clients (if enabled)
    if m.config.API.WebSocket.Enabled && m.wsHub != nil {
        msg, err := NewEventMessage(event)
        if err != nil {
            m.logger.Warnf("Failed to create WebSocket message: %v", err)
        } else {
            m.wsHub.Broadcast(msg)
        }
    }

    return nil
}
```

**Configuration**:
- Add `wsHub *WebSocketHub` to Manager struct
- Initialize in `NewManager()` with hub reference
- Add feature flag: `config.api.websocket.broadcast_events`

---

### 5.2 Detection Engine Integration

**File**: `detect/engine.go`

**Integration Point**: After alert creation

```go
// After creating alert
func (e *Engine) createAlert(event *core.Event, rule *core.Rule) (*core.Alert, error) {
    alert := &core.Alert{
        ID:       uuid.New().String(),
        RuleID:   rule.ID,
        RuleName: rule.Name,
        Event:    event,
        Severity: rule.Severity,
        Status:   core.AlertStatusNew,
        Created:  time.Now(),
    }

    // Store alert in database
    if err := e.alertStorage.CreateAlert(alert); err != nil {
        return nil, err
    }

    // Broadcast to WebSocket clients (if enabled)
    if e.config.API.WebSocket.Enabled && e.wsHub != nil {
        msg, err := NewAlertMessage(alert)
        if err != nil {
            e.logger.Warnf("Failed to create WebSocket message: %v", err)
        } else {
            e.wsHub.Broadcast(msg)
        }
    }

    return alert, nil
}
```

---

### 5.3 Dashboard Stats Broadcasting

**File**: `api/websocket_dashboard.go`

**New Background Service**:

```go
// DashboardStatsUpdater periodically broadcasts dashboard stats
type DashboardStatsUpdater struct {
    hub            *WebSocketHub
    eventStorage   EventStorer
    alertStorage   AlertStorer
    updateInterval time.Duration
    logger         *zap.SugaredLogger
    done           chan struct{}
}

func NewDashboardStatsUpdater(
    hub *WebSocketHub,
    eventStorage EventStorer,
    alertStorage AlertStorer,
    interval time.Duration,
    logger *zap.SugaredLogger,
) *DashboardStatsUpdater {
    return &DashboardStatsUpdater{
        hub:            hub,
        eventStorage:   eventStorage,
        alertStorage:   alertStorage,
        updateInterval: interval,
        logger:         logger,
        done:           make(chan struct{}),
    }
}

func (u *DashboardStatsUpdater) Start() {
    ticker := time.NewTicker(u.updateInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            u.broadcastStats()
        case <-u.done:
            return
        }
    }
}

func (u *DashboardStatsUpdater) broadcastStats() {
    // Calculate current stats
    stats, err := u.calculateDashboardStats()
    if err != nil {
        u.logger.Errorf("Failed to calculate dashboard stats: %v", err)
        return
    }

    // Broadcast to all clients
    msg, err := NewDashboardStatsMessage(stats)
    if err != nil {
        u.logger.Errorf("Failed to create dashboard stats message: %v", err)
        return
    }

    u.hub.Broadcast(msg)
}

func (u *DashboardStatsUpdater) calculateDashboardStats() (*DashboardStats, error) {
    totalEvents, err := u.eventStorage.GetEventCount()
    if err != nil {
        return nil, err
    }

    totalAlerts, err := u.alertStorage.GetAlertCount()
    if err != nil {
        return nil, err
    }

    // Additional calculations...

    return &DashboardStats{
        TotalEvents:   totalEvents,
        ActiveAlerts:  activeAlerts,
        EventsPerSec:  eps,
        SystemHealth:  health,
        Timestamp:     time.Now(),
    }, nil
}
```

**Start in main.go**:
```go
// Start dashboard stats broadcaster
dashboardUpdater := NewDashboardStatsUpdater(
    wsHub,
    clickhouseStorage,
    sqliteAlerts,
    5*time.Second, // Update every 5 seconds
    logger,
)
go dashboardUpdater.Start()
```

---

### 5.4 Listener Status Broadcasting

**File**: `api/websocket_listeners.go`

**Integration**: Hook into existing listener health checks

```go
// When listener status changes
func (l *Listener) updateStatus(status ListenerStatus) {
    l.status = status

    // Broadcast status change
    if l.wsHub != nil {
        msg := &WebSocketMessage{
            Type:      MessageTypeListenerStatus,
            Data:      json.RawMessage(marshalListenerStatus(l)),
            Timestamp: time.Now(),
        }
        l.wsHub.Broadcast(msg)
    }
}
```

---

## 6. Security Requirements

### 6.1 Authentication

**Requirements**:
- ✅ All WebSocket connections MUST be authenticated with valid JWT token
- ✅ Token can be provided via query parameter (`?token=JWT`) or Authorization header
- ✅ Token validation uses same JWT library and secret as REST API
- ✅ Expired tokens are rejected during upgrade
- ✅ Token blacklist is checked (if user logged out)

**Implementation**:
```go
func (a *API) validateWebSocketJWT(tokenString string) (*JWTClaims, error) {
    // Check token blacklist first
    if a.isTokenBlacklisted(tokenString) {
        return nil, errors.New("token has been revoked")
    }

    // Parse and validate token
    token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(a.config.Auth.JWTSecret), nil
    })

    if err != nil {
        return nil, err
    }

    if !token.Valid {
        return nil, errors.New("invalid token")
    }

    claims, ok := token.Claims.(*JWTClaims)
    if !ok {
        return nil, errors.New("invalid claims")
    }

    return claims, nil
}
```

---

### 6.2 Authorization (RBAC)

**Requirements**:
- ✅ Clients only receive messages for resources they have permission to read
- ✅ Permissions extracted from JWT claims
- ✅ Permission check before sending each message
- ✅ Users without any read permissions cannot connect

**Permission Mapping**:
| Message Type | Required Permission |
|-------------|---------------------|
| event | `read:events` |
| alert | `read:alerts` |
| dashboard_stats | Any authenticated user |
| listener_status | `read:listeners` |
| investigation | `read:alerts` (or assigned to investigation) |

**Implementation**:
```go
func (h *WebSocketHub) canReceiveMessage(client *WebSocketClient, msg *WebSocketMessage) bool {
    switch msg.Type {
    case MessageTypeEvent:
        return client.HasPermission(storage.PermReadEvents)
    case MessageTypeAlert:
        return client.HasPermission(storage.PermReadAlerts)
    case MessageTypeDashboardStats:
        return true // All authenticated users
    case MessageTypeListenerStatus:
        return client.HasPermission(storage.PermReadListeners)
    case MessageTypeInvestigation:
        // Check if user is assigned to investigation
        return h.isUserAssignedToInvestigation(client.username, msg)
    default:
        return false
    }
}
```

---

### 6.3 Rate Limiting

**Requirements**:
- ✅ WebSocket upgrade attempts rate limited (10 per minute per IP)
- ✅ Per-client message send rate limited (100 messages per minute)
- ✅ Slow clients that can't keep up have messages dropped (no backpressure to hub)

**Implementation**:
```go
// Check upgrade rate limit
func (a *API) checkWebSocketUpgradeRateLimit(r *http.Request) error {
    clientIP := getClientIP(r)

    key := fmt.Sprintf("ws_upgrade:%s", clientIP)
    allowed, err := a.multiTierRateLimiter.Allow(r.Context(), key, "websocket")
    if err != nil {
        return err
    }

    if !allowed {
        return errors.New("rate limit exceeded")
    }

    return nil
}

// Drop messages if client send buffer full
func (c *WebSocketClient) Send(message []byte) error {
    select {
    case c.send <- message:
        return nil
    default:
        // Buffer full, drop message
        atomic.AddUint64(&c.messagesDropped, 1)
        return errors.New("send buffer full, message dropped")
    }
}
```

---

### 6.4 Connection Limits

**Requirements**:
- ✅ Maximum 5 connections per user (configurable)
- ✅ Maximum 1000 total connections (configurable)
- ✅ New connections rejected when limit reached
- ✅ Oldest connection closed if user exceeds limit (optional)

**Implementation**:
```go
func (h *WebSocketHub) GetUserConnectionCount(username string) int {
    h.clientsMu.RLock()
    defer h.clientsMu.RUnlock()

    count := 0
    for _, client := range h.clients {
        if client.username == username {
            count++
        }
    }
    return count
}

func (h *WebSocketHub) enforceConnectionLimits(newClient *WebSocketClient) error {
    totalConnections := len(h.clients)
    if totalConnections >= h.config.API.WebSocket.MaxTotalConnections {
        return errors.New("maximum total connections reached")
    }

    userConnections := h.GetUserConnectionCount(newClient.username)
    if userConnections >= h.config.API.WebSocket.MaxConnectionsPerUser {
        return errors.New("maximum connections per user reached")
    }

    return nil
}
```

---

### 6.5 Input Validation

**Requirements**:
- ✅ All client messages validated against schema
- ✅ Malformed messages logged and ignored
- ✅ Large messages rejected (max 1MB)
- ✅ Unknown message types logged and ignored

**Implementation**:
```go
func (c *WebSocketClient) handleClientMessage(messageBytes []byte) {
    // Validate message size
    if len(messageBytes) > c.hub.config.API.WebSocket.MaxMessageSize {
        c.hub.logger.Warnf("Client %s sent oversized message (%d bytes)", c.id, len(messageBytes))
        return
    }

    // Parse message
    var msg ClientMessage
    if err := json.Unmarshal(messageBytes, &msg); err != nil {
        c.hub.logger.Warnf("Client %s sent malformed message: %v", c.id, err)
        return
    }

    // Handle based on type
    switch msg.Type {
    case "subscribe":
        c.handleSubscribe(msg.Data)
    case "unsubscribe":
        c.handleUnsubscribe(msg.Data)
    default:
        c.hub.logger.Warnf("Client %s sent unknown message type: %s", c.id, msg.Type)
    }
}
```

---

### 6.6 XSS Prevention

**Requirements**:
- ✅ All string data in messages sanitized before sending
- ✅ Event messages from untrusted sources escaped
- ✅ Frontend validates and escapes all WebSocket data before rendering

**Implementation**:
```go
import "html"

func sanitizeEventForWebSocket(event *core.Event) *core.Event {
    // Create copy to avoid mutating original
    sanitized := *event

    // Escape HTML in message field
    sanitized.Message = html.EscapeString(event.Message)

    // Escape other string fields
    for k, v := range sanitized.Fields {
        if str, ok := v.(string); ok {
            sanitized.Fields[k] = html.EscapeString(str)
        }
    }

    return &sanitized
}
```

**Note**: Frontend already has XSS protection in `websocket.ts` (line 64-73), but backend should also sanitize.

---

## 7. Testing Strategy

### 7.1 Unit Tests

**Files to Test**:
- `api/websocket_hub_test.go`
- `api/websocket_client_test.go`
- `api/websocket_messages_test.go`
- `api/websocket_permissions_test.go`

**Test Cases**:
```go
// Hub Tests
TestHubRegisterClient
TestHubUnregisterClient
TestHubBroadcastToAll
TestHubBroadcastFiltering
TestHubConcurrentOperations
TestHubShutdown

// Client Tests
TestClientSend
TestClientSendBufferFull
TestClientPermissionCheck
TestClientSubscriptionManagement
TestClientReadPump
TestClientWritePump

// Message Tests
TestMessageSerialization
TestMessageDeserialization
TestMessageValidation

// Permission Tests
TestRBACFiltering
TestSubscriptionFiltering
TestInvestigationAssignmentCheck
```

**Coverage Target**: >80%

---

### 7.2 Integration Tests

**File**: `api/websocket_integration_test.go`

**Test Scenarios**:
```go
func TestWebSocketEndToEnd(t *testing.T) {
    // 1. Start test server with WebSocket hub
    server := setupTestServer(t)
    defer server.Close()

    // 2. Connect WebSocket client with valid JWT
    client := connectWebSocketClient(t, server.URL, validJWT)
    defer client.Close()

    // 3. Ingest event via REST API
    event := createTestEvent()
    ingestEvent(t, server, event)

    // 4. Verify client receives event via WebSocket
    received := waitForMessage(t, client, 5*time.Second)
    assert.Equal(t, "event", received.Type)
    assert.Equal(t, event.ID, parseEventFromMessage(received).ID)
}

func TestWebSocketAuthentication(t *testing.T) {
    tests := []struct{
        name        string
        token       string
        expectError bool
    }{
        {"Valid JWT", validJWT, false},
        {"Expired JWT", expiredJWT, true},
        {"Invalid signature", tamperedJWT, true},
        {"No token", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            conn, _, err := websocket.DefaultDialer.Dial(
                fmt.Sprintf("ws://localhost:8081/ws?token=%s", tt.token),
                nil,
            )

            if tt.expectError {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                conn.Close()
            }
        })
    }
}

func TestWebSocketRBACFiltering(t *testing.T) {
    // Client 1: Has read:events only
    client1 := connectWithPermissions(t, []string{"read:events"})

    // Client 2: Has read:alerts only
    client2 := connectWithPermissions(t, []string{"read:alerts"})

    // Broadcast event
    hub.BroadcastEvent(testEvent)

    // Client 1 should receive, Client 2 should not
    assertReceivesMessage(t, client1, "event")
    assertNoMessage(t, client2, 1*time.Second)

    // Broadcast alert
    hub.BroadcastAlert(testAlert)

    // Client 2 should receive, Client 1 should not
    assertReceivesMessage(t, client2, "alert")
    assertNoMessage(t, client1, 1*time.Second)
}
```

---

### 7.3 Performance Tests

**File**: `api/websocket_benchmark_test.go`

**Benchmarks**:
```go
func BenchmarkWebSocketBroadcast(b *testing.B) {
    hub := setupTestHub(b)
    defer hub.Shutdown(context.Background())

    // Connect 100 clients
    clients := connectNClients(b, hub, 100)
    defer disconnectAll(clients)

    msg := createTestMessage()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        hub.Broadcast(msg)
    }
}

func BenchmarkWebSocketConcurrentConnections(b *testing.B) {
    hub := setupTestHub(b)
    defer hub.Shutdown(context.Background())

    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            client := connectWebSocketClient(b, testServer.URL)
            client.Close()
        }
    })
}

func TestWebSocket1000Connections(t *testing.T) {
    hub := setupTestHub(t)
    defer hub.Shutdown(context.Background())

    // Connect 1000 clients concurrently
    var wg sync.WaitGroup
    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            client := connectWebSocketClient(t, testServer.URL)
            defer client.Close()

            // Receive messages for 10 seconds
            time.Sleep(10 * time.Second)
        }()
    }

    // Broadcast messages while clients connected
    for i := 0; i < 100; i++ {
        hub.Broadcast(createTestMessage())
        time.Sleep(100 * time.Millisecond)
    }

    wg.Wait()
}
```

**Performance Targets**:
- Support 1000+ concurrent connections
- Broadcast latency < 100ms for 1000 clients
- Memory usage < 50MB for 1000 connections
- CPU usage < 50% during normal operation

---

### 7.4 Load Tests

**Tool**: Use `k6` or `artillery` for WebSocket load testing

**Load Test Script** (`tests/load/websocket_load.js`):
```javascript
import ws from 'k6/ws';
import { check } from 'k6';

export let options = {
  stages: [
    { duration: '1m', target: 100 },   // Ramp up to 100 users
    { duration: '3m', target: 500 },   // Ramp up to 500 users
    { duration: '5m', target: 500 },   // Stay at 500 users
    { duration: '1m', target: 0 },     // Ramp down
  ],
};

export default function () {
  const url = 'ws://localhost:8081/ws?token=YOUR_JWT_TOKEN';

  const res = ws.connect(url, {}, function (socket) {
    socket.on('open', () => console.log('connected'));

    socket.on('message', (data) => {
      const msg = JSON.parse(data);
      check(msg, {
        'has type': (m) => m.type !== undefined,
        'has data': (m) => m.data !== undefined,
        'has timestamp': (m) => m.timestamp !== undefined,
      });
    });

    socket.on('close', () => console.log('disconnected'));

    socket.setTimeout(() => {
      socket.close();
    }, 60000); // Stay connected for 60 seconds
  });

  check(res, { 'status is 101': (r) => r && r.status === 101 });
}
```

**Run Load Test**:
```bash
k6 run tests/load/websocket_load.js
```

---

## 8. Performance & Scalability

### 8.1 Single-Server Performance

**Optimizations**:
1. **Buffered Channels**: Use buffered send channels (256 capacity) to decouple broadcast from send
2. **Goroutine Pooling**: Reuse goroutines for read/write pumps
3. **Message Caching**: Pre-serialize common messages (dashboard stats)
4. **Zero-Copy Broadcasting**: Use `json.RawMessage` to avoid repeated marshaling
5. **Efficient Locking**: Use `sync.RWMutex` for read-heavy operations

**Expected Performance** (single server):
- Concurrent Connections: 1000+
- Broadcast Throughput: 10,000 messages/sec
- Latency (p95): < 100ms
- Memory per Connection: ~50KB
- CPU per 1000 connections: ~20%

---

### 8.2 Multi-Server Scaling (Redis Pub/Sub)

**Architecture**:
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ API Server 1│     │ API Server 2│     │ API Server 3│
│             │     │             │     │             │
│ 300 WS      │     │ 350 WS      │     │ 350 WS      │
│ Clients     │     │ Clients     │     │ Clients     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                  ┌────────────────┐
                  │ Redis Pub/Sub  │
                  │ Channel: "ws"  │
                  └────────────────┘
```

**Implementation**:
```go
// Subscribe to Redis channel
func (h *WebSocketHub) subscribeRedis() {
    pubsub := h.redisClient.Subscribe(context.Background(), "cerberus:websocket")
    defer pubsub.Close()

    ch := pubsub.Channel()

    for msg := range ch {
        var wsMsg WebSocketMessage
        if err := json.Unmarshal([]byte(msg.Payload), &wsMsg); err != nil {
            h.logger.Errorf("Failed to unmarshal Redis message: %v", err)
            continue
        }

        // Broadcast to local clients only
        h.broadcastLocal(&wsMsg)
    }
}

// Publish to Redis when broadcasting
func (h *WebSocketHub) Broadcast(msg *WebSocketMessage) {
    // Serialize message
    data, err := json.Marshal(msg)
    if err != nil {
        h.logger.Errorf("Failed to marshal message: %v", err)
        return
    }

    // Publish to Redis (all servers receive)
    if err := h.redisClient.Publish(context.Background(), "cerberus:websocket", data).Err(); err != nil {
        h.logger.Errorf("Failed to publish to Redis: %v", err)
        // Fallback: broadcast to local clients only
        h.broadcastLocal(msg)
    }
}
```

**Scaling Targets** (with Redis):
- Total Concurrent Connections: 10,000+ (across all servers)
- Servers: 3-10
- Redis Pub/Sub Latency: < 10ms

---

### 8.3 Message Batching (Optional)

**Purpose**: Reduce protocol overhead by batching multiple messages

**Implementation**:
```go
type MessageBatcher struct {
    messages   []*WebSocketMessage
    mu         sync.Mutex
    batchSize  int
    flushTimer *time.Timer
    onFlush    func([]*WebSocketMessage)
}

func (b *MessageBatcher) Add(msg *WebSocketMessage) {
    b.mu.Lock()
    defer b.mu.Unlock()

    b.messages = append(b.messages, msg)

    if len(b.messages) >= b.batchSize {
        b.flush()
    } else if b.flushTimer == nil {
        // Auto-flush after 100ms
        b.flushTimer = time.AfterFunc(100*time.Millisecond, b.flush)
    }
}

func (b *MessageBatcher) flush() {
    if len(b.messages) == 0 {
        return
    }

    batch := b.messages
    b.messages = nil
    b.flushTimer = nil

    b.onFlush(batch)
}
```

**Configuration**:
```yaml
api:
  websocket:
    batching:
      enabled: true
      batch_size: 10
      flush_timeout: 100ms
```

---

## 9. Monitoring & Observability

### 9.1 Prometheus Metrics

**File**: `metrics/websocket_metrics.go`

**Metrics to Collect**:
```go
var (
    // Connection metrics
    websocketConnectionsActive = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "cerberus_websocket_connections_active",
            Help: "Number of active WebSocket connections",
        },
    )

    websocketConnectionsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cerberus_websocket_connections_total",
            Help: "Total WebSocket connections",
        },
        []string{"status"}, // "success", "auth_failed", "rate_limited"
    )

    // Message metrics
    websocketMessagesSent = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cerberus_websocket_messages_sent_total",
            Help: "Total WebSocket messages sent",
        },
        []string{"type"}, // "event", "alert", "dashboard_stats"
    )

    websocketMessagesDropped = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cerberus_websocket_messages_dropped_total",
            Help: "Total WebSocket messages dropped (slow client)",
        },
        []string{"reason"}, // "buffer_full", "client_disconnected"
    )

    // Latency metrics
    websocketLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "cerberus_websocket_latency_seconds",
            Help: "WebSocket message latency",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to 1s
        },
        []string{"type"},
    )

    // Error metrics
    websocketErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cerberus_websocket_errors_total",
            Help: "Total WebSocket errors",
        },
        []string{"type"}, // "upgrade_failed", "send_failed", "auth_failed"
    )
)
```

**Metric Collection**:
```go
func (h *WebSocketHub) recordConnectionMetrics() {
    websocketConnectionsActive.Set(float64(len(h.clients)))
}

func (c *WebSocketClient) recordMessageSent(msgType string, latency time.Duration) {
    websocketMessagesSent.WithLabelValues(msgType).Inc()
    websocketLatency.WithLabelValues(msgType).Observe(latency.Seconds())
}

func (c *WebSocketClient) recordMessageDropped(reason string) {
    websocketMessagesDropped.WithLabelValues(reason).Inc()
}
```

---

### 9.2 Structured Logging

**Log Events**:
```go
// Connection events
logger.Infof("WebSocket client connected: user=%s, id=%s, ip=%s", username, clientID, ip)
logger.Infof("WebSocket client disconnected: user=%s, id=%s, duration=%s", username, clientID, duration)

// Error events
logger.Errorf("WebSocket upgrade failed: ip=%s, error=%v", ip, err)
logger.Warnf("WebSocket send failed: client=%s, error=%v", clientID, err)

// Rate limiting
logger.Warnf("WebSocket connection rate limited: ip=%s", ip)
logger.Warnf("WebSocket message dropped (slow client): client=%s, buffer_size=%d", clientID, bufferSize)

// Broadcasting
logger.Debugf("Broadcasting message: type=%s, recipients=%d", msgType, recipientCount)
```

**Correlation IDs**:
```go
// Add correlation ID to client context
type WebSocketClient struct {
    correlationID string // UUID for request tracing
    // ... other fields
}

// Use in logs
logger.Infof("correlation_id=%s user=%s action=send_message type=%s", c.correlationID, c.username, msgType)
```

---

### 9.3 Health Check Endpoint

**Endpoint**: `GET /api/v1/websocket/health`

**Response**:
```json
{
  "status": "healthy",
  "active_connections": 342,
  "total_connections": 15423,
  "uptime_seconds": 86400,
  "hub_status": "running",
  "redis_connected": true,
  "message_rate": {
    "last_minute": 1250,
    "last_hour": 75000
  },
  "error_rate": {
    "last_minute": 0,
    "last_hour": 3
  }
}
```

**Implementation**:
```go
func (a *API) getWebSocketHealth(w http.ResponseWriter, r *http.Request) {
    health := map[string]interface{}{
        "status":              "healthy",
        "active_connections":  a.wsHub.GetConnectionCount(),
        "total_connections":   a.wsHub.GetTotalConnections(),
        "uptime_seconds":      time.Since(a.wsHub.startTime).Seconds(),
        "hub_status":          a.wsHub.GetStatus(),
        "redis_connected":     a.wsHub.IsRedisConnected(),
    }

    respondJSON(w, http.StatusOK, health)
}
```

---

### 9.4 Grafana Dashboard

**Panels**:
1. **Active Connections** (time series)
   - Query: `cerberus_websocket_connections_active`
   - Threshold: Warning at 800, Critical at 950

2. **Message Throughput** (time series)
   - Query: `rate(cerberus_websocket_messages_sent_total[5m])`
   - By message type (event, alert, dashboard_stats)

3. **Error Rate** (time series)
   - Query: `rate(cerberus_websocket_errors_total[5m])`
   - By error type

4. **Latency Percentiles** (time series)
   - Query P50: `histogram_quantile(0.50, cerberus_websocket_latency_seconds_bucket)`
   - Query P95: `histogram_quantile(0.95, cerberus_websocket_latency_seconds_bucket)`
   - Query P99: `histogram_quantile(0.99, cerberus_websocket_latency_seconds_bucket)`

5. **Message Drop Rate** (single stat)
   - Query: `rate(cerberus_websocket_messages_dropped_total[5m])`

6. **Connection Duration** (heatmap)
   - Distribution of connection lifetimes

**Dashboard JSON**: `monitoring/grafana/websocket_dashboard.json`

---

## 10. Deployment Considerations

### 10.1 Configuration

**Config File** (`config.yaml`):
```yaml
api:
  websocket:
    # Enable/disable WebSocket endpoint
    enabled: true

    # Connection limits
    max_connections_per_user: 5
    max_total_connections: 1000

    # Rate limiting
    upgrade_rate_limit: 10 # per minute per IP
    message_rate_limit: 100 # per minute per client

    # Timeouts
    ping_interval: 30s
    pong_wait: 60s
    write_wait: 10s
    read_buffer_size: 1024
    write_buffer_size: 1024

    # Security
    max_message_size: 1048576 # 1MB
    allowed_origins:
      - "http://localhost:3000"
      - "https://cerberus.example.com"

    # Broadcasting
    broadcast_events: true
    broadcast_alerts: true
    broadcast_dashboard_stats: true
    dashboard_stats_interval: 5s

    # Redis (for multi-server scaling)
    redis:
      enabled: false
      addr: "localhost:6379"
      password: ""
      db: 0
      channel: "cerberus:websocket"
```

---

### 10.2 Production Checklist

**Pre-Deployment**:
- ✅ All tests passing (unit, integration, performance)
- ✅ Load testing completed (1000+ connections)
- ✅ Security audit completed (RBAC, rate limiting, input validation)
- ✅ Metrics and dashboards configured
- ✅ Alerting rules set up
- ✅ Documentation updated (API docs, runbooks)

**Deployment Steps**:
1. Deploy backend with WebSocket support
2. Verify `/ws` endpoint accessible
3. Test with single client (wscat)
4. Enable frontend WebSocket connection
5. Monitor metrics for anomalies
6. Gradually increase traffic

**Rollback Plan**:
- Disable `config.api.websocket.enabled = false`
- Frontend falls back to polling
- No data loss (messages still available via REST API)

---

### 10.3 Monitoring Alerts

**Alert Rules** (`monitoring/alerts/websocket.yaml`):
```yaml
groups:
  - name: websocket
    interval: 30s
    rules:
      # Connection limit approaching
      - alert: WebSocketConnectionsHigh
        expr: cerberus_websocket_connections_active > 900
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "WebSocket connections approaching limit"
          description: "{{ $value }} active connections (limit: 1000)"

      # High error rate
      - alert: WebSocketErrorRateHigh
        expr: rate(cerberus_websocket_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "WebSocket error rate > 5%"

      # High message drop rate
      - alert: WebSocketMessageDropRateHigh
        expr: rate(cerberus_websocket_messages_dropped_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "WebSocket dropping > 1% of messages"

      # Redis disconnected (if using multi-server)
      - alert: WebSocketRedisDisconnected
        expr: cerberus_websocket_redis_connected == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WebSocket Redis Pub/Sub disconnected"
```

---

### 10.4 Troubleshooting Guide

**Common Issues**:

| Issue | Symptom | Solution |
|-------|---------|----------|
| Connection refused | Clients can't connect | Check firewall, verify `/ws` route registered |
| Authentication failed | 401 errors | Verify JWT secret matches, check token expiration |
| Messages not received | Clients connected but no data | Check RBAC permissions, verify broadcast integration |
| High latency | Messages delayed > 2s | Check broadcast channel buffer, scale horizontally |
| Connection drops | Clients disconnect randomly | Increase pong_wait timeout, check network stability |
| Redis errors | Multi-server sync broken | Verify Redis connectivity, check Pub/Sub subscription |

**Debug Commands**:
```bash
# Test WebSocket connection
wscat -c "ws://localhost:8081/ws?token=YOUR_JWT_TOKEN"

# Check active connections
curl http://localhost:8081/api/v1/websocket/health

# View metrics
curl http://localhost:8081/metrics | grep websocket

# Enable debug logging
export LOG_LEVEL=debug
./cerberus
```

---

## Summary

This plan provides a complete roadmap for implementing production-grade WebSocket functionality in the Cerberus SIEM backend. The implementation is broken down into 7 weekly phases:

1. **Week 1**: Foundation (hub, client, upgrade handler, authentication)
2. **Week 2**: Broadcasting (event, alert, dashboard stats integration)
3. **Week 3**: RBAC filtering and subscriptions
4. **Week 4**: Security hardening (rate limiting, connection limits, validation)
5. **Week 5**: Scalability (buffering, Redis Pub/Sub, batching)
6. **Week 6**: Monitoring (metrics, logging, dashboards, alerts)
7. **Week 7**: Testing (unit, integration, performance, security)

Each phase builds on the previous, allowing for incremental delivery and testing. The plan includes:
- ✅ Detailed component specifications
- ✅ Integration points with existing backend
- ✅ Security requirements and implementations
- ✅ Comprehensive testing strategy
- ✅ Performance targets and optimization techniques
- ✅ Monitoring and observability setup
- ✅ Deployment checklist and troubleshooting guide

**Next Steps**: Parse this document with task-master to generate actionable tasks.
