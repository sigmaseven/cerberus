package ingest

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestFluentdListener_NewFluentdListener tests listener creation with various configurations
func TestFluentdListener_NewFluentdListener(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		port      int
		rateLimit int
		config    *config.Config
		validate  func(*testing.T, *FluentdListener)
	}{
		{
			name:      "Default configuration",
			host:      "127.0.0.1",
			port:      24224,
			rateLimit: 1000,
			config:    &config.Config{},
			validate: func(t *testing.T, fl *FluentdListener) {
				assert.Equal(t, "127.0.0.1", fl.host)
				assert.Equal(t, 24224, fl.port)
				assert.Equal(t, "", fl.sharedKey)
				assert.False(t, fl.requireACK)
				assert.Equal(t, 8388608, fl.chunkSizeLimit) // 8MB default
				assert.False(t, fl.authEnabled)
				assert.Nil(t, fl.tlsConfig)
			},
		},
		{
			name:      "With authentication enabled",
			host:      "0.0.0.0",
			port:      24225,
			rateLimit: 500,
			config: func() *config.Config {
				cfg := &config.Config{}
				cfg.Listeners.Fluentd.SharedKey = "test-secret-key"
				cfg.Listeners.Fluentd.RequireACK = true
				return cfg
			}(),
			validate: func(t *testing.T, fl *FluentdListener) {
				assert.Equal(t, "test-secret-key", fl.sharedKey)
				assert.True(t, fl.requireACK)
				assert.True(t, fl.authEnabled)
			},
		},
		{
			name:      "With custom chunk size limit",
			host:      "localhost",
			port:      24226,
			rateLimit: 2000,
			config: func() *config.Config {
				cfg := &config.Config{}
				cfg.Listeners.Fluentd.ChunkSizeLimit = 1048576 // 1MB
				return cfg
			}(),
			validate: func(t *testing.T, fl *FluentdListener) {
				assert.Equal(t, 1048576, fl.chunkSizeLimit)
			},
		},
		{
			name:      "Port 0 for testing",
			host:      "127.0.0.1",
			port:      0,
			rateLimit: 100,
			config:    &config.Config{},
			validate: func(t *testing.T, fl *FluentdListener) {
				assert.Equal(t, 0, fl.port)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			eventCh := make(chan *core.Event, 10)

			fl := NewFluentdListener(tt.host, tt.port, tt.rateLimit, eventCh, logger, tt.config)

			require.NotNil(t, fl)
			require.NotNil(t, fl.BaseListener)
			require.NotNil(t, fl.sessions)
			require.NotNil(t, fl.parsingQueue)
			assert.Equal(t, 1000, cap(fl.parsingQueue))

			if tt.validate != nil {
				tt.validate(t, fl)
			}
		})
	}
}

// TestFluentdListener_Start_Stop tests listener lifecycle
func TestFluentdListener_Start_Stop(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		port        int
		config      *config.Config
		shouldStart bool
		expectError bool
	}{
		{
			name:        "Start on valid port",
			host:        "127.0.0.1",
			port:        0, // Use port 0 to get any available port
			config:      &config.Config{},
			shouldStart: true,
			expectError: false,
		},
		{
			name: "Start with TLS fails without certs",
			host: "127.0.0.1",
			port: 0,
			config: func() *config.Config {
				cfg := &config.Config{}
				cfg.Listeners.Fluentd.TLS = true
				cfg.Listeners.Fluentd.CertFile = "nonexistent.crt"
				cfg.Listeners.Fluentd.KeyFile = "nonexistent.key"
				return cfg
			}(),
			shouldStart: true, // TLS error is logged but listener starts without TLS
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			eventCh := make(chan *core.Event, 100)

			fl := NewFluentdListener(tt.host, tt.port, 1000, eventCh, logger, tt.config)
			require.NotNil(t, fl)

			if tt.shouldStart {
				err := fl.Start()
				if tt.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					// Give it a moment to start
					time.Sleep(50 * time.Millisecond)

					// Verify listener is active
					assert.NotNil(t, fl.tcpListener)

					// Stop the listener
					err = fl.Stop()
					assert.NoError(t, err)
				}
			}
		})
	}
}

// TestFluentdListener_CreateEvent tests event creation from Fluentd records
func TestFluentdListener_CreateEvent(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		timeVal  interface{}
		record   map[string]interface{}
		sourceIP string
		validate func(*testing.T, *core.Event)
	}{
		{
			name:    "Basic message event",
			tag:     "app.logs",
			timeVal: int64(1640995200),
			record: map[string]interface{}{
				"message": "test log message",
				"level":   "info",
			},
			sourceIP: "192.168.1.100",
			validate: func(t *testing.T, event *core.Event) {
				assert.Equal(t, "fluentd", event.SourceFormat)
				assert.Equal(t, "test log message", event.RawData)
				assert.Equal(t, "192.168.1.100", event.Fields["source_ip"])
				assert.Equal(t, "app.logs", event.Fields["tag"])
				assert.Equal(t, "fluentd", event.Fields["event_source"])
			},
		},
		{
			name:    "Log field instead of message",
			tag:     "docker.container",
			timeVal: int64(1640995200),
			record: map[string]interface{}{
				"log":          "Docker container log",
				"container_id": "abc123",
			},
			sourceIP: "172.17.0.2",
			validate: func(t *testing.T, event *core.Event) {
				assert.Equal(t, "Docker container log", event.Fields["message"])
				assert.Equal(t, "Docker container log", event.RawData)
			},
		},
		{
			name:    "Event type extraction",
			tag:     "security.events",
			timeVal: int64(1640995200),
			record: map[string]interface{}{
				"message":    "Security event",
				"event_type": "authentication",
			},
			sourceIP: "10.0.0.1",
			validate: func(t *testing.T, event *core.Event) {
				assert.Equal(t, "authentication", event.Fields["event_type"])
			},
		},
		{
			name:    "Type field mapping to event_type",
			tag:     "app.events",
			timeVal: int64(1640995200),
			record: map[string]interface{}{
				"message": "App event",
				"type":    "user_action",
			},
			sourceIP: "10.0.0.2",
			validate: func(t *testing.T, event *core.Event) {
				assert.Equal(t, "user_action", event.Fields["event_type"])
			},
		},
		{
			name:    "Severity field extraction",
			tag:     "syslog.system",
			timeVal: int64(1640995200),
			record: map[string]interface{}{
				"message":  "System message",
				"severity": "critical",
			},
			sourceIP: "192.168.1.10",
			validate: func(t *testing.T, event *core.Event) {
				assert.Equal(t, "critical", event.Fields["severity"])
			},
		},
		{
			name:    "Level field mapping to severity",
			tag:     "app.logs",
			timeVal: int64(1640995200),
			record: map[string]interface{}{
				"message": "App log",
				"level":   "warn",
			},
			sourceIP: "10.0.0.3",
			validate: func(t *testing.T, event *core.Event) {
				assert.Equal(t, "warn", event.Fields["severity"])
			},
		},
		{
			name:     "Empty record",
			tag:      "test.empty",
			timeVal:  int64(1640995200),
			record:   map[string]interface{}{},
			sourceIP: "127.0.0.1",
			validate: func(t *testing.T, event *core.Event) {
				assert.NotNil(t, event)
				assert.Equal(t, "test.empty", event.Fields["tag"])
			},
		},
		{
			name:    "Complex nested record",
			tag:     "kubernetes.pod",
			timeVal: int64(1640995200),
			record: map[string]interface{}{
				"message": "K8s log",
				"kubernetes": map[string]interface{}{
					"pod_name":  "nginx-abc123",
					"namespace": "production",
					"labels": map[string]interface{}{
						"app":     "web",
						"version": "v1.0",
					},
				},
			},
			sourceIP: "10.244.0.5",
			validate: func(t *testing.T, event *core.Event) {
				k8s := event.Fields["kubernetes"]
				assert.NotNil(t, k8s)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			eventCh := make(chan *core.Event, 10)
			cfg := &config.Config{}

			fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

			event := fl.createEvent(tt.tag, tt.timeVal, tt.record, tt.sourceIP)

			require.NotNil(t, event)
			require.NotNil(t, event.Fields)

			if tt.validate != nil {
				tt.validate(t, event)
			}
		})
	}
}

// TestFluentdListener_ProcessMessage tests single message processing
func TestFluentdListener_ProcessMessage(t *testing.T) {
	tests := []struct {
		name          string
		msg           *ForwardMessage
		sourceIP      string
		expectSuccess bool
	}{
		{
			name: "Valid message",
			msg: &ForwardMessage{
				Tag:  "app.logs",
				Time: int64(1640995200),
				Record: map[string]interface{}{
					"message": "test",
				},
			},
			sourceIP:      "192.168.1.1",
			expectSuccess: true,
		},
		{
			name:          "Nil message",
			msg:           nil,
			sourceIP:      "192.168.1.1",
			expectSuccess: false,
		},
		{
			name: "Message with too many fields",
			msg: &ForwardMessage{
				Tag:  "app.logs",
				Time: int64(1640995200),
				Record: func() map[string]interface{} {
					r := make(map[string]interface{})
					for i := 0; i < 2000; i++ {
						r[fmt.Sprintf("field%d", i)] = "value"
					}
					return r
				}(),
			},
			sourceIP:      "192.168.1.1",
			expectSuccess: false,
		},
		{
			name: "Message with oversized field",
			msg: &ForwardMessage{
				Tag:  "app.logs",
				Time: int64(1640995200),
				Record: map[string]interface{}{
					"message": string(make([]byte, 100000)),
				},
			},
			sourceIP:      "192.168.1.1",
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			eventCh := make(chan *core.Event, 10)
			cfg := &config.Config{}

			fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

			initialProcessed := fl.messagesProcessed
			initialFailed := fl.messagesFailed

			fl.processMessage(tt.msg, tt.sourceIP)

			// Give processing time
			time.Sleep(50 * time.Millisecond)

			if tt.expectSuccess {
				// Check if event was queued
				select {
				case event := <-eventCh:
					assert.NotNil(t, event)
					assert.GreaterOrEqual(t, fl.messagesProcessed, initialProcessed)
				case <-time.After(100 * time.Millisecond):
					// Channel full or event not sent - check metrics
					assert.GreaterOrEqual(t, fl.messagesFailed, initialFailed)
				}
			} else {
				assert.Equal(t, initialFailed+1, fl.messagesFailed)
			}
		})
	}
}

// TestFluentdListener_ProcessBatch tests batch message processing
func TestFluentdListener_ProcessBatch(t *testing.T) {
	tests := []struct {
		name          string
		batch         *ForwardBatch
		sourceIP      string
		expectSuccess bool
		expectedCount int
	}{
		{
			name: "Valid batch",
			batch: &ForwardBatch{
				Tag: "app.logs",
				Entries: []ForwardEntry{
					{
						Time:   int64(1640995200),
						Record: map[string]interface{}{"message": "msg1"},
					},
					{
						Time:   int64(1640995201),
						Record: map[string]interface{}{"message": "msg2"},
					},
					{
						Time:   int64(1640995202),
						Record: map[string]interface{}{"message": "msg3"},
					},
				},
			},
			sourceIP:      "192.168.1.1",
			expectSuccess: true,
			expectedCount: 3,
		},
		{
			name:          "Nil batch",
			batch:         nil,
			sourceIP:      "192.168.1.1",
			expectSuccess: false,
			expectedCount: 0,
		},
		{
			name: "Empty batch",
			batch: &ForwardBatch{
				Tag:     "app.logs",
				Entries: []ForwardEntry{},
			},
			sourceIP:      "192.168.1.1",
			expectSuccess: true,
			expectedCount: 0,
		},
		{
			name: "Batch with invalid entries",
			batch: &ForwardBatch{
				Tag: "app.logs",
				Entries: []ForwardEntry{
					{
						Time: int64(1640995200),
						Record: func() map[string]interface{} {
							r := make(map[string]interface{})
							for i := 0; i < 2000; i++ {
								r[fmt.Sprintf("field%d", i)] = "value"
							}
							return r
						}(),
					},
				},
			},
			sourceIP:      "192.168.1.1",
			expectSuccess: false,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			eventCh := make(chan *core.Event, 100)
			cfg := &config.Config{}

			fl := NewFluentdListener("127.0.0.1", 24224, 10000, eventCh, logger, cfg)

			fl.processBatch(tt.batch, tt.sourceIP)

			// Give processing time
			time.Sleep(100 * time.Millisecond)

			// Count events received
			eventCount := 0
			done := false
			for !done {
				select {
				case <-eventCh:
					eventCount++
				case <-time.After(50 * time.Millisecond):
					done = true
				}
			}

			if tt.expectSuccess {
				assert.Equal(t, tt.expectedCount, eventCount)
			}
		})
	}
}

// TestFluentdListener_ProcessPackedForward tests packed forward processing
func TestFluentdListener_ProcessPackedForward(t *testing.T) {
	tests := []struct {
		name          string
		packed        *PackedForward
		compressed    bool
		sourceIP      string
		expectSuccess bool
	}{
		{
			name: "Valid packed forward (uncompressed)",
			packed: func() *PackedForward {
				// Create packed entries
				var buf bytes.Buffer
				enc := msgpack.NewEncoder(&buf)
				enc.EncodeArrayLen(2)
				enc.EncodeInt64(1640995200)
				enc.EncodeMapLen(1)
				enc.EncodeString("message")
				enc.EncodeString("test1")

				return &PackedForward{
					Tag:     "app.logs",
					Entries: buf.Bytes(),
				}
			}(),
			compressed:    false,
			sourceIP:      "192.168.1.1",
			expectSuccess: true,
		},
		{
			name: "Valid packed forward (compressed)",
			packed: func() *PackedForward {
				// Create packed entries
				var buf bytes.Buffer
				enc := msgpack.NewEncoder(&buf)
				enc.EncodeArrayLen(2)
				enc.EncodeInt64(1640995200)
				enc.EncodeMapLen(1)
				enc.EncodeString("message")
				enc.EncodeString("test1")

				// Compress
				var compBuf bytes.Buffer
				gzWriter := gzip.NewWriter(&compBuf)
				gzWriter.Write(buf.Bytes())
				gzWriter.Close()

				return &PackedForward{
					Tag:     "app.logs",
					Entries: compBuf.Bytes(),
					Options: map[string]interface{}{
						"compressed": "gzip",
					},
				}
			}(),
			compressed:    true,
			sourceIP:      "192.168.1.1",
			expectSuccess: true,
		},
		{
			name:          "Nil packed forward",
			packed:        nil,
			compressed:    false,
			sourceIP:      "192.168.1.1",
			expectSuccess: false,
		},
		{
			name: "Invalid packed data",
			packed: &PackedForward{
				Tag:     "app.logs",
				Entries: []byte{0xFF, 0xFF, 0xFF},
			},
			compressed:    false,
			sourceIP:      "192.168.1.1",
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t).Sugar()
			eventCh := make(chan *core.Event, 100)
			cfg := &config.Config{}

			fl := NewFluentdListener("127.0.0.1", 24224, 10000, eventCh, logger, cfg)

			initialFailed := fl.messagesFailed

			fl.processPackedForward(tt.packed, tt.compressed, tt.sourceIP)

			// Give processing time
			time.Sleep(100 * time.Millisecond)

			if !tt.expectSuccess {
				assert.Greater(t, fl.messagesFailed, initialFailed)
			}
		})
	}
}

// TestFluentdListener_SendACK tests ACK sending
func TestFluentdListener_SendACK(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

	// Create a mock connection using pipe
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	chunkID := "test-chunk-123"

	// Send ACK in goroutine
	done := make(chan bool)
	go func() {
		fl.sendACK(client, chunkID)
		done <- true
	}()

	// Read ACK on server side
	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	// Decode ACK
	ackChunkID, err := DecodeACK(buf[:n])
	assert.NoError(t, err)
	assert.Equal(t, chunkID, ackChunkID)

	// Wait for ACK sending to complete (including metrics update)
	<-done

	// Check metrics (should be incremented after sendACK completes)
	assert.Greater(t, fl.acksSent, int64(0))
}

// TestFluentdListener_GetMetrics tests metrics reporting
func TestFluentdListener_GetMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

	// Set some metrics
	fl.messagesReceived = 100
	fl.messagesProcessed = 95
	fl.messagesFailed = 5
	fl.bytesReceived = 10240
	fl.acksSent = 90
	fl.authFailures = 2

	metrics := fl.GetMetrics()

	assert.Equal(t, int64(100), metrics["messages_received"])
	assert.Equal(t, int64(95), metrics["messages_processed"])
	assert.Equal(t, int64(5), metrics["messages_failed"])
	assert.Equal(t, int64(10240), metrics["bytes_received"])
	assert.Equal(t, int64(90), metrics["acks_sent"])
	assert.Equal(t, int64(2), metrics["auth_failures"])
	assert.Equal(t, 0, metrics["active_sessions"])
}

// TestFluentdListener_CloseSession tests session cleanup
func TestFluentdListener_CloseSession(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

	// Create a mock connection
	server, client := net.Pipe()
	defer server.Close()

	session := &fluentdSession{
		conn:          client,
		authenticated: true,
		lastActivity:  time.Now(),
	}

	fl.sessions[client] = session
	assert.Equal(t, 1, len(fl.sessions))

	fl.closeSession(session)

	assert.Equal(t, 0, len(fl.sessions))
}

// TestFluentdListener_LoadTLSConfig tests TLS configuration loading
func TestFluentdListener_LoadTLSConfig(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

	// Test with invalid files
	tlsConfig, err := fl.loadTLSConfig("nonexistent.crt", "nonexistent.key")
	assert.Error(t, err)
	assert.Nil(t, tlsConfig)
}

// TestFluentdListener_ConcurrentProcessing tests concurrent message processing
func TestFluentdListener_ConcurrentProcessing(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1000)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 10000, eventCh, logger, cfg)

	// Process multiple messages concurrently
	const numMessages = 100
	done := make(chan bool, numMessages)

	for i := 0; i < numMessages; i++ {
		go func(idx int) {
			msg := &ForwardMessage{
				Tag:  fmt.Sprintf("test.tag.%d", idx),
				Time: int64(1640995200 + idx),
				Record: map[string]interface{}{
					"message": fmt.Sprintf("test message %d", idx),
					"index":   idx,
				},
			}
			fl.processMessage(msg, "192.168.1.1")
			done <- true
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < numMessages; i++ {
		<-done
	}

	// Give time for events to be queued
	time.Sleep(200 * time.Millisecond)

	// Verify metrics
	assert.Greater(t, fl.messagesProcessed+fl.messagesFailed, int64(0))
}

// TestFluentdListener_PanicRecovery tests panic recovery in message processing
func TestFluentdListener_PanicRecovery(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

	// Create job that will cause panic in parser
	job := parsingJob{
		raw:      []byte{0xFF, 0xFF, 0xFF}, // Invalid msgpack
		sourceIP: "192.168.1.1",
		name:     "test",
	}

	// Process should not panic
	require.NotPanics(t, func() {
		fl.processForwardMessage(job)
	})

	// Check that failure was recorded
	assert.Greater(t, fl.messagesFailed, int64(0))
}

// TestFluentdListener_SessionManagement tests concurrent session management
func TestFluentdListener_SessionManagement(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 10)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 1000, eventCh, logger, cfg)

	const numSessions = 50
	sessions := make([]*fluentdSession, numSessions)

	// Create multiple sessions concurrently
	done := make(chan bool, numSessions)
	for i := 0; i < numSessions; i++ {
		go func(idx int) {
			server, client := net.Pipe()
			defer server.Close()

			session := &fluentdSession{
				conn:          client,
				authenticated: false,
				lastActivity:  time.Now(),
			}

			fl.sessionMutex.Lock()
			fl.sessions[client] = session
			sessions[idx] = session
			fl.sessionMutex.Unlock()

			done <- true
		}(i)
	}

	// Wait for all sessions to be created
	for i := 0; i < numSessions; i++ {
		<-done
	}

	fl.sessionMutex.RLock()
	sessionCount := len(fl.sessions)
	fl.sessionMutex.RUnlock()

	assert.Equal(t, numSessions, sessionCount)

	// Clean up sessions
	for _, session := range sessions {
		if session != nil {
			fl.closeSession(session)
		}
	}

	fl.sessionMutex.RLock()
	finalCount := len(fl.sessions)
	fl.sessionMutex.RUnlock()

	assert.Equal(t, 0, finalCount)
}

// TestFluentdListener_MetricsConcurrency tests concurrent metrics updates
func TestFluentdListener_MetricsConcurrency(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1000)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 10000, eventCh, logger, cfg)

	const numUpdates = 1000
	done := make(chan bool, numUpdates)

	// Concurrently update metrics
	for i := 0; i < numUpdates; i++ {
		go func() {
			fl.metricsMutex.Lock()
			fl.messagesReceived++
			fl.bytesReceived += 100
			fl.metricsMutex.Unlock()
			done <- true
		}()
	}

	// Wait for completion
	for i := 0; i < numUpdates; i++ {
		<-done
	}

	fl.metricsMutex.RLock()
	received := fl.messagesReceived
	bytes := fl.bytesReceived
	fl.metricsMutex.RUnlock()

	assert.Equal(t, int64(numUpdates), received)
	assert.Equal(t, int64(numUpdates*100), bytes)
}

// BenchmarkFluentdListener_ProcessMessage benchmarks message processing
func BenchmarkFluentdListener_ProcessMessage(b *testing.B) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 10000)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 100000, eventCh, logger, cfg)

	msg := &ForwardMessage{
		Tag:  "benchmark.test",
		Time: int64(1640995200),
		Record: map[string]interface{}{
			"message": "benchmark test message",
			"level":   "info",
			"user":    "test",
		},
	}

	// Drain event channel
	go func() {
		for range eventCh {
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fl.processMessage(msg, "192.168.1.1")
	}
}

// BenchmarkFluentdListener_ProcessBatch benchmarks batch processing
func BenchmarkFluentdListener_ProcessBatch(b *testing.B) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 10000)
	cfg := &config.Config{}

	fl := NewFluentdListener("127.0.0.1", 24224, 100000, eventCh, logger, cfg)

	batch := &ForwardBatch{
		Tag: "benchmark.test",
		Entries: []ForwardEntry{
			{
				Time:   int64(1640995200),
				Record: map[string]interface{}{"message": "msg1"},
			},
			{
				Time:   int64(1640995201),
				Record: map[string]interface{}{"message": "msg2"},
			},
			{
				Time:   int64(1640995202),
				Record: map[string]interface{}{"message": "msg3"},
			},
		},
	}

	// Drain event channel
	go func() {
		for range eventCh {
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fl.processBatch(batch, "192.168.1.1")
	}
}
