package ingest

import (
	"cerberus/config"
	"cerberus/core"
	"cerberus/metrics"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"go.uber.org/zap"
)

// FluentdListener implements the Fluentd Forward protocol listener
type FluentdListener struct {
	*BaseListener
	sharedKey      string
	requireACK     bool
	chunkSizeLimit int
	tlsConfig      *tls.Config
	sessions       map[net.Conn]*fluentdSession
	sessionMutex   sync.RWMutex
	authEnabled    bool
	parsingQueue   chan parsingJob

	// Metrics
	messagesReceived  int64
	messagesProcessed int64
	messagesFailed    int64
	bytesReceived     int64
	acksSent          int64
	authFailures      int64
	panicCount        int64 // Track panics for circuit breaker
	metricsMutex      sync.RWMutex
}

// fluentdSession tracks per-connection state
type fluentdSession struct {
	conn          net.Conn
	authenticated bool
	serverNonce   []byte
	clientNonce   []byte
	lastActivity  time.Time
	mu            sync.Mutex
}

// parsingJob represents a job for parsing Fluentd messages
type parsingJob struct {
	raw      []byte
	sourceIP string
	name     string
}

// NewFluentdListener creates a new Fluentd listener
func NewFluentdListener(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger, cfg *config.Config) *FluentdListener {
	base := NewBaseListenerWithConfig(host, port, rateLimit, eventCh, logger, cfg)

	fl := &FluentdListener{
		BaseListener:   base,
		sharedKey:      "",
		requireACK:     false,
		chunkSizeLimit: 8388608, // 8MB default
		sessions:       make(map[net.Conn]*fluentdSession),
		authEnabled:    false,
		parsingQueue:   make(chan parsingJob, 1000),
	}

	// Apply configuration
	if cfg != nil {
		if cfg.Listeners.Fluentd.SharedKey != "" {
			fl.sharedKey = cfg.Listeners.Fluentd.SharedKey
			fl.authEnabled = true
		}
		fl.requireACK = cfg.Listeners.Fluentd.RequireACK
		if cfg.Listeners.Fluentd.ChunkSizeLimit > 0 {
			fl.chunkSizeLimit = cfg.Listeners.Fluentd.ChunkSizeLimit
		}

		// TLS configuration
		if cfg.Listeners.Fluentd.TLS {
			tlsConfig, err := fl.loadTLSConfig(
				cfg.Listeners.Fluentd.CertFile,
				cfg.Listeners.Fluentd.KeyFile,
			)
			if err != nil {
				logger.Errorf("Failed to load TLS config: %v", err)
			} else {
				fl.tlsConfig = tlsConfig
			}
		}
	}

	return fl
}

// Start starts the Fluentd listener
func (fl *FluentdListener) Start() error {
	var listener net.Listener
	var err error

	address := fmt.Sprintf("%s:%d", fl.host, fl.port)

	if fl.tlsConfig != nil {
		listener, err = tls.Listen("tcp", address, fl.tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
		fl.logger.Infof("Fluentd listener started with TLS on %s", address)
	} else {
		listener, err = net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		fl.logger.Infof("Fluentd listener started on %s", address)
	}

	fl.tcpListener = listener

	// Start parsing workers
	// Note: Fluentd doesn't use the standard parsing workers since it handles msgpack binary protocol
	// The processForwardMessage is called directly from handleConnection

	// Start connection acceptor
	fl.wg.Add(1)
	go fl.acceptConnections()

	// Start metrics reporter
	fl.wg.Add(1)
	go fl.reportMetrics()

	return nil
}

// acceptConnections accepts incoming TCP connections
func (fl *FluentdListener) acceptConnections() {
	defer fl.wg.Done()

	for {
		select {
		case <-fl.stopCh:
			return
		default:
		}

		// Set accept deadline to allow checking stopCh
		fl.tcpListener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

		conn, err := fl.tcpListener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, check stopCh
			}
			fl.logger.Errorf("Failed to accept connection: %v", err)
			continue
		}

		fl.logger.Debugf("Accepted connection from %s", conn.RemoteAddr())

		// Create session
		session := &fluentdSession{
			conn:          conn,
			authenticated: !fl.authEnabled, // If auth disabled, mark as authenticated
			lastActivity:  time.Now(),
		}

		fl.sessionMutex.Lock()
		fl.sessions[conn] = session
		fl.sessionMutex.Unlock()

		// Handle connection in goroutine
		fl.wg.Add(1)
		go fl.handleConnection(session)
	}
}

// handleConnection handles a single TCP connection
func (fl *FluentdListener) handleConnection(session *fluentdSession) {
	defer fl.wg.Done()
	defer fl.closeSession(session)

	// If authentication is enabled, handle auth handshake first
	if fl.authEnabled {
		if err := fl.handleAuthentication(session); err != nil {
			fl.logger.Warnf("Authentication failed for %s: %v", session.conn.RemoteAddr(), err)
			fl.metricsMutex.Lock()
			fl.authFailures++
			fl.metricsMutex.Unlock()
			return
		}
		fl.logger.Debugf("Authentication successful for %s", session.conn.RemoteAddr())
	}

	// Read and process messages
	reader := session.conn

	// Create timer for queue timeout to prevent memory leak
	queueTimer := time.NewTimer(1 * time.Second)
	defer queueTimer.Stop()

	for {
		select {
		case <-fl.stopCh:
			return
		default:
		}

		// Set read deadline
		session.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Read MessagePack message
		// We need to read the message in chunks
		dec := msgpack.NewDecoder(reader)

		// Decode the message
		var rawMessage []interface{}
		err := dec.Decode(&rawMessage)
		if err != nil {
			if err == io.EOF {
				fl.logger.Debugf("Connection closed by client: %s", session.conn.RemoteAddr())
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fl.logger.Debugf("Read timeout for %s", session.conn.RemoteAddr())
				continue
			}
			fl.logger.Errorf("Failed to decode message from %s: %v", session.conn.RemoteAddr(), err)
			return
		}

		// Update last activity
		session.mu.Lock()
		session.lastActivity = time.Now()
		session.mu.Unlock()

		// Re-encode the message to pass to parser
		data, err := msgpack.Marshal(rawMessage)
		if err != nil {
			fl.logger.Errorf("Failed to re-encode message: %v", err)
			continue
		}

		fl.metricsMutex.Lock()
		fl.messagesReceived++
		fl.bytesReceived += int64(len(data))
		fl.metricsMutex.Unlock()

		// Check if rate limiter allows
		if !fl.limiter.Allow() {
			fl.logger.Warnf("Rate limit exceeded, dropping message from %s", session.conn.RemoteAddr())
			continue
		}

		// Queue for processing
		sourceIP := session.conn.RemoteAddr().String()
		job := parsingJob{
			raw:      data,
			sourceIP: sourceIP,
			name:     "fluentd",
		}

		// Reset timer before using it
		if !queueTimer.Stop() {
			select {
			case <-queueTimer.C:
			default:
			}
		}
		queueTimer.Reset(1 * time.Second)

		select {
		case fl.parsingQueue <- job:
			// Queued successfully
		case <-queueTimer.C:
			fl.logger.Warnf("Parsing queue full, dropping message from %s", sourceIP)
		}

		// Send ACK if required
		if fl.requireACK {
			if options, ok := rawMessage[len(rawMessage)-1].(map[string]interface{}); ok {
				if chunkID, ok := options["chunk"].(string); ok {
					fl.sendACK(session.conn, chunkID)
				}
			}
		}
	}
}

// processForwardMessage processes a Forward protocol message
// SECURITY: Panic recovery prevents malformed messages from crashing the listener
func (fl *FluentdListener) processForwardMessage(job parsingJob) {
	// Recover from any panics during message processing
	defer func() {
		if r := recover(); r != nil {
			// SECURITY: Get stack trace for debugging and monitoring
			stackBuf := make([]byte, 4096)
			stackSize := runtime.Stack(stackBuf, false)

			fl.logger.Errorf("CRITICAL PANIC in message processing from %s: %v\nStack:\n%s",
				job.sourceIP, r, string(stackBuf[:stackSize]))

			fl.metricsMutex.Lock()
			fl.messagesFailed++
			fl.panicCount++
			lastPanicCount := fl.panicCount
			fl.metricsMutex.Unlock()

			// Metric for monitoring
			metrics.FluentdPanics.WithLabelValues("fluentd").Inc()

			// SAFETY: Circuit breaker - stop listener after too many panics to prevent data corruption
			if lastPanicCount > 100 {
				fl.logger.Fatal("Too many panics (>100), stopping listener to prevent data corruption")
			}
		}
	}()

	// Parse the Forward message
	msg, batch, packed, msgType, err := ParseForwardMessage(job.raw)
	if err != nil {
		fl.logger.Errorf("Failed to parse Forward message from %s: %v", job.sourceIP, err)
		fl.metricsMutex.Lock()
		fl.messagesFailed++
		fl.metricsMutex.Unlock()
		return
	}

	// Process based on message type
	switch msgType {
	case MessageMode:
		fl.processMessage(msg, job.sourceIP)
	case ForwardMode:
		fl.processBatch(batch, job.sourceIP)
	case PackedForwardMode, CompressedPackedForwardMode:
		fl.processPackedForward(packed, msgType == CompressedPackedForwardMode, job.sourceIP)
	}
}

// processMessage processes a single message
// SECURITY: Defensive nil checks prevent panics from malformed input
func (fl *FluentdListener) processMessage(msg *ForwardMessage, sourceIP string) {
	// SECURITY: Nil check to prevent panic
	if msg == nil {
		fl.logger.Errorf("Received nil message from %s", sourceIP)
		fl.metricsMutex.Lock()
		fl.messagesFailed++
		fl.metricsMutex.Unlock()
		return
	}

	// Validate record
	if err := ValidateRecord(msg.Record, 1000, 65536); err != nil {
		fl.logger.Warnf("Invalid record from %s: %v", sourceIP, err)
		fl.metricsMutex.Lock()
		fl.messagesFailed++
		fl.metricsMutex.Unlock()
		return
	}

	// Sanitize record
	sanitized := SanitizeRecord(msg.Record)

	// Create event
	event := fl.createEvent(msg.Tag, msg.Time, sanitized, sourceIP)

	// Send to event channel with timeout
	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()

	select {
	case fl.eventCh <- event:
		fl.metricsMutex.Lock()
		fl.messagesProcessed++
		fl.metricsMutex.Unlock()
	case <-timer.C:
		fl.logger.Warnf("Event channel full, dropping event from %s", sourceIP)
		fl.metricsMutex.Lock()
		fl.messagesFailed++
		fl.metricsMutex.Unlock()
	}
}

// processBatch processes a batch of messages
// SECURITY: Defensive nil checks prevent panics from malformed input
func (fl *FluentdListener) processBatch(batch *ForwardBatch, sourceIP string) {
	// SECURITY: Nil check to prevent panic
	if batch == nil {
		fl.logger.Errorf("Received nil batch from %s", sourceIP)
		fl.metricsMutex.Lock()
		fl.messagesFailed++
		fl.metricsMutex.Unlock()
		return
	}

	// Create timer once for the loop to prevent memory leak
	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()

	for _, entry := range batch.Entries {
		// Validate record
		if err := ValidateRecord(entry.Record, 1000, 65536); err != nil {
			fl.logger.Warnf("Invalid record in batch from %s: %v", sourceIP, err)
			fl.metricsMutex.Lock()
			fl.messagesFailed++
			fl.metricsMutex.Unlock()
			continue
		}

		// Sanitize record
		sanitized := SanitizeRecord(entry.Record)

		// Create event
		event := fl.createEvent(batch.Tag, entry.Time, sanitized, sourceIP)

		// Reset timer before using it
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(1 * time.Second)

		// Send to event channel
		select {
		case fl.eventCh <- event:
			fl.metricsMutex.Lock()
			fl.messagesProcessed++
			fl.metricsMutex.Unlock()
		case <-timer.C:
			fl.logger.Warnf("Event channel full, dropping event from %s", sourceIP)
			fl.metricsMutex.Lock()
			fl.messagesFailed++
			fl.metricsMutex.Unlock()
		}
	}
}

// processPackedForward processes a packed forward message
// SECURITY: Defensive nil checks prevent panics from malformed input
func (fl *FluentdListener) processPackedForward(packed *PackedForward, compressed bool, sourceIP string) {
	// SECURITY: Nil check to prevent panic
	if packed == nil {
		fl.logger.Errorf("Received nil packed forward from %s", sourceIP)
		fl.metricsMutex.Lock()
		fl.messagesFailed++
		fl.metricsMutex.Unlock()
		return
	}

	// Unpack entries
	entries, err := UnpackPackedForward(packed, compressed)
	if err != nil {
		fl.logger.Errorf("Failed to unpack PackedForward from %s: %v", sourceIP, err)
		fl.metricsMutex.Lock()
		fl.messagesFailed++
		fl.metricsMutex.Unlock()
		return
	}

	// Create timer once for the loop to prevent memory leak
	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()

	// Process each entry
	for _, entry := range entries {
		// Validate record
		if err := ValidateRecord(entry.Record, 1000, 65536); err != nil {
			fl.logger.Warnf("Invalid record in packed message from %s: %v", sourceIP, err)
			fl.metricsMutex.Lock()
			fl.messagesFailed++
			fl.metricsMutex.Unlock()
			continue
		}

		// Sanitize record
		sanitized := SanitizeRecord(entry.Record)

		// Create event
		event := fl.createEvent(packed.Tag, entry.Time, sanitized, sourceIP)

		// Reset timer before using it
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(1 * time.Second)

		// Send to event channel
		select {
		case fl.eventCh <- event:
			fl.metricsMutex.Lock()
			fl.messagesProcessed++
			fl.metricsMutex.Unlock()
		case <-timer.C:
			fl.logger.Warnf("Event channel full, dropping event from %s", sourceIP)
			fl.metricsMutex.Lock()
			fl.messagesFailed++
			fl.metricsMutex.Unlock()
		}
	}
}

// createEvent creates a Cerberus event from a Fluentd record
func (fl *FluentdListener) createEvent(tag string, timeVal interface{}, record map[string]interface{}, sourceIP string) *core.Event {
	// Convert time
	var timestamp time.Time
	switch t := timeVal.(type) {
	case int64:
		timestamp = time.Unix(t, 0)
	case uint64:
		timestamp = time.Unix(int64(t), 0)
	case EventTime:
		timestamp = time.Unix(int64(t.Seconds), int64(t.Nanoseconds))
	case map[string]interface{}:
		// EventTime as map (msgpack decoded format)
		if seconds, ok := t["seconds"].(uint32); ok {
			nanoseconds, _ := t["nanoseconds"].(uint32)
			timestamp = time.Unix(int64(seconds), int64(nanoseconds))
		} else {
			timestamp = time.Now()
		}
	default:
		timestamp = time.Now()
	}

	// Create event using NewEvent to get proper initialization
	event := core.NewEvent()
	event.Timestamp = timestamp
	event.SourceFormat = "fluentd"

	// Copy all fields from the record
	if event.Fields == nil {
		event.Fields = make(map[string]interface{})
	}
	for k, v := range record {
		event.Fields[k] = v
	}

	// Add metadata fields
	event.Fields["event_source"] = "fluentd"
	event.Fields["tag"] = tag
	event.Fields["source_ip"] = sourceIP

	// Extract common fields
	if msg, ok := record["message"].(string); ok {
		event.Fields["message"] = msg
		// JSON-encode the string to make it valid JSON for RawData
		rawJSON, _ := json.Marshal(msg)
		event.RawData = rawJSON
	} else if log, ok := record["log"].(string); ok {
		event.Fields["message"] = log
		// JSON-encode the string to make it valid JSON for RawData
		rawJSON, _ := json.Marshal(log)
		event.RawData = rawJSON
	}

	// Extract event type if available
	if eventType, ok := record["event_type"].(string); ok {
		event.Fields["event_type"] = eventType
	} else if eventType, ok := record["type"].(string); ok {
		event.Fields["event_type"] = eventType
	}

	// Extract severity if available
	if severity, ok := record["severity"].(string); ok {
		event.Fields["severity"] = severity
	} else if level, ok := record["level"].(string); ok {
		event.Fields["severity"] = level
	}

	// Apply SIGMA field normalization at ingestion time
	if fl.fieldNormalizer != nil && event.Fields != nil {
		// Determine log source: use configured source, or auto-detect from fields
		logSource := fl.listenerSource
		if logSource == "" {
			logSource = core.DetectLogSource(event.Fields)
		}
		event.Fields = fl.fieldNormalizer.NormalizeToSIGMA(event.Fields, logSource)
	}

	// Set listener metadata
	if fl.listenerID != "" {
		event.ListenerID = fl.listenerID
	}
	if fl.listenerName != "" {
		event.ListenerName = fl.listenerName
	}

	return event
}

// handleAuthentication handles the Fluentd authentication handshake
func (fl *FluentdListener) handleAuthentication(session *fluentdSession) error {
	// Generate server nonce
	serverNonce, err := GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	session.serverNonce = serverNonce

	// Wait for HELO from client
	// The client should send: ["HELO", {"nonce": "...", "auth": "..."}]
	dec := msgpack.NewDecoder(session.conn)
	var helo []interface{}
	if err := dec.Decode(&helo); err != nil {
		return fmt.Errorf("failed to decode HELO: %w", err)
	}

	if len(helo) < 2 || helo[0] != "HELO" {
		return fmt.Errorf("invalid HELO message")
	}

	heloData, ok := helo[1].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid HELO data")
	}

	clientNonceHex, ok := heloData["nonce"].(string)
	if !ok {
		return fmt.Errorf("missing client nonce")
	}

	clientNonce := []byte(clientNonceHex)
	session.clientNonce = clientNonce

	// Send PING with server nonce
	// Format: ["PING", {"server_hostname": "...", "nonce": "...", "auth": "..."}]
	ping := []interface{}{
		"PING",
		map[string]interface{}{
			"nonce": fmt.Sprintf("%x", serverNonce),
			"auth":  "", // Empty for now
		},
	}

	pingData, err := msgpack.Marshal(ping)
	if err != nil {
		return fmt.Errorf("failed to encode PING: %w", err)
	}

	if _, err := session.conn.Write(pingData); err != nil {
		return fmt.Errorf("failed to send PING: %w", err)
	}

	// Wait for PONG from client
	// Format: ["PONG", {"auth": "..."}]
	var pong []interface{}
	if err := dec.Decode(&pong); err != nil {
		return fmt.Errorf("failed to decode PONG: %w", err)
	}

	if len(pong) < 2 || pong[0] != "PONG" {
		return fmt.Errorf("invalid PONG message")
	}

	pongData, ok := pong[1].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid PONG data")
	}

	clientAuth, ok := pongData["auth"].(string)
	if !ok {
		return fmt.Errorf("missing client auth")
	}

	// Validate HMAC
	if !ValidateHMAC(fl.sharedKey, serverNonce, clientNonce, clientAuth) {
		return fmt.Errorf("invalid authentication")
	}

	// Mark session as authenticated
	session.mu.Lock()
	session.authenticated = true
	session.mu.Unlock()

	return nil
}

// sendACK sends an acknowledgment response
func (fl *FluentdListener) sendACK(conn net.Conn, chunkID string) {
	ackData, err := EncodeACK(chunkID)
	if err != nil {
		fl.logger.Errorf("Failed to encode ACK: %v", err)
		return
	}

	if _, err := conn.Write(ackData); err != nil {
		fl.logger.Errorf("Failed to send ACK: %v", err)
		return
	}

	fl.metricsMutex.Lock()
	fl.acksSent++
	fl.metricsMutex.Unlock()
}

// closeSession closes a session and cleans up
func (fl *FluentdListener) closeSession(session *fluentdSession) {
	if err := session.conn.Close(); err != nil {
		fl.logger.Warnf("Failed to close session connection: %v", err)
	}

	fl.sessionMutex.Lock()
	delete(fl.sessions, session.conn)
	fl.sessionMutex.Unlock()

	fl.logger.Debugf("Closed session for %s", session.conn.RemoteAddr())
}

// loadTLSConfig loads TLS configuration
func (fl *FluentdListener) loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
		},
	}, nil
}

// reportMetrics periodically reports metrics
func (fl *FluentdListener) reportMetrics() {
	defer fl.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fl.stopCh:
			return
		case <-ticker.C:
			fl.metricsMutex.RLock()
			fl.logger.Infof("Fluentd metrics: received=%d, processed=%d, failed=%d, acks=%d, auth_failures=%d, bytes=%d",
				fl.messagesReceived, fl.messagesProcessed, fl.messagesFailed,
				fl.acksSent, fl.authFailures, fl.bytesReceived)
			fl.metricsMutex.RUnlock()
		}
	}
}

// Stop stops the listener
func (fl *FluentdListener) Stop() error {
	close(fl.stopCh)

	// Close all sessions
	fl.sessionMutex.Lock()
	for conn := range fl.sessions {
		if err := conn.Close(); err != nil {
			fl.logger.Warnf("Failed to close session connection: %v", err)
		}
	}
	fl.sessionMutex.Unlock()

	// Close TCP listener
	if fl.tcpListener != nil {
		if err := fl.tcpListener.Close(); err != nil {
			fl.logger.Warnf("Failed to close TCP listener: %v", err)
		}
	}

	fl.wg.Wait()
	fl.logger.Info("Fluentd listener stopped")
	return nil
}

// GetMetrics returns current metrics
func (fl *FluentdListener) GetMetrics() map[string]interface{} {
	fl.metricsMutex.RLock()
	defer fl.metricsMutex.RUnlock()

	return map[string]interface{}{
		"messages_received":  fl.messagesReceived,
		"messages_processed": fl.messagesProcessed,
		"messages_failed":    fl.messagesFailed,
		"bytes_received":     fl.bytesReceived,
		"acks_sent":          fl.acksSent,
		"auth_failures":      fl.authFailures,
		"active_sessions":    len(fl.sessions),
	}
}
