package ingest

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/metrics"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	// DefaultMaxTCPConnections is the default maximum number of concurrent TCP connections
	DefaultMaxTCPConnections = 1000
	// DefaultMaxConnectionsPerIP is the default maximum number of concurrent connections per IP
	// SECURITY: Prevents single IP from exhausting the connection pool (Slowloris protection)
	DefaultMaxConnectionsPerIP = 10
	// MinPort is the minimum valid port number
	MinPort = 1
	// MaxPort is the maximum valid port number
	MaxPort = 65535
)

// validatePort validates that a port number is within the valid range
// SECURITY: Prevents invalid port numbers that could cause network operations to fail
// Port 0 is allowed for automatic port assignment (commonly used in testing)
func validatePort(port int) error {
	if port < 0 || port > MaxPort {
		return fmt.Errorf("invalid port number: %d (must be between 0 and %d)", port, MaxPort)
	}
	return nil
}

// BaseListener provides common functionality for listeners
type BaseListener struct {
	host                string
	port                int
	limiter             *rate.Limiter
	eventCh             chan<- *core.Event
	stopCh              chan struct{}
	wg                  sync.WaitGroup
	logger              *zap.SugaredLogger
	udpConn             net.PacketConn
	tcpListener         net.Listener
	fieldNormalizer     *core.FieldNormalizer
	listenerID          string
	listenerName        string
	listenerSource      string
	fieldMapping        string
	connSemaphore       chan struct{}  // PERFORMANCE: Semaphore for limiting concurrent TCP connections
	maxConnections      int            // Maximum concurrent TCP connections
	ipConnections       map[string]int // SECURITY: Per-IP connection tracking
	ipConnectionsMutex  sync.RWMutex   // CONCURRENCY: Protects ipConnections map
	maxConnectionsPerIP int            // SECURITY: Maximum connections per IP
	dlq                 *DLQ           // TASK 7.3: DLQ for malformed events
	protocol            string         // TASK 7.3: Protocol name for DLQ ('syslog', 'cef', 'json', 'fluentd')
}

// NewBaseListener creates a new base listener with default max connections
func NewBaseListener(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger) *BaseListener {
	// SECURITY: Validate port before creating listener
	if err := validatePort(port); err != nil {
		logger.Fatalf("Invalid port in NewBaseListener: %v", err)
	}
	return NewBaseListenerWithMaxConnections(host, port, rateLimit, eventCh, logger, DefaultMaxTCPConnections)
}

// NewBaseListenerWithDLQ creates a new base listener with DLQ support
// TASK 7.3: Add DLQ support to listeners
func NewBaseListenerWithDLQ(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger, dlq *DLQ, protocol string) *BaseListener {
	listener := NewBaseListener(host, port, rateLimit, eventCh, logger)
	listener.dlq = dlq
	listener.protocol = protocol
	return listener
}

// NewBaseListenerWithConfig creates a new base listener with config (config currently unused)
func NewBaseListenerWithConfig(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger, cfg interface{}) *BaseListener {
	return NewBaseListener(host, port, rateLimit, eventCh, logger)
}

// NewBaseListenerWithMaxConnections creates a new base listener with configurable max connections
// PERFORMANCE: Bounded connection pool prevents resource exhaustion from connection storms
func NewBaseListenerWithMaxConnections(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger, maxConnections int) *BaseListener {
	// SECURITY: Validate port before creating listener
	if err := validatePort(port); err != nil {
		logger.Fatalf("Invalid port in NewBaseListenerWithMaxConnections: %v", err)
	}

	if maxConnections <= 0 {
		maxConnections = DefaultMaxTCPConnections
	}

	return &BaseListener{
		host:                host,
		port:                port,
		limiter:             rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
		eventCh:             eventCh,
		stopCh:              make(chan struct{}),
		logger:              logger,
		maxConnections:      maxConnections,
		connSemaphore:       make(chan struct{}, maxConnections),
		ipConnections:       make(map[string]int),
		maxConnectionsPerIP: DefaultMaxConnectionsPerIP,
	}
}

// processEvent processes a raw event string, parses it, and sends it to the event channel
// TASK 7.3: Integrate DLQ for parse failures
// Field normalization: Converts event fields to SIGMA-standard names at ingestion time
func (b *BaseListener) processEvent(raw string, sourceIP string, parseFunc func(string) (*core.Event, error), name string) {
	if !b.limiter.Allow() {
		b.logger.Warnf("Rate limit exceeded for %s", name)
		return
	}
	event, err := parseFunc(raw)
	if err != nil {
		b.logger.Errorf("Failed to parse %s: %v", name, err)
		// TASK 7.3: Send malformed event to DLQ instead of just logging
		if b.dlq != nil && b.protocol != "" {
			failedEvent := &FailedEvent{
				Protocol:     b.protocol,
				RawEvent:     raw,
				ErrorReason:  "parse_failure",
				ErrorDetails: err.Error(),
				SourceIP:     sourceIP,
			}
			if dlqErr := b.dlq.Add(failedEvent); dlqErr != nil {
				// Log DLQ write failure but don't block ingestion pipeline
				b.logger.Warnf("Failed to write event to DLQ: %v (original parse error: %v)", dlqErr, err)
			}
		}
		return
	}
	event.SourceIP = sourceIP

	// Apply SIGMA field normalization at ingestion time
	// This converts source-specific field names to SIGMA-standard names
	if b.fieldNormalizer != nil && event.Fields != nil {
		// Determine log source: use configured source, or auto-detect from fields
		logSource := b.listenerSource
		if logSource == "" {
			logSource = core.DetectLogSource(event.Fields)
		}
		event.Fields = b.fieldNormalizer.NormalizeToSIGMA(event.Fields, logSource)
	}

	// Set listener metadata on event
	if b.listenerID != "" {
		event.ListenerID = b.listenerID
	}
	if b.listenerName != "" {
		event.ListenerName = b.listenerName
	}

	select {
	case b.eventCh <- event:
	default:
		b.logger.Warnf("Event channel full, dropping %s event", name)
	}
}

// StartUDP starts a UDP listener with the given parse function
func (b *BaseListener) StartUDP(parseFunc func(string) (*core.Event, error), name string) {
	// SECURITY: Validate port before attempting network operations
	if err := validatePort(b.port); err != nil {
		b.logger.Errorf("Invalid port for %s UDP listener: %v", name, err)
		return
	}

	addr := fmt.Sprintf("%s:%d", b.host, b.port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		b.logger.Errorf("Failed to start %s UDP listener: %v", name, err)
		return
	}
	b.udpConn = conn
	b.logger.Infof("%s UDP listener started on %s", name, addr)
	b.wg.Add(1)
	defer b.wg.Done()

	buffer := make([]byte, 65536)
	for {
		select {
		case <-b.stopCh:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			b.logger.Errorf("%s UDP read error: %v", name, err)
			continue
		}
		raw := strings.TrimSpace(string(buffer[:n]))
		if raw == "" {
			continue
		}
		b.processEvent(raw, addr.String(), parseFunc, name+" UDP")
	}
}

// StartTCP starts a TCP listener with the given parse function
// PERFORMANCE: Implements bounded connection pool to prevent resource exhaustion
func (b *BaseListener) StartTCP(parseFunc func(string) (*core.Event, error), name string) {
	// SECURITY: Validate port before attempting network operations
	if err := validatePort(b.port); err != nil {
		b.logger.Errorf("Invalid port for %s TCP listener: %v", name, err)
		return
	}

	addr := fmt.Sprintf("%s:%d", b.host, b.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		b.logger.Errorf("Failed to start %s TCP listener: %v", name, err)
		return
	}
	b.tcpListener = listener
	b.logger.Infof("%s TCP listener started on %s (max connections: %d)", name, addr, b.maxConnections)
	b.wg.Add(1)
	defer b.wg.Done()

	for {
		select {
		case <-b.stopCh:
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			b.logger.Errorf("%s TCP accept error: %v", name, err)
			continue
		}

		// SECURITY: Extract IP address for per-IP connection tracking
		remoteAddr := conn.RemoteAddr().String()
		ip, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			// If we can't parse the IP, use the full address
			ip = remoteAddr
		}

		// SECURITY: Check per-IP connection limit to prevent single IP from exhausting pool
		b.ipConnectionsMutex.RLock()
		ipConnCount := b.ipConnections[ip]
		b.ipConnectionsMutex.RUnlock()

		if ipConnCount >= b.maxConnectionsPerIP {
			b.logger.Warnf("%s Per-IP connection limit exceeded for %s (%d/%d), rejecting connection",
				name, ip, ipConnCount, b.maxConnectionsPerIP)
			metrics.TCPConnectionPoolRejected.WithLabelValues(name).Inc()
			conn.Close()
			continue
		}

		// PERFORMANCE: Acquire semaphore slot (bounded connection pool)
		// Non-blocking check to prevent Accept() from blocking
		select {
		case b.connSemaphore <- struct{}{}:
			// Successfully acquired slot, increment per-IP counter
			b.ipConnectionsMutex.Lock()
			b.ipConnections[ip]++
			b.ipConnectionsMutex.Unlock()

			metrics.TCPConnectionPoolActive.WithLabelValues(name).Inc()
			b.wg.Add(1)
			go b.handleTCPConnection(conn, parseFunc, name, ip)
		default:
			// Pool is full, reject connection with graceful backpressure
			b.logger.Warnf("%s TCP connection pool full (%d/%d), rejecting connection from %s",
				name, b.maxConnections, b.maxConnections, remoteAddr)
			metrics.TCPConnectionPoolRejected.WithLabelValues(name).Inc()
			conn.Close()
		}
	}
}

func (b *BaseListener) handleTCPConnection(conn net.Conn, parseFunc func(string) (*core.Event, error), name, ip string) {
	defer conn.Close()
	defer b.wg.Done()
	// PERFORMANCE: Release semaphore slot when connection handler completes
	defer func() {
		<-b.connSemaphore
		metrics.TCPConnectionPoolActive.WithLabelValues(name).Dec()
	}()
	// SECURITY: Decrement per-IP connection counter when connection closes
	defer func() {
		b.ipConnectionsMutex.Lock()
		if b.ipConnections[ip] > 0 {
			b.ipConnections[ip]--
		}
		// Clean up map entry if count reaches zero to prevent unbounded memory growth
		if b.ipConnections[ip] == 0 {
			delete(b.ipConnections, ip)
		}
		b.ipConnectionsMutex.Unlock()
	}()

	// SECURITY: Set read deadline to prevent indefinite blocking on slow clients
	// This prevents slowloris-style DoS attacks where clients hold connections open
	conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		b.processEvent(line, conn.RemoteAddr().String(), parseFunc, name+" TCP")

		// SECURITY: Update read deadline after each successful read
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	}
	if err := scanner.Err(); err != nil {
		b.logger.Errorf("%s scanner error: %v", name, err)
	}
}

// Stop stops the listener
func (b *BaseListener) Stop() {
	close(b.stopCh)
	if b.udpConn != nil {
		b.udpConn.Close()
	}
	if b.tcpListener != nil {
		b.tcpListener.Close()
	}
	b.wg.Wait()
}

// SetMetadata sets the listener metadata (ID, name, source, field mapping)
func (b *BaseListener) SetMetadata(id, name, source, fieldMapping string) {
	b.listenerID = id
	b.listenerName = name
	b.listenerSource = source
	b.fieldMapping = fieldMapping
}

// SetDLQ sets the DLQ instance and protocol for malformed event capture
// TASK 7.3: Setter method for DLQ integration
func (b *BaseListener) SetDLQ(dlq *DLQ, protocol string) {
	b.dlq = dlq
	b.protocol = protocol
}

// SetFieldNormalizer sets the field normalizer for SIGMA field name conversion
// This enables ingestion-time normalization of event fields to SIGMA standard
func (b *BaseListener) SetFieldNormalizer(normalizer *core.FieldNormalizer) {
	b.fieldNormalizer = normalizer
}
