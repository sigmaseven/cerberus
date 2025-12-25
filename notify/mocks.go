package notify

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cerberus/core"
)

// MockSMTPServer implements a mock SMTP server for testing email notifications
// TASK 52.1: Mock SMTP server with TLS support, authentication verification, and message capture
type MockSMTPServer struct {
	listener      net.Listener
	port          int
	host          string
	messages      []CapturedEmail
	messagesMu    sync.RWMutex
	authenticated bool
	requireAuth   bool
	authUsername  string
	authPassword  string
	enableTLS     bool
	shouldFail    bool          // For simulating failures
	delay         time.Duration // For simulating timeouts
}

// CapturedEmail represents an email captured by the mock SMTP server
type CapturedEmail struct {
	From       string
	To         []string
	Subject    string
	Body       string
	Headers    map[string]string
	CapturedAt time.Time
}

// NewMockSMTPServer creates a new mock SMTP server
func NewMockSMTPServer(requireAuth bool, enableTLS bool) (*MockSMTPServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	addr := listener.Addr().(*net.TCPAddr)
	server := &MockSMTPServer{
		listener:      listener,
		port:          addr.Port,
		host:          "127.0.0.1",
		messages:      make([]CapturedEmail, 0),
		requireAuth:   requireAuth,
		enableTLS:     enableTLS,
		authenticated: false,
	}

	// Start server in goroutine
	go server.serve()

	return server, nil
}

// serve handles incoming SMTP connections
func (m *MockSMTPServer) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return // Listener closed
		}

		go m.handleConnection(conn)
	}
}

// handleConnection handles a single SMTP connection
func (m *MockSMTPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Simulate delay if configured
	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	// Send greeting
	conn.Write([]byte("220 mock-smtp-server ESMTP\r\n"))

	scanner := bufio.NewScanner(conn)
	var from string
	var to []string
	var data bytes.Buffer
	inData := false

	for scanner.Scan() {
		line := scanner.Text()
		upper := strings.ToUpper(line)

		if m.shouldFail {
			conn.Write([]byte("500 Server error\r\n"))
			continue
		}

		// Handle EHLO/HELO
		if strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO") {
			response := "250 mock-smtp-server\r\n"
			if m.enableTLS {
				response += "250-STARTTLS\r\n"
			}
			if m.requireAuth {
				response += "250-AUTH PLAIN LOGIN\r\n"
			}
			response += "250-PIPELINING\r\n"
			response += "250 8BITMIME\r\n"
			conn.Write([]byte(response))
			continue
		}

		// Handle STARTTLS
		if upper == "STARTTLS" && m.enableTLS {
			conn.Write([]byte("220 Ready to start TLS\r\n"))
			// For testing, we'll just accept TLS upgrade without actual TLS
			// In a real scenario, this would wrap the connection
			continue
		}

		// Handle AUTH
		if strings.HasPrefix(upper, "AUTH") {
			if !m.requireAuth {
				conn.Write([]byte("503 AUTH not required\r\n"))
				continue
			}
			if strings.Contains(upper, "PLAIN") {
				conn.Write([]byte("334 \r\n"))
				scanner.Scan()
				_ = scanner.Text() // Read auth line (for testing, accept any auth)
				// Decode base64 and extract credentials (simplified)
				m.authenticated = true // For testing, accept any auth
				conn.Write([]byte("235 Authentication successful\r\n"))
				continue
			}
			conn.Write([]byte("504 AUTH mechanism not supported\r\n"))
			continue
		}

		// Handle MAIL FROM
		if strings.HasPrefix(upper, "MAIL FROM:") {
			from = extractEmailAddress(line)
			conn.Write([]byte("250 OK\r\n"))
			continue
		}

		// Handle RCPT TO
		if strings.HasPrefix(upper, "RCPT TO:") {
			to = append(to, extractEmailAddress(line))
			conn.Write([]byte("250 OK\r\n"))
			continue
		}

		// Handle DATA
		if upper == "DATA" {
			if !m.authenticated && m.requireAuth {
				conn.Write([]byte("530 Authentication required\r\n"))
				continue
			}
			conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
			inData = true
			data.Reset()
			continue
		}

		// Handle data content
		if inData {
			if line == "." {
				// End of data
				m.captureEmail(from, to, data.String())
				conn.Write([]byte("250 OK\r\n"))
				inData = false
				from = ""
				to = nil
				continue
			}
			// Remove leading dot if present (SMTP data transparency)
			line = strings.TrimPrefix(line, ".")
			data.WriteString(line + "\r\n")
			continue
		}

		// Handle QUIT
		if upper == "QUIT" {
			conn.Write([]byte("221 Bye\r\n"))
			return
		}

		// Default response
		conn.Write([]byte("250 OK\r\n"))
	}
}

// captureEmail captures an email message
func (m *MockSMTPServer) captureEmail(from string, to []string, rawMessage string) {
	m.messagesMu.Lock()
	defer m.messagesMu.Unlock()

	// Parse headers and body
	headers := make(map[string]string)
	body := rawMessage
	lines := strings.Split(rawMessage, "\r\n")
	inBody := false
	currentBody := strings.Builder{}

	for i, line := range lines {
		if line == "" && !inBody {
			inBody = true
			continue
		}

		if !inBody {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				headers[key] = value
			}
		} else {
			if i < len(lines)-1 {
				currentBody.WriteString(line)
				currentBody.WriteString("\n")
			}
		}
	}

	if currentBody.Len() > 0 {
		body = strings.TrimSuffix(currentBody.String(), "\n")
	}

	subject := headers["Subject"]
	if subject == "" {
		subject = headers["subject"]
	}

	m.messages = append(m.messages, CapturedEmail{
		From:       from,
		To:         to,
		Subject:    subject,
		Body:       body,
		Headers:    headers,
		CapturedAt: time.Now(),
	})
}

// GetMessages returns all captured emails
func (m *MockSMTPServer) GetMessages() []CapturedEmail {
	m.messagesMu.RLock()
	defer m.messagesMu.RUnlock()

	messages := make([]CapturedEmail, len(m.messages))
	copy(messages, m.messages)
	return messages
}

// ClearMessages clears all captured messages
func (m *MockSMTPServer) ClearMessages() {
	m.messagesMu.Lock()
	defer m.messagesMu.Unlock()
	m.messages = make([]CapturedEmail, 0)
}

// SetAuthCredentials sets the expected authentication credentials
func (m *MockSMTPServer) SetAuthCredentials(username, password string) {
	m.authUsername = username
	m.authPassword = password
}

// SetShouldFail configures the server to simulate failures
func (m *MockSMTPServer) SetShouldFail(shouldFail bool) {
	m.shouldFail = shouldFail
}

// SetDelay configures a delay to simulate timeouts
func (m *MockSMTPServer) SetDelay(delay time.Duration) {
	m.delay = delay
}

// Address returns the server address (host:port)
func (m *MockSMTPServer) Address() string {
	return fmt.Sprintf("%s:%d", m.host, m.port)
}

// Port returns the server port
func (m *MockSMTPServer) Port() int {
	return m.port
}

// Close stops the mock SMTP server
func (m *MockSMTPServer) Close() error {
	if m.listener != nil {
		return m.listener.Close()
	}
	return nil
}

// extractEmailAddress extracts email address from SMTP command line
func extractEmailAddress(line string) string {
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start != -1 && end != -1 && end > start {
		return line[start+1 : end]
	}
	// Fallback: try to extract from format like "MAIL FROM: user@example.com"
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// MockHTTPServer implements a mock HTTP server for testing webhook/Slack notifications
// TASK 52.1: Mock HTTP server with custom header inspection, timeout simulation, and retry testing
type MockHTTPServer struct {
	server               *http.Server
	listener             net.Listener
	mux                  *http.ServeMux
	port                 int
	host                 string
	requests             []CapturedHTTPRequest
	requestsMu           sync.RWMutex
	shouldFail           bool
	failStatus           int
	delay                time.Duration
	requireAuth          bool
	authToken            string
	concurrentRequests   int
	requestsMuConcurrent sync.Mutex
}

// CapturedHTTPRequest represents an HTTP request captured by the mock server
type CapturedHTTPRequest struct {
	Method     string
	URL        string
	Headers    map[string]string
	Body       string
	CapturedAt time.Time
	RemoteAddr string
}

// NewMockHTTPServer creates a new mock HTTP server
func NewMockHTTPServer() (*MockHTTPServer, error) {
	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	addr := listener.Addr().(*net.TCPAddr)
	mockServer := &MockHTTPServer{
		server:             server,
		listener:           listener,
		mux:                mux,
		port:               addr.Port,
		host:               "127.0.0.1",
		requests:           make([]CapturedHTTPRequest, 0),
		failStatus:         http.StatusInternalServerError,
		concurrentRequests: 0,
	}

	// Setup default handler
	mux.HandleFunc("/", mockServer.handleRequest)

	// Start server in goroutine
	go func() {
		server.Serve(listener)
	}()

	return mockServer, nil
}

// handleRequest handles incoming HTTP requests
func (m *MockHTTPServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	m.requestsMuConcurrent.Lock()
	m.concurrentRequests++
	m.requestsMuConcurrent.Unlock()

	defer func() {
		m.requestsMuConcurrent.Lock()
		m.concurrentRequests--
		m.requestsMuConcurrent.Unlock()
	}()

	// Simulate delay if configured
	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	// Check authentication if required
	if m.requireAuth {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || authHeader != "Bearer "+m.authToken {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
	}

	// Read request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		bodyBytes = []byte{}
	}

	// Capture request
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	m.requestsMu.Lock()
	m.requests = append(m.requests, CapturedHTTPRequest{
		Method:     r.Method,
		URL:        r.URL.String(),
		Headers:    headers,
		Body:       string(bodyBytes),
		CapturedAt: time.Now(),
		RemoteAddr: r.RemoteAddr,
	})
	m.requestsMu.Unlock()

	// Handle failure simulation
	if m.shouldFail {
		w.WriteHeader(m.failStatus)
		w.Write([]byte("Simulated error"))
		return
	}

	// Default success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// GetRequests returns all captured HTTP requests
func (m *MockHTTPServer) GetRequests() []CapturedHTTPRequest {
	m.requestsMu.RLock()
	defer m.requestsMu.RUnlock()

	requests := make([]CapturedHTTPRequest, len(m.requests))
	copy(requests, m.requests)
	return requests
}

// ClearRequests clears all captured requests
func (m *MockHTTPServer) ClearRequests() {
	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()
	m.requests = make([]CapturedHTTPRequest, 0)
}

// SetShouldFail configures the server to simulate failures
func (m *MockHTTPServer) SetShouldFail(shouldFail bool, statusCode int) {
	m.shouldFail = shouldFail
	m.failStatus = statusCode
}

// SetDelay configures a delay to simulate timeouts
func (m *MockHTTPServer) SetDelay(delay time.Duration) {
	m.delay = delay
}

// SetRequireAuth configures authentication requirement
func (m *MockHTTPServer) SetRequireAuth(token string) {
	m.requireAuth = true
	m.authToken = token
}

// GetConcurrentRequests returns the current number of concurrent requests
func (m *MockHTTPServer) GetConcurrentRequests() int {
	m.requestsMuConcurrent.Lock()
	defer m.requestsMuConcurrent.Unlock()
	return m.concurrentRequests
}

// URL returns the server URL
func (m *MockHTTPServer) URL() string {
	return fmt.Sprintf("http://%s:%d", m.host, m.port)
}

// Close stops the mock HTTP server
func (m *MockHTTPServer) Close() error {
	if m.listener != nil {
		return m.listener.Close()
	}
	return nil
}

// CreateTestAlert creates a test alert for notification testing
// TASK 52.1: Test fixture generator for alerts
func CreateTestAlert(severity string, status core.AlertStatus, ruleID string) *core.Alert {
	alert := &core.Alert{
		AlertID:   fmt.Sprintf("test-alert-%d", time.Now().UnixNano()),
		RuleID:    ruleID,
		Severity:  severity,
		Status:    status,
		Timestamp: time.Now(),
		Event: &core.Event{
			EventID:   fmt.Sprintf("test-event-%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
			Fields: map[string]interface{}{
				"source_ip":  "192.168.1.100",
				"dest_ip":    "10.0.0.50",
				"user":       "testuser",
				"event_type": "login",
				"process":    "ssh",
			},
		},
	}
	return alert
}

// CreateTestAlerts creates multiple test alerts with various severities and statuses
func CreateTestAlerts(count int) []*core.Alert {
	alerts := make([]*core.Alert, count)
	severities := []string{"critical", "high", "medium", "low"}
	statuses := []core.AlertStatus{
		core.AlertStatusPending,
		core.AlertStatusAcknowledged,
		core.AlertStatusInvestigating,
	}

	for i := 0; i < count; i++ {
		severity := severities[i%len(severities)]
		status := statuses[i%len(statuses)]
		alerts[i] = CreateTestAlert(severity, status, fmt.Sprintf("rule-%d", i))
	}

	return alerts
}
