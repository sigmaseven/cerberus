package threat

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// MockThreatIntelServer implements a mock HTTP server for testing threat intelligence providers
// TASK 53.1: Mock threat intelligence API server (VirusTotal, AbuseCH, AlienVault OTX)
type MockThreatIntelServer struct {
	server      *httptest.Server
	mux         *http.ServeMux
	requests    []CapturedThreatIntelRequest
	requestsMu  sync.RWMutex
	responses   map[string]ThreatIntelResponse
	responsesMu sync.RWMutex
	shouldFail  bool
	failStatus  int
	delay       time.Duration
	rateLimited bool
	apiKey      string // For authentication testing
}

// CapturedThreatIntelRequest represents a request captured by the mock server
type CapturedThreatIntelRequest struct {
	Method     string
	URL        string
	Path       string
	Headers    map[string]string
	Body       string
	APIKey     string
	CapturedAt time.Time
}

// ThreatIntelResponse represents a response from the mock threat intel API
type ThreatIntelResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
}

// NewMockThreatIntelServer creates a new mock threat intelligence server
func NewMockThreatIntelServer() *MockThreatIntelServer {
	mux := http.NewServeMux()
	server := &MockThreatIntelServer{
		mux:        mux,
		requests:   make([]CapturedThreatIntelRequest, 0),
		responses:  make(map[string]ThreatIntelResponse),
		failStatus: http.StatusInternalServerError,
		apiKey:     "test-api-key",
	}

	// Setup default routes for different providers
	mux.HandleFunc("/api/v3/ip_addresses/", server.handleVirusTotalIP)
	mux.HandleFunc("/api/v3/domains/", server.handleVirusTotalDomain)
	mux.HandleFunc("/api/v3/files/", server.handleVirusTotalHash)
	mux.HandleFunc("/api/v3/urls/", server.handleVirusTotalURL)

	// AbuseCH endpoints
	mux.HandleFunc("/api/v2/", server.handleAbuseCH)

	// AlienVault OTX endpoints
	mux.HandleFunc("/api/v1/", server.handleAlienVaultOTX)

	server.server = httptest.NewServer(mux)
	return server
}

// handleVirusTotalIP handles VirusTotal IP address lookup requests
func (m *MockThreatIntelServer) handleVirusTotalIP(w http.ResponseWriter, r *http.Request) {
	m.captureRequest(r)

	// Check API key
	if !m.authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check rate limiting
	if m.rateLimited {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": {"code": "QuotaExceededError", "message": "Rate limit exceeded"}}`))
		return
	}

	// Simulate delay
	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	// Handle failure
	if m.shouldFail {
		w.WriteHeader(m.failStatus)
		w.Write([]byte(`{"error": {"code": "InternalError", "message": "Simulated error"}}`))
		return
	}

	// Extract IP from path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/ip_addresses/"), "/")
	ip := pathParts[0]

	// Check if we have a custom response
	if resp, ok := m.getResponse("ip:" + ip); ok {
		w.WriteHeader(resp.StatusCode)
		for key, value := range resp.Headers {
			w.Header().Set(key, value)
		}
		w.Write([]byte(resp.Body))
		return
	}

	// Default response based on IP
	if strings.HasPrefix(ip, "192.168.1.100") || strings.HasPrefix(ip, "10.0.0.1") {
		// Malicious IP
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"id": ip,
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  10,
						"suspicious": 2,
						"harmless":   5,
						"undetected": 0,
					},
					"reputation": -50,
					"country":    "US",
					"as_owner":   "Example ISP",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	} else {
		// Clean IP
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"id": ip,
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  0,
						"suspicious": 0,
						"harmless":   50,
						"undetected": 5,
					},
					"reputation": 100,
					"country":    "US",
					"as_owner":   "Example ISP",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}
}

// handleVirusTotalDomain handles VirusTotal domain lookup requests
func (m *MockThreatIntelServer) handleVirusTotalDomain(w http.ResponseWriter, r *http.Request) {
	m.captureRequest(r)

	if !m.authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if m.rateLimited {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldFail {
		w.WriteHeader(m.failStatus)
		return
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/domains/"), "/")
	domain := pathParts[0]
	domain = strings.ToLower(domain)

	if resp, ok := m.getResponse("domain:" + domain); ok {
		w.WriteHeader(resp.StatusCode)
		for key, value := range resp.Headers {
			w.Header().Set(key, value)
		}
		w.Write([]byte(resp.Body))
		return
	}

	// Default response
	if strings.Contains(domain, "evil") || strings.Contains(domain, "malicious") {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"id": domain,
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  15,
						"suspicious": 3,
						"harmless":   2,
						"undetected": 0,
					},
					"reputation": -100,
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"id": domain,
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  0,
						"suspicious": 0,
						"harmless":   60,
						"undetected": 0,
					},
					"reputation": 100,
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}
}

// handleVirusTotalHash handles VirusTotal file hash lookup requests
func (m *MockThreatIntelServer) handleVirusTotalHash(w http.ResponseWriter, r *http.Request) {
	m.captureRequest(r)

	if !m.authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if m.rateLimited {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldFail {
		w.WriteHeader(m.failStatus)
		return
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/files/"), "/")
	hash := strings.ToLower(pathParts[0])

	if resp, ok := m.getResponse("hash:" + hash); ok {
		w.WriteHeader(resp.StatusCode)
		for key, value := range resp.Headers {
			w.Header().Set(key, value)
		}
		w.Write([]byte(resp.Body))
		return
	}

	// Default response
	if hash == "5d41402abc4b2a76b9719d911017c592" || hash == "5d41402abc4b2a76b9719d911017c593" {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"id": hash,
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  20,
						"suspicious": 5,
						"harmless":   0,
						"undetected": 0,
					},
					"reputation":       -100,
					"type_description": "PE32 executable",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"id": hash,
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  0,
						"suspicious": 0,
						"harmless":   40,
						"undetected": 10,
					},
					"reputation": 100,
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}
}

// handleVirusTotalURL handles VirusTotal URL lookup requests
func (m *MockThreatIntelServer) handleVirusTotalURL(w http.ResponseWriter, r *http.Request) {
	m.captureRequest(r)

	if !m.authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if m.rateLimited {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldFail {
		w.WriteHeader(m.failStatus)
		return
	}

	// Default response for URL (not fully implemented)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": map[string]interface{}{
				"last_analysis_stats": map[string]int{
					"malicious":  0,
					"suspicious": 0,
					"harmless":   1,
					"undetected": 0,
				},
			},
		},
	}
	json.NewEncoder(w).Encode(response)
}

// handleAbuseCH handles AbuseCH API requests
func (m *MockThreatIntelServer) handleAbuseCH(w http.ResponseWriter, r *http.Request) {
	m.captureRequest(r)

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldFail {
		w.WriteHeader(m.failStatus)
		return
	}

	// Default AbuseCH response format
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"data": []map[string]interface{}{},
	}
	json.NewEncoder(w).Encode(response)
}

// handleAlienVaultOTX handles AlienVault OTX API requests
func (m *MockThreatIntelServer) handleAlienVaultOTX(w http.ResponseWriter, r *http.Request) {
	m.captureRequest(r)

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldFail {
		w.WriteHeader(m.failStatus)
		return
	}

	// Default AlienVault OTX response format
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"pulse_info": map[string]interface{}{
			"count": 0,
		},
	}
	json.NewEncoder(w).Encode(response)
}

// captureRequest captures an incoming HTTP request
func (m *MockThreatIntelServer) captureRequest(r *http.Request) {
	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()

	// Read body
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	// Capture headers
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	apiKey := r.Header.Get("x-apikey")
	if apiKey == "" {
		apiKey = r.Header.Get("X-API-Key")
	}

	m.requests = append(m.requests, CapturedThreatIntelRequest{
		Method:     r.Method,
		URL:        r.URL.String(),
		Path:       r.URL.Path,
		Headers:    headers,
		Body:       string(bodyBytes),
		APIKey:     apiKey,
		CapturedAt: time.Now(),
	})
}

// authenticate checks if the request is authenticated
func (m *MockThreatIntelServer) authenticate(r *http.Request) bool {
	apiKey := r.Header.Get("x-apikey")
	if apiKey == "" {
		apiKey = r.Header.Get("X-API-Key")
	}
	return apiKey == m.apiKey
}

// SetResponse sets a custom response for a specific IOC
func (m *MockThreatIntelServer) SetResponse(key string, response ThreatIntelResponse) {
	m.responsesMu.Lock()
	defer m.responsesMu.Unlock()
	m.responses[key] = response
}

// getResponse retrieves a custom response for a specific IOC
func (m *MockThreatIntelServer) getResponse(key string) (ThreatIntelResponse, bool) {
	m.responsesMu.RLock()
	defer m.responsesMu.RUnlock()
	resp, ok := m.responses[key]
	return resp, ok
}

// GetRequests returns all captured requests
func (m *MockThreatIntelServer) GetRequests() []CapturedThreatIntelRequest {
	m.requestsMu.RLock()
	defer m.requestsMu.RUnlock()

	requests := make([]CapturedThreatIntelRequest, len(m.requests))
	copy(requests, m.requests)
	return requests
}

// ClearRequests clears all captured requests
func (m *MockThreatIntelServer) ClearRequests() {
	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()
	m.requests = make([]CapturedThreatIntelRequest, 0)
}

// SetShouldFail configures the server to simulate failures
func (m *MockThreatIntelServer) SetShouldFail(shouldFail bool, statusCode int) {
	m.shouldFail = shouldFail
	m.failStatus = statusCode
}

// SetDelay configures a delay to simulate timeouts
func (m *MockThreatIntelServer) SetDelay(delay time.Duration) {
	m.delay = delay
}

// SetRateLimited configures rate limiting simulation
func (m *MockThreatIntelServer) SetRateLimited(rateLimited bool) {
	m.rateLimited = rateLimited
}

// SetAPIKey sets the expected API key for authentication
func (m *MockThreatIntelServer) SetAPIKey(apiKey string) {
	m.apiKey = apiKey
}

// URL returns the server URL
func (m *MockThreatIntelServer) URL() string {
	if m.server == nil {
		return ""
	}
	return m.server.URL
}

// Close stops the mock server
func (m *MockThreatIntelServer) Close() {
	if m.server != nil {
		m.server.Close()
	}
}
