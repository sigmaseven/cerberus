package threat

import (
	"cerberus/core"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// VirusTotalProvider implements ThreatFeed interface for VirusTotal API
type VirusTotalProvider struct {
	apiKey         string
	client         *http.Client
	circuitBreaker *core.CircuitBreaker
}

// NewVirusTotalProvider creates a new VirusTotal provider
func NewVirusTotalProvider(apiKey string) *VirusTotalProvider {
	// Configure HTTP client with proper TLS settings and timeouts
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &VirusTotalProvider{
		apiKey: apiKey,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
		// TASK 137: Use MustNewCircuitBreaker since default config is always valid
		circuitBreaker: core.MustNewCircuitBreaker(core.DefaultCircuitBreakerConfig()),
	}
}

// Name returns the provider name
func (p *VirusTotalProvider) Name() string {
	return "VirusTotal"
}

// CheckIOC checks an IOC against VirusTotal
func (p *VirusTotalProvider) CheckIOC(ctx context.Context, value string, iocType IOCType) (*ThreatIntel, error) {
	var endpoint string

	switch iocType {
	case IOCTypeIP:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", value)
	case IOCTypeDomain:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", value)
	case IOCTypeHash:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", value)
	case IOCTypeURL:
		// URL needs base64 encoding for VT API - skip for now
		return &ThreatIntel{
			IOC:         value,
			Type:        iocType,
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "URL enrichment not implemented",
			References:  []string{},
			Metadata:    map[string]string{},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported IOC type: %s", iocType)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("x-apikey", p.apiKey)

	// Check circuit breaker
	if err := p.circuitBreaker.Allow(); err != nil {
		return &ThreatIntel{
			IOC:         value,
			Type:        iocType,
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Circuit breaker open - service unavailable",
			References:  []string{},
			Metadata:    map[string]string{"error": "circuit_breaker_open"},
		}, nil
	}

	resp, err := p.client.Do(req)
	if err != nil {
		p.circuitBreaker.RecordFailure()
		return nil, fmt.Errorf("failed to query VirusTotal: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error silently, response already processed
		}
	}()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		p.circuitBreaker.RecordFailure()
		return &ThreatIntel{
			IOC:         value,
			Type:        iocType,
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Rate limited",
			References:  []string{},
			Metadata:    map[string]string{"error": "rate_limited"},
		}, nil
	}

	if resp.StatusCode == 404 {
		p.circuitBreaker.RecordSuccess()
		// Not found in VT - return clean result
		return &ThreatIntel{
			IOC:         value,
			Type:        iocType,
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "No threat intelligence found",
			References:  []string{},
			Metadata:    map[string]string{},
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		p.circuitBreaker.RecordFailure()
		return nil, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	// Success
	p.circuitBreaker.RecordSuccess()

	var vtResponse struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				Categories       map[string]string `json:"categories"`
				Tags             []string          `json:"tags"`
				LastAnalysisDate int64             `json:"last_analysis_date"`
				Reputation       int               `json:"reputation"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	attrs := vtResponse.Data.Attributes
	stats := attrs.LastAnalysisStats

	// Calculate confidence based on detection ratio
	totalEngines := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
	var confidence float64
	if totalEngines > 0 {
		confidence = float64(stats.Malicious) / float64(totalEngines)
	}

	// Extract categories
	var categories []string
	for _, cat := range attrs.Categories {
		categories = append(categories, cat)
	}

	// Combine categories and tags
	allTags := append(categories, attrs.Tags...)

	isMalicious := stats.Malicious > 0

	description := "Clean"
	if isMalicious {
		description = fmt.Sprintf("Detected as malicious by %d/%d engines", stats.Malicious, totalEngines)
	}

	return &ThreatIntel{
		IOC:         value,
		Type:        iocType,
		IsMalicious: isMalicious,
		Confidence:  confidence,
		Tags:        allTags,
		Description: description,
		References:  []string{fmt.Sprintf("https://www.virustotal.com/gui/%s/%s", iocType, value)},
		Metadata: map[string]string{
			"source":            "VirusTotal",
			"reputation":        fmt.Sprintf("%d", attrs.Reputation),
			"malicious_engines": fmt.Sprintf("%d", stats.Malicious),
			"total_engines":     fmt.Sprintf("%d", totalEngines),
		},
	}, nil
}

// AbuseIPDBProvider implements ThreatFeed interface for AbuseIPDB API
type AbuseIPDBProvider struct {
	apiKey string
	client *http.Client
}

// NewAbuseIPDBProvider creates a new AbuseIPDB provider
func NewAbuseIPDBProvider(apiKey string) *AbuseIPDBProvider {
	// Configure HTTP client with proper TLS settings and timeouts
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &AbuseIPDBProvider{
		apiKey: apiKey,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}
}

// Name returns the provider name
func (p *AbuseIPDBProvider) Name() string {
	return "AbuseIPDB"
}

// CheckIOC checks an IOC against AbuseIPDB (IP addresses only)
func (p *AbuseIPDBProvider) CheckIOC(ctx context.Context, value string, iocType IOCType) (*ThreatIntel, error) {
	// AbuseIPDB only supports IP addresses
	if iocType != IOCTypeIP {
		return &ThreatIntel{
			IOC:         value,
			Type:        iocType,
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "AbuseIPDB only supports IP addresses",
			References:  []string{},
			Metadata:    map[string]string{},
		}, nil
	}

	endpoint := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", value)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Key", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query AbuseIPDB: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error silently, response already processed
		}
	}()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		return &ThreatIntel{
			IOC:         value,
			Type:        iocType,
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Rate limited",
			References:  []string{},
			Metadata:    map[string]string{"error": "rate_limited"},
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AbuseIPDB returned status %d", resp.StatusCode)
	}

	var abuseResponse struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			UsageType            string `json:"usageType"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			CountryCode          string `json:"countryCode"`
			IsWhitelisted        bool   `json:"isWhitelisted"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
			Reports              []struct {
				ReportedAt string `json:"reportedAt"`
				Comment    string `json:"comment"`
				Categories []int  `json:"categories"`
			} `json:"reports"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&abuseResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data := abuseResponse.Data

	// Map category IDs to names
	categoryMap := map[int]string{
		3:  "Fraud",
		4:  "DDoS Attack",
		9:  "Hacking",
		10: "Spam",
		14: "Port Scan",
		18: "Brute Force",
		19: "Bad Web Bot",
		20: "Exploited Host",
		21: "Web App Attack",
		22: "SSH",
		23: "IoT Targeted",
	}

	// Extract unique categories
	categorySet := make(map[string]bool)
	for _, report := range data.Reports {
		for _, catID := range report.Categories {
			if catName, exists := categoryMap[catID]; exists {
				categorySet[catName] = true
			}
		}
	}

	var tags []string
	for cat := range categorySet {
		tags = append(tags, cat)
	}

	// Add usage type as tag
	if data.UsageType != "" {
		tags = append(tags, data.UsageType)
	}

	// Calculate confidence based on abuse score (0-100)
	confidence := float64(data.AbuseConfidenceScore) / 100.0

	// Consider malicious if score > 50 and not whitelisted
	isMalicious := data.AbuseConfidenceScore > 50 && !data.IsWhitelisted

	description := "Clean"
	if isMalicious {
		description = fmt.Sprintf("Abuse confidence score: %d%% (%d reports)", data.AbuseConfidenceScore, data.TotalReports)
	} else if data.IsWhitelisted {
		description = "Whitelisted"
	}

	return &ThreatIntel{
		IOC:         value,
		Type:        iocType,
		IsMalicious: isMalicious,
		Confidence:  confidence,
		Tags:        tags,
		Description: description,
		References:  []string{fmt.Sprintf("https://www.abuseipdb.com/check/%s", value)},
		Metadata: map[string]string{
			"source":         "AbuseIPDB",
			"abuse_score":    fmt.Sprintf("%d", data.AbuseConfidenceScore),
			"total_reports":  fmt.Sprintf("%d", data.TotalReports),
			"isp":            data.ISP,
			"domain":         data.Domain,
			"country":        data.CountryCode,
			"is_whitelisted": fmt.Sprintf("%t", data.IsWhitelisted),
			"last_reported":  data.LastReportedAt,
		},
	}, nil
}

// AlienVaultOTXProvider implements ThreatFeed interface for AlienVault OTX
type AlienVaultOTXProvider struct {
	apiKey string
	client *http.Client
}

// NewAlienVaultOTXProvider creates a new AlienVault OTX provider
func NewAlienVaultOTXProvider(apiKey string) *AlienVaultOTXProvider {
	// Configure HTTP client with proper TLS settings and timeouts
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &AlienVaultOTXProvider{
		apiKey: apiKey,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}
}

// Name returns the provider name
func (p *AlienVaultOTXProvider) Name() string {
	return "AlienVault OTX"
}

// CheckIOC checks an IOC against AlienVault OTX
func (p *AlienVaultOTXProvider) CheckIOC(ctx context.Context, value string, iocType IOCType) (*ThreatIntel, error) {
	var endpoint string

	switch iocType {
	case IOCTypeIP:
		endpoint = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", value)
	case IOCTypeDomain:
		endpoint = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", value)
	case IOCTypeHash:
		endpoint = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/file/%s/general", value)
	case IOCTypeURL:
		endpoint = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/url/%s/general", value)
	default:
		return nil, fmt.Errorf("unsupported IOC type: %s", iocType)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-OTX-API-KEY", p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query AlienVault OTX: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error silently, response already processed
		}
	}()

	if resp.StatusCode == 404 {
		// Not found - return clean result
		return &ThreatIntel{
			IOC:         value,
			Type:        iocType,
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "No threat intelligence found",
			References:  []string{},
			Metadata:    map[string]string{},
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AlienVault OTX returned status %d", resp.StatusCode)
	}

	var otxResponse struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Tags        []string `json:"tags"`
				Created     string   `json:"created"`
			} `json:"pulses"`
		} `json:"pulse_info"`
		Reputation int `json:"reputation"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&otxResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pulseCount := otxResponse.PulseInfo.Count
	reputation := otxResponse.Reputation

	// Extract tags from all pulses
	tagSet := make(map[string]bool)
	for _, pulse := range otxResponse.PulseInfo.Pulses {
		for _, tag := range pulse.Tags {
			tagSet[tag] = true
		}
	}

	var tags []string
	for tag := range tagSet {
		tags = append(tags, tag)
	}

	// Calculate confidence based on pulse count and reputation
	var confidence float64
	if pulseCount > 0 {
		// More pulses = higher confidence, cap at 0.95
		confidence = float64(pulseCount) / 10.0
		if confidence > 0.95 {
			confidence = 0.95
		}
	}

	// Negative reputation indicates malicious
	isMalicious := reputation < 0 || pulseCount > 0

	description := "Clean"
	if isMalicious {
		description = fmt.Sprintf("Found in %d threat pulses", pulseCount)
		if reputation < 0 {
			description += fmt.Sprintf(", reputation: %d", reputation)
		}
	}

	return &ThreatIntel{
		IOC:         value,
		Type:        iocType,
		IsMalicious: isMalicious,
		Confidence:  confidence,
		Tags:        tags,
		Description: description,
		References:  []string{fmt.Sprintf("https://otx.alienvault.com/indicator/%s/%s", iocType, value)},
		Metadata: map[string]string{
			"source":      "AlienVault OTX",
			"pulse_count": fmt.Sprintf("%d", pulseCount),
			"reputation":  fmt.Sprintf("%d", reputation),
		},
	}, nil
}
