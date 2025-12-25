package threat

import (
	"cerberus/core"
	"time"
)

// TestFixtures provides test data for threat intelligence testing
// TASK 53.1: Comprehensive test fixtures for IOCs (IPs, domains, hashes, URLs)

// GetTestIPs returns test IP addresses covering various scenarios
func GetTestIPs() map[string]TestIOCData {
	return map[string]TestIOCData{
		// Malicious IPs (known bad)
		"192.168.1.100": {
			Type:        IOCTypeIP,
			Value:       "192.168.1.100",
			IsMalicious: true,
			Confidence:  0.9,
			Tags:        []string{"botnet", "malware", "c2"},
			Description: "Known C2 server",
		},
		"10.0.0.1": {
			Type:        IOCTypeIP,
			Value:       "10.0.0.1",
			IsMalicious: true,
			Confidence:  0.8,
			Tags:        []string{"scanner", "bruteforce"},
			Description: "SSH bruteforce source",
		},
		"203.0.113.50": {
			Type:        IOCTypeIP,
			Value:       "203.0.113.50",
			IsMalicious: true,
			Confidence:  0.95,
			Tags:        []string{"phishing", "credential-theft"},
			Description: "Phishing campaign source",
		},
		// Clean IPs (known good)
		"8.8.8.8": {
			Type:        IOCTypeIP,
			Value:       "8.8.8.8",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Google DNS - clean",
		},
		"1.1.1.1": {
			Type:        IOCTypeIP,
			Value:       "1.1.1.1",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Cloudflare DNS - clean",
		},
		// Edge cases
		"127.0.0.1": {
			Type:        IOCTypeIP,
			Value:       "127.0.0.1",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"localhost"},
			Description: "Localhost - should be ignored",
		},
		"::1": {
			Type:        IOCTypeIP,
			Value:       "::1",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"localhost"},
			Description: "IPv6 localhost",
		},
		// Private IP ranges
		"192.168.0.1": {
			Type:        IOCTypeIP,
			Value:       "192.168.0.1",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"private"},
			Description: "Private IP - should be filtered",
		},
		"172.16.0.1": {
			Type:        IOCTypeIP,
			Value:       "172.16.0.1",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"private"},
			Description: "Private IP - should be filtered",
		},
	}
}

// GetTestDomains returns test domain names covering various scenarios
func GetTestDomains() map[string]TestIOCData {
	return map[string]TestIOCData{
		// Malicious domains
		"evil.example.com": {
			Type:        IOCTypeDomain,
			Value:       "evil.example.com",
			IsMalicious: true,
			Confidence:  0.95,
			Tags:        []string{"phishing", "credential-theft"},
			Description: "Phishing domain",
		},
		"malicious.test.org": {
			Type:        IOCTypeDomain,
			Value:       "malicious.test.org",
			IsMalicious: true,
			Confidence:  0.85,
			Tags:        []string{"malware", "c2"},
			Description: "Malware C2 domain",
		},
		"phishing-attack.net": {
			Type:        IOCTypeDomain,
			Value:       "phishing-attack.net",
			IsMalicious: true,
			Confidence:  0.90,
			Tags:        []string{"phishing", "typosquatting"},
			Description: "Typosquatting domain",
		},
		// Clean domains
		"google.com": {
			Type:        IOCTypeDomain,
			Value:       "google.com",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Known legitimate domain",
		},
		"example.com": {
			Type:        IOCTypeDomain,
			Value:       "example.com",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "RFC example domain",
		},
		// Edge cases
		"test.local": {
			Type:        IOCTypeDomain,
			Value:       "test.local",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"local"},
			Description: "Local domain - should be filtered",
		},
		"xn--e1afmkfd.xn--p1ai": {
			Type:        IOCTypeDomain,
			Value:       "xn--e1afmkfd.xn--p1ai",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"idn"},
			Description: "IDN/punycode domain (example.com in Cyrillic)",
		},
		"subdomain.example.com": {
			Type:        IOCTypeDomain,
			Value:       "subdomain.example.com",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Subdomain",
		},
	}
}

// GetTestHashes returns test file hashes covering various scenarios
func GetTestHashes() map[string]TestIOCData {
	return map[string]TestIOCData{
		// Malicious hashes (MD5)
		"5d41402abc4b2a76b9719d911017c592": {
			Type:        IOCTypeHash,
			Value:       "5d41402abc4b2a76b9719d911017c592",
			IsMalicious: true,
			Confidence:  0.85,
			Tags:        []string{"trojan", "ransomware"},
			Description: "Known ransomware sample (MD5)",
		},
		// Malicious hashes (SHA256)
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
			Type:        IOCTypeHash,
			Value:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			IsMalicious: true,
			Confidence:  0.90,
			Tags:        []string{"malware", "trojan"},
			Description: "Known malware sample (SHA256)",
		},
		// Clean hashes
		"098f6bcd4621d373cade4e832627b4f6": {
			Type:        IOCTypeHash,
			Value:       "098f6bcd4621d373cade4e832627b4f6",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Clean file hash (MD5)",
		},
		"da39a3ee5e6b4b0d3255bfef95601890afd80709": {
			Type:        IOCTypeHash,
			Value:       "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Empty file hash (SHA1)",
		},
		// Edge cases
		"5D41402ABC4B2A76B9719D911017C592": {
			Type:        IOCTypeHash,
			Value:       "5D41402ABC4B2A76B9719D911017C592",
			IsMalicious: true,
			Confidence:  0.85,
			Tags:        []string{"trojan", "ransomware"},
			Description: "Uppercase hash (should normalize to lowercase)",
		},
		"5d41402abc4b2a76b9719d911017c593": {
			Type:        IOCTypeHash,
			Value:       "5d41402abc4b2a76b9719d911017c593",
			IsMalicious: true,
			Confidence:  0.80,
			Tags:        []string{"malware"},
			Description: "Another malicious hash",
		},
	}
}

// GetTestURLs returns test URLs covering various scenarios
func GetTestURLs() map[string]TestIOCData {
	return map[string]TestIOCData{
		// Malicious URLs
		"http://evil.example.com/phishing": {
			Type:        IOCTypeURL,
			Value:       "http://evil.example.com/phishing",
			IsMalicious: true,
			Confidence:  0.90,
			Tags:        []string{"phishing", "credential-theft"},
			Description: "Phishing URL",
		},
		"https://malicious.test.org/malware.exe": {
			Type:        IOCTypeURL,
			Value:       "https://malicious.test.org/malware.exe",
			IsMalicious: true,
			Confidence:  0.85,
			Tags:        []string{"malware", "download"},
			Description: "Malware download URL",
		},
		// Clean URLs
		"https://www.google.com": {
			Type:        IOCTypeURL,
			Value:       "https://www.google.com",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "Known legitimate URL",
		},
		"https://example.com": {
			Type:        IOCTypeURL,
			Value:       "https://example.com",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "RFC example URL",
		},
		// Edge cases
		"http://localhost:8080/test": {
			Type:        IOCTypeURL,
			Value:       "http://localhost:8080/test",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"localhost"},
			Description: "Localhost URL - should be filtered",
		},
		"ftp://192.168.1.1/file.txt": {
			Type:        IOCTypeURL,
			Value:       "ftp://192.168.1.1/file.txt",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{"private"},
			Description: "Private IP URL - should be filtered",
		},
		"https://example.com/path?query=value&another=param": {
			Type:        IOCTypeURL,
			Value:       "https://example.com/path?query=value&another=param",
			IsMalicious: false,
			Confidence:  0.0,
			Tags:        []string{},
			Description: "URL with query parameters",
		},
	}
}

// TestIOCData represents test data for an IOC
type TestIOCData struct {
	Type        IOCType
	Value       string
	IsMalicious bool
	Confidence  float64
	Tags        []string
	Description string
}

// CreateTestAlertWithIOC creates a test alert with a specific IOC in the event data
func CreateTestAlertWithIOC(iocType IOCType, iocValue string) *core.Alert {
	alert := &core.Alert{
		AlertID:   "test-alert-" + iocValue,
		RuleID:    "test-rule-1",
		Severity:  "high",
		Status:    core.AlertStatusPending,
		Timestamp: time.Now(),
		Event: &core.Event{
			EventID:   "test-event-" + iocValue,
			Timestamp: time.Now(),
			Fields:    make(map[string]interface{}),
		},
	}

	// Add IOC to event fields based on type
	switch iocType {
	case IOCTypeIP:
		alert.Event.Fields["source_ip"] = iocValue
		alert.Event.Fields["dest_ip"] = iocValue
	case IOCTypeDomain:
		alert.Event.Fields["domain"] = iocValue
		alert.Event.Fields["hostname"] = iocValue
	case IOCTypeHash:
		alert.Event.Fields["file_hash"] = iocValue
		alert.Event.Fields["md5"] = iocValue
		alert.Event.Fields["sha256"] = iocValue
	case IOCTypeURL:
		alert.Event.Fields["url"] = iocValue
	}

	return alert
}

// CreateTestAlertsWithIOCs creates multiple test alerts from a map of IOC test data
func CreateTestAlertsWithIOCs(testData map[string]TestIOCData) []*core.Alert {
	alerts := make([]*core.Alert, 0, len(testData))
	for value, data := range testData {
		alert := CreateTestAlertWithIOC(data.Type, value)
		alerts = append(alerts, alert)
	}
	return alerts
}

// GetTestThreatFeeds returns test threat feeds for testing
func GetTestThreatFeeds() []ThreatFeed {
	return []ThreatFeed{
		NewMockThreatFeed(),
	}
}
