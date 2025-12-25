package threat

import (
	"context"
	"strings"
)

// ThreatFeed interface for threat intelligence feeds
type ThreatFeed interface {
	Name() string
	CheckIOC(ctx context.Context, value string, iocType IOCType) (*ThreatIntel, error)
}

// MockThreatFeed is a simple mock threat feed for demonstration
// In production, this would be replaced with real feeds like AlienVault OTX, VirusTotal, etc.
type MockThreatFeed struct {
	name string
	// Known malicious IOCs for demonstration
	knownMalicious map[string]ThreatIntel
}

// NewMockThreatFeed creates a new mock threat feed
func NewMockThreatFeed() *MockThreatFeed {
	return &MockThreatFeed{
		name: "Mock Threat Feed",
		knownMalicious: map[string]ThreatIntel{
			// Example malicious IPs
			"192.168.1.100": {
				IOC:         "192.168.1.100",
				Type:        IOCTypeIP,
				IsMalicious: true,
				Confidence:  0.9,
				Tags:        []string{"botnet", "malware"},
				Description: "Known C2 server",
				References:  []string{"https://example.com/threat-intel"},
				Metadata:    map[string]string{"category": "c2"},
			},
			"10.0.0.1": {
				IOC:         "10.0.0.1",
				Type:        IOCTypeIP,
				IsMalicious: true,
				Confidence:  0.8,
				Tags:        []string{"scanner", "bruteforce"},
				Description: "SSH bruteforce source",
				References:  []string{"https://example.com/threat-intel"},
				Metadata:    map[string]string{"category": "bruteforce"},
			},
			// Example malicious domain
			"evil.example.com": {
				IOC:         "evil.example.com",
				Type:        IOCTypeDomain,
				IsMalicious: true,
				Confidence:  0.95,
				Tags:        []string{"phishing", "credential-theft"},
				Description: "Phishing domain",
				References:  []string{"https://example.com/threat-intel"},
				Metadata:    map[string]string{"category": "phishing"},
			},
			// Example malicious hash
			"5d41402abc4b2a76b9719d911017c592": {
				IOC:         "5d41402abc4b2a76b9719d911017c592",
				Type:        IOCTypeHash,
				IsMalicious: true,
				Confidence:  0.85,
				Tags:        []string{"trojan", "ransomware"},
				Description: "Known ransomware sample",
				References:  []string{"https://example.com/threat-intel"},
				Metadata:    map[string]string{"category": "ransomware"},
			},
		},
	}
}

// Name returns the feed name
func (mtf *MockThreatFeed) Name() string {
	return mtf.name
}

// CheckIOC checks if an IOC is malicious
func (mtf *MockThreatFeed) CheckIOC(ctx context.Context, value string, iocType IOCType) (*ThreatIntel, error) {
	// Normalize value
	value = strings.TrimSpace(strings.ToLower(value))

	// Check if IOC is in our known malicious list
	if intel, found := mtf.knownMalicious[value]; found {
		return &intel, nil
	}

	// Return clean result
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
