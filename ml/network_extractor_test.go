package ml

import (
	"context"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 59.2: Network Feature Extractor Tests
// Tests cover: IP addresses, ports, protocols, network patterns, geo-IP (placeholder)

// TestNetworkFeatureExtractor_PortExtraction tests port number extraction
func TestNetworkFeatureExtractor_PortExtraction(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test",
		SourceIP:  "192.168.1.1",
		Fields: map[string]interface{}{
			"destination_port": "443",
		},
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err, "Should extract port features")

	// Verify port is extracted
	portVal, exists := features["destination_port"]
	assert.True(t, exists, "Should extract destination port")
	assert.Equal(t, 443.0, portVal, "Should extract correct port number")
}

// TestNetworkFeatureExtractor_IPv6Extraction tests IPv6 address extraction
func TestNetworkFeatureExtractor_IPv6Extraction(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test",
		SourceIP:  "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err, "Should extract IPv6 features")

	// Verify IPv6 detection
	assert.Equal(t, 6.0, features["ip_version"], "Should detect IPv6")
	assert.Equal(t, 0.0, features["ip_octet_1"], "IPv6 should have zero octets (IPv4-specific)")
}

// TestNetworkFeatureExtractor_PublicIP tests public IP detection
func TestNetworkFeatureExtractor_PublicIP(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test",
		SourceIP:  "8.8.8.8", // Google DNS (public IP)
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err)

	assert.Equal(t, 0.0, features["ip_is_private"], "8.8.8.8 is public IP")
	assert.Equal(t, 0.0, features["ip_is_loopback"], "8.8.8.8 is not loopback")
}

// TestNetworkFeatureExtractor_IPWithPort tests IP with port stripping
func TestNetworkFeatureExtractor_IPWithPort(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test",
		SourceIP:  "192.168.1.100:8080", // IP with port
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err)

	// Should strip port and extract IP correctly
	assert.Equal(t, 1.0, features["ip_is_private"], "Should detect private IP after port stripping")
	assert.Equal(t, 100.0, features["ip_octet_4"], "Should extract correct octet after port stripping")
}

// TestNetworkFeatureExtractor_InvalidIP tests invalid IP handling
func TestNetworkFeatureExtractor_InvalidIP(t *testing.T) {
	extractor := NewNetworkFeatureExtractor()

	event := &core.Event{
		EventID:   "test-event",
		Timestamp: time.Now().UTC(),
		RawData:   "test",
		SourceIP:  "invalid.ip.address", // Invalid IP
		Fields:    make(map[string]interface{}),
	}

	features, err := extractor.Extract(context.Background(), event)
	require.NoError(t, err, "Should handle invalid IP gracefully")

	// Should set default features for invalid IP
	assert.Equal(t, 0.0, features["ip_is_private"], "Invalid IP should default to not private")
	assert.Equal(t, 0.0, features["ip_version"], "Invalid IP should have version 0")
}

// TestNetworkFeatureExtractor_GeoIPEnrichment tests geo-IP enrichment (placeholder)
func TestNetworkFeatureExtractor_GeoIPEnrichment(t *testing.T) {
	t.Skip("Geo-IP enrichment requires external service or database - placeholder for integration")

	// Expected behavior when implemented:
	// 1. Lookup IP in geo-IP database
	// 2. Extract country, city, ASN
	// 3. Add features: country_code, city_name, asn
	// 4. Handle lookup failures gracefully

	t.Log("TODO: Implement geo-IP enrichment tests")
}
