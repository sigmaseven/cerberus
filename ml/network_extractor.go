package ml

import (
	"context"
	"net"
	"strconv"
	"strings"

	"cerberus/core"
)

// NetworkFeatureExtractor extracts network-related features from events
type NetworkFeatureExtractor struct{}

// NewNetworkFeatureExtractor creates a new network feature extractor
func NewNetworkFeatureExtractor() *NetworkFeatureExtractor {
	return &NetworkFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *NetworkFeatureExtractor) Name() string {
	return "network"
}

// Extract extracts network features from an event
func (e *NetworkFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)

	// Extract source IP - check struct field first, then Fields
	var sourceIP string
	if event.SourceIP != "" {
		sourceIP = event.SourceIP
	} else if event.Fields != nil {
		if ip, ok := event.Fields["source_ip"].(string); ok {
			sourceIP = ip
		}
	}
	if sourceIP == "" {
		sourceIP = "0.0.0.0" // Default for missing IP
	}

	// Strip port if present (e.g., "192.168.1.1:8080" -> "192.168.1.1")
	if colonIdx := strings.Index(sourceIP, ":"); colonIdx != -1 {
		// Check if this is IPv6 (contains multiple colons) or IPv4 with port (single colon)
		if strings.Count(sourceIP, ":") == 1 {
			sourceIP = sourceIP[:colonIdx]
		}
	}

	// Parse IP address
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		// Invalid IP, set default features
		features["ip_is_private"] = 0.0
		features["ip_is_loopback"] = 0.0
		features["ip_is_multicast"] = 0.0
		features["ip_version"] = 0.0 // Unknown
		features["ip_octet_1"] = 0.0
		features["ip_octet_2"] = 0.0
		features["ip_octet_3"] = 0.0
		features["ip_octet_4"] = 0.0
		return features, nil
	}

	// IP type checks
	features["ip_is_private"] = boolToFloat(ip.IsPrivate())
	features["ip_is_loopback"] = boolToFloat(ip.IsLoopback())
	features["ip_is_multicast"] = boolToFloat(ip.IsMulticast())
	features["ip_is_unspecified"] = boolToFloat(ip.IsUnspecified())

	// IP version (4 or 6)
	ipVersion := 4.0
	if ip.To4() == nil {
		ipVersion = 6.0
	}
	features["ip_version"] = ipVersion

	// Extract IP octets for IPv4
	if ip.To4() != nil {
		octets := strings.Split(sourceIP, ".")
		if len(octets) == 4 {
			for i, octetStr := range octets {
				if octet, err := strconv.Atoi(octetStr); err == nil {
					features["ip_octet_"+strconv.Itoa(i+1)] = float64(octet)
				} else {
					features["ip_octet_"+strconv.Itoa(i+1)] = 0.0
				}
			}
		}
	} else {
		// For IPv6, set octets to 0
		for i := 1; i <= 4; i++ {
			features["ip_octet_"+strconv.Itoa(i)] = 0.0
		}
	}

	// Extract port from fields if available
	if portVal, exists := event.Fields["destination_port"]; exists {
		if portStr, ok := portVal.(string); ok {
			if port, err := strconv.Atoi(portStr); err == nil {
				features["destination_port"] = float64(port)
				features["port_is_well_known"] = boolToFloat(port < 1024)
				features["port_is_registered"] = boolToFloat(port >= 1024 && port < 49152)
				features["port_is_dynamic"] = boolToFloat(port >= 49152)
			}
		}
	}

	// Protocol features
	if protoVal, exists := event.Fields["protocol"]; exists {
		if protoStr, ok := protoVal.(string); ok {
			features["protocol_tcp"] = boolToFloat(strings.ToLower(protoStr) == "tcp")
			features["protocol_udp"] = boolToFloat(strings.ToLower(protoStr) == "udp")
			features["protocol_icmp"] = boolToFloat(strings.ToLower(protoStr) == "icmp")
			features["protocol_http"] = boolToFloat(strings.Contains(strings.ToLower(protoStr), "http"))
		}
	}

	// Connection state features
	if stateVal, exists := event.Fields["connection_state"]; exists {
		if stateStr, ok := stateVal.(string); ok {
			state := strings.ToLower(stateStr)
			features["conn_established"] = boolToFloat(state == "established" || state == "connected")
			features["conn_closed"] = boolToFloat(state == "closed" || state == "fin")
			features["conn_failed"] = boolToFloat(state == "failed" || state == "reset")
		}
	}

	return features, nil
}

// boolToFloat converts boolean to float64 (1.0 for true, 0.0 for false)
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}
