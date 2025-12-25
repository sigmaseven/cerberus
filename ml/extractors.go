package ml

import (
	"context"
	"net"
	"strconv"
	"strings"
	"unicode"

	"cerberus/core"
)

// ContentFeatureExtractor extracts content-based features from events
type ContentFeatureExtractor struct{}

// NewContentFeatureExtractor creates a new content feature extractor
func NewContentFeatureExtractor() *ContentFeatureExtractor {
	return &ContentFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *ContentFeatureExtractor) Name() string {
	return "content"
}

// Extract extracts content features from an event
func (e *ContentFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)

	// Message length features - convert RawData (json.RawMessage) to string
	message := string(event.RawData)
	features["message_length"] = float64(len(message))
	features["message_word_count"] = float64(len(strings.Fields(message)))

	// Keyword presence (basic security keywords)
	securityKeywords := []string{"password", "login", "auth", "admin", "root", "sudo", "error", "fail", "attack", "malware", "virus"}
	messageLower := strings.ToLower(message)
	for _, keyword := range securityKeywords {
		if strings.Contains(messageLower, keyword) {
			features["keyword_"+keyword] = 1.0
		}
	}

	// Character type ratios
	if len(message) > 0 {
		upperCount := 0
		lowerCount := 0
		digitCount := 0
		specialCount := 0

		for _, char := range message {
			switch {
			case unicode.IsUpper(char):
				upperCount++
			case unicode.IsLower(char):
				lowerCount++
			case unicode.IsDigit(char):
				digitCount++
			case !unicode.IsLetter(char) && !unicode.IsDigit(char) && !unicode.IsSpace(char):
				specialCount++
			}
		}

		totalChars := float64(len(message))
		features["uppercase_ratio"] = float64(upperCount) / totalChars
		features["lowercase_ratio"] = float64(lowerCount) / totalChars
		features["digit_ratio"] = float64(digitCount) / totalChars
		features["special_char_ratio"] = float64(specialCount) / totalChars
	}

	return features, nil
}

// FrequencyFeatureExtractor extracts frequency-based features from events
type FrequencyFeatureExtractor struct{}

// NewFrequencyFeatureExtractor creates a new frequency feature extractor
func NewFrequencyFeatureExtractor() *FrequencyFeatureExtractor {
	return &FrequencyFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *FrequencyFeatureExtractor) Name() string {
	return "frequency"
}

// Extract extracts frequency features from an event
func (e *FrequencyFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)

	// Basic time-based features
	timestamp := event.Timestamp

	// Hour of day (0-23)
	hour := timestamp.Hour()
	features["hour_of_day"] = float64(hour)

	// Day of week (0-6, Sunday=0)
	dayOfWeek := int(timestamp.Weekday())
	features["day_of_week"] = float64(dayOfWeek)

	// Is weekend
	isWeekend := dayOfWeek == 0 || dayOfWeek == 6
	if isWeekend {
		features["is_weekend"] = 1.0
	} else {
		features["is_weekend"] = 0.0
	}

	// Is business hours (9-17)
	isBusinessHours := hour >= 9 && hour <= 17 && !isWeekend
	if isBusinessHours {
		features["is_business_hours"] = 1.0
	} else {
		features["is_business_hours"] = 0.0
	}

	// Time since epoch (for trend analysis)
	features["timestamp_seconds"] = float64(timestamp.Unix())

	return features, nil
}

// PatternFeatureExtractor extracts pattern-based features from events
type PatternFeatureExtractor struct{}

// NewPatternFeatureExtractor creates a new pattern feature extractor
func NewPatternFeatureExtractor() *PatternFeatureExtractor {
	return &PatternFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *PatternFeatureExtractor) Name() string {
	return "pattern"
}

// Extract extracts pattern features from an event
func (e *PatternFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)
	// TODO: Implement pattern feature extraction
	// Features like: sequence patterns, anomaly patterns, etc.
	features["pattern_placeholder"] = 1.0
	return features, nil
}

// RiskFeatureExtractor extracts risk-related features from events
type RiskFeatureExtractor struct{}

// NewRiskFeatureExtractor creates a new risk feature extractor
func NewRiskFeatureExtractor() *RiskFeatureExtractor {
	return &RiskFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *RiskFeatureExtractor) Name() string {
	return "risk"
}

// Extract extracts risk features from an event
func (e *RiskFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)
	// TODO: Implement risk feature extraction
	// Features like: threat scores, risk indicators, etc.
	features["risk_placeholder"] = 1.0
	return features, nil
}

// VolumeFeatureExtractor extracts volume-based features from events
type VolumeFeatureExtractor struct{}

// NewVolumeFeatureExtractor creates a new volume feature extractor
func NewVolumeFeatureExtractor() *VolumeFeatureExtractor {
	return &VolumeFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *VolumeFeatureExtractor) Name() string {
	return "volume"
}

// Extract extracts volume features from an event
func (e *VolumeFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)

	// Basic volume features based on event data
	features["event_data_fields"] = float64(len(event.Fields))

	// Source and destination information
	sourceIP := getStringField(event.Fields, "source_ip")
	if sourceIP != "" {
		features["has_source_ip"] = 1.0
	} else {
		features["has_source_ip"] = 0.0
	}

	destIP := getStringField(event.Fields, "dest_ip")
	if destIP != "" {
		features["has_destination_ip"] = 1.0
	} else {
		features["has_destination_ip"] = 0.0
	}

	sourcePort := getIntField(event.Fields, "source_port")
	if sourcePort > 0 {
		features["has_source_port"] = 1.0
		features["source_port"] = float64(sourcePort)
	} else {
		features["has_source_port"] = 0.0
	}

	destPort := getIntField(event.Fields, "dest_port")
	if destPort > 0 {
		features["has_destination_port"] = 1.0
		features["destination_port"] = float64(destPort)
	} else {
		features["has_destination_port"] = 0.0
	}

	// Protocol information
	protocol := getStringField(event.Fields, "protocol")
	if protocol != "" {
		features["has_protocol"] = 1.0
		// Simple protocol encoding
		switch strings.ToLower(protocol) {
		case "tcp":
			features["protocol_tcp"] = 1.0
		case "udp":
			features["protocol_udp"] = 1.0
		case "icmp":
			features["protocol_icmp"] = 1.0
		case "http":
			features["protocol_http"] = 1.0
		case "https":
			features["protocol_https"] = 1.0
		default:
			features["protocol_other"] = 1.0
		}
	} else {
		features["has_protocol"] = 0.0
	}

	return features, nil
}

// AnomalyFeatureExtractor extracts anomaly-related features from events
type AnomalyFeatureExtractor struct{}

// NewAnomalyFeatureExtractor creates a new anomaly feature extractor
func NewAnomalyFeatureExtractor() *AnomalyFeatureExtractor {
	return &AnomalyFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *AnomalyFeatureExtractor) Name() string {
	return "anomaly"
}

// Extract extracts anomaly features from an event
func (e *AnomalyFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)
	// TODO: Implement anomaly feature extraction
	// Features like: deviation scores, outlier indicators, etc.
	features["anomaly_placeholder"] = 1.0
	return features, nil
}

// CorrelationFeatureExtractor extracts correlation features from events
type CorrelationFeatureExtractor struct{}

// NewCorrelationFeatureExtractor creates a new correlation feature extractor
func NewCorrelationFeatureExtractor() *CorrelationFeatureExtractor {
	return &CorrelationFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *CorrelationFeatureExtractor) Name() string {
	return "correlation"
}

// Extract extracts correlation features from an event
func (e *CorrelationFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)
	// TODO: Implement correlation feature extraction
	// Features like: event relationships, dependency scores, etc.
	features["correlation_placeholder"] = 1.0
	return features, nil
}

// SequenceFeatureExtractor extracts sequence-based features from events
type SequenceFeatureExtractor struct{}

// NewSequenceFeatureExtractor creates a new sequence feature extractor
func NewSequenceFeatureExtractor() *SequenceFeatureExtractor {
	return &SequenceFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *SequenceFeatureExtractor) Name() string {
	return "sequence"
}

// Extract extracts sequence features from an event
func (e *SequenceFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)
	// TODO: Implement sequence feature extraction
	// Features like: event sequences, temporal patterns, etc.
	features["sequence_placeholder"] = 1.0
	return features, nil
}

// GeographicFeatureExtractor extracts geographic features from events
type GeographicFeatureExtractor struct{}

// NewGeographicFeatureExtractor creates a new geographic feature extractor
func NewGeographicFeatureExtractor() *GeographicFeatureExtractor {
	return &GeographicFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *GeographicFeatureExtractor) Name() string {
	return "geographic"
}

// Extract extracts geographic features from an event
func (e *GeographicFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)

	// Extract IP addresses from event fields
	sourceIP := getStringField(event.Fields, "source_ip")
	destIP := getStringField(event.Fields, "dest_ip")

	// Basic geographic features
	if sourceIP != "" {
		// Check if IP is private/internal
		if isPrivateIP(sourceIP) {
			features["source_ip_private"] = 1.0
			features["source_ip_public"] = 0.0
		} else {
			features["source_ip_private"] = 0.0
			features["source_ip_public"] = 1.0
		}

		// Basic IP class features (simplified)
		if strings.HasPrefix(sourceIP, "10.") ||
			strings.HasPrefix(sourceIP, "192.168.") ||
			(strings.HasPrefix(sourceIP, "172.") &&
				len(strings.Split(sourceIP, ".")) >= 2 &&
				func() bool {
					secondOctet := strings.Split(sourceIP, ".")[1]
					if val, err := strconv.Atoi(secondOctet); err == nil {
						return val >= 16 && val <= 31
					}
					return false
				}()) {
			features["source_ip_rfc1918"] = 1.0
		} else {
			features["source_ip_rfc1918"] = 0.0
		}
	}

	if destIP != "" {
		if isPrivateIP(destIP) {
			features["dest_ip_private"] = 1.0
			features["dest_ip_public"] = 0.0
		} else {
			features["dest_ip_private"] = 0.0
			features["dest_ip_public"] = 1.0
		}
	}

	return features, nil
}

// ProtocolFeatureExtractor extracts protocol-specific features from events
type ProtocolFeatureExtractor struct{}

// NewProtocolFeatureExtractor creates a new protocol feature extractor
func NewProtocolFeatureExtractor() *ProtocolFeatureExtractor {
	return &ProtocolFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *ProtocolFeatureExtractor) Name() string {
	return "protocol"
}

// Extract extracts protocol features from an event
func (e *ProtocolFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)
	// TODO: Implement protocol feature extraction
	// Features like: protocol-specific metrics, header analysis, etc.
	features["protocol_placeholder"] = 1.0
	return features, nil
}

// ResourceFeatureExtractor extracts resource-related features from events
type ResourceFeatureExtractor struct{}

// NewResourceFeatureExtractor creates a new resource feature extractor
func NewResourceFeatureExtractor() *ResourceFeatureExtractor {
	return &ResourceFeatureExtractor{}
}

// Name returns the name of the extractor
func (e *ResourceFeatureExtractor) Name() string {
	return "resource"
}

// Extract extracts resource features from an event
func (e *ResourceFeatureExtractor) Extract(ctx context.Context, event *core.Event) (map[string]float64, error) {
	features := make(map[string]float64)
	// TODO: Implement resource feature extraction
	// Features like: CPU usage, memory usage, disk I/O, etc.
	features["resource_placeholder"] = 1.0
	return features, nil
}

// isPrivateIP checks if an IP address is in a private range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

// getStringField safely extracts a string value from event fields
func getStringField(fields map[string]interface{}, key string) string {
	if val, ok := fields[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// getIntField safely extracts an int value from event fields
func getIntField(fields map[string]interface{}, key string) int {
	if val, ok := fields[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case string:
			if intVal, err := strconv.Atoi(v); err == nil {
				return intVal
			}
		}
	}
	return 0
}
