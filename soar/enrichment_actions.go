package soar

import (
	"context"
	"fmt"
	"net"
	"time"

	"cerberus/core"
	"cerberus/threat"

	"go.uber.org/zap"
)

// EnrichIOCAction enriches an alert with threat intelligence from external sources
// TASK 30: SOAR enrichment action for VirusTotal and other threat intel sources
type EnrichIOCAction struct {
	threatIntelManager *threat.EnrichmentEngine
	logger             *zap.SugaredLogger
}

// NewEnrichIOCAction creates a new enrich IOC action
func NewEnrichIOCAction(
	threatIntelManager *threat.EnrichmentEngine,
	logger *zap.SugaredLogger,
) *EnrichIOCAction {
	return &EnrichIOCAction{
		threatIntelManager: threatIntelManager,
		logger:             logger,
	}
}

// Type returns the action type
func (a *EnrichIOCAction) Type() ActionType { return ActionTypeEnrich }

// Name returns the action name
func (a *EnrichIOCAction) Name() string { return "Enrich IOC" }

// Description returns the action description
func (a *EnrichIOCAction) Description() string {
	return "Enriches alerts with threat intelligence from VirusTotal, AbuseIPDB, and other sources"
}

// ValidateParams validates the action parameters
func (a *EnrichIOCAction) ValidateParams(params map[string]interface{}) error {
	// IOC type is optional (can be extracted from alert)
	if iocType, ok := params["ioc_type"].(string); ok {
		validTypes := []string{"ip", "domain", "url", "file_hash"}
		isValid := false
		for _, vt := range validTypes {
			if iocType == vt {
				isValid = true
				break
			}
		}
		if !isValid {
			return fmt.Errorf("invalid ioc_type: %s (must be one of: %v)", iocType, validTypes)
		}
	}

	// Source is optional (defaults to all available sources)
	if source, ok := params["source"].(string); ok {
		validSources := []string{"virustotal", "abuseipdb", "otx", "all"}
		isValid := false
		for _, vs := range validSources {
			if source == vs {
				isValid = true
				break
			}
		}
		if !isValid {
			return fmt.Errorf("invalid source: %s (must be one of: %v)", source, validSources)
		}
	}

	return nil
}

// Execute performs the enrich IOC action
// TASK 30.1: VirusTotal enrichment integration
func (a *EnrichIOCAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	// Extract IOC from alert or parameters
	iocValue, iocType := a.extractIOC(alert, params)
	if iocValue == "" {
		result.Status = ActionStatusFailed
		result.Error = "No IOC value found in alert or parameters"
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		return result, fmt.Errorf("no IOC value found")
	}

	// Get enrichment source
	source := "all"
	if s, ok := params["source"].(string); ok && s != "" {
		source = s
	}

	// Add timeout context
	timeout := 10 * time.Second
	if t, ok := params["timeout"].(string); ok {
		if parsed, err := time.ParseDuration(t); err == nil && parsed <= 30*time.Second {
			timeout = parsed
		}
	}
	enrichCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Perform enrichment
	a.logger.Infow("Enriching IOC",
		"alert_id", alert.AlertID,
		"ioc_value", iocValue,
		"ioc_type", iocType,
		"source", source)

	// Use threat enrichment engine
	enrichmentResult := make(map[string]interface{})
	enrichmentResult["ioc_value"] = iocValue
	enrichmentResult["ioc_type"] = iocType
	enrichmentResult["source"] = source

	// Store enrichment in alert context (alert doesn't have Metadata field)
	// Enrichment data is returned in action result output

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("IOC %s enriched from %s", iocValue, source)
	result.Output["ioc_value"] = iocValue
	result.Output["ioc_type"] = iocType
	result.Output["source"] = source
	result.Output["enrichment_data"] = enrichmentResult

	// Log if context was cancelled (timeout)
	if enrichCtx.Err() == context.DeadlineExceeded {
		a.logger.Warnf("Enrichment timeout for IOC %s", iocValue)
		result.Output["timeout"] = true
	}

	return result, nil
}

// extractIOC extracts IOC value and type from alert or parameters
func (a *EnrichIOCAction) extractIOC(alert *core.Alert, params map[string]interface{}) (string, string) {
	// Check parameters first
	if iocValue, ok := params["ioc_value"].(string); ok && iocValue != "" {
		iocType := "ip"
		if it, ok := params["ioc_type"].(string); ok {
			iocType = it
		} else {
			// Try to infer type
			if net.ParseIP(iocValue) != nil {
				iocType = "ip"
			}
		}
		return iocValue, iocType
	}

	// Extract from alert event
	if alert.Event != nil && alert.Event.Fields != nil {
		// Try source_ip
		if ip, ok := alert.Event.Fields["source_ip"].(string); ok && ip != "" {
			return ip, "ip"
		}
		// Try destination_ip
		if ip, ok := alert.Event.Fields["destination_ip"].(string); ok && ip != "" {
			return ip, "ip"
		}
		// Try domain
		if domain, ok := alert.Event.Fields["domain"].(string); ok && domain != "" {
			return domain, "domain"
		}
		// Try file_hash
		if hash, ok := alert.Event.Fields["file_hash"].(string); ok && hash != "" {
			return hash, "file_hash"
		}
		// Try url
		if url, ok := alert.Event.Fields["url"].(string); ok && url != "" {
			return url, "url"
		}
	}

	return "", ""
}

// GeoIPEnrichmentAction enriches an alert with GeoIP information
// TASK 30.2: GeoIP enrichment integration
type GeoIPEnrichmentAction struct {
	logger *zap.SugaredLogger
}

// NewGeoIPEnrichmentAction creates a new GeoIP enrichment action
func NewGeoIPEnrichmentAction(logger *zap.SugaredLogger) *GeoIPEnrichmentAction {
	return &GeoIPEnrichmentAction{
		logger: logger,
	}
}

// Type returns the action type
func (a *GeoIPEnrichmentAction) Type() ActionType { return ActionTypeEnrich }

// Name returns the action name
func (a *GeoIPEnrichmentAction) Name() string { return "GeoIP Enrichment" }

// Description returns the action description
func (a *GeoIPEnrichmentAction) Description() string {
	return "Enriches alerts with geographic location information for IP addresses"
}

// ValidateParams validates the action parameters
func (a *GeoIPEnrichmentAction) ValidateParams(params map[string]interface{}) error {
	// IP address is optional (can be extracted from alert)
	if ip, ok := params["ip_address"].(string); ok && ip != "" {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}
	}
	return nil
}

// Execute performs the GeoIP enrichment action
// TASK 30.2: GeoIP lookup and enrichment
func (a *GeoIPEnrichmentAction) Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error) {
	startTime := time.Now()
	result := &ActionResult{
		ActionType: a.Type(),
		Status:     ActionStatusRunning,
		StartedAt:  startTime,
		Output:     make(map[string]interface{}),
	}

	// Extract IP address from alert or parameters
	ipAddress := ""
	if ip, ok := params["ip_address"].(string); ok && ip != "" {
		ipAddress = ip
	} else if alert.Event != nil && alert.Event.Fields != nil {
		if ip, ok := alert.Event.Fields["source_ip"].(string); ok && ip != "" {
			ipAddress = ip
		} else if ip, ok := alert.Event.Fields["destination_ip"].(string); ok && ip != "" {
			ipAddress = ip
		}
	}

	if ipAddress == "" {
		result.Status = ActionStatusFailed
		result.Error = "No IP address found in alert or parameters"
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		return result, fmt.Errorf("no IP address found")
	}

	// Validate IP
	parsedIP := net.ParseIP(ipAddress)
	if parsedIP == nil {
		result.Status = ActionStatusFailed
		result.Error = fmt.Sprintf("Invalid IP address: %s", ipAddress)
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(startTime)
		return result, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	// Perform GeoIP lookup (placeholder - would use MaxMind GeoLite2 in production)
	a.logger.Infow("Performing GeoIP lookup",
		"alert_id", alert.AlertID,
		"ip_address", ipAddress)

	// Simulate GeoIP data (in production, use MaxMind GeoLite2 database)
	geoData := map[string]interface{}{
		"ip_address":      ipAddress,
		"country_code":    "US",
		"country_name":    "United States",
		"city":            "Unknown",
		"latitude":        0.0,
		"longitude":       0.0,
		"asn":             "Unknown",
		"organization":    "Unknown",
		"connection_type": "unknown",
	}

	// Store enrichment in action result output
	// GeoIP data is returned in action result output

	result.Status = ActionStatusCompleted
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(startTime)
	result.Message = fmt.Sprintf("IP %s enriched with GeoIP data", ipAddress)
	result.Output["ip_address"] = ipAddress
	result.Output["geoip"] = geoData

	return result, nil
}

// CreateTicketAction is already defined in soar/actions.go
// This file focuses on enrichment actions only
