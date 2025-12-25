package threat

import (
	"context"
	"regexp"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

// EnrichmentEngine enriches alerts with threat intelligence
type EnrichmentEngine struct {
	feeds  []ThreatFeed
	cache  *IOCCache
	logger *zap.SugaredLogger
}

// NewEnrichmentEngine creates a new enrichment engine
func NewEnrichmentEngine(feeds []ThreatFeed, logger *zap.SugaredLogger) *EnrichmentEngine {
	return &EnrichmentEngine{
		feeds:  feeds,
		cache:  NewIOCCache(),
		logger: logger,
	}
}

// EnrichAlert enriches an alert with threat intelligence
func (ee *EnrichmentEngine) EnrichAlert(alert *core.Alert) error {
	// Extract IOCs from alert
	iocs := ee.extractIOCs(alert)

	if len(iocs) == 0 {
		return nil
	}

	var enrichments []ThreatIntel

	for _, ioc := range iocs {
		// Check cache first
		if cached, found := ee.cache.Get(ioc.Value); found {
			if cached.IsMalicious {
				enrichments = append(enrichments, *cached)
			}
			continue
		}

		// Query threat feeds asynchronously with timeout
		type feedResult struct {
			intel *ThreatIntel
			err   error
			feed  string
		}

		results := make(chan feedResult, len(ee.feeds))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Start goroutines for each feed
		for _, feed := range ee.feeds {
			go func(f ThreatFeed) {
				intel, err := f.CheckIOC(ctx, ioc.Value, ioc.Type)
				results <- feedResult{
					intel: intel,
					err:   err,
					feed:  f.Name(),
				}
			}(feed)
		}

		// Collect results with timeout
		feedCount := len(ee.feeds)
		for i := 0; i < feedCount; i++ {
			select {
			case result := <-results:
				if result.err != nil {
					ee.logger.Warnf("Failed to check IOC %s with feed %s: %v", ioc.Value, result.feed, result.err)
					continue
				}

				// Cache the result
				ee.cache.Set(ioc.Value, result.intel, 24*time.Hour)

				if result.intel.IsMalicious {
					enrichments = append(enrichments, *result.intel)
					cancel() // Cancel remaining requests since we found malicious IOC
					// Drain remaining results
					for j := i + 1; j < feedCount; j++ {
						select {
						case <-results:
						default:
						}
					}
					break
				}
			case <-ctx.Done():
				ee.logger.Debugw("Context cancelled during IOC feed collection",
					"ioc", ioc.Value,
					"checked_feeds", i,
					"total_feeds", feedCount)
				// Drain any remaining results
				for j := i + 1; j < feedCount; j++ {
					select {
					case <-results:
					default:
					}
				}
				break
			}
		}
	}

	// Add threat intel to alert if any malicious IOCs found
	if len(enrichments) > 0 {
		// Convert enrichments to map[string]interface{} for storage
		threatIntel := make(map[string]interface{})
		threatIntel["enrichments"] = enrichments
		threatIntel["count"] = len(enrichments)
		alert.ThreatIntel = threatIntel

		// Escalate severity if high-confidence threats found
		highestConfidence := 0.0
		for _, ti := range enrichments {
			if ti.Confidence > highestConfidence {
				highestConfidence = ti.Confidence
			}
		}

		// Escalate severity based on confidence
		if highestConfidence >= 0.8 && alert.Severity != "critical" {
			ee.logger.Infof("Escalating alert %s severity from %s to high due to high-confidence threat intel", alert.AlertID, alert.Severity)
			alert.Severity = "high"
		} else if highestConfidence >= 0.6 && (alert.Severity == "low" || alert.Severity == "info") {
			ee.logger.Infof("Escalating alert %s severity from %s to medium due to threat intel", alert.AlertID, alert.Severity)
			alert.Severity = "medium"
		}
	}

	return nil
}

// extractIOCs extracts IOCs from alert event data
func (ee *EnrichmentEngine) extractIOCs(alert *core.Alert) []IOC {
	var iocs []IOC

	// Extract from event if available
	if alert.Event == nil || alert.Event.Fields == nil {
		return iocs
	}

	// Extract IPs from common fields
	if sourceIP, ok := alert.Event.Fields["source_ip"].(string); ok && sourceIP != "" {
		iocs = append(iocs, IOC{Type: IOCTypeIP, Value: sourceIP})
	}

	if destIP, ok := alert.Event.Fields["dest_ip"].(string); ok && destIP != "" {
		iocs = append(iocs, IOC{Type: IOCTypeIP, Value: destIP})
	}

	if remoteIP, ok := alert.Event.Fields["remote_ip"].(string); ok && remoteIP != "" {
		iocs = append(iocs, IOC{Type: IOCTypeIP, Value: remoteIP})
	}

	// Extract domains
	if domain, ok := alert.Event.Fields["domain"].(string); ok && domain != "" {
		iocs = append(iocs, IOC{Type: IOCTypeDomain, Value: domain})
	}

	if hostname, ok := alert.Event.Fields["hostname"].(string); ok && hostname != "" {
		// Check if hostname looks like a domain (contains dot)
		if regexp.MustCompile(`\.`).MatchString(hostname) {
			iocs = append(iocs, IOC{Type: IOCTypeDomain, Value: hostname})
		}
	}

	// Extract file hashes
	if hash, ok := alert.Event.Fields["file_hash"].(string); ok && hash != "" {
		iocs = append(iocs, IOC{Type: IOCTypeHash, Value: hash})
	}

	if md5, ok := alert.Event.Fields["md5"].(string); ok && md5 != "" {
		iocs = append(iocs, IOC{Type: IOCTypeHash, Value: md5})
	}

	if sha256, ok := alert.Event.Fields["sha256"].(string); ok && sha256 != "" {
		iocs = append(iocs, IOC{Type: IOCTypeHash, Value: sha256})
	}

	// Extract URLs
	if url, ok := alert.Event.Fields["url"].(string); ok && url != "" {
		iocs = append(iocs, IOC{Type: IOCTypeURL, Value: url})
	}

	return iocs
}
