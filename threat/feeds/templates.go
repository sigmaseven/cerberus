package feeds

import "cerberus/core"

// =============================================================================
// IOC Feed Templates
// =============================================================================

// GetIOCFeedTemplates returns all available feed templates
func GetIOCFeedTemplates() []*IOCFeedTemplate {
	return []*IOCFeedTemplate{
		// AlienVault OTX
		{
			ID:           "alienvault-otx",
			Name:         "AlienVault OTX",
			Description:  "Open Threat Exchange - community-driven threat intelligence",
			Type:         IOCFeedTypeOTX,
			RequiresAuth: true,
			AuthFields:   []string{"api_key"},
			DefaultConfig: map[string]interface{}{
				"update_strategy": "scheduled",
				"update_schedule": "0 0 */6 * * *", // Every 6 hours
				// Mixed IOC types - use type-specific defaults (auto_expire_days=0)
			},
			RecommendedPriority: 50,
			EstimatedIOCCount:   100000,
			Tags:                []string{"otx", "community", "free"},
		},

		// Abuse.ch URLhaus
		{
			ID:           "abuse-ch-urlhaus",
			Name:         "Abuse.ch URLhaus",
			Description:  "Malicious URLs used for malware distribution",
			Type:         IOCFeedTypeCSV,
			URL:          "https://urlhaus.abuse.ch/downloads/csv_recent/",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"delimiter":        ",",
				"skip_header":      true,
				"comment_char":     "#", // URLhaus has comment lines starting with #
				"value_column":     2,   // URL column
				"default_type":     "url",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 */2 * * *", // Every 2 hours
				"auto_expire_days": 30,              // URLs are ephemeral
			},
			FieldMapping: map[string]string{
				"external_id": "0",
				"description": "4",
				"first_seen":  "1",
			},
			RecommendedPriority: 70,
			EstimatedIOCCount:   50000,
			Tags:                []string{"malware", "urls", "free"},
		},

		// Abuse.ch Malware Bazaar
		{
			ID:           "abuse-ch-malwarebazaar",
			Name:         "Abuse.ch MalwareBazaar",
			Description:  "Malware samples and their hashes",
			Type:         IOCFeedTypeJSON,
			URL:          "https://mb-api.abuse.ch/api/v1/",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"default_type":     "hash",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 */4 * * *", // Every 4 hours
				"auto_expire_days": 730,             // File hashes persist for 2 years
			},
			FieldMapping: map[string]string{
				"value":       "sha256_hash",
				"external_id": "sha256_hash",
				"first_seen":  "first_seen",
				"tags":        "tags",
			},
			RecommendedPriority: 75,
			EstimatedIOCCount:   200000,
			Tags:                []string{"malware", "hashes", "free"},
		},

		// Abuse.ch Feodo Tracker
		{
			ID:           "abuse-ch-feodo",
			Name:         "Abuse.ch Feodo Tracker",
			Description:  "Botnet C&C servers (Dridex, Emotet, TrickBot)",
			Type:         IOCFeedTypeCSV,
			URL:          "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"delimiter":        ",",
				"skip_header":      true,
				"comment_char":     "#", // Feodo has comment lines starting with #
				"value_column":     1,   // IP column
				"default_type":     "ip",
				"default_severity": "high",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 * * * *", // Every hour
				"auto_expire_days": 30,            // C2 IPs rotate frequently
			},
			FieldMapping: map[string]string{
				"first_seen":  "0",
				"description": "4",
			},
			RecommendedPriority: 80,
			EstimatedIOCCount:   5000,
			Tags:                []string{"botnet", "c2", "free"},
		},

		// SANS ISC Suspicious Domains
		{
			ID:           "sans-isc-suspicious",
			Name:         "SANS ISC Suspicious Domains",
			Description:  "Domains flagged as suspicious by SANS Internet Storm Center",
			Type:         IOCFeedTypeCSV,
			URL:          "https://isc.sans.edu/feeds/suspiciousdomains_High.txt",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"skip_header":      true,
				"value_column":     0,
				"default_type":     "domain",
				"default_severity": "high",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 */12 * * *", // Every 12 hours
				"auto_expire_days": 60,               // Domains expire slower than IPs
			},
			RecommendedPriority: 60,
			EstimatedIOCCount:   10000,
			Tags:                []string{"domains", "sans", "free"},
		},

		// EmergingThreats Compromised IPs
		{
			ID:           "et-compromised",
			Name:         "EmergingThreats Compromised IPs",
			Description:  "Known compromised IP addresses",
			Type:         IOCFeedTypeCSV,
			URL:          "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"value_column":     0,
				"default_type":     "ip",
				"default_severity": "high",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 */6 * * *", // Every 6 hours
				"auto_expire_days": 30,              // IPs rotate frequently
			},
			RecommendedPriority: 65,
			EstimatedIOCCount:   5000,
			Tags:                []string{"compromised", "ips", "free"},
		},

		// OpenPhish
		{
			ID:           "openphish",
			Name:         "OpenPhish",
			Description:  "Phishing URLs detected by OpenPhish",
			Type:         IOCFeedTypeCSV,
			URL:          "https://openphish.com/feed.txt",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"value_column":     0,
				"default_type":     "url",
				"default_severity": "high",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 */30 * * * *", // Every 30 minutes
				"auto_expire_days": 30,              // Phishing URLs are ephemeral
			},
			RecommendedPriority: 70,
			EstimatedIOCCount:   10000,
			Tags:                []string{"phishing", "urls", "free"},
		},

		// PhishTank
		{
			ID:           "phishtank",
			Name:         "PhishTank",
			Description:  "Community-verified phishing URLs",
			Type:         IOCFeedTypeJSON,
			URL:          "http://data.phishtank.com/data/online-valid.json",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"default_type":     "url",
				"default_severity": "high",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 * * * *", // Every hour
				"auto_expire_days": 30,            // Phishing URLs are ephemeral
			},
			FieldMapping: map[string]string{
				"value":       "url",
				"external_id": "phish_id",
				"first_seen":  "submission_time",
			},
			RecommendedPriority: 70,
			EstimatedIOCCount:   50000,
			Tags:                []string{"phishing", "urls", "free"},
		},

		// MISP (requires instance)
		{
			ID:           "misp",
			Name:         "MISP Threat Intelligence",
			Description:  "MISP (Malware Information Sharing Platform) instance",
			Type:         IOCFeedTypeMISP,
			RequiresAuth: true,
			AuthFields:   []string{"api_key", "url"},
			DefaultConfig: map[string]interface{}{
				"update_strategy": "scheduled",
				"update_schedule": "0 0 */4 * * *", // Every 4 hours
			},
			RecommendedPriority: 80,
			EstimatedIOCCount:   0, // Depends on instance
			Tags:                []string{"misp", "enterprise"},
		},

		// STIX/TAXII (requires server)
		{
			ID:           "stix-taxii",
			Name:         "STIX/TAXII Feed",
			Description:  "STIX 2.x over TAXII 2.x protocol",
			Type:         IOCFeedTypeSTIX,
			RequiresAuth: true,
			AuthFields:   []string{"url", "collection_id"},
			DefaultConfig: map[string]interface{}{
				"update_strategy": "scheduled",
				"update_schedule": "0 0 */6 * * *", // Every 6 hours
			},
			RecommendedPriority: 85,
			EstimatedIOCCount:   0, // Depends on collection
			Tags:                []string{"stix", "taxii", "enterprise"},
		},

		// Custom CSV
		{
			ID:           "custom-csv",
			Name:         "Custom CSV Feed",
			Description:  "Custom CSV feed from URL or file",
			Type:         IOCFeedTypeCSV,
			RequiresAuth: false,
			AuthFields:   []string{"api_key", "username", "password"},
			DefaultConfig: map[string]interface{}{
				"delimiter":       ",",
				"skip_header":     true,
				"value_column":    0,
				"update_strategy": "manual",
			},
			RecommendedPriority: 50,
			EstimatedIOCCount:   0,
			Tags:                []string{"custom", "csv"},
		},

		// Custom JSON
		{
			ID:           "custom-json",
			Name:         "Custom JSON Feed",
			Description:  "Custom JSON feed from URL or file",
			Type:         IOCFeedTypeJSON,
			RequiresAuth: false,
			AuthFields:   []string{"api_key", "bearer_token", "username", "password"},
			DefaultConfig: map[string]interface{}{
				"update_strategy": "manual",
			},
			RecommendedPriority: 50,
			EstimatedIOCCount:   0,
			Tags:                []string{"custom", "json"},
		},

		// Spamhaus DROP
		{
			ID:           "spamhaus-drop",
			Name:         "Spamhaus DROP",
			Description:  "Don't Route Or Peer - stolen IP ranges",
			Type:         IOCFeedTypeCSV,
			URL:          "https://www.spamhaus.org/drop/drop.txt",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"value_column":     0,
				"default_type":     "cidr",
				"default_severity": "critical",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 */24 * * *", // Daily
				"auto_expire_days": 30,               // CIDR blocks can change ownership
			},
			RecommendedPriority: 90,
			EstimatedIOCCount:   1000,
			Tags:                []string{"spam", "cidr", "free"},
		},

		// DShield Top Attackers
		{
			ID:           "dshield-top-attackers",
			Name:         "DShield Top Attackers",
			Description:  "Top attacking IPs from SANS Internet Storm Center",
			Type:         IOCFeedTypeCSV,
			URL:          "https://www.dshield.org/feeds/topips.txt",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"skip_header":      true,
				"value_column":     0,
				"default_type":     "ip",
				"default_severity": "high",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 */6 * * *", // Every 6 hours
				"auto_expire_days": 30,              // Attack IPs rotate frequently
			},
			RecommendedPriority: 65,
			EstimatedIOCCount:   100,
			Tags:                []string{"attackers", "ips", "free"},
		},

		// Blocklist.de
		{
			ID:           "blocklist-de",
			Name:         "Blocklist.de All Attackers",
			Description:  "All known attackers from blocklist.de",
			Type:         IOCFeedTypeCSV,
			URL:          "https://lists.blocklist.de/lists/all.txt",
			RequiresAuth: false,
			DefaultConfig: map[string]interface{}{
				"value_column":     0,
				"default_type":     "ip",
				"default_severity": "medium",
				"update_strategy":  "scheduled",
				"update_schedule":  "0 0 */12 * * *", // Every 12 hours
				"auto_expire_days": 30,               // IPs rotate frequently
			},
			RecommendedPriority: 55,
			EstimatedIOCCount:   50000,
			Tags:                []string{"blocklist", "ips", "free"},
		},
	}
}

// GetTemplateByID returns a template by its ID
func GetTemplateByID(id string) *IOCFeedTemplate {
	templates := GetIOCFeedTemplates()
	for _, t := range templates {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// CreateFeedFromTemplate creates a new IOCFeed from a template
func CreateFeedFromTemplate(template *IOCFeedTemplate, name string, authConfig map[string]interface{}) *IOCFeed {
	feed := &IOCFeed{
		Name:        name,
		Description: template.Description,
		Type:        template.Type,
		URL:         template.URL,
		AuthConfig:  authConfig,
		Tags:        template.Tags,
		Priority:    template.RecommendedPriority,
		Enabled:     true,
		Status:      IOCFeedStatusActive,
	}

	// Apply default config
	if template.DefaultConfig != nil {
		if strategy, ok := template.DefaultConfig["update_strategy"].(string); ok {
			feed.UpdateStrategy = IOCFeedUpdateStrategy(strategy)
		}
		if schedule, ok := template.DefaultConfig["update_schedule"].(string); ok {
			feed.UpdateSchedule = schedule
		}
		if delimiter, ok := template.DefaultConfig["delimiter"].(string); ok {
			feed.Delimiter = delimiter
		}
		if skipHeader, ok := template.DefaultConfig["skip_header"].(bool); ok {
			feed.SkipHeader = skipHeader
		}
		if valueCol, ok := template.DefaultConfig["value_column"].(int); ok {
			feed.ValueColumn = valueCol
		}
		if defaultType, ok := template.DefaultConfig["default_type"].(string); ok {
			feed.DefaultType = parseIOCType(defaultType)
		}
		if defaultSeverity, ok := template.DefaultConfig["default_severity"].(string); ok {
			feed.DefaultSeverity = parseIOCSeverity(defaultSeverity)
		}
	}

	// Apply field mappings
	if template.FieldMapping != nil {
		feed.FieldMapping = template.FieldMapping
	}

	return feed
}

// IOCType alias for template parsing
type IOCType = core.IOCType

// IOCSeverity alias for template parsing
type IOCSeverity = core.IOCSeverity

// parseIOCType converts string to IOCType
func parseIOCType(s string) IOCType {
	switch s {
	case "ip":
		return core.IOCTypeIP
	case "domain":
		return core.IOCTypeDomain
	case "url":
		return core.IOCTypeURL
	case "hash":
		return core.IOCTypeHash
	case "email":
		return core.IOCTypeEmail
	case "filename":
		return core.IOCTypeFilename
	case "registry":
		return core.IOCTypeRegistry
	case "cve":
		return core.IOCTypeCVE
	case "cidr":
		return core.IOCTypeCIDR
	default:
		return ""
	}
}

// parseIOCSeverity converts string to IOCSeverity
func parseIOCSeverity(s string) IOCSeverity {
	switch s {
	case "critical":
		return core.IOCSeverityCritical
	case "high":
		return core.IOCSeverityHigh
	case "medium":
		return core.IOCSeverityMedium
	case "low":
		return core.IOCSeverityLow
	case "informational":
		return core.IOCSeverityInformational
	default:
		return core.IOCSeverityMedium
	}
}
