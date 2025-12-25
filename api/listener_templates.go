package api

import (
	"cerberus/storage"
)

// ListenerTemplate represents a pre-configured listener template
type ListenerTemplate struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Category    string                  `json:"category"`
	Icon        string                  `json:"icon"`
	Config      storage.DynamicListener `json:"config"`
	Tags        []string                `json:"tags"`
}

// GetBuiltInTemplates returns all built-in listener templates
func GetBuiltInTemplates() []ListenerTemplate {
	return []ListenerTemplate{
		{
			ID:          "palo-alto-syslog",
			Name:        "Palo Alto Firewall",
			Description: "Syslog listener for Palo Alto Networks firewalls",
			Category:    "Firewall",
			Icon:        "security",
			Config: storage.DynamicListener{
				Name:        "Palo Alto Firewall",
				Description: "Receives syslog messages from Palo Alto Networks firewall",
				Type:        "syslog",
				Protocol:    "udp",
				Host:        "0.0.0.0",
				Port:        5514,
				TLS:         false,
				Source:      "palo-alto-firewall",
				Tags:        []string{"firewall", "palo-alto", "network-security"},
			},
			Tags: []string{"firewall", "palo-alto", "syslog", "network-security"},
		},
		{
			ID:          "cisco-asa-syslog",
			Name:        "Cisco ASA Firewall",
			Description: "Syslog listener for Cisco ASA firewalls",
			Category:    "Firewall",
			Icon:        "security",
			Config: storage.DynamicListener{
				Name:        "Cisco ASA Firewall",
				Description: "Receives syslog messages from Cisco ASA firewall",
				Type:        "syslog",
				Protocol:    "udp",
				Host:        "0.0.0.0",
				Port:        5515,
				TLS:         false,
				Source:      "cisco-asa",
				Tags:        []string{"firewall", "cisco", "network-security"},
			},
			Tags: []string{"firewall", "cisco", "syslog", "network-security"},
		},
		{
			ID:          "windows-wef",
			Name:        "Windows Event Forwarding",
			Description: "Receives Windows events via WEF over HTTP/JSON",
			Category:    "Endpoint",
			Icon:        "desktop_windows",
			Config: storage.DynamicListener{
				Name:        "Windows Event Forwarding",
				Description: "Receives Windows events forwarded via WEF",
				Type:        "json",
				Protocol:    "http",
				Host:        "0.0.0.0",
				Port:        5985,
				TLS:         false,
				Source:      "windows-wef",
				Tags:        []string{"windows", "endpoint", "wef"},
			},
			Tags: []string{"windows", "endpoint", "json", "http"},
		},
		{
			ID:          "apache-access-log",
			Name:        "Apache Access Logs",
			Description: "Syslog listener for Apache web server access logs",
			Category:    "Web Server",
			Icon:        "public",
			Config: storage.DynamicListener{
				Name:        "Apache Access Logs",
				Description: "Receives Apache access logs via syslog",
				Type:        "syslog",
				Protocol:    "udp",
				Host:        "0.0.0.0",
				Port:        5516,
				TLS:         false,
				Source:      "apache-access",
				Tags:        []string{"web", "apache", "access-logs"},
			},
			Tags: []string{"web", "apache", "syslog"},
		},
		{
			ID:          "checkpoint-firewall",
			Name:        "Check Point Firewall",
			Description: "CEF listener for Check Point firewalls",
			Category:    "Firewall",
			Icon:        "security",
			Config: storage.DynamicListener{
				Name:        "Check Point Firewall",
				Description: "Receives CEF messages from Check Point firewall",
				Type:        "cef",
				Protocol:    "tcp",
				Host:        "0.0.0.0",
				Port:        5517,
				TLS:         false,
				Source:      "checkpoint-firewall",
				Tags:        []string{"firewall", "checkpoint", "network-security"},
			},
			Tags: []string{"firewall", "checkpoint", "cef"},
		},
		{
			ID:          "linux-auditd",
			Name:        "Linux Auditd",
			Description: "Syslog listener for Linux audit daemon",
			Category:    "Endpoint",
			Icon:        "computer",
			Config: storage.DynamicListener{
				Name:        "Linux Auditd",
				Description: "Receives Linux audit logs via syslog",
				Type:        "syslog",
				Protocol:    "tcp",
				Host:        "0.0.0.0",
				Port:        5518,
				TLS:         true,
				CertFile:    "/path/to/cert.pem",
				KeyFile:     "/path/to/key.pem",
				Source:      "linux-auditd",
				Tags:        []string{"linux", "endpoint", "audit"},
			},
			Tags: []string{"linux", "endpoint", "syslog", "tls"},
		},
		{
			ID:          "aws-cloudwatch",
			Name:        "AWS CloudWatch Logs",
			Description: "JSON listener for AWS CloudWatch log streams",
			Category:    "Cloud",
			Icon:        "cloud",
			Config: storage.DynamicListener{
				Name:        "AWS CloudWatch Logs",
				Description: "Receives JSON logs from AWS CloudWatch",
				Type:        "json",
				Protocol:    "http",
				Host:        "0.0.0.0",
				Port:        5519,
				TLS:         true,
				CertFile:    "/path/to/cert.pem",
				KeyFile:     "/path/to/key.pem",
				Source:      "aws-cloudwatch",
				Tags:        []string{"aws", "cloud", "cloudwatch"},
			},
			Tags: []string{"aws", "cloud", "json", "http", "tls"},
		},
	}
}

// GetTemplateByID returns a specific template by ID
// BLOCKING-2 FIX: Return pointer to slice element, not loop variable
// The loop variable has a single address reused each iteration (Go < 1.22)
// which would cause all returned pointers to reference the last element
func GetTemplateByID(id string) *ListenerTemplate {
	templates := GetBuiltInTemplates()
	for i := range templates {
		if templates[i].ID == id {
			return &templates[i]
		}
	}
	return nil
}

// GetTemplatesByCategory returns templates filtered by category
func GetTemplatesByCategory(category string) []ListenerTemplate {
	templates := GetBuiltInTemplates()
	var filtered []ListenerTemplate
	for _, template := range templates {
		if template.Category == category {
			filtered = append(filtered, template)
		}
	}
	return filtered
}

// GetTemplatesByTag returns templates that have a specific tag
func GetTemplatesByTag(tag string) []ListenerTemplate {
	templates := GetBuiltInTemplates()
	var filtered []ListenerTemplate
	for _, template := range templates {
		for _, t := range template.Tags {
			if t == tag {
				filtered = append(filtered, template)
				break
			}
		}
	}
	return filtered
}
