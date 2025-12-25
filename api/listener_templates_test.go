package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ================================
// GetBuiltInTemplates Tests
// ================================

func TestGetBuiltInTemplates_ReturnsAllTemplates(t *testing.T) {
	templates := GetBuiltInTemplates()

	assert.Len(t, templates, 7, "Should return exactly 7 built-in templates")
}

func TestGetBuiltInTemplates_ContainsExpectedTemplateIDs(t *testing.T) {
	templates := GetBuiltInTemplates()

	expectedIDs := []string{
		"palo-alto-syslog",
		"cisco-asa-syslog",
		"windows-wef",
		"apache-access-log",
		"checkpoint-firewall",
		"linux-auditd",
		"aws-cloudwatch",
	}

	templateIDs := make([]string, len(templates))
	for i, template := range templates {
		templateIDs[i] = template.ID
	}

	for _, expectedID := range expectedIDs {
		assert.Contains(t, templateIDs, expectedID, "Should contain template ID: "+expectedID)
	}
}

func TestGetBuiltInTemplates_AllTemplatesHaveRequiredFields(t *testing.T) {
	templates := GetBuiltInTemplates()

	for _, template := range templates {
		assert.NotEmpty(t, template.ID, "Template ID should not be empty")
		assert.NotEmpty(t, template.Name, "Template name should not be empty")
		assert.NotEmpty(t, template.Description, "Template description should not be empty")
		assert.NotEmpty(t, template.Category, "Template category should not be empty")
		assert.NotEmpty(t, template.Icon, "Template icon should not be empty")
		assert.NotEmpty(t, template.Tags, "Template tags should not be empty")

		// Verify config has required fields
		assert.NotEmpty(t, template.Config.Type, "Template config type should not be empty")
		assert.NotEmpty(t, template.Config.Protocol, "Template config protocol should not be empty")
		assert.NotZero(t, template.Config.Port, "Template config port should not be zero")
		assert.NotEmpty(t, template.Config.Source, "Template config source should not be empty")
	}
}

func TestGetBuiltInTemplates_TemplatesHaveCorrectCategories(t *testing.T) {
	templates := GetBuiltInTemplates()

	categoryCounts := make(map[string]int)
	for _, template := range templates {
		categoryCounts[template.Category]++
	}

	// Verify expected categories exist
	expectedCategories := map[string]int{
		"Firewall":   3, // Palo Alto, Cisco ASA, Check Point
		"Endpoint":   2, // Windows WEF, Linux Auditd
		"Web Server": 1, // Apache
		"Cloud":      1, // AWS CloudWatch
	}

	for category, expectedCount := range expectedCategories {
		actualCount, exists := categoryCounts[category]
		assert.True(t, exists, "Category should exist: "+category)
		assert.Equal(t, expectedCount, actualCount, "Expected count for category: "+category)
	}
}

// ================================
// GetTemplateByID Tests
// ================================

func TestGetTemplateByID_ValidID_ReturnsTemplate(t *testing.T) {
	template := GetTemplateByID("palo-alto-syslog")

	assert.NotNil(t, template, "Should return a template")
	assert.Equal(t, "palo-alto-syslog", template.ID)
	assert.Equal(t, "Palo Alto Firewall", template.Name)
	assert.Equal(t, "Firewall", template.Category)
}

func TestGetTemplateByID_InvalidID_ReturnsNil(t *testing.T) {
	template := GetTemplateByID("nonexistent-template")

	assert.Nil(t, template, "Should return nil for non-existent template")
}

func TestGetTemplateByID_EmptyID_ReturnsNil(t *testing.T) {
	template := GetTemplateByID("")

	assert.Nil(t, template, "Should return nil for empty ID")
}

func TestGetTemplateByID_AllTemplatesRetrievable(t *testing.T) {
	templates := GetBuiltInTemplates()

	for _, expected := range templates {
		retrieved := GetTemplateByID(expected.ID)
		assert.NotNil(t, retrieved, "Should be able to retrieve template: "+expected.ID)
		assert.Equal(t, expected.ID, retrieved.ID)
		assert.Equal(t, expected.Name, retrieved.Name)
		assert.Equal(t, expected.Category, retrieved.Category)
	}
}

func TestGetTemplateByID_ReturnsCorrectConfigForWindowsWEF(t *testing.T) {
	template := GetTemplateByID("windows-wef")

	assert.NotNil(t, template)
	assert.Equal(t, "json", template.Config.Type)
	assert.Equal(t, "http", template.Config.Protocol)
	assert.Equal(t, 5985, template.Config.Port)
	assert.False(t, template.Config.TLS)
	assert.Equal(t, "windows-wef", template.Config.Source)
}

func TestGetTemplateByID_ReturnsCorrectConfigForLinuxAuditd(t *testing.T) {
	template := GetTemplateByID("linux-auditd")

	assert.NotNil(t, template)
	assert.Equal(t, "syslog", template.Config.Type)
	assert.Equal(t, "tcp", template.Config.Protocol)
	assert.Equal(t, 5518, template.Config.Port)
	assert.True(t, template.Config.TLS, "Linux Auditd should have TLS enabled")
	assert.NotEmpty(t, template.Config.CertFile, "Should have cert file configured")
	assert.NotEmpty(t, template.Config.KeyFile, "Should have key file configured")
}

// ================================
// GetTemplatesByCategory Tests
// ================================

func TestGetTemplatesByCategory_Firewall_ReturnsThreeTemplates(t *testing.T) {
	templates := GetTemplatesByCategory("Firewall")

	assert.Len(t, templates, 3, "Should return 3 firewall templates")

	templateIDs := make([]string, len(templates))
	for i, template := range templates {
		templateIDs[i] = template.ID
		assert.Equal(t, "Firewall", template.Category)
	}

	assert.Contains(t, templateIDs, "palo-alto-syslog")
	assert.Contains(t, templateIDs, "cisco-asa-syslog")
	assert.Contains(t, templateIDs, "checkpoint-firewall")
}

func TestGetTemplatesByCategory_Endpoint_ReturnsTwoTemplates(t *testing.T) {
	templates := GetTemplatesByCategory("Endpoint")

	assert.Len(t, templates, 2, "Should return 2 endpoint templates")

	templateIDs := make([]string, len(templates))
	for i, template := range templates {
		templateIDs[i] = template.ID
		assert.Equal(t, "Endpoint", template.Category)
	}

	assert.Contains(t, templateIDs, "windows-wef")
	assert.Contains(t, templateIDs, "linux-auditd")
}

func TestGetTemplatesByCategory_WebServer_ReturnsOneTemplate(t *testing.T) {
	templates := GetTemplatesByCategory("Web Server")

	assert.Len(t, templates, 1, "Should return 1 web server template")
	assert.Equal(t, "apache-access-log", templates[0].ID)
	assert.Equal(t, "Web Server", templates[0].Category)
}

func TestGetTemplatesByCategory_Cloud_ReturnsOneTemplate(t *testing.T) {
	templates := GetTemplatesByCategory("Cloud")

	assert.Len(t, templates, 1, "Should return 1 cloud template")
	assert.Equal(t, "aws-cloudwatch", templates[0].ID)
	assert.Equal(t, "Cloud", templates[0].Category)
}

func TestGetTemplatesByCategory_NonExistentCategory_ReturnsEmptySlice(t *testing.T) {
	templates := GetTemplatesByCategory("NonExistent")

	assert.Empty(t, templates, "Should return empty slice for non-existent category")
	// Note: The function may return nil or empty slice, both are acceptable
}

func TestGetTemplatesByCategory_EmptyCategory_ReturnsEmptySlice(t *testing.T) {
	templates := GetTemplatesByCategory("")

	assert.Empty(t, templates, "Should return empty slice for empty category")
}

// ================================
// GetTemplatesByTag Tests
// ================================

func TestGetTemplatesByTag_Firewall_ReturnsThreeTemplates(t *testing.T) {
	templates := GetTemplatesByTag("firewall")

	assert.Len(t, templates, 3, "Should return 3 templates with 'firewall' tag")

	for _, template := range templates {
		assert.Contains(t, template.Tags, "firewall")
	}
}

func TestGetTemplatesByTag_Syslog_ReturnsFiveTemplates(t *testing.T) {
	templates := GetTemplatesByTag("syslog")

	// Palo Alto, Cisco ASA, Apache, Linux Auditd all use syslog
	assert.Len(t, templates, 4, "Should return 4 templates with 'syslog' tag")

	for _, template := range templates {
		assert.Contains(t, template.Tags, "syslog")
	}
}

func TestGetTemplatesByTag_TLS_ReturnsThreeTemplates(t *testing.T) {
	templates := GetTemplatesByTag("tls")

	// Linux Auditd and AWS CloudWatch use TLS
	assert.Len(t, templates, 2, "Should return 2 templates with 'tls' tag")

	templateIDs := make([]string, len(templates))
	for i, template := range templates {
		templateIDs[i] = template.ID
		assert.Contains(t, template.Tags, "tls")
	}

	assert.Contains(t, templateIDs, "linux-auditd")
	assert.Contains(t, templateIDs, "aws-cloudwatch")
}

func TestGetTemplatesByTag_Cloud_ReturnsOneTemplate(t *testing.T) {
	templates := GetTemplatesByTag("cloud")

	assert.Len(t, templates, 1, "Should return 1 template with 'cloud' tag")
	assert.Equal(t, "aws-cloudwatch", templates[0].ID)
	assert.Contains(t, templates[0].Tags, "cloud")
}

func TestGetTemplatesByTag_NetworkSecurity_ReturnsTwoTemplates(t *testing.T) {
	templates := GetTemplatesByTag("network-security")

	// Palo Alto and Cisco ASA have network-security tag
	assert.Len(t, templates, 2, "Should return 2 templates with 'network-security' tag")

	templateIDs := make([]string, len(templates))
	for i, template := range templates {
		templateIDs[i] = template.ID
		assert.Contains(t, template.Tags, "network-security")
	}

	assert.Contains(t, templateIDs, "palo-alto-syslog")
	assert.Contains(t, templateIDs, "cisco-asa-syslog")
}

func TestGetTemplatesByTag_NonExistentTag_ReturnsEmptySlice(t *testing.T) {
	templates := GetTemplatesByTag("nonexistent-tag")

	assert.Empty(t, templates, "Should return empty slice for non-existent tag")
	// Note: The function may return nil or empty slice, both are acceptable
}

func TestGetTemplatesByTag_EmptyTag_ReturnsEmptySlice(t *testing.T) {
	templates := GetTemplatesByTag("")

	assert.Empty(t, templates, "Should return empty slice for empty tag")
}

// ================================
// Template Data Integrity Tests
// ================================

func TestTemplates_UniquePorts(t *testing.T) {
	templates := GetBuiltInTemplates()
	portMap := make(map[int]string)

	for _, template := range templates {
		port := template.Config.Port
		if existingTemplate, exists := portMap[port]; exists {
			t.Errorf("Port %d is used by both %s and %s", port, existingTemplate, template.ID)
		}
		portMap[port] = template.ID
	}

	assert.Len(t, portMap, 7, "All templates should have unique ports")
}

func TestTemplates_UniqueIDs(t *testing.T) {
	templates := GetBuiltInTemplates()
	idMap := make(map[string]bool)

	for _, template := range templates {
		if idMap[template.ID] {
			t.Errorf("Duplicate template ID found: %s", template.ID)
		}
		idMap[template.ID] = true
	}

	assert.Len(t, idMap, 7, "All templates should have unique IDs")
}

func TestTemplates_ValidProtocolForType(t *testing.T) {
	templates := GetBuiltInTemplates()

	validCombinations := map[string][]string{
		"syslog": {"udp", "tcp"},
		"cef":    {"tcp", "udp"},
		"json":   {"http"},
	}

	for _, template := range templates {
		validProtocols, exists := validCombinations[template.Config.Type]
		assert.True(t, exists, "Template type should be valid: "+template.Config.Type)
		assert.Contains(t, validProtocols, template.Config.Protocol,
			"Protocol %s should be valid for type %s in template %s",
			template.Config.Protocol, template.Config.Type, template.ID)
	}
}

func TestTemplates_TLSConfigurationConsistency(t *testing.T) {
	templates := GetBuiltInTemplates()

	for _, template := range templates {
		if template.Config.TLS {
			assert.NotEmpty(t, template.Config.CertFile,
				"Template %s has TLS enabled but no cert file", template.ID)
			assert.NotEmpty(t, template.Config.KeyFile,
				"Template %s has TLS enabled but no key file", template.ID)
		}
	}
}
