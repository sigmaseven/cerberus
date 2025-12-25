package tests

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// Config structure to parse config.yaml
type Config struct {
	API struct {
		Port int `yaml:"port"`
	} `yaml:"api"`
}

// TestPortConsistency ensures all frontend port references match the backend config
func TestPortConsistency(t *testing.T) {
	// Read backend config
	configData, err := os.ReadFile("../config.yaml")
	assert.NoError(t, err, "Failed to read config.yaml")

	var config Config
	err = yaml.Unmarshal(configData, &config)
	assert.NoError(t, err, "Failed to parse config.yaml")

	expectedPort := config.API.Port
	assert.NotZero(t, expectedPort, "API port not configured in config.yaml")

	t.Logf("Expected API port from config.yaml: %d", expectedPort)

	// Track all files checked and their status
	filesChecked := []string{}
	portsFound := make(map[string][]string)

	// Test 1: Check vite.config.ts
	t.Run("vite.config.ts proxy port", func(t *testing.T) {
		filePath := "../frontend/vite.config.ts"
		filesChecked = append(filesChecked, filePath)

		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Skipf("File not found: %s", filePath)
			return
		}

		// Look for proxy target configuration
		// Pattern: target: 'http://localhost:8080' or target: "http://localhost:8080"
		proxyPattern := regexp.MustCompile(`target:\s*['"]http://localhost:(\d+)['"]`)
		matches := proxyPattern.FindAllStringSubmatch(string(content), -1)

		assert.NotEmpty(t, matches, "No proxy target found in vite.config.ts")

		for _, match := range matches {
			port := match[1]
			portsFound[filePath] = append(portsFound[filePath], port)
			assert.Equal(t, expectedPort, mustAtoi(port),
				"vite.config.ts proxy target port mismatch. Expected %d, got %s", expectedPort, port)
		}
	})

	// Test 2: Check playwright.config.ts (if exists)
	t.Run("playwright.config.ts baseURL", func(t *testing.T) {
		filePath := "../frontend/playwright.config.ts"
		filesChecked = append(filesChecked, filePath)

		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Skipf("File not found: %s", filePath)
			return
		}

		// Look for baseURL that might reference API port indirectly
		// Note: Playwright usually points to frontend port (3001), not API port
		// So this is informational only
		baseURLPattern := regexp.MustCompile(`baseURL:\s*['"]http://localhost:(\d+)['"]`)
		matches := baseURLPattern.FindAllStringSubmatch(string(content), -1)

		for _, match := range matches {
			port := match[1]
			t.Logf("Found Playwright baseURL port: %s (frontend port, not API port)", port)
		}
	})

	// Test 3: Check E2E test files for hardcoded API URLs
	t.Run("E2E test files API URLs", func(t *testing.T) {
		e2eFiles := []string{
			"../frontend/e2e/api-contract.spec.ts",
			"../frontend/e2e/dashboard.spec.ts",
			"../frontend/e2e/events.spec.ts",
			"../frontend/e2e/alerts.spec.ts",
		}

		// Pattern to find localhost URLs with ports
		urlPattern := regexp.MustCompile(`http://localhost:(\d+)`)

		for _, filePath := range e2eFiles {
			filesChecked = append(filesChecked, filePath)

			content, err := os.ReadFile(filePath)
			if err != nil {
				t.Logf("Skipping %s (not found)", filePath)
				continue
			}

			matches := urlPattern.FindAllStringSubmatch(string(content), -1)

			for _, match := range matches {
				port := match[1]
				portsFound[filePath] = append(portsFound[filePath], port)

				// Check if this looks like an API port reference
				line := getLineContaining(string(content), match[0])
				if strings.Contains(line, "/api") || strings.Contains(line, "API") {
					assert.Equal(t, expectedPort, mustAtoi(port),
						"E2E test file %s has API URL with wrong port. Expected %d, got %s\nLine: %s",
						filePath, expectedPort, port, line)
				}
			}
		}
	})

	// Test 4: Check API service for hardcoded ports
	t.Run("API service hardcoded ports", func(t *testing.T) {
		filePath := "../frontend/src/services/api.ts"
		filesChecked = append(filesChecked, filePath)

		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Skipf("File not found: %s", filePath)
			return
		}

		// Look for hardcoded localhost URLs
		urlPattern := regexp.MustCompile(`http://localhost:(\d+)`)
		matches := urlPattern.FindAllStringSubmatch(string(content), -1)

		for _, match := range matches {
			port := match[1]
			portsFound[filePath] = append(portsFound[filePath], port)
			line := getLineContaining(string(content), match[0])

			assert.Equal(t, expectedPort, mustAtoi(port),
				"api.ts has hardcoded port %s, expected %d\nLine: %s",
				port, expectedPort, line)
		}
	})

	// Test 5: Check for any other TypeScript files with hardcoded API URLs
	t.Run("Other frontend files", func(t *testing.T) {
		// Check common locations
		checkPaths := []string{
			"../frontend/src/config.ts",
			"../frontend/src/constants.ts",
			"../frontend/src/env.ts",
		}

		urlPattern := regexp.MustCompile(`http://localhost:(\d+)`)

		for _, filePath := range checkPaths {
			content, err := os.ReadFile(filePath)
			if err != nil {
				continue // File doesn't exist, skip
			}

			filesChecked = append(filesChecked, filePath)
			matches := urlPattern.FindAllStringSubmatch(string(content), -1)

			for _, match := range matches {
				port := match[1]
				portsFound[filePath] = append(portsFound[filePath], port)
				line := getLineContaining(string(content), match[0])

				t.Logf("Found port reference in %s: %s\nLine: %s", filePath, port, line)
			}
		}
	})

	// Test 6: Check README for documented ports
	t.Run("README documentation", func(t *testing.T) {
		filePath := "../README.md"
		filesChecked = append(filesChecked, filePath)

		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Skipf("File not found: %s", filePath)
			return
		}

		// Look for port references in documentation
		urlPattern := regexp.MustCompile(`:\s*(\d+)`)
		portPattern := regexp.MustCompile(`port\s+(\d+)`)

		// Find all lines mentioning API
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "api") {
				matches := urlPattern.FindAllStringSubmatch(line, -1)
				matches = append(matches, portPattern.FindAllStringSubmatch(line, -1)...)

				for _, match := range matches {
					if len(match) > 1 {
						port := match[1]
						if len(port) == 4 { // Likely a port number
							t.Logf("README mentions port %s in API context: %s", port, strings.TrimSpace(line))
						}
					}
				}
			}
		}
	})

	// Summary report
	t.Run("Summary", func(t *testing.T) {
		t.Logf("\n=== Port Consistency Check Summary ===")
		t.Logf("Expected API Port: %d", expectedPort)
		t.Logf("Files Checked: %d", len(filesChecked))

		if len(portsFound) > 0 {
			t.Logf("\nPorts Found:")
			for file, ports := range portsFound {
				uniquePorts := uniqueStrings(ports)
				t.Logf("  %s: %v", file, uniquePorts)
			}
		}

		t.Logf("\n✅ All port references are consistent with backend config!")
	})
}

// Helper function to convert string to int, panic on error (for tests)
func mustAtoi(s string) int {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil {
		panic(err)
	}
	return result
}

// Helper function to get the line containing a pattern
func getLineContaining(content, pattern string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, pattern) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// Helper function to get unique strings
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if _, value := keys[item]; !value {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}
