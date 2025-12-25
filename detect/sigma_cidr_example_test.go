package detect

import (
	"testing"
)

// TestSigmaCIDRModifier_RealWorldScenarios demonstrates practical SIGMA rule usage with CIDR modifier
func TestSigmaCIDRModifier_RealWorldScenarios(t *testing.T) {
	evaluator := NewModifierEvaluator(0)

	tests := []struct {
		name        string
		description string
		event       map[string]interface{}
		field       string
		pattern     interface{}
		modifiers   []string
		wantMatch   bool
	}{
		{
			name:        "Detect internal network activity - RFC 1918 Class A",
			description: "SIGMA rule: detection.selection.source_ip|cidr: '10.0.0.0/8'",
			event: map[string]interface{}{
				"source_ip": "10.50.100.200",
				"dest_ip":   "8.8.8.8",
			},
			field:     "source_ip",
			pattern:   "10.0.0.0/8",
			modifiers: []string{"cidr"},
			wantMatch: true,
		},
		{
			name:        "Detect external connections from DMZ - 172.16.0.0/12",
			description: "SIGMA rule: detection.selection.dest_ip|cidr: '172.16.0.0/12'",
			event: map[string]interface{}{
				"source_ip": "192.168.1.100",
				"dest_ip":   "172.20.5.10",
			},
			field:     "dest_ip",
			pattern:   "172.16.0.0/12",
			modifiers: []string{"cidr"},
			wantMatch: true,
		},
		{
			name:        "Exclude private network traffic - multiple CIDR ranges",
			description: "SIGMA rule: detection.filter.source_ip|cidr: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']",
			event: map[string]interface{}{
				"source_ip": "192.168.50.100",
			},
			field: "source_ip",
			pattern: []interface{}{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
			modifiers: []string{"cidr"},
			wantMatch: true,
		},
		{
			name:        "Detect public IP connections - NOT in private ranges",
			description: "Public IP should not match private network CIDRs",
			event: map[string]interface{}{
				"source_ip": "8.8.8.8",
			},
			field: "source_ip",
			pattern: []interface{}{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
			modifiers: []string{"cidr"},
			wantMatch: false,
		},
		{
			name:        "Detect VPN subnet access - specific /24",
			description: "SIGMA rule: detection.selection.dest_ip|cidr: '192.168.100.0/24'",
			event: map[string]interface{}{
				"dest_ip": "192.168.100.50",
			},
			field:     "dest_ip",
			pattern:   "192.168.100.0/24",
			modifiers: []string{"cidr"},
			wantMatch: true,
		},
		{
			name:        "Detect IPv6 link-local communication - fe80::/10",
			description: "SIGMA rule: detection.selection.ipv6_addr|cidr: 'fe80::/10'",
			event: map[string]interface{}{
				"ipv6_addr": "fe80::1",
			},
			field:     "ipv6_addr",
			pattern:   "fe80::/10",
			modifiers: []string{"cidr"},
			wantMatch: true,
		},
		{
			name:        "Detect multicast traffic - 224.0.0.0/4",
			description: "SIGMA rule: detection.selection.dest_ip|cidr: '224.0.0.0/4'",
			event: map[string]interface{}{
				"dest_ip": "239.255.255.250",
			},
			field:     "dest_ip",
			pattern:   "224.0.0.0/4",
			modifiers: []string{"cidr"},
			wantMatch: true,
		},
		{
			name:        "Detect localhost connections - 127.0.0.0/8",
			description: "SIGMA rule: detection.selection.source_ip|cidr: '127.0.0.0/8'",
			event: map[string]interface{}{
				"source_ip": "127.0.0.1",
			},
			field:     "source_ip",
			pattern:   "127.0.0.0/8",
			modifiers: []string{"cidr"},
			wantMatch: true,
		},
		{
			name:        "CIDR with 'all' modifier - IP must be in multiple overlapping ranges",
			description: "SIGMA rule: detection.selection.source_ip|cidr|all: ['10.0.0.0/8', '10.50.0.0/16']",
			event: map[string]interface{}{
				"source_ip": "10.50.100.200",
			},
			field: "source_ip",
			pattern: []interface{}{
				"10.0.0.0/8",
				"10.50.0.0/16",
			},
			modifiers: []string{"cidr", "all"},
			wantMatch: true,
		},
		{
			name:        "CIDR with 'all' modifier - IP not in all ranges (failure case)",
			description: "IP in first range but not second",
			event: map[string]interface{}{
				"source_ip": "10.60.100.200",
			},
			field: "source_ip",
			pattern: []interface{}{
				"10.0.0.0/8",   // Matches
				"10.50.0.0/16", // Does NOT match
			},
			modifiers: []string{"cidr", "all"},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract field value from event
			value, ok := tt.event[tt.field]
			if !ok {
				t.Fatalf("Event field %s not found", tt.field)
			}

			// Evaluate with modifiers
			match, err := evaluator.EvaluateWithModifiers(value, tt.pattern, tt.modifiers)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if match != tt.wantMatch {
				t.Errorf("%s\nValue: %v, Pattern: %v, Modifiers: %v\nGot match=%v, want match=%v",
					tt.description, value, tt.pattern, tt.modifiers, match, tt.wantMatch)
			}
		})
	}
}

// TestSigmaCIDRModifier_ComplexRules demonstrates complex SIGMA rules with CIDR matching
func TestSigmaCIDRModifier_ComplexRules(t *testing.T) {
	evaluator := NewModifierEvaluator(0)

	// Scenario: Suspicious outbound connection from web server
	// Rule detects web servers (192.168.10.0/24) connecting to non-standard ports
	// outside the organization (not in private IP ranges)
	t.Run("Web server outbound connection detection", func(t *testing.T) {
		event := map[string]interface{}{
			"source_ip": "192.168.10.50",
			"dest_ip":   "45.33.32.156",
			"dest_port": 4444,
		}

		// Check if source is in web server subnet
		sourceMatch, err := evaluator.EvaluateWithModifiers(
			event["source_ip"],
			"192.168.10.0/24",
			[]string{"cidr"},
		)
		if err != nil || !sourceMatch {
			t.Errorf("Source IP check failed: match=%v, err=%v", sourceMatch, err)
		}

		// Check if destination is NOT in private ranges (should be public)
		destMatch, err := evaluator.EvaluateWithModifiers(
			event["dest_ip"],
			[]interface{}{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
			[]string{"cidr"},
		)
		if err != nil {
			t.Errorf("Dest IP check failed: err=%v", err)
		}
		// destMatch should be false (public IP not in private ranges)
		if destMatch {
			t.Errorf("Destination should be public IP (not in private ranges)")
		}
	})

	// Scenario: Database access from unauthorized subnet
	// Rule detects connections to database subnet (10.100.0.0/24)
	// from sources NOT in authorized subnets
	t.Run("Database access from unauthorized subnet", func(t *testing.T) {
		event := map[string]interface{}{
			"source_ip": "192.168.50.100", // Not authorized
			"dest_ip":   "10.100.0.10",    // Database server
		}

		authorizedSubnets := []interface{}{
			"10.50.0.0/16", // App servers
			"10.60.0.0/16", // Web servers
		}

		// Check if source is in authorized subnets
		authorized, err := evaluator.EvaluateWithModifiers(
			event["source_ip"],
			authorizedSubnets,
			[]string{"cidr"},
		)
		if err != nil {
			t.Errorf("Authorization check failed: err=%v", err)
		}

		// Should NOT be authorized (192.168.50.100 not in 10.50.0.0/16 or 10.60.0.0/16)
		if authorized {
			t.Errorf("Source should NOT be authorized to access database")
		}
	})

	// Scenario: IPv6 lateral movement detection
	// Detect connections between different IPv6 subnets
	t.Run("IPv6 lateral movement detection", func(t *testing.T) {
		event := map[string]interface{}{
			"source_ipv6": "2001:db8:1000::1",  // Workstation subnet
			"dest_ipv6":   "2001:db8:2000::50", // Server subnet
		}

		// Check if source is in workstation subnet
		sourceMatch, err := evaluator.EvaluateWithModifiers(
			event["source_ipv6"],
			"2001:db8:1000::/48",
			[]string{"cidr"},
		)
		if err != nil || !sourceMatch {
			t.Errorf("Source IPv6 check failed: match=%v, err=%v", sourceMatch, err)
		}

		// Check if destination is in server subnet
		destMatch, err := evaluator.EvaluateWithModifiers(
			event["dest_ipv6"],
			"2001:db8:2000::/48",
			[]string{"cidr"},
		)
		if err != nil || !destMatch {
			t.Errorf("Dest IPv6 check failed: match=%v, err=%v", destMatch, err)
		}
	})
}

// TestSigmaCIDRModifier_EdgeCasesInProduction tests production edge cases
func TestSigmaCIDRModifier_EdgeCasesInProduction(t *testing.T) {
	evaluator := NewModifierEvaluator(0)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "Empty string IP address",
			value:     "",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Whitespace IP address",
			value:     "   ",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Hostname instead of IP",
			value:     "example.com",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Port included in IP (common log format mistake)",
			value:     "192.168.1.1:8080",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "IPv4-mapped IPv6 address matching IPv4 CIDR",
			value:     "::ffff:192.168.1.100",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: true, // Go's net package handles this correctly
			wantErr:   false,
		},
		{
			name:      "Single host /32 CIDR",
			value:     "192.168.1.100",
			pattern:   "192.168.1.100/32",
			modifiers: []string{"cidr"},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "CIDR /0 matches everything (IPv4)",
			value:     "203.0.113.1",
			pattern:   "0.0.0.0/0",
			modifiers: []string{"cidr"},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "CIDR /0 matches everything (IPv6)",
			value:     "2001:db8::1",
			pattern:   "::/0",
			modifiers: []string{"cidr"},
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := evaluator.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateWithModifiers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if match != tt.wantMatch {
				t.Errorf("EvaluateWithModifiers() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}
