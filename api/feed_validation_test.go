package api

import (
	"net"
	"testing"

	"cerberus/sigma/feeds"
)

// TestValidateAuthConfig tests the validateAuthConfig function
func TestValidateAuthConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]interface{}
		expectErr bool
	}{
		{
			name:      "nil config",
			config:    nil,
			expectErr: false,
		},
		{
			name:      "empty config",
			config:    map[string]interface{}{},
			expectErr: false,
		},
		{
			name: "valid username/password",
			config: map[string]interface{}{
				"username": "user",
				"password": "pass",
			},
			expectErr: false,
		},
		{
			name: "valid token",
			config: map[string]interface{}{
				"token": "abc123",
			},
			expectErr: false,
		},
		{
			name: "invalid key",
			config: map[string]interface{}{
				"evil_injection": "malicious",
			},
			expectErr: true,
		},
		{
			name: "mixed valid and invalid",
			config: map[string]interface{}{
				"username":       "user",
				"malicious_code": "evil",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthConfig(tt.config)
			if (err != nil) != tt.expectErr {
				t.Errorf("validateAuthConfig() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

// TestValidateURL tests the validateURL function for SSRF protection
func TestValidateURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		expectErr bool
	}{
		{
			name:      "valid https URL",
			url:       "https://github.com/SigmaHQ/sigma.git",
			expectErr: false,
		},
		{
			name:      "valid git URL",
			url:       "git://github.com/SigmaHQ/sigma.git",
			expectErr: false,
		},
		{
			name:      "http scheme blocked",
			url:       "http://example.com",
			expectErr: true,
		},
		{
			name:      "file scheme blocked",
			url:       "file:///etc/passwd",
			expectErr: true,
		},
		{
			name:      "localhost blocked",
			url:       "https://127.0.0.1/malicious",
			expectErr: true,
		},
		{
			name:      "private IP 10.x blocked",
			url:       "https://10.0.0.1/internal",
			expectErr: true,
		},
		{
			name:      "private IP 192.168.x blocked",
			url:       "https://192.168.1.1/router",
			expectErr: true,
		},
		{
			name:      "private IP 172.16.x blocked",
			url:       "https://172.16.0.1/internal",
			expectErr: true,
		},
		{
			name:      "link-local blocked",
			url:       "https://169.254.169.254/metadata",
			expectErr: true,
		},
		{
			name:      "invalid URL",
			url:       "not a url",
			expectErr: true,
		},
		{
			name:      "empty hostname",
			url:       "https://",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(tt.url)
			if (err != nil) != tt.expectErr {
				t.Errorf("validateURL() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

// TestValidatePath tests the validatePath function for path traversal protection
func TestValidatePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		expectErr bool
	}{
		{
			name:      "empty path",
			path:      "",
			expectErr: false,
		},
		{
			name:      "simple relative path",
			path:      "rules/windows",
			expectErr: false,
		},
		{
			name:      "path traversal with ..",
			path:      "../../../etc/passwd",
			expectErr: true,
		},
		{
			name:      "path traversal hidden",
			path:      "rules/../../sensitive",
			expectErr: true,
		},
		{
			name:      "absolute path /etc",
			path:      "/etc/passwd",
			expectErr: true,
		},
		{
			name:      "absolute path /sys",
			path:      "/sys/kernel",
			expectErr: true,
		},
		{
			name:      "Windows system path",
			path:      "C:\\Windows\\System32",
			expectErr: true,
		},
		{
			name:      "Windows Program Files",
			path:      "C:\\Program Files\\sensitive",
			expectErr: true,
		},
		{
			name:      "safe absolute path",
			path:      "/opt/sigma/rules",
			expectErr: false,
		},
		// CRITICAL: Windows path bypass tests
		// On Windows, Unix paths like "/etc/passwd" are NOT absolute
		// so IsAbs() returns false, bypassing system directory checks
		{
			name:      "Windows bypass - Unix /etc path",
			path:      "/etc/passwd",
			expectErr: true,
		},
		{
			name:      "Windows bypass - Unix /sys path",
			path:      "/sys/kernel/debug",
			expectErr: true,
		},
		{
			name:      "Windows bypass - Unix /proc path",
			path:      "/proc/self/environ",
			expectErr: true,
		},
		{
			name:      "Windows bypass - Unix /dev path",
			path:      "/dev/null",
			expectErr: true,
		},
		{
			name:      "Windows bypass - Unix /root path",
			path:      "/root/.ssh/id_rsa",
			expectErr: true,
		},
		{
			name:      "Windows bypass - Unix /boot path",
			path:      "/boot/grub/grub.cfg",
			expectErr: true,
		},
		// Windows backslash variants
		{
			name:      "Windows backslash - etc path",
			path:      "\\etc\\passwd",
			expectErr: true,
		},
		{
			name:      "Windows backslash - sys path",
			path:      "\\sys\\kernel",
			expectErr: true,
		},
		// Case insensitivity tests
		{
			name:      "Windows path - mixed case",
			path:      "C:\\WINDOWS\\System32",
			expectErr: true,
		},
		{
			name:      "Windows path - lowercase",
			path:      "c:\\windows\\system.ini",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePath(tt.path)
			if (err != nil) != tt.expectErr {
				t.Errorf("validatePath() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

// TestIsPrivateIP tests the isPrivateIP function
func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		expectPriv bool
	}{
		// Public IPs
		{name: "Google DNS", ip: "8.8.8.8", expectPriv: false},
		{name: "Cloudflare DNS", ip: "1.1.1.1", expectPriv: false},

		// RFC1918 Private ranges
		{name: "10.x private", ip: "10.0.0.1", expectPriv: true},
		{name: "172.16.x private", ip: "172.16.0.1", expectPriv: true},
		{name: "192.168.x private", ip: "192.168.1.1", expectPriv: true},

		// Loopback
		{name: "localhost", ip: "127.0.0.1", expectPriv: true},
		{name: "loopback range", ip: "127.0.0.2", expectPriv: true},

		// Link-local
		{name: "link-local", ip: "169.254.1.1", expectPriv: true},
		{name: "AWS metadata", ip: "169.254.169.254", expectPriv: true},

		// Other reserved ranges
		{name: "current network", ip: "0.0.0.1", expectPriv: true},
		{name: "shared address space", ip: "100.64.0.1", expectPriv: true},
		{name: "multicast", ip: "224.0.0.1", expectPriv: true},
		{name: "broadcast", ip: "255.255.255.255", expectPriv: true},

		// IPv6
		{name: "IPv6 loopback", ip: "::1", expectPriv: true},
		{name: "IPv6 link-local", ip: "fe80::1", expectPriv: true},
		{name: "IPv6 unique local", ip: "fc00::1", expectPriv: true},
		{name: "IPv6 public", ip: "2001:4860:4860::8888", expectPriv: false}, // Google DNS
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			result := isPrivateIP(ip)
			if result != tt.expectPriv {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expectPriv)
			}
		})
	}
}

// TestMaskAuthConfig tests the maskAuthConfig function
func TestMaskAuthConfig(t *testing.T) {
	tests := []struct {
		name   string
		setup  func() *feeds.RuleFeed
		verify func(*testing.T, *feeds.RuleFeed)
	}{
		{
			name: "nil feed",
			setup: func() *feeds.RuleFeed {
				return nil
			},
			verify: func(t *testing.T, feed *feeds.RuleFeed) {
				if feed != nil {
					t.Error("expected nil feed")
				}
			},
		},
		{
			name: "nil AuthConfig",
			setup: func() *feeds.RuleFeed {
				return &feeds.RuleFeed{
					ID:         "test",
					AuthConfig: nil,
				}
			},
			verify: func(t *testing.T, feed *feeds.RuleFeed) {
				if feed.AuthConfig != nil {
					t.Error("expected nil AuthConfig")
				}
			},
		},
		{
			name: "empty AuthConfig",
			setup: func() *feeds.RuleFeed {
				return &feeds.RuleFeed{
					ID:         "test",
					AuthConfig: map[string]interface{}{},
				}
			},
			verify: func(t *testing.T, feed *feeds.RuleFeed) {
				if len(feed.AuthConfig) != 0 {
					t.Error("expected empty AuthConfig")
				}
			},
		},
		{
			name: "mask username/password",
			setup: func() *feeds.RuleFeed {
				return &feeds.RuleFeed{
					ID: "test",
					AuthConfig: map[string]interface{}{
						"username": "admin",
						"password": "secret123",
					},
				}
			},
			verify: func(t *testing.T, feed *feeds.RuleFeed) {
				if len(feed.AuthConfig) != 2 {
					t.Errorf("expected 2 keys, got %d", len(feed.AuthConfig))
				}
				for key, val := range feed.AuthConfig {
					if val != "***REDACTED***" {
						t.Errorf("key %s not redacted: %v", key, val)
					}
				}
			},
		},
		{
			name: "mask all sensitive fields",
			setup: func() *feeds.RuleFeed {
				return &feeds.RuleFeed{
					ID: "test",
					AuthConfig: map[string]interface{}{
						"username":      "user",
						"password":      "pass",
						"token":         "abc123",
						"api_key":       "key456",
						"private_key":   "-----BEGIN PRIVATE KEY-----",
						"client_secret": "secret789",
					},
				}
			},
			verify: func(t *testing.T, feed *feeds.RuleFeed) {
				if len(feed.AuthConfig) != 6 {
					t.Errorf("expected 6 keys, got %d", len(feed.AuthConfig))
				}
				for key, val := range feed.AuthConfig {
					if val != "***REDACTED***" {
						t.Errorf("key %s not redacted: %v", key, val)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feed := tt.setup()
			maskAuthConfig(feed)
			tt.verify(t, feed)
		})
	}
}
