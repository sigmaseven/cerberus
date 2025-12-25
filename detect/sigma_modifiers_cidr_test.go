package detect

import (
	"testing"
)

// TestMatchCIDR_IPv4_ValidMatches tests IPv4 addresses that should match CIDR ranges
func TestMatchCIDR_IPv4_ValidMatches(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		cidr    string
		wantErr bool
	}{
		{
			name:    "IP in /24 network - beginning",
			ip:      "192.168.1.0",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "IP in /24 network - middle",
			ip:      "192.168.1.100",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "IP in /24 network - end",
			ip:      "192.168.1.255",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "IP in /16 network",
			ip:      "10.50.100.200",
			cidr:    "10.50.0.0/16",
			wantErr: false,
		},
		{
			name:    "IP in /8 network - class A private",
			ip:      "10.255.255.255",
			cidr:    "10.0.0.0/8",
			wantErr: false,
		},
		{
			name:    "IP in /32 single host",
			ip:      "192.168.1.1",
			cidr:    "192.168.1.1/32",
			wantErr: false,
		},
		{
			name:    "IP in /0 all addresses",
			ip:      "1.2.3.4",
			cidr:    "0.0.0.0/0",
			wantErr: false,
		},
		{
			name:    "Private IP in 172.16.0.0/12",
			ip:      "172.20.10.5",
			cidr:    "172.16.0.0/12",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := matchCIDR(tt.ip, tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !match {
				t.Errorf("matchCIDR(%s, %s) = false, want true", tt.ip, tt.cidr)
			}
		})
	}
}

// TestMatchCIDR_IPv4_NoMatches tests IPv4 addresses that should NOT match CIDR ranges
func TestMatchCIDR_IPv4_NoMatches(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		cidr    string
		wantErr bool
	}{
		{
			name:    "IP outside /24 network - different third octet",
			ip:      "192.168.2.1",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "IP outside /16 network - different second octet",
			ip:      "10.51.1.1",
			cidr:    "10.50.0.0/16",
			wantErr: false,
		},
		{
			name:    "IP outside /8 network - different first octet",
			ip:      "11.0.0.1",
			cidr:    "10.0.0.0/8",
			wantErr: false,
		},
		{
			name:    "IP not matching /32 single host",
			ip:      "192.168.1.2",
			cidr:    "192.168.1.1/32",
			wantErr: false,
		},
		{
			name:    "Public IP not in private range",
			ip:      "8.8.8.8",
			cidr:    "192.168.0.0/16",
			wantErr: false,
		},
		{
			name:    "IP just outside /12 range - lower bound",
			ip:      "172.15.255.255",
			cidr:    "172.16.0.0/12",
			wantErr: false,
		},
		{
			name:    "IP just outside /12 range - upper bound",
			ip:      "172.32.0.0",
			cidr:    "172.16.0.0/12",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := matchCIDR(tt.ip, tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if match {
				t.Errorf("matchCIDR(%s, %s) = true, want false", tt.ip, tt.cidr)
			}
		})
	}
}

// TestMatchCIDR_IPv6_ValidMatches tests IPv6 addresses that should match CIDR ranges
func TestMatchCIDR_IPv6_ValidMatches(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		cidr    string
		wantErr bool
	}{
		{
			name:    "IPv6 in /64 network",
			ip:      "2001:db8::1",
			cidr:    "2001:db8::/64",
			wantErr: false,
		},
		{
			name:    "IPv6 in /32 network",
			ip:      "2001:db8:1234:5678::1",
			cidr:    "2001:db8::/32",
			wantErr: false,
		},
		{
			name:    "IPv6 link-local address in fe80::/10",
			ip:      "fe80::1",
			cidr:    "fe80::/10",
			wantErr: false,
		},
		{
			name:    "IPv6 in /128 single host",
			ip:      "2001:db8::1",
			cidr:    "2001:db8::1/128",
			wantErr: false,
		},
		{
			name:    "IPv6 localhost in ::1/128",
			ip:      "::1",
			cidr:    "::1/128",
			wantErr: false,
		},
		{
			name:    "IPv6 in ::/0 all addresses",
			ip:      "2001:db8:abcd:1234:5678:90ab:cdef:1234",
			cidr:    "::/0",
			wantErr: false,
		},
		{
			name:    "IPv6 full address in /48 network",
			ip:      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			cidr:    "2001:db8:85a3::/48",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := matchCIDR(tt.ip, tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !match {
				t.Errorf("matchCIDR(%s, %s) = false, want true", tt.ip, tt.cidr)
			}
		})
	}
}

// TestMatchCIDR_IPv6_NoMatches tests IPv6 addresses that should NOT match CIDR ranges
func TestMatchCIDR_IPv6_NoMatches(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		cidr    string
		wantErr bool
	}{
		{
			name:    "IPv6 outside /32 network",
			ip:      "2001:db9::1",
			cidr:    "2001:db8::/32",
			wantErr: false,
		},
		{
			name:    "IPv6 not matching /128 single host",
			ip:      "2001:db8::2",
			cidr:    "2001:db8::1/128",
			wantErr: false,
		},
		{
			name:    "IPv6 outside /64 network",
			ip:      "2001:db8:1::1",
			cidr:    "2001:db8::/64",
			wantErr: false,
		},
		{
			name:    "IPv6 link-local not in documentation range",
			ip:      "fe80::1",
			cidr:    "2001:db8::/32",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := matchCIDR(tt.ip, tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if match {
				t.Errorf("matchCIDR(%s, %s) = true, want false", tt.ip, tt.cidr)
			}
		})
	}
}

// TestMatchCIDR_ErrorCases tests error handling for invalid inputs
func TestMatchCIDR_ErrorCases(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		cidr      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "Empty IP address",
			ip:        "",
			cidr:      "192.168.1.0/24",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Empty CIDR notation",
			ip:        "192.168.1.1",
			cidr:      "",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Both empty",
			ip:        "",
			cidr:      "",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid IP address format",
			ip:        "not-an-ip",
			cidr:      "192.168.1.0/24",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid IP - too many octets",
			ip:        "192.168.1.1.1",
			cidr:      "192.168.1.0/24",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid IP - octet out of range",
			ip:        "192.168.1.256",
			cidr:      "192.168.1.0/24",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid CIDR - no prefix length",
			ip:        "192.168.1.1",
			cidr:      "192.168.1.0",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid CIDR - prefix too large",
			ip:        "192.168.1.1",
			cidr:      "192.168.1.0/33",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid CIDR - negative prefix",
			ip:        "192.168.1.1",
			cidr:      "192.168.1.0/-1",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid CIDR - malformed",
			ip:        "192.168.1.1",
			cidr:      "not-a-cidr/24",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid IPv6 CIDR - prefix too large",
			ip:        "2001:db8::1",
			cidr:      "2001:db8::/129",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid IPv6 address",
			ip:        "not:a:valid:ipv6",
			cidr:      "2001:db8::/32",
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := matchCIDR(tt.ip, tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if match != tt.wantMatch {
				t.Errorf("matchCIDR() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

// TestMatchCIDR_EdgeCases tests boundary conditions and special cases
func TestMatchCIDR_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		cidr      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "Broadcast address in /24",
			ip:        "192.168.1.255",
			cidr:      "192.168.1.0/24",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "Network address in /24",
			ip:        "192.168.1.0",
			cidr:      "192.168.1.0/24",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "Localhost IPv4",
			ip:        "127.0.0.1",
			cidr:      "127.0.0.0/8",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "Localhost IPv6",
			ip:        "::1",
			cidr:      "::1/128",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "IPv4 mapped IPv6 address - Go's net.ParseIP handles this as IPv6",
			ip:        "::ffff:192.168.1.1",
			cidr:      "192.168.1.0/24",
			wantMatch: true, // Go's net package correctly maps this to IPv4 address
			wantErr:   false,
		},
		{
			name:      "Multicast address",
			ip:        "224.0.0.1",
			cidr:      "224.0.0.0/4",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "IPv6 multicast address",
			ip:        "ff02::1",
			cidr:      "ff00::/8",
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := matchCIDR(tt.ip, tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if match != tt.wantMatch {
				t.Errorf("matchCIDR() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

// TestModifierEvaluator_CIDRModifier tests CIDR modifier integration with ModifierEvaluator
func TestModifierEvaluator_CIDRModifier(t *testing.T) {
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
			name:      "Simple CIDR match - IPv4",
			value:     "192.168.1.100",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "Simple CIDR no match - IPv4",
			value:     "192.168.2.100",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "CIDR match - IPv6",
			value:     "2001:db8::1",
			pattern:   "2001:db8::/32",
			modifiers: []string{"cidr"},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "CIDR with list of patterns - OR logic (any match)",
			value:     "192.168.1.100",
			pattern:   []interface{}{"10.0.0.0/8", "192.168.1.0/24"},
			modifiers: []string{"cidr"},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "CIDR with list of patterns - no match",
			value:     "8.8.8.8",
			pattern:   []interface{}{"10.0.0.0/8", "192.168.1.0/24"},
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "CIDR with list of values - match any",
			value:     []interface{}{"192.168.1.100", "8.8.8.8"},
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "CIDR with 'all' modifier - all patterns must match",
			value:     "10.50.100.200",
			pattern:   []interface{}{"10.0.0.0/8", "10.50.0.0/16"},
			modifiers: []string{"cidr", "all"},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "CIDR with 'all' modifier - not all patterns match",
			value:     "10.50.100.200",
			pattern:   []interface{}{"10.0.0.0/8", "192.168.1.0/24"},
			modifiers: []string{"cidr", "all"},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "CIDR with invalid IP - error",
			value:     "not-an-ip",
			pattern:   "192.168.1.0/24",
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "CIDR with invalid CIDR - error",
			value:     "192.168.1.1",
			pattern:   "invalid-cidr",
			modifiers: []string{"cidr"},
			wantMatch: false,
			wantErr:   true,
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

// TestMatchCIDR_PrivateNetworkRanges tests common private network CIDR ranges
func TestMatchCIDR_PrivateNetworkRanges(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		cidr      string
		wantMatch bool
	}{
		// RFC 1918 Private Networks
		{
			name:      "Class A private - 10.0.0.0/8",
			ip:        "10.123.45.67",
			cidr:      "10.0.0.0/8",
			wantMatch: true,
		},
		{
			name:      "Class B private - 172.16.0.0/12",
			ip:        "172.16.0.1",
			cidr:      "172.16.0.0/12",
			wantMatch: true,
		},
		{
			name:      "Class B private upper bound - 172.31.255.255",
			ip:        "172.31.255.255",
			cidr:      "172.16.0.0/12",
			wantMatch: true,
		},
		{
			name:      "Class C private - 192.168.0.0/16",
			ip:        "192.168.255.255",
			cidr:      "192.168.0.0/16",
			wantMatch: true,
		},
		// Loopback
		{
			name:      "Loopback - 127.0.0.0/8",
			ip:        "127.0.0.1",
			cidr:      "127.0.0.0/8",
			wantMatch: true,
		},
		// Link-Local
		{
			name:      "Link-local - 169.254.0.0/16",
			ip:        "169.254.1.1",
			cidr:      "169.254.0.0/16",
			wantMatch: true,
		},
		// Public IP not in private ranges
		{
			name:      "Public IP not in private range",
			ip:        "8.8.8.8",
			cidr:      "10.0.0.0/8",
			wantMatch: false,
		},
		{
			name:      "Public IP not in private range 172.16/12",
			ip:        "8.8.8.8",
			cidr:      "172.16.0.0/12",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := matchCIDR(tt.ip, tt.cidr)
			if err != nil {
				t.Errorf("matchCIDR() unexpected error = %v", err)
				return
			}
			if match != tt.wantMatch {
				t.Errorf("matchCIDR(%s, %s) = %v, want %v", tt.ip, tt.cidr, match, tt.wantMatch)
			}
		})
	}
}
