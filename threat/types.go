package threat

import (
	"time"
)

// IOCType represents different types of indicators of compromise
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeHash   IOCType = "hash"
	IOCTypeURL    IOCType = "url"
)

// IOC represents an indicator of compromise
type IOC struct {
	Type       IOCType   `json:"type"`
	Value      string    `json:"value"`
	Confidence float64   `json:"confidence"`
	Tags       []string  `json:"tags"`
	Source     string    `json:"source"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// ThreatIntel represents threat intelligence information
type ThreatIntel struct {
	IOC         string            `json:"ioc"`
	Type        IOCType           `json:"type"`
	IsMalicious bool              `json:"is_malicious"`
	Confidence  float64           `json:"confidence"`
	Tags        []string          `json:"tags"`
	Description string            `json:"description"`
	References  []string          `json:"references"`
	Metadata    map[string]string `json:"metadata"`
}
