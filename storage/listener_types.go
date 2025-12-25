package storage

import (
	"time"
)

// DynamicListener represents a dynamically configured listener
type DynamicListener struct {
	ID              string    `json:"id" bson:"_id,omitempty"`
	Name            string    `json:"name" bson:"name"`
	Description     string    `json:"description" bson:"description"`
	Type            string    `json:"type" bson:"type"`         // syslog, cef, json, fluentd, fluentbit
	Protocol        string    `json:"protocol" bson:"protocol"` // tcp, udp, tls
	Host            string    `json:"host" bson:"host"`
	Port            int       `json:"port" bson:"port"`
	TLS             bool      `json:"tls" bson:"tls"`
	CertFile        string    `json:"cert_file,omitempty" bson:"cert_file,omitempty"`
	KeyFile         string    `json:"key_file,omitempty" bson:"key_file,omitempty"`
	Status          string    `json:"status" bson:"status"` // stopped, starting, running, error
	Tags            []string  `json:"tags" bson:"tags"`
	Source          string    `json:"source" bson:"source"`
	FieldMapping    string    `json:"field_mapping" bson:"field_mapping"` // Field mapping to use for normalization
	EventsReceived  int64     `json:"events_received" bson:"events_received"`
	ErrorCount      int64     `json:"error_count" bson:"error_count"`
	EventsPerMinute float64   `json:"events_per_minute" bson:"events_per_minute"`
	LastEvent       time.Time `json:"last_event,omitempty" bson:"last_event,omitempty"`
	CreatedAt       time.Time `json:"created_at" bson:"created_at"`
	CreatedBy       string    `json:"created_by,omitempty" bson:"created_by,omitempty"`
	UpdatedAt       time.Time `json:"updated_at" bson:"updated_at"`
	StartedAt       time.Time `json:"started_at,omitempty" bson:"started_at,omitempty"`
	StoppedAt       time.Time `json:"stopped_at,omitempty" bson:"stopped_at,omitempty"`
}

// ListenerStats represents per-listener statistics
type ListenerStats struct {
	EventsReceived  int64     `json:"events_received"`
	EventsPerMinute float64   `json:"events_per_minute"`
	ErrorCount      int64     `json:"error_count"`
	ErrorRate       float64   `json:"error_rate"`
	LastEvent       time.Time `json:"last_event,omitempty"`
	UptimeDuration  float64   `json:"uptime_duration"`
}
