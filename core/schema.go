package core

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Event represents the common event schema for all ingested security events
type Event struct {
	EventID      string                 `json:"event_id" bson:"event_id" example:"event-123"`
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp" swaggertype:"string" example:"2023-10-31T12:00:00Z"`
	IngestedAt   time.Time              `json:"ingested_at" bson:"ingested_at" swaggertype:"string"`
	ListenerID   string                 `json:"listener_id,omitempty" bson:"listener_id,omitempty"`
	ListenerName string                 `json:"listener_name,omitempty" bson:"listener_name,omitempty"`
	Source       string                 `json:"source,omitempty" bson:"source,omitempty"`
	SourceFormat string                 `json:"source_format" bson:"source_format" example:"json"`
	SourceIP     string                 `json:"source_ip" bson:"source_ip" example:"192.168.1.100"`
	EventType    string                 `json:"event_type" bson:"event_type" example:"user_login"`
	Severity     string                 `json:"severity" bson:"severity" example:"info"`
	// RawData stores the original raw event data. Using json.RawMessage prevents
	// double-encoding when the event is serialized to JSON for API responses.
	// For JSON events, this contains valid JSON that should be embedded as-is.
	// For non-JSON events (syslog, CEF), this contains the raw string.
	RawData      json.RawMessage        `json:"raw_data" bson:"raw_data" swaggertype:"string" example:"{\"key\":\"value\"}"`
	Fields       map[string]interface{} `json:"fields" bson:"fields"`
}

// NewEvent creates a new Event with a generated UUID
func NewEvent() *Event {
	return &Event{
		EventID:   uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Fields:    make(map[string]interface{}),
	}
}
