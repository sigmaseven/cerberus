package core

import (
	"time"

	"github.com/google/uuid"
)

// Event represents the common event schema for all ingested security events
type Event struct {
	EventID      string                 `json:"event_id" bson:"event_id" example:"event-123"`
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp" swaggertype:"string" example:"2023-10-31T12:00:00Z"`
	SourceFormat string                 `json:"source_format" bson:"source_format" example:"json"`
	SourceIP     string                 `json:"source_ip" bson:"source_ip" example:"192.168.1.100"`
	EventType    string                 `json:"event_type" bson:"event_type" example:"user_login"`
	Severity     string                 `json:"severity" bson:"severity" example:"info"`
	RawData      string                 `json:"raw_data" bson:"raw_data" example:"raw log data"`
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
