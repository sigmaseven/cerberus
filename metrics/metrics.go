package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsIngested = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_events_ingested_total",
			Help: "Total number of events ingested",
		},
		[]string{"source"},
	)

	AlertsGenerated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_alerts_generated_total",
			Help: "Total number of alerts generated",
		},
		[]string{"severity"},
	)

	ActionsExecuted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_actions_executed_total",
			Help: "Total number of actions executed",
		},
		[]string{"type"},
	)

	EventProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerberus_event_processing_duration_seconds",
			Help:    "Time taken to process events",
			Buckets: prometheus.DefBuckets,
		},
	)

	DeadLetterInsertFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cerberus_dead_letter_insert_failures_total",
			Help: "Total number of dead letter insertion failures",
		},
	)
)
