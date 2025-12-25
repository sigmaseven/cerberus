// Package steps implements BDD step definitions for performance testing
// Requirement: FR-ING-008 - High-Throughput Ingestion
// Requirement: NFR-ING-001 - Ingestion Throughput
// Source: docs/requirements/data-ingestion-requirements.md
// Source: docs/requirements/performance-requirements.md
package steps

import (
	"time"

	"github.com/cucumber/godog"
)

// PerformanceContext maintains state for performance test scenarios
// Per AFFIRMATIONS.md Line 147: Context pattern for proper state encapsulation
type PerformanceContext struct {
	baseURL             string
	eventsSent          int
	eventsReceived      int
	latencies           []time.Duration
	dataLossRate        float64
	bufferCapacity      int
	bufferFull          bool
	backpressureApplied bool
	metricsCollected    map[string]interface{}
}

// InitializePerformanceContext registers all performance test step definitions
// Requirement: NFR-ING-001 - Performance test coverage
func InitializePerformanceContext(sc *godog.ScenarioContext) {
	ctx := &PerformanceContext{
		baseURL:          "http://localhost:8080",
		metricsCollected: make(map[string]interface{}),
		latencies:        make([]time.Duration, 0),
	}

	// Background steps
	sc.Step(`^the Cerberus ingestion service is running$`, ctx.theCerberusIngestionServiceIsRunning)
	sc.Step(`^the storage backend is ready$`, ctx.theStorageBackendIsReady)
	sc.Step(`^ingestion metrics are being collected$`, ctx.ingestionMetricsAreBeingCollected)
	sc.Step(`^the ingestion service is idle$`, ctx.theIngestionServiceIsIdle)
	sc.Step(`^the event buffer capacity is (\d+) events$`, ctx.theEventBufferCapacityIsEvents)
	sc.Step(`^the storage backend is slow$`, ctx.theStorageBackendIsSlow)
	sc.Step(`^the Syslog listener is active on port (\d+)$`, ctx.theSyslogListenerIsActiveOnPort)
	sc.Step(`^the JSON HTTP endpoint is active$`, ctx.theJSONHTTPEndpointIsActive)
	sc.Step(`^the CEF listener is active on port (\d+)$`, ctx.theCEFListenerIsActiveOnPort)

	// Event sending steps
	sc.Step(`^I send (\d+) events per second for (\d+) minutes$`, ctx.iSendEventsPerSecondForMinutes)
	sc.Step(`^I send (\d+) events per second for (\d+) seconds$`, ctx.iSendEventsPerSecondForSeconds)
	sc.Step(`^I send events faster than they can be processed$`, ctx.iSendEventsFasterThanProcessed)
	sc.Step(`^I send (\d+) Syslog messages per second via UDP$`, ctx.iSendSyslogMessagesPerSecondViaUDP)
	sc.Step(`^I POST (\d+) JSON events per second to "([^"]*)"$`, ctx.iPOSTJSONEventsPerSecondTo)
	sc.Step(`^I send (\d+) CEF messages per second via TCP$`, ctx.iSendCEFMessagesPerSecondViaTCP)
	sc.Step(`^I send an event to the ingestion pipeline$`, ctx.iSendAnEventToTheIngestionPipeline)

	// Assertion steps
	sc.Step(`^all ([\d,]+) events should be ingested$`, ctx.allEventsShouldBeIngested)
	sc.Step(`^the data loss rate should be (\d+)%$`, ctx.theDataLossRateShouldBe)
	sc.Step(`^the p(\d+) latency should be less than (\d+) (milliseconds?|seconds?)$`, ctx.thePNLatencyShouldBeLessThan)
	sc.Step(`^all ([\d,]+) events should be buffered$`, ctx.allEventsShouldBeBuffered)
	sc.Step(`^the events should be processed successfully$`, ctx.theEventsShouldBeProcessedSuccessfully)
	sc.Step(`^the system should recover to normal state within (\d+) minutes$`, ctx.theSystemShouldRecoverWithinMinutes)
	sc.Step(`^no events should be dropped$`, ctx.noEventsShouldBeDropped)
	sc.Step(`^no events should be lost$`, ctx.noEventsShouldBeLost)
	sc.Step(`^the event buffer should fill up$`, ctx.theEventBufferShouldFillUp)
	sc.Step(`^ingestion should slow down gracefully$`, ctx.ingestionShouldSlowDownGracefully)
	sc.Step(`^HTTP clients should receive (\d+) (.+)$`, ctx.httpClientsShouldReceiveStatus)
	sc.Step(`^TCP clients should experience backpressure$`, ctx.tcpClientsShouldExperienceBackpressure)
	sc.Step(`^all messages should be parsed successfully$`, ctx.allMessagesShouldBeParsedSuccessfully)
	sc.Step(`^the parse error rate should be less than ([\d.]+)%$`, ctx.theParseErrorRateShouldBeLessThan)
	sc.Step(`^the ingestion latency should be less than (\d+)ms \(p(\d+)\)$`, ctx.theIngestionLatencyShouldBeLessThan)
	sc.Step(`^all events should be accepted \((\d+) (.+)\)$`, ctx.allEventsShouldBeAccepted)
	sc.Step(`^the HTTP response time should be less than (\d+)ms \(p(\d+)\)$`, ctx.theHTTPResponseTimeShouldBeLessThan)
	sc.Step(`^all events should be persisted to storage$`, ctx.allEventsShouldBePersistedToStorage)
	sc.Step(`^all messages should be parsed correctly$`, ctx.allMessagesShouldBeParsedCorrectly)
	sc.Step(`^CEF extension fields should be extracted$`, ctx.cefExtensionFieldsShouldBeExtracted)
	sc.Step(`^the throughput should be sustained without packet loss$`, ctx.theThroughputShouldBeSustainedWithoutPacketLoss)
	sc.Step(`^the event should be available for search within (\d+)ms \(p(\d+)\)$`, ctx.theEventShouldBeAvailableForSearchWithin)
	sc.Step(`^the latency should be measured from receipt to queryable$`, ctx.theLatencyShouldBeMeasuredFromReceiptToQueryable)

	// Cleanup
}
