package testing

import "time"

// ==============================================================================
// TEST CONFIGURATION CONSTANTS
// ==============================================================================
// These constants define standard test configuration values with documented
// rationale for each choice. Using constants instead of magic numbers improves
// maintainability and makes test intent clear.

const (
	// TestChannelBufferSize is set to 1 to verify non-blocking behavior
	// with minimal buffering.
	// WHY: Tests should work with minimal buffering to catch blocking issues.
	// Tests that specifically need buffering override this value.
	TestChannelBufferSize = 1

	// TestWorkerCount is set to 2 to verify concurrent execution
	// without excessive goroutine overhead in tests.
	// WHY: 2 workers prove concurrency works without creating hundreds of
	// goroutines that slow down test execution and make debugging harder.
	TestWorkerCount = 2

	// TestActionWorkerCount is set to 1 for predictable action execution
	// order in tests.
	// WHY: Single worker makes action timing deterministic for easier testing.
	// Tests requiring concurrent action execution override this value.
	TestActionWorkerCount = 1

	// TestRateLimit is disabled (0) in tests by default to avoid
	// rate-limiting affecting test timing.
	// WHY: Rate limiting introduces timing dependencies that make tests flaky.
	// Tests specifically testing rate limiting set this explicitly.
	TestRateLimit = 0

	// TestCorrelationStateTTL is set to 60 seconds for tests that need
	// correlation state without dealing with expiration.
	// WHY: Long enough that tests don't have to worry about expiration,
	// short enough to verify TTL behavior if needed.
	TestCorrelationStateTTL = 60

	// TestActionTimeout is set to 10 seconds to allow actions to complete
	// while still catching hung actions reasonably quickly.
	// WHY: Long enough for actions to complete even on slow CI systems,
	// short enough that hung action tests don't take forever.
	TestActionTimeout = 10

	// TestCircuitBreakerMaxFailures is set to 3 as a realistic threshold
	// that's large enough to avoid false positives but small enough to test.
	// WHY: Common production value. Low enough for fast tests, high enough
	// to prove the counting logic works correctly.
	TestCircuitBreakerMaxFailures = 3

	// TestCircuitBreakerTimeoutSeconds is set to 1 second for fast test execution
	// while still being long enough to verify state transitions.
	// WHY: Short enough for fast tests, long enough to verify timeout behavior.
	// Note: This is in seconds to match config.Config structure.
	TestCircuitBreakerTimeoutSeconds = 1

	// TestCircuitBreakerMaxHalfOpenRequests is set to 2 to verify the
	// half-open request limiting logic without excessive complexity.
	// WHY: 2 is enough to prove the limiting works (need at least 2 to verify
	// counting) but small enough to keep tests simple.
	TestCircuitBreakerMaxHalfOpenRequests = 2

	// TestStorageBufferSize is the buffer size for storage operations in tests.
	// WHY: Small buffer size ensures tests catch blocking issues while
	// still allowing basic batching functionality to work.
	TestStorageBufferSize = 10
)

// ==============================================================================
// TEST TIMING CONSTANTS
// ==============================================================================
// These constants define standard timeout values for different operation types.
// Using standardized timeouts makes tests more consistent and easier to tune
// for different environments (fast dev machines vs slow CI).

const (
	// TestShortTimeout is used for operations that should complete immediately
	// (e.g., in-memory operations, channel sends to buffered channels).
	// WHY: 100ms is fast enough for quick tests but long enough for slow CI.
	// Operations taking longer than this indicate a performance problem.
	TestShortTimeout = 100 * time.Millisecond

	// TestMediumTimeout is used for operations that involve I/O or network
	// (e.g., database queries, HTTP requests to localhost).
	// WHY: 1 second handles typical I/O delays plus margin for slow CI.
	// Most I/O operations complete in <100ms, but CI can be 10x slower.
	TestMediumTimeout = 1 * time.Second

	// TestLongTimeout is used for complex operations or slow CI environments
	// (e.g., batch processing, multiple sequential operations).
	// WHY: 5 seconds is long enough for complex operations on slow CI
	// but short enough that hanging tests fail reasonably quickly.
	TestLongTimeout = 5 * time.Second

	// TestVeryLongTimeout is used for integration tests or operations
	// that may involve external systems.
	// WHY: 30 seconds handles worst-case scenarios including Docker
	// container startup, network delays, and slow CI environments.
	TestVeryLongTimeout = 30 * time.Second

	// TestPollInterval is the interval for WaitForCondition polling.
	// WHY: 10ms provides responsive polling (100 checks/second) without
	// excessive CPU usage. Catches state changes quickly while being
	// efficient enough for hundreds of concurrent tests.
	TestPollInterval = 10 * time.Millisecond
)

// ==============================================================================
// TEST DATA CONSTANTS
// ==============================================================================
// These constants define standard test data values to improve consistency
// across tests and make test intent clearer.

const (
	// TestEventType is a standard event type for testing.
	// WHY: Using a consistent event type across tests makes it easier
	// to write and understand tests. "user_login" is realistic and common.
	TestEventType = "user_login"

	// TestUsername is a standard username for testing.
	// WHY: Consistent username makes tests easier to read and maintain.
	// "testuser" is clearly a test value, not production data.
	TestUsername = "testuser"

	// TestRuleID is a standard rule ID for testing.
	// WHY: Consistent rule ID format (test-rule-NNN) makes tests clear.
	// 001 leaves room for test-rule-002, test-rule-003, etc.
	TestRuleID = "test-rule-001"

	// TestAlertSeverity is a standard alert severity for testing.
	// WHY: "High" is a common severity level that's realistic but
	// clearly distinguishable in test output.
	TestAlertSeverity = "High"

	// TestRuleName is a standard rule name for testing.
	// WHY: Descriptive name that clearly indicates this is test data.
	TestRuleName = "Test Rule for Unit Tests"

	// TestAlertTitle is a standard alert title for testing.
	// WHY: Descriptive title that's clearly test data.
	TestAlertTitle = "Test Alert"

	// TestSourceIP is a standard source IP for testing.
	// WHY: 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for documentation.
	// Using reserved IP prevents accidental blocking of real IPs.
	TestSourceIP = "192.0.2.1"

	// TestDestinationIP is a standard destination IP for testing.
	// WHY: 198.51.100.0/24 is TEST-NET-2 (RFC 5737), reserved for documentation.
	TestDestinationIP = "198.51.100.1"

	// TestHostname is a standard hostname for testing.
	// WHY: .test TLD is reserved for testing (RFC 6761).
	TestHostname = "testhost.test"

	// TestActionID is a standard action ID for testing.
	// WHY: Consistent format makes tests clearer.
	TestActionID = "test-action-001"

	// TestActionType is a standard action type for testing.
	// WHY: "webhook" is a common action type that's easy to mock.
	TestActionType = "webhook"

	// TestWebhookURL is a standard webhook URL for testing.
	// WHY: Using example.com (reserved for documentation) prevents
	// accidental requests to real endpoints during testing.
	TestWebhookURL = "https://example.com/webhook"
)

// ==============================================================================
// TEST SIZE CONSTANTS
// ==============================================================================
// These constants define standard sizes for collections and iterations in tests.

const (
	// TestSmallCollectionSize is for small collection tests (basic iteration).
	// WHY: 10 items is enough to prove iteration works without being slow.
	TestSmallCollectionSize = 10

	// TestMediumCollectionSize is for medium collection tests (batching, pagination).
	// WHY: 100 items proves batching/pagination logic without excessive memory use.
	TestMediumCollectionSize = 100

	// TestLargeCollectionSize is for large collection tests (performance, memory).
	// WHY: 1000 items is large enough to catch O(n²) algorithms but small
	// enough to complete quickly. Larger sizes belong in benchmarks.
	TestLargeCollectionSize = 1000

	// TestConcurrencyLevel is the standard number of concurrent goroutines in tests.
	// WHY: 10 concurrent operations proves concurrency works without creating
	// hundreds of goroutines that obscure race conditions.
	TestConcurrencyLevel = 10

	// TestHighConcurrencyLevel is for stress testing concurrent operations.
	// WHY: 100 concurrent operations catches race conditions that only appear
	// under high load while still completing quickly.
	TestHighConcurrencyLevel = 100
)

// ==============================================================================
// TEST RETRY CONSTANTS
// ==============================================================================
// These constants define retry behavior for flaky external dependencies.

const (
	// TestMaxRetries is the maximum number of retries for flaky operations.
	// WHY: 3 retries handles transient failures without excessive delay.
	// Most flaky operations succeed within 2-3 attempts.
	TestMaxRetries = 3

	// TestRetryDelay is the delay between retry attempts.
	// WHY: 100ms is long enough for transient issues to resolve but
	// short enough that tests don't take forever.
	TestRetryDelay = 100 * time.Millisecond
)
