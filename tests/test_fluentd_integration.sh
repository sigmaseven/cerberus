#!/bin/bash
# Integration test script for Cerberus Fluentd/Fluent Bit listener
# Tests the Forward protocol implementation

set -e

# Configuration
CERBERUS_HOST="${CERBERUS_HOST:-localhost}"
FLUENTD_PORT="${FLUENTD_PORT:-24224}"
FLUENTBIT_PORT="${FLUENTBIT_PORT:-24225}"
API_PORT="${API_PORT:-8080}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_section() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo "  $1"
}

# Check dependencies
check_dependencies() {
    print_section "Checking Dependencies"

    if ! command -v python3 &> /dev/null; then
        print_error "python3 is required but not installed"
        exit 1
    fi
    print_success "python3 found"

    if ! python3 -c "import msgpack" &> /dev/null; then
        print_error "msgpack is required: pip install msgpack"
        exit 1
    fi
    print_success "msgpack installed"

    if ! python3 -c "import requests" &> /dev/null; then
        print_error "requests is required: pip install requests"
        exit 1
    fi
    print_success "requests installed"
}

# Check if Cerberus is running
check_cerberus() {
    print_section "Checking Cerberus Status"

    if ! curl -s "http://${CERBERUS_HOST}:${API_PORT}/api/v1/health" > /dev/null 2>&1; then
        print_error "Cerberus API is not reachable at http://${CERBERUS_HOST}:${API_PORT}"
        print_info "Make sure Cerberus is running and the API port is correct"
        exit 1
    fi
    print_success "Cerberus API is reachable"

    # Check if Fluentd listener is enabled
    if ! nc -z -w1 "${CERBERUS_HOST}" "${FLUENTD_PORT}" 2>/dev/null; then
        print_error "Fluentd listener is not reachable on port ${FLUENTD_PORT}"
        print_info "Enable Fluentd in config.yaml: listeners.fluentd.enabled: true"
        exit 1
    fi
    print_success "Fluentd listener is reachable on port ${FLUENTD_PORT}"
}

# Run Python integration tests
run_integration_tests() {
    print_section "Running Integration Tests"

    python3 tests/test_fluentd_integration.py \
        --host "${CERBERUS_HOST}" \
        --port "${FLUENTD_PORT}" \
        --api-port "${API_PORT}" \
        --test all
}

# Run Fluent Bit tests
run_fluentbit_tests() {
    print_section "Running Fluent Bit Tests"

    if nc -z -w1 "${CERBERUS_HOST}" "${FLUENTBIT_PORT}" 2>/dev/null; then
        print_info "Testing Fluent Bit listener on port ${FLUENTBIT_PORT}"

        python3 tests/test_fluentd_integration.py \
            --host "${CERBERUS_HOST}" \
            --port "${FLUENTBIT_PORT}" \
            --api-port "${API_PORT}" \
            --test basic

        print_success "Fluent Bit listener test complete"
    else
        print_info "Fluent Bit listener not enabled (port ${FLUENTBIT_PORT}), skipping"
    fi
}

# Query and display recent events
check_events() {
    print_section "Recent Events from Cerberus"

    print_info "Querying events from Fluentd..."
    curl -s "http://${CERBERUS_HOST}:${API_PORT}/api/v1/events?source=fluentd&limit=5" | python3 -m json.tool || true

    print_info "\nQuerying events from Fluent Bit..."
    curl -s "http://${CERBERUS_HOST}:${API_PORT}/api/v1/events?source=fluentbit&limit=5" | python3 -m json.tool || true
}

# Test with real Fluentd installation
test_with_real_fluentd() {
    print_section "Testing with Real Fluentd"

    if ! command -v fluentd &> /dev/null; then
        print_info "Fluentd not installed, skipping real Fluentd test"
        print_info "Install Fluentd: https://docs.fluentd.org/installation"
        return
    fi

    print_info "Creating temporary Fluentd config..."

    cat > /tmp/fluentd-test.conf <<EOF
<source>
  @type forward
  port 24223
  bind 127.0.0.1
</source>

<match **>
  @type forward
  <server>
    host ${CERBERUS_HOST}
    port ${FLUENTD_PORT}
  </server>
  <buffer>
    flush_interval 1s
  </buffer>
</match>
EOF

    print_info "Starting Fluentd relay..."
    fluentd -c /tmp/fluentd-test.conf &
    FLUENTD_PID=$!
    sleep 2

    print_info "Sending test logs to Fluentd..."
    echo '{"message":"Test from real Fluentd","level":"info"}' | \
        fluent-cat test.app --host 127.0.0.1 --port 24223

    sleep 2
    kill $FLUENTD_PID 2>/dev/null || true
    rm /tmp/fluentd-test.conf

    print_success "Real Fluentd test complete"
}

# Performance test
run_performance_test() {
    print_section "Performance Test"

    print_info "Sending 1000 events..."

    python3 tests/test_fluentd_integration.py \
        --host "${CERBERUS_HOST}" \
        --port "${FLUENTD_PORT}" \
        --api-port "${API_PORT}" \
        --test performance \
        --skip-verification

    print_success "Performance test complete"
}

# Main execution
main() {
    echo "Cerberus Fluentd/Fluent Bit Integration Test"
    echo "============================================="
    echo "Target: ${CERBERUS_HOST}:${FLUENTD_PORT}"
    echo "API: http://${CERBERUS_HOST}:${API_PORT}"

    check_dependencies
    check_cerberus
    run_integration_tests
    run_fluentbit_tests
    check_events

    # Optional tests
    if [ "$1" = "--full" ]; then
        test_with_real_fluentd
        run_performance_test
    fi

    print_section "Test Complete"
    print_success "All tests passed!"
    print_info "View events in Cerberus UI: http://${CERBERUS_HOST}:${API_PORT}"
}

# Run main with arguments
main "$@"
