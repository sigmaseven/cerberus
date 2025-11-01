package ingest

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewBaseListener(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event)

	bl := NewBaseListener("localhost", 514, 1000, eventCh, logger)

	assert.NotNil(t, bl)
	assert.Equal(t, "localhost", bl.host)
	assert.Equal(t, 514, bl.port)
	assert.NotNil(t, bl.limiter)
	assert.NotNil(t, bl.eventCh)
	assert.NotNil(t, bl.stopCh)
	assert.Equal(t, logger, bl.logger)
	assert.Nil(t, bl.udpConn)
	assert.Nil(t, bl.tcpListener)
}

func TestProcessEvent(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	bl := NewBaseListener("localhost", 514, 1000, eventCh, logger)

	// Test processEvent
	raw := `{"message": "test"}`
	sourceIP := "127.0.0.1"
	event, err := ParseJSON(raw)
	assert.NoError(t, err)

	bl.processEvent(raw, sourceIP, ParseJSON, "test")

	select {
	case received := <-eventCh:
		assert.Equal(t, event.Fields["message"], received.Fields["message"])
		assert.Equal(t, sourceIP, received.SourceIP)
	default:
		t.Fatal("Event not received")
	}
}

func TestProcessEvent_RateLimit(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	bl := NewBaseListener("localhost", 514, 0, eventCh, logger) // rateLimit 0

	// Test processEvent with rate limit
	raw := `{"message": "test"}`
	sourceIP := "127.0.0.1"

	bl.processEvent(raw, sourceIP, ParseJSON, "test")

	// Should not send event
	select {
	case <-eventCh:
		t.Fatal("Event should not be sent due to rate limit")
	default:
		// Good
	}
}

func TestStartUDP(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	bl := NewBaseListener("localhost", 0, 1000, eventCh, logger) // port 0 for auto

	go bl.StartUDP(ParseJSON, "Test")

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual port
	addr := bl.udpConn.LocalAddr().(*net.UDPAddr)
	port := addr.Port

	// Send UDP packet
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	assert.NoError(t, err)
	defer conn.Close()

	raw := `{"event": "test"}`
	_, err = conn.Write([]byte(raw))
	assert.NoError(t, err)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Check event
	select {
	case event := <-eventCh:
		assert.Equal(t, "json", event.SourceFormat)
		assert.Contains(t, event.SourceIP, "127.0.0.1")
	default:
		t.Fatal("Event not received")
	}

	bl.Stop()
}

func TestJSONListener_Start(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	listener := NewJSONListener("localhost", 18080, false, "", "", 1000, eventCh, logger)

	err := listener.Start()
	assert.NoError(t, err)

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// POST request
	resp, err := http.Post("http://localhost:18080/api/v1/ingest/json", "application/json", strings.NewReader(`{"test": "data"}`))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()

	// Check event
	select {
	case event := <-eventCh:
		assert.Equal(t, "json", event.SourceFormat)
		assert.Contains(t, event.SourceIP, "127.0.0.1")
	case <-time.After(1 * time.Second):
		t.Fatal("Event not received")
	}

	listener.Stop()
}

func TestSyslogListener_Start(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	listener := NewSyslogListener("localhost", 0, 1000, eventCh, logger)

	err := listener.Start()
	assert.NoError(t, err)

	// Wait
	time.Sleep(100 * time.Millisecond)

	// Get port from UDP conn
	addr := listener.BaseListener.udpConn.LocalAddr().(*net.UDPAddr)
	port := addr.Port

	// Send UDP syslog
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	assert.NoError(t, err)
	defer conn.Close()

	raw := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed`
	_, err = conn.Write([]byte(raw))
	assert.NoError(t, err)

	// Wait
	time.Sleep(100 * time.Millisecond)

	// Check event
	select {
	case event := <-eventCh:
		assert.Equal(t, "syslog", event.SourceFormat)
		assert.Contains(t, event.SourceIP, "127.0.0.1")
	case <-time.After(1 * time.Second):
		t.Fatal("Event not received")
	}

	listener.Stop()
}

func TestCEFListener_Start(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	listener := NewCEFListener("localhost", 0, 1000, eventCh, logger)

	err := listener.Start()
	assert.NoError(t, err)

	// Wait
	time.Sleep(100 * time.Millisecond)

	// Get port from UDP conn
	addr := listener.BaseListener.udpConn.LocalAddr().(*net.UDPAddr)
	port := addr.Port

	// Send UDP CEF
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	assert.NoError(t, err)
	defer conn.Close()

	raw := `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 suser=pat`
	_, err = conn.Write([]byte(raw))
	assert.NoError(t, err)

	// Wait
	time.Sleep(100 * time.Millisecond)

	// Check event
	select {
	case event := <-eventCh:
		assert.Equal(t, "cef", event.SourceFormat)
		assert.Contains(t, event.SourceIP, "127.0.0.1")
	case <-time.After(1 * time.Second):
		t.Fatal("Event not received")
	}

	listener.Stop()
}

func TestStartTCP(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	bl := NewBaseListener("localhost", 0, 1000, eventCh, logger) // port 0 for auto

	go bl.StartTCP(ParseJSON, "Test")

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual port
	addr := bl.tcpListener.Addr().(*net.TCPAddr)
	port := addr.Port

	// Connect TCP
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	assert.NoError(t, err)

	// Send data
	raw := `{"event": "test"}` + "\n"
	_, err = conn.Write([]byte(raw))
	assert.NoError(t, err)

	// Close connection to signal EOF
	conn.Close()

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Check event
	select {
	case event := <-eventCh:
		assert.Equal(t, "json", event.SourceFormat)
		assert.Contains(t, event.SourceIP, "127.0.0.1")
	default:
		t.Fatal("Event not received")
	}

	bl.Stop()
}

func TestJSONListener_RateLimit(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	listener := NewJSONListener("localhost", 18081, false, "", "", 0, eventCh, logger) // rateLimit 0

	err := listener.Start()
	assert.NoError(t, err)

	// Wait
	time.Sleep(500 * time.Millisecond)

	// POST request
	resp, err := http.Post("http://localhost:18081/api/v1/ingest/json", "application/json", strings.NewReader(`{"test": "data"}`))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	resp.Body.Close()

	// No event
	select {
	case <-eventCh:
		t.Fatal("Event should not be sent")
	case <-time.After(100 * time.Millisecond):
		// Good
	}

	listener.Stop()
}
