package ingest

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewJSONListener(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event)

	listener := NewJSONListener("localhost", 8080, true, "cert.crt", "key.key", 1000, eventCh, logger)

	assert.NotNil(t, listener)
	assert.NotNil(t, listener.BaseListener)
	assert.Equal(t, "localhost", listener.BaseListener.host)
	assert.Equal(t, 8080, listener.BaseListener.port)
	assert.True(t, listener.tls)
}

func TestJSONListener_InvalidJSON(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	listener := NewJSONListener("localhost", 18082, false, "", "", 1000, eventCh, logger)

	err := listener.Start()
	assert.NoError(t, err)

	// Wait
	time.Sleep(500 * time.Millisecond)

	// POST invalid JSON
	resp, err := http.Post("http://localhost:18082/api/v1/ingest/json", "application/json", strings.NewReader(`invalid json`))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	listener.Stop()
}

func TestJSONListener_BodyTooLarge(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1)

	listener := NewJSONListener("localhost", 18083, false, "", "", 1000, eventCh, logger)

	err := listener.Start()
	assert.NoError(t, err)

	// Wait
	time.Sleep(500 * time.Millisecond)

	// POST large body (over 1MB)
	largeBody := strings.Repeat("a", 1024*1024+1)
	resp, err := http.Post("http://localhost:18083/api/v1/ingest/json", "application/json", strings.NewReader(largeBody))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	resp.Body.Close()

	listener.Stop()
}

func TestJSONListener_ChannelFull(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event) // no buffer, full

	listener := NewJSONListener("localhost", 18084, false, "", "", 1000, eventCh, logger)

	err := listener.Start()
	assert.NoError(t, err)

	// Wait
	time.Sleep(500 * time.Millisecond)

	// POST request
	resp, err := http.Post("http://localhost:18084/api/v1/ingest/json", "application/json", strings.NewReader(`{"test": "data"}`))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()

	listener.Stop()
}
