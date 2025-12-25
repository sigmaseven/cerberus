package ingest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/util/goroutine"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const maxBodySize = 1024 * 1024 // 1MB limit for JSON requests

// JSONListener listens for JSON events over HTTP POST and UDP
type JSONListener struct {
	*BaseListener
	tls         bool
	certFile    string
	keyFile     string
	server      *http.Server
	maxBodySize int64
}

// NewJSONListener creates a new JSON listener
func NewJSONListener(host string, port int, tls bool, certFile, keyFile string, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger) *JSONListener {
	return &JSONListener{
		BaseListener: NewBaseListener(host, port, rateLimit, eventCh, logger),
		tls:          tls,
		certFile:     certFile,
		keyFile:      keyFile,
		maxBodySize:  maxBodySize,
	}
}

// NewJSONListenerWithConfig creates a new JSON listener with config
func NewJSONListenerWithConfig(host string, port int, tls bool, certFile, keyFile string, rateLimit int, maxBodySize int64, eventCh chan<- *core.Event, logger *zap.SugaredLogger, cfg *config.Config) *JSONListener {
	return &JSONListener{
		BaseListener: NewBaseListenerWithConfig(host, port, rateLimit, eventCh, logger, cfg),
		tls:          tls,
		certFile:     certFile,
		keyFile:      keyFile,
		maxBodySize:  maxBodySize,
	}
}

// Start starts the HTTP server and UDP listener
func (j *JSONListener) Start() error {
	// Start HTTP server
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/ingest/json", j.handlePost).Methods("POST")

	addr := fmt.Sprintf("%s:%d", j.host, j.port)
	j.server = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	j.logger.Infof("JSON HTTP listener started on %s", addr)

	// Start HTTP server in goroutine with proper WaitGroup tracking
	// TASK 147: Added panic recovery to prevent server crashes from affecting entire system
	j.wg.Add(1)
	go func() {
		defer j.wg.Done()
		defer goroutine.Recover("json-http-server", j.logger)
		var err error
		if j.tls {
			err = j.server.ListenAndServeTLS(j.certFile, j.keyFile)
		} else {
			err = j.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			j.logger.Errorf("JSON server error: %v", err)
		}
	}()

	// Start UDP listener
	go j.BaseListener.StartUDP(ParseJSON, "JSON")
	return nil
}

func (j *JSONListener) handlePost(w http.ResponseWriter, r *http.Request) {
	if !j.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, j.maxBodySize))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if len(body) >= maxBodySize {
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	raw := string(body)
	event, err := ParseJSON(raw)
	if err != nil {
		j.logger.Errorf("Failed to parse JSON: %v", err)
		// TASK 7.3: Send malformed event to DLQ instead of just logging
		if j.dlq != nil && j.protocol != "" {
			failedEvent := &FailedEvent{
				Protocol:     j.protocol,
				RawEvent:     raw,
				ErrorReason:  "parse_failure",
				ErrorDetails: err.Error(),
				SourceIP:     r.RemoteAddr,
			}
			if dlqErr := j.dlq.Add(failedEvent); dlqErr != nil {
				// Log DLQ write failure but don't block ingestion pipeline
				j.logger.Warnf("Failed to write event to DLQ: %v (original parse error: %v)", dlqErr, err)
			}
		}
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	event.SourceIP = r.RemoteAddr

	select {
	case j.eventCh <- event:
		w.WriteHeader(http.StatusAccepted)
	default:
		j.logger.Warn("Event channel full, dropping JSON event")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
	}
}

// Stop stops the server and listeners
func (j *JSONListener) Stop() {
	close(j.stopCh)
	if j.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := j.server.Shutdown(ctx); err != nil {
			j.logger.Errorw("Failed to shutdown JSON HTTP server gracefully", "error", err)
		}
	}
	j.wg.Wait()
}
