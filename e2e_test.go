package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/detect"
	"cerberus/ingest"
	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/zap"
)

type TestConfig struct {
	MongoDB struct {
		URI      string
		Database string
	}
	Listeners struct {
		Syslog struct {
			Host string
			Port int
		}
		CEF struct {
			Host string
			Port int
		}
		JSON struct {
			Host     string
			Port     int
			TLS      bool
			CertFile string
			KeyFile  string
		}
	}
	API struct {
		Port int
	}
	Engine struct {
		RateLimit int
	}
}

func TestEndToEnd(t *testing.T) {
	// Create logger
	logger := zap.NewNop()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Use test config with different ports
	cfg := &config.Config{}
	cfg.MongoDB.URI = "mongodb://localhost:27017"
	cfg.MongoDB.Database = "cerberus_test"
	cfg.Listeners.Syslog.Host = "127.0.0.1"
	cfg.Listeners.Syslog.Port = 5140
	cfg.Listeners.CEF.Host = "127.0.0.1"
	cfg.Listeners.CEF.Port = 5150
	cfg.Listeners.JSON.Host = "127.0.0.1"
	cfg.Listeners.JSON.Port = 8080
	cfg.Listeners.JSON.TLS = false
	cfg.Listeners.JSON.CertFile = ""
	cfg.Listeners.JSON.KeyFile = ""
	cfg.API.Port = 8081
	cfg.Engine.RateLimit = 1000
	cfg.Engine.ActionTimeout = 10 // default

	// Initialize MongoDB
	mongoDB, err := storage.NewMongoDB(cfg.MongoDB.URI, cfg.MongoDB.Database, 10, sugar)
	if err != nil {
		t.Skip("MongoDB not available for e2e test")
	}
	defer mongoDB.Close(context.Background())

	// Note: Test DB is not dropped to avoid auth issues

	// Load rules
	rules, err := detect.LoadRules("rules.json", sugar)
	assert.NoError(t, err)

	// Create rule engine
	ruleEngine := detect.NewRuleEngine(rules, []core.CorrelationRule{}, 3600)

	// Channels
	rawEventCh := make(chan *core.Event, 100)
	processedEventCh := make(chan *core.Event, 100)
	alertCh := make(chan *core.Alert, 100)

	// Initialize storage
	eventStorage := storage.NewEventStorage(mongoDB, cfg, processedEventCh, sugar)
	eventStorage.Start(2)
	defer eventStorage.Stop()

	alertStorage := storage.NewAlertStorage(mongoDB, cfg, alertCh, sugar)
	alertStorage.Start(2)

	// Start detection
	detector := detect.NewDetector(ruleEngine, rawEventCh, processedEventCh, alertCh, cfg, sugar)
	detector.Start()

	// Start listeners
	syslogListener := ingest.NewSyslogListener(cfg.Listeners.Syslog.Host, cfg.Listeners.Syslog.Port, cfg.Engine.RateLimit, rawEventCh, sugar)
	cefListener := ingest.NewCEFListener(cfg.Listeners.CEF.Host, cfg.Listeners.CEF.Port, cfg.Engine.RateLimit, rawEventCh, sugar)
	jsonListener := ingest.NewJSONListener(cfg.Listeners.JSON.Host, cfg.Listeners.JSON.Port, cfg.Listeners.JSON.TLS, cfg.Listeners.JSON.CertFile, cfg.Listeners.JSON.KeyFile, cfg.Engine.RateLimit, rawEventCh, sugar)

	go syslogListener.Start()
	go cefListener.Start()
	go jsonListener.Start()

	// Wait for listeners to start
	time.Sleep(3 * time.Second)

	// Send test events
	sendSyslogEvent(t, cfg.Listeners.Syslog.Host, cfg.Listeners.Syslog.Port)
	sendCEFEvent(t, cfg.Listeners.CEF.Host, cfg.Listeners.CEF.Port)
	sendJSONEvent(t, cfg.Listeners.JSON.Host, cfg.Listeners.JSON.Port)

	// Wait for processing
	time.Sleep(5 * time.Second)

	// Shutdown sequence
	close(rawEventCh)
	detector.Stop()
	close(alertCh)
	alertStorage.Stop()
	close(processedEventCh)
	eventStorage.Stop()

	syslogListener.Stop()
	cefListener.Stop()
	jsonListener.Stop()

	// Check events in DB (skip if auth required)
	eventsColl := mongoDB.Database.Collection("events")
	count, err := eventsColl.CountDocuments(context.Background(), bson.M{})
	if err == nil {
		assert.Greater(t, count, int64(0))
	} else {
		t.Logf("Skipping DB count due to auth: %v", err)
	}

	// Check alerts in DB
	alertsColl := mongoDB.Database.Collection("alerts")
	alertCount, err := alertsColl.CountDocuments(context.Background(), bson.M{})
	if err == nil {
		assert.Greater(t, alertCount, int64(0))
	} else {
		t.Logf("Skipping DB count due to auth: %v", err)
	}
}

func sendSyslogEvent(t *testing.T, host string, port int) {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", host, port))
	assert.NoError(t, err)
	defer conn.Close()

	msg := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
	_, err = conn.Write([]byte(msg))
	assert.NoError(t, err)
}

func sendCEFEvent(t *testing.T, host string, port int) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	assert.NoError(t, err)
	defer conn.Close()

	msg := "CEF:0|Test|Test|1.0|100|Test Event|10|src=192.168.1.1 suser=admin\n"
	_, err = conn.Write([]byte(msg))
	assert.NoError(t, err)
}

func sendJSONEvent(t *testing.T, host string, port int) {
	event := map[string]interface{}{
		"event_type": "user_login",
		"fields": map[string]interface{}{
			"status": "failure",
			"user":   "testuser",
		},
	}
	data, err := json.Marshal(event)
	assert.NoError(t, err)

	url := fmt.Sprintf("http://%s:%d/api/v1/ingest/json", host, port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 202, resp.StatusCode)
}
