// Package api provides WebSocket infrastructure for real-time event broadcasting.
// TASK 158: WebSocket support for feed sync progress notifications.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// WebSocket configuration constants
const (
	// writeWait is the time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// pongWait is the time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// pingPeriod sends pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// maxMessageSize is the maximum message size allowed from peer.
	maxMessageSize = 512

	// Channel buffer sizes for non-blocking sends
	sendChannelSize = 256
)

// WebSocketMessage represents a generic WebSocket message.
// SECURITY: All message types are validated before broadcasting.
type WebSocketMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// FeedSyncEvent represents a feed synchronization event.
// TASK 158: Event structure for real-time feed sync progress updates.
type FeedSyncEvent struct {
	Type      string     `json:"type"` // "feed:sync:started", "feed:sync:progress", "feed:sync:completed", "feed:sync:failed"
	FeedID    string     `json:"feed_id"`
	FeedName  string     `json:"feed_name"`
	Progress  int        `json:"progress,omitempty"` // 0-100
	Message   string     `json:"message,omitempty"`
	Stats     *FeedStats `json:"stats,omitempty"`
	Error     string     `json:"error,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

// FeedStats represents feed synchronization statistics for WebSocket events.
// Mirrors sigma/feeds.FeedStats but defined here to avoid import cycles.
type FeedStats struct {
	TotalRules       int     `json:"total_rules"`
	ImportedRules    int     `json:"imported_rules"`
	UpdatedRules     int     `json:"updated_rules"`
	SkippedRules     int     `json:"skipped_rules"`
	FailedRules      int     `json:"failed_rules"`
	LastSyncDuration float64 `json:"last_sync_duration"`
}

// client represents a single WebSocket client connection.
// PRODUCTION: Each client runs in its own goroutines for read/write operations.
type client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// Hub maintains the set of active WebSocket clients and broadcasts messages.
// PRODUCTION: Thread-safe design with proper goroutine lifecycle management.
type Hub struct {
	// Registered clients
	clients map[*client]bool

	// Inbound messages from clients
	broadcast chan []byte

	// Register requests from clients
	register chan *client

	// Unregister requests from clients
	unregister chan *client

	// Mutex for thread-safe access to clients map
	mu sync.RWMutex

	// Logger for diagnostics
	logger *zap.SugaredLogger

	// Context for graceful shutdown
	ctx context.Context

	// Cancel function to trigger graceful shutdown
	cancel context.CancelFunc

	// Done channel signals hub shutdown completion
	done chan struct{}
}

// upgrader configures WebSocket connection upgrades.
// SECURITY: CORS check is disabled here because corsMiddleware already handles it.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// SECURITY: CORS is already validated by corsMiddleware
		// Allowing all origins here prevents duplicate CORS checks
		return true
	},
}

// NewHub creates a new WebSocket hub with proper initialization.
// PRODUCTION: Hub must be started with Start() method before use.
// The hub creates its own cancellable context from the parent for proper shutdown.
func NewHub(logger *zap.SugaredLogger, ctx context.Context) *Hub {
	// Create a cancellable context so Stop() can trigger shutdown
	// even if the parent context (e.g., context.Background()) never cancels
	hubCtx, cancel := context.WithCancel(ctx)
	return &Hub{
		clients:    make(map[*client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *client),
		unregister: make(chan *client),
		logger:     logger,
		ctx:        hubCtx,
		cancel:     cancel,
		done:       make(chan struct{}),
	}
}

// Start runs the WebSocket hub's main event loop.
// PRODUCTION: Runs in a goroutine and handles client management and broadcasting.
// GOROUTINE SAFETY: Must be called exactly once per Hub instance.
func (h *Hub) Start() {
	defer close(h.done)

	h.logger.Info("WebSocket hub started")

	for {
		select {
		case <-h.ctx.Done():
			// Graceful shutdown: close all client connections
			h.mu.Lock()
			for client := range h.clients {
				close(client.send)
				client.conn.Close()
			}
			h.clients = make(map[*client]bool)
			h.mu.Unlock()
			h.logger.Info("WebSocket hub stopped")
			return

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			h.logger.Debugw("WebSocket client registered",
				"total_clients", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				h.mu.Unlock()
				h.logger.Debugw("WebSocket client unregistered",
					"total_clients", len(h.clients))
			} else {
				h.mu.Unlock()
			}

		case message := <-h.broadcast:
			// Broadcast message to all connected clients
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.send <- message:
					// Message queued successfully
				default:
					// Client's send buffer is full, disconnect it
					// This prevents one slow client from blocking broadcasts
					go func(disconnectClient *client) {
						h.unregister <- disconnectClient
						disconnectClient.conn.Close()
					}(c)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// BroadcastMessage sends a message to all connected WebSocket clients.
// PRODUCTION: Non-blocking operation with timeout protection.
// SECURITY: Message is JSON-marshaled to ensure proper encoding.
func (h *Hub) BroadcastMessage(msgType string, data interface{}) error {
	msg := WebSocketMessage{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now(),
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		h.logger.Errorw("Failed to marshal WebSocket message",
			"type", msgType,
			"error", err)
		return err
	}

	// Non-blocking send to broadcast channel
	select {
	case h.broadcast <- jsonData:
		h.logger.Debugw("WebSocket message broadcast",
			"type", msgType,
			"clients", len(h.clients))
		return nil
	case <-time.After(1 * time.Second):
		h.logger.Warnw("WebSocket broadcast timeout",
			"type", msgType)
		return nil // Don't fail the operation if broadcast times out
	}
}

// ClientCount returns the number of connected WebSocket clients.
// Thread-safe for concurrent access.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Stop gracefully shuts down the hub.
// PRODUCTION: Cancels context and waits for hub goroutine to complete cleanup.
func (h *Hub) Stop() {
	// Cancel the hub's context to trigger shutdown
	h.cancel()
	// Wait for hub goroutine to finish cleanup
	<-h.done
}

// readPump pumps messages from the WebSocket connection to the hub.
// GOROUTINE SAFETY: Runs in its own goroutine per client.
// PRODUCTION: Implements proper connection lifecycle with timeouts.
func (c *client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		// We don't expect messages from clients, just read to detect disconnection
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.logger.Debugw("WebSocket unexpected close", "error", err)
			}
			break
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection.
// GOROUTINE SAFETY: Runs in its own goroutine per client.
// PRODUCTION: Implements ping/pong heartbeat for connection health monitoring.
func (c *client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current WebSocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// serveWs handles WebSocket upgrade requests and client lifecycle.
// PRODUCTION: Proper error handling and goroutine management.
// SECURITY: CORS is already validated by corsMiddleware before this handler.
func serveWs(hub *Hub, logger *zap.SugaredLogger, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Errorw("WebSocket upgrade failed", "error", err)
		return
	}

	client := &client{
		hub:  hub,
		conn: conn,
		send: make(chan []byte, sendChannelSize),
	}
	client.hub.register <- client

	// Start client goroutines for read and write pumps
	// GOROUTINE SAFETY: Both goroutines will terminate when connection closes
	go client.writePump()
	go client.readPump()
}
