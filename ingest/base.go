package ingest

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// BaseListener provides common functionality for listeners
type BaseListener struct {
	host        string
	port        int
	limiter     *rate.Limiter
	eventCh     chan<- *core.Event
	stopCh      chan struct{}
	wg          sync.WaitGroup
	logger      *zap.SugaredLogger
	udpConn     net.PacketConn
	tcpListener net.Listener
}

// NewBaseListener creates a new base listener
func NewBaseListener(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger) *BaseListener {
	return &BaseListener{
		host:    host,
		port:    port,
		limiter: rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
		eventCh: eventCh,
		stopCh:  make(chan struct{}),
		logger:  logger,
	}
}

// processEvent processes a raw event string, parses it, and sends it to the event channel
func (b *BaseListener) processEvent(raw string, sourceIP string, parseFunc func(string) (*core.Event, error), name string) {
	if !b.limiter.Allow() {
		b.logger.Warnf("Rate limit exceeded for %s", name)
		return
	}
	event, err := parseFunc(raw)
	if err != nil {
		b.logger.Errorf("Failed to parse %s: %v", name, err)
		return
	}
	event.SourceIP = sourceIP
	select {
	case b.eventCh <- event:
	default:
		b.logger.Warnf("Event channel full, dropping %s event", name)
	}
}

// StartUDP starts a UDP listener with the given parse function
func (b *BaseListener) StartUDP(parseFunc func(string) (*core.Event, error), name string) {
	addr := fmt.Sprintf("%s:%d", b.host, b.port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		b.logger.Errorf("Failed to start %s UDP listener: %v", name, err)
		return
	}
	b.udpConn = conn
	b.logger.Infof("%s UDP listener started on %s", name, addr)
	b.wg.Add(1)
	defer b.wg.Done()

	buffer := make([]byte, 65536)
	for {
		select {
		case <-b.stopCh:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			b.logger.Errorf("%s UDP read error: %v", name, err)
			continue
		}
		raw := strings.TrimSpace(string(buffer[:n]))
		if raw == "" {
			continue
		}
		b.processEvent(raw, addr.String(), parseFunc, name+" UDP")
	}
}

// StartTCP starts a TCP listener with the given parse function
func (b *BaseListener) StartTCP(parseFunc func(string) (*core.Event, error), name string) {
	addr := fmt.Sprintf("%s:%d", b.host, b.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		b.logger.Errorf("Failed to start %s TCP listener: %v", name, err)
		return
	}
	b.tcpListener = listener
	b.logger.Infof("%s TCP listener started on %s", name, addr)
	b.wg.Add(1)
	defer b.wg.Done()

	for {
		select {
		case <-b.stopCh:
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			b.logger.Errorf("%s TCP accept error: %v", name, err)
			continue
		}
		b.wg.Add(1)
		go b.handleTCPConnection(conn, parseFunc, name)
	}
}

func (b *BaseListener) handleTCPConnection(conn net.Conn, parseFunc func(string) (*core.Event, error), name string) {
	defer conn.Close()
	defer b.wg.Done()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		b.processEvent(line, conn.RemoteAddr().String(), parseFunc, name+" TCP")
	}
	if err := scanner.Err(); err != nil {
		b.logger.Errorf("%s scanner error: %v", name, err)
	}
}

// Stop stops the listener
func (b *BaseListener) Stop() {
	close(b.stopCh)
	if b.udpConn != nil {
		b.udpConn.Close()
	}
	if b.tcpListener != nil {
		b.tcpListener.Close()
	}
	b.wg.Wait()
}
