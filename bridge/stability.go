package main

// Stability helpers (2026-11-19):
//  - an ordered worker queue so DB work for incoming messages/receipts does not block whatsmeow's node loop
//  - connection-state tracking + logging for disconnect/ban/replaced/connect-failure events
//  - a supervisor that reconnects when whatsmeow gave up (ConnectFailure without auto-reconnect)
//  - an HTTP server with timeouts, bound before connecting so a second bridge instance exits at once

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// ---------- ordered event worker ----------

// eventQueue runs persistence work for events one at a time, in arrival order (edits/receipts must be applied
// after the message they refer to). When full, enqueue blocks, which is the same back-pressure as before.
type eventQueue struct {
	ch   chan func()
	done chan struct{}
	once sync.Once
}

func newEventQueue(size int) *eventQueue {
	q := &eventQueue{ch: make(chan func(), size), done: make(chan struct{})}
	go func() {
		defer close(q.done)
		for fn := range q.ch {
			runSafely("event worker", fn)
		}
	}()
	return q
}

func (q *eventQueue) enqueue(fn func()) {
	defer func() {
		// queue already closed (shutting down): run inline instead of losing the event
		if recover() != nil {
			runSafely("event (inline)", fn)
		}
	}()
	q.ch <- fn
}

// drain stops accepting work and waits (up to timeout) for queued work to finish.
func (q *eventQueue) drain(timeout time.Duration) bool {
	q.once.Do(func() { close(q.ch) })
	select {
	case <-q.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// flush waits (up to timeout) until everything queued so far has run, without closing the queue.
func (q *eventQueue) flush(timeout time.Duration) bool {
	done := make(chan struct{})
	go q.enqueue(func() { close(done) })
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// runSafely runs fn and turns a panic into a log line (a panic in our own goroutines would kill the process).
func runSafely(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[stability] panic in %s: %v\n%s\n", what, r, debug.Stack())
		}
	}()
	fn()
}

// ---------- connection state ----------

var (
	connMu        sync.Mutex
	connState     = "starting"
	connReason    = ""
	connChangedAt = time.Now()
	retryAfter    time.Time // supervisor: earliest time for a manual reconnect (zero = no manual reconnect wanted)
	noReconnect   bool      // stream replaced / logged out / outdated: reconnecting would not help
)

func setConnState(state, reason string) {
	connMu.Lock()
	connState, connReason, connChangedAt = state, reason, time.Now()
	connMu.Unlock()
}

func connStatus() (string, string, time.Time) {
	connMu.Lock()
	defer connMu.Unlock()
	return connState, connReason, connChangedAt
}

// handleConnectionEvent logs connection lifecycle events. Returns true when the event was one of them.
func handleConnectionEvent(evt interface{}, logger waLog.Logger) bool {
	switch v := evt.(type) {
	case *events.Connected:
		logger.Infof("Connected to WhatsApp")
		connMu.Lock()
		retryAfter, noReconnect = time.Time{}, false
		connMu.Unlock()
		setConnState("connected", "")
	case *events.Disconnected:
		logger.Warnf("Disconnected from WhatsApp (auto-reconnect will retry)")
		setConnState("disconnected", "socket closed")
	case *events.KeepAliveTimeout:
		logger.Warnf("Keepalive timeout (%d errors, last success %s ago)", v.ErrorCount, time.Since(v.LastSuccess).Round(time.Second))
	case *events.KeepAliveRestored:
		logger.Infof("Keepalive restored")
	case *events.StreamReplaced:
		// another client logged in with the same session (usually a second bridge instance). Do not fight it.
		logger.Errorf("Stream replaced: another client is using this WhatsApp session; not reconnecting")
		connMu.Lock()
		noReconnect = true
		connMu.Unlock()
		setConnState("replaced", "stream replaced by another client")
	case *events.TemporaryBan:
		logger.Errorf("Temporary ban from WhatsApp: %s", v.String())
		connMu.Lock()
		retryAfter = time.Now().Add(v.Expire + time.Minute)
		connMu.Unlock()
		setConnState("banned", v.String())
	case *events.ClientOutdated:
		logger.Errorf("WhatsApp says this client version is outdated: update whatsmeow (go get -u go.mau.fi/whatsmeow) and rebuild")
		connMu.Lock()
		noReconnect = true
		connMu.Unlock()
		setConnState("outdated", "client outdated")
	case *events.ConnectFailure:
		logger.Errorf("Connect failure: reason=%d (%s) message=%q", int(v.Reason), v.Reason.String(), v.Message)
		connMu.Lock()
		if retryAfter.IsZero() {
			retryAfter = time.Now().Add(time.Minute)
		}
		connMu.Unlock()
		setConnState("failed", fmt.Sprintf("connect failure %d %s", int(v.Reason), v.Message))
	case *events.StreamError:
		logger.Warnf("Stream error code=%s", v.Code)
	case *events.CATRefreshError:
		logger.Errorf("CAT refresh error: %v", v.Error)
		connMu.Lock()
		if retryAfter.IsZero() {
			retryAfter = time.Now().Add(time.Minute)
		}
		connMu.Unlock()
		setConnState("failed", "CAT refresh error")
	default:
		return false
	}
	return true
}

// superviseConnection reconnects when whatsmeow stopped trying by itself (connect failures without auto-reconnect,
// or a temporary ban that expired). Backoff doubles up to 15 minutes. Never acts after stream-replaced/outdated.
func superviseConnection(client *whatsmeow.Client, logger waLog.Logger) {
	backoff := time.Minute
	for range time.Tick(30 * time.Second) {
		connMu.Lock()
		due := !retryAfter.IsZero() && time.Now().After(retryAfter) && !noReconnect
		connMu.Unlock()
		if !due || client.Store.ID == nil || pairingActive() {
			continue
		}
		if client.IsConnected() {
			connMu.Lock()
			retryAfter = time.Time{}
			connMu.Unlock()
			backoff = time.Minute
			continue
		}
		logger.Warnf("Supervisor: not connected and no automatic reconnect pending, trying to connect...")
		err := client.Connect()
		connMu.Lock()
		if err != nil && err != whatsmeow.ErrAlreadyConnected {
			logger.Errorf("Supervisor: reconnect failed: %v (next try in %s)", err, backoff)
			retryAfter = time.Now().Add(backoff)
			if backoff < 15*time.Minute {
				backoff *= 2
			}
		} else {
			retryAfter = time.Now().Add(2 * time.Minute) // check again; cleared on Connected
		}
		connMu.Unlock()
	}
}

// connectWithRetry is used at startup for an already-paired device: the network may not be up yet right after boot.
func connectWithRetry(client *whatsmeow.Client, logger waLog.Logger) {
	wait := 5 * time.Second
	for {
		if client.Store.ID == nil || pairingActive() {
			return // unpaired device: never Connect here (pairing is on demand)
		}
		err := client.Connect()
		if err == nil || err == whatsmeow.ErrAlreadyConnected {
			return
		}
		logger.Errorf("Failed to connect: %v (retrying in %s)", err, wait)
		time.Sleep(wait)
		if wait < 2*time.Minute {
			wait *= 2
		}
	}
}

// ---------- HTTP server ----------

var apiServer *http.Server

// listenAPI binds the REST port. If it is taken, another bridge is already running: exit before touching WhatsApp,
// otherwise both would connect with the same session and kick each other off (stream replaced).
func listenAPI(port int) net.Listener {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("REST API port %s unavailable (%v): another bridge is probably running. Exiting.\n", addr, err)
		os.Exit(5)
	}
	return ln
}

func serveAPI(ln net.Listener, handler http.Handler, onFatal func()) {
	apiServer = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// no WriteTimeout: /api/send and /api/download can legitimately take minutes (uploads, media retry)
	}
	go func() {
		err := apiServer.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("REST API server error: %v\n", err)
			onFatal()
		}
	}()
}

func shutdownAPI(timeout time.Duration) {
	if apiServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = apiServer.Shutdown(ctx)
}
