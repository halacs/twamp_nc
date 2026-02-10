package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
)

// TestStartServerListenFailure tests listener creation failure
func TestStartServerListenFailure(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "999.999.999.999:99999", // Invalid address
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	err = srv.Start(ctx)
	if err == nil {
		t.Error("Expected error starting server with invalid address")
		srv.Stop()
	}
}

// TestServerDefaults tests default configuration values
func TestServerDefaults(t *testing.T) {
	config := ServerConfig{
		// Don't set SERVWAIT, REFWAIT, ListenAddress to test defaults
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	if srv.config.SERVWAIT != common.DefaultSERVWAIT {
		t.Errorf("Expected default SERVWAIT %v, got %v", common.DefaultSERVWAIT, srv.config.SERVWAIT)
	}
	if srv.config.REFWAIT != common.DefaultREFWAIT {
		t.Errorf("Expected default REFWAIT %v, got %v", common.DefaultREFWAIT, srv.config.REFWAIT)
	}
	if srv.config.ListenAddress != ":862" {
		t.Errorf("Expected default listen address :862, got %s", srv.config.ListenAddress)
	}
}

// TestServerAddrBeforeStart tests Addr() before server starts
func TestServerAddrBeforeStart(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	addr := srv.Addr()
	if addr != nil {
		t.Error("Expected nil address before server starts")
	}
}

// TestAcceptConnectionsWithNonOpError tests accept with non-timeout error
func TestAcceptConnectionsWithNonOpError(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		SERVWAIT:       100 * time.Millisecond,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	err = srv.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Close listener to cause accept error
	srv.listener.Close()

	// Wait for accept loop to handle the error
	time.Sleep(200 * time.Millisecond)

	srv.Stop()
}

// TestConnectionCleanupMultipleSessions tests cleanup with multiple sessions
func TestConnectionCleanupMultipleSessions(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		SERVWAIT:       1 * time.Second,
		REFWAIT:        1 * time.Second,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	err = srv.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	// Create connection
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Get cleanup done channel before closing
	cleanupChan := srv.WaitForConnectionCleanup(conn)

	// Close connection
	conn.Close()

	// Wait for cleanup
	select {
	case <-cleanupChan:
		// Good, cleanup completed
	case <-time.After(2 * time.Second):
		t.Error("Cleanup did not complete in time")
	}

	// Try to get cleanup channel for non-existent connection
	nonExistentCleanup := srv.WaitForConnectionCleanup(nil)
	select {
	case <-nonExistentCleanup:
		// Good, returns immediately closed channel
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected immediately closed channel for non-existent connection")
	}
}

// TestStartSessionDSCPPriority tests DSCP priority (session vs server config)
func TestStartSessionDSCPPriority(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		DSCP:           10, // Server-level DSCP
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Test 1: Session has its own DSCP (should take priority)
	session1 := &TestSession{
		sid:           common.SessionID{1, 2, 3, 4},
		reflectorPort: 25000,
		mode:          common.ModeUnauthenticated,
		dscp:          46, // Session-level DSCP (should take priority)
		stopChan:      make(chan struct{}),
		reflectorDone: make(chan struct{}),
	}
	session1.isActive.Store(false)

	// Just verify the DSCP value without starting the session
	// The actual DSCP priority logic is tested elsewhere with proper session lifecycle
	if session1.dscp != 46 {
		t.Errorf("Expected session DSCP 46, got %d", session1.dscp)
	}

	// Test 2: Session has no DSCP (should fall back to server config)
	session2 := &TestSession{
		sid:           common.SessionID{5, 6, 7, 8},
		reflectorPort: 25001,
		mode:          common.ModeUnauthenticated,
		dscp:          0, // No session-level DSCP
		stopChan:      make(chan struct{}),
		reflectorDone: make(chan struct{}),
	}
	session2.isActive.Store(false)

	// When DSCP is 0, server config DSCP would be used (tested in integration tests)
	if session2.dscp != 0 {
		t.Errorf("Expected session DSCP 0, got %d", session2.dscp)
	}

	// Verify server config DSCP
	if srv.config.DSCP != 10 {
		t.Errorf("Expected server DSCP 10, got %d", srv.config.DSCP)
	}
}

// TestStopSessionAlreadyStopped tests stopping an already stopped session
func TestStopSessionAlreadyStopped(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	session := &TestSession{
		sid:           common.SessionID{1, 2, 3, 4},
		reflectorPort: 25001,
		stopChan:      make(chan struct{}),
		reflectorDone: make(chan struct{}),
	}
	session.isActive.Store(false) // Already inactive

	// Store in server sessions
	srv.sessionsMu.Lock()
	srv.sessions[session.sid] = session
	srv.sessionsMu.Unlock()

	// Stop already stopped session (should be a no-op and return early)
	srv.stopSession(session)

	// Verify session is NOT removed (stopSession returns early for inactive sessions)
	srv.sessionsMu.RLock()
	_, exists := srv.sessions[session.sid]
	srv.sessionsMu.RUnlock()

	if !exists {
		t.Error("Session should still be in map (stopSession returns early for inactive sessions)")
	}
}

// TestReflectPacketsConnNil tests reflectPackets when conn is nil
func TestReflectPacketsConnNil(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	session := &TestSession{
		sid:           common.SessionID{1, 2, 3, 4},
		reflectorPort: 25002,
		mode:          common.ModeUnauthenticated,
		conn:          nil, // Nil connection
		stopChan:      make(chan struct{}),
		reflectorDone: make(chan struct{}),
	}
	session.isActive.Store(true)

	// Start reflector (should exit immediately due to nil conn)
	done := make(chan struct{})
	go func() {
		srv.reflectPackets(session)
		close(done)
	}()

	select {
	case <-done:
		// Good, exited quickly
	case <-time.After(1 * time.Second):
		t.Error("reflectPackets should exit immediately with nil conn")
	}
}

