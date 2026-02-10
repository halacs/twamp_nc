//go:build integration

package client

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/server"
)

const (
	// Server startup wait: Time for server to bind and start accepting connections
	serverStartupWait = 100 * time.Millisecond

	// Session propagation wait: Time for session state changes to propagate
	sessionPropagationWait = 50 * time.Millisecond

	// Test timeout: Maximum total time for entire test (prevents hanging on failures)
	testTimeout = 10 * time.Second

	// Server shutdown timeout: Maximum time to wait for graceful server shutdown
	serverShutdownTimeout = 2 * time.Second
)

// TestRFC5938RequestSessionIndividual tests RequestSessionIndividual in a real client-server setup
func TestRFC5938RequestSessionIndividual(t *testing.T) {
	// Use timeout context to prevent test from hanging indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Get free ports
	ports := testutil.GetFreePorts(t, "tcp", 1)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", ports[0])

	// Create and start server
	srv := server.NewServerWithLogger(server.Config{
		ListenAddress:  serverAddr,
		SupportedModes: common.ModeUnauthenticated,
	}, logging.NewNoop())

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start(ctx)
	}()

	// Wait for server to start accepting connections
	time.Sleep(serverStartupWait)

	// Create client
	c := NewClientWithLogger(ClientConfig{
		ServerAddress:  serverAddr,
		RequestedModes: common.ModeUnauthenticated,
	}, logging.NewNoop())

	// Connect to server
	err := c.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	// Test RequestSessionIndividual with specific SID (RFC 5938 Section 3.1)
	customSID := common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sessionConfig := TestSessionConfig{
		SenderPort:      testutil.GetFreePorts(t, "udp", 1)[0],
		ReceiverPort:    testutil.GetFreePorts(t, "udp", 1)[0],
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   100,
		Timeout:         time.Second,
	}

	session, err := c.RequestSessionIndividual(sessionConfig, customSID)
	if err != nil {
		t.Fatalf("Failed to request individual session: %v", err)
	}

	if session == nil {
		t.Fatal("Session is nil")
	}

	// Start the specific session using StartSession
	// Note: RFC 5938 sessions still use regular Start-Sessions command
	err = c.StartSession(customSID)
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Allow time for session state to propagate
	time.Sleep(sessionPropagationWait)

	// Test StopNSessions (RFC 5938 Section 3.4)
	err = c.StopNSessions(1)
	if err != nil {
		t.Fatalf("Failed to stop N sessions: %v", err)
	}

	// Cleanup: cancel context to signal server shutdown
	cancel()

	// Wait for server to shut down gracefully
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(serverShutdownTimeout):
		t.Error("Server did not shut down in time")
	}
}

// TestRFC5938MultipleIndividualSessions tests multiple individually created sessions
func TestRFC5938MultipleIndividualSessions(t *testing.T) {
	// Use timeout context to prevent test from hanging indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Get free ports
	ports := testutil.GetFreePorts(t, "tcp", 1)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", ports[0])

	// Create and start server
	srv := server.NewServerWithLogger(server.Config{
		ListenAddress:  serverAddr,
		SupportedModes: common.ModeUnauthenticated,
	}, logging.NewNoop())

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start(ctx)
	}()

	// Wait for server to start accepting connections
	time.Sleep(serverStartupWait)

	// Create client
	c := NewClientWithLogger(ClientConfig{
		ServerAddress:  serverAddr,
		RequestedModes: common.ModeUnauthenticated,
	}, logging.NewNoop())

	// Connect to server
	err := c.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	// Create multiple individual sessions with custom SIDs
	numSessions := 3
	udpPorts := testutil.GetFreePorts(t, "udp", numSessions*2)
	sids := make([]common.SessionID, numSessions)

	for i := 0; i < numSessions; i++ {
		// Each session gets a unique SID
		sids[i] = common.SessionID{byte(i + 1), 0, 0, 0}
		sessionConfig := TestSessionConfig{
			SenderPort:      udpPorts[i*2],
			ReceiverPort:    udpPorts[i*2+1],
			ReceiverAddress: "127.0.0.1",
			PaddingLength:   100,
			Timeout:         time.Second,
		}

		session, err := c.RequestSessionIndividual(sessionConfig, sids[i])
		if err != nil {
			t.Fatalf("Failed to request individual session %d: %v", i, err)
		}

		if session == nil {
			t.Fatalf("Session %d is nil", i)
		}
	}

	// Start all sessions using regular Start-Sessions command
	err = c.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify all sessions were created
	sessionIDs := c.GetSessionIDs()
	if len(sessionIDs) != numSessions {
		t.Errorf("Expected %d sessions, got %d", numSessions, len(sessionIDs))
	}

	// Stop 2 sessions using StopNSessions (RFC 5938 Section 3.4)
	err = c.StopNSessions(2)
	if err != nil {
		t.Fatalf("Failed to stop N sessions: %v", err)
	}

	// Allow time for session state changes to propagate
	time.Sleep(sessionPropagationWait)

	// Verify only 1 session remains
	remainingSessions := c.GetSessionIDs()
	if len(remainingSessions) != 1 {
		t.Errorf("Expected 1 remaining session after StopNSessions, got %d", len(remainingSessions))
	}

	// Stop remaining session individually
	err = c.StopSession(remainingSessions[0])
	if err != nil {
		t.Fatalf("Failed to stop remaining session: %v", err)
	}

	// Cleanup: cancel context to signal server shutdown
	cancel()

	// Wait for server to shut down gracefully
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(serverShutdownTimeout):
		t.Error("Server did not shut down in time")
	}
}
