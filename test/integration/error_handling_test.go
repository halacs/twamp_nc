// Package integration provides comprehensive integration tests for the TWAMP protocol implementation.
// This file tests error conditions, context cancellation, connection interruption, and cleanup paths.
package integration

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/client"
	"github.com/ncode/twamp/common"
	"github.com/stretchr/testify/require"
)

// TestConnectionInterruptionDuringHandshake tests client behavior when connection is lost during handshake
func TestConnectionInterruptionDuringHandshake(t *testing.T) {
	// Create a listener that will close immediately after accepting
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Accept and immediately close the connection
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close() // Close before sending greeting
	}()

	// Try to connect - should fail during receiveServerGreeting
	cfg := client.ClientConfig{
		ServerAddress: serverAddr,
		PreferredMode: common.ModeUnauthenticated,
	}

	twampClient := client.NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = twampClient.Connect(ctx)
	require.Error(t, err, "Connect should fail when server closes connection during handshake")
	require.ErrorIs(t, err, client.ErrServerGreeting)
}

// TestMalformedServerGreeting tests client behavior when server sends invalid greeting
func TestMalformedServerGreeting(t *testing.T) {
	// Create a listener that sends invalid data
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Send invalid greeting data
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send truncated greeting (less than 64 bytes)
		invalidGreeting := make([]byte, 30)
		conn.Write(invalidGreeting)
	}()

	// Try to connect - should fail during greeting unmarshal
	cfg := client.ClientConfig{
		ServerAddress: serverAddr,
		PreferredMode: common.ModeUnauthenticated,
	}

	twampClient := client.NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = twampClient.Connect(ctx)
	require.Error(t, err, "Connect should fail when server sends malformed greeting")
	require.ErrorIs(t, err, client.ErrServerGreeting)
}

// TestServerNoSupportedModes tests client behavior when server supports no modes
func TestServerNoSupportedModes(t *testing.T) {
	// Create a listener that sends greeting with Modes=0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Send greeting with no supported modes
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Create valid 64-byte greeting but with Modes=0
		greeting := make([]byte, 64)
		// Modes field is bytes 12-15, all zeros = no modes
		conn.Write(greeting)
	}()

	// Try to connect - should fail with ErrServerNoModes
	cfg := client.ClientConfig{
		ServerAddress: serverAddr,
		PreferredMode: common.ModeUnauthenticated,
	}

	twampClient := client.NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = twampClient.Connect(ctx)
	require.Error(t, err, "Connect should fail when server supports no modes")
	require.ErrorIs(t, err, common.ErrServerNoModes)
}

// TestContextCancellationDuringSession tests session behavior when context is cancelled
func TestContextCancellationDuringSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Get free ports for session
	ports := testutil.GetFreePorts(t, "udp", 2)

	// Request a session
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	// Start the session
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Create a context that will be cancelled
	sessionCtx, sessionCancel := context.WithCancel(ctx)

	// Start sending packets with proper goroutine tracking
	var senderWg sync.WaitGroup
	senderWg.Add(1)
	go func() {
		defer senderWg.Done()
		for i := 0; i < 10; i++ {
			select {
			case <-sessionCtx.Done():
				return
			default:
				if err := session.SendTestPacket(); err != nil {
					// Errors expected during cancellation, just log them
					t.Logf("SendTestPacket failed (expected during cancellation): %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Start receiving with the cancellable context
	session.StartReceiving(sessionCtx)

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	// Cancel the context - this should trigger ctx.Done() in StartReceiving
	sessionCancel()

	// Wait for sender goroutine to exit (with timeout)
	done := make(chan struct{})
	go func() {
		senderWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// Success - goroutine exited cleanly
	case <-time.After(1 * time.Second):
		t.Fatal("Sender goroutine did not exit after context cancellation")
	}

	// Session should still be stoppable
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions after context cancellation")
}

// TestSessionStopBeforeStart tests stopping a session before it's started
func TestSessionStopBeforeStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Get free ports for session
	ports := testutil.GetFreePorts(t, "udp", 2)

	// Request a session
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	// Try to stop the session before starting it
	// This tests the early return path in session lifecycle
	session.Stop()

	// Should still be able to start sessions normally
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestSessionDoubleStop tests stopping a session twice
func TestSessionDoubleStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Get free ports for session
	ports := testutil.GetFreePorts(t, "udp", 2)

	// Request a session
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Start receiving
	session.StartReceiving(ctx)
	time.Sleep(100 * time.Millisecond)

	// Stop once
	session.Stop()

	// Stop again - should be safe (idempotent)
	session.Stop()

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestRapidSessionStartStop tests rapid session start/stop cycles
func TestRapidSessionStartStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Test rapid start/stop cycles by requesting new sessions each time
	for i := 0; i < 3; i++ {
		// Get free ports for this session
		ports := testutil.GetFreePorts(t, "udp", 2)

		// Request a session
		sessionConfig := client.TestSessionConfig{
			SenderPort:   uint16(ports[0]),
			ReceiverPort: uint16(ports[1]),
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session on iteration %d", i)

		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions on iteration %d", i)

		session.StartReceiving(ctx)
		time.Sleep(50 * time.Millisecond)

		session.Stop()

		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions on iteration %d", i)

		time.Sleep(50 * time.Millisecond)
	}
}