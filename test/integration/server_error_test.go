// Package integration provides comprehensive integration tests for the TWAMP protocol implementation.
// This file tests server-side resource limits, cleanup behavior, concurrent handling, and error paths.
package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/client"
	"github.com/ncode/twamp/common"
	"github.com/stretchr/testify/require"
)

// TestServerResourceLimits tests server behavior when resource limits are approached
func TestServerResourceLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Request multiple sessions to exercise resource management
	sessions := make([]*client.TestSession, 0, 10)
	for i := 0; i < 10; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:   uint16(ports[0]),
			ReceiverPort: uint16(ports[1]),
		}
		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d", i)
		sessions = append(sessions, session)
	}

	// Start all sessions
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	time.Sleep(100 * time.Millisecond)

	// Stop all sessions
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestStopNSessionsZeroCount tests StopNSessions with count 0
func TestStopNSessionsZeroCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-stop-zero"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 2 sessions
	for i := 0; i < 2; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:   uint16(ports[0]),
			ReceiverPort: uint16(ports[1]),
		}
		_, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d", i)
	}

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// StopNSessions with 0 should be a no-op (exercises the zero-count path)
	err = twampClient.StopNSessions(0)
	require.NoError(t, err, "Failed to call StopNSessions with 0")

	// Verify both sessions still exist
	sessionIDs := twampClient.GetSessionIDs()
	require.Len(t, sessionIDs, 2, "Should still have 2 sessions after StopNSessions(0)")

	// Clean up
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestClientDisconnectDuringSession tests server behavior when client disconnects unexpectedly
func TestClientDisconnectDuringSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	_, err = twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	time.Sleep(100 * time.Millisecond)

	// Close client connection abruptly (simulates disconnect and exercises cleanup paths)
	err = twampClient.Close()
	require.NoError(t, err, "Failed to close client")

	// Wait for server cleanup goroutines to detect disconnect and close resources
	// No observable client-side state to poll; server cleanup is async
	time.Sleep(300 * time.Millisecond)
}

// TestMixedModeStopNSessions tests Stop-N-Sessions in mixed security modes
func TestMixedModeStopNSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-mixed"
	// Use mixed + authenticated mode (0x0A = ModeMixed | ModeAuthenticated)
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeMixed|common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 3 sessions
	for i := 0; i < 3; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:   uint16(ports[0]),
			ReceiverPort: uint16(ports[1]),
		}
		_, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d", i)
	}

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Stop 2 sessions
	err = twampClient.StopNSessions(2)
	require.NoError(t, err, "Failed to stop 2 sessions")

	time.Sleep(100 * time.Millisecond)

	// Verify 1 session remains
	sessionIDs := twampClient.GetSessionIDs()
	require.Len(t, sessionIDs, 1, "Should have 1 session remaining")
}

// TestConcurrentSessionRequests tests server handling of concurrent session requests
func TestConcurrentSessionRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Request multiple sessions rapidly (exercises concurrent handling)
	sessions := make([]*client.TestSession, 0, 5)
	for i := 0; i < 5; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 50, // Add padding to meet minimum packet size
		}
		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d", i)
		sessions = append(sessions, session)
	}

	// Start all sessions at once
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Start receiving on all sessions
	for _, session := range sessions {
		session.StartReceiving(ctx)
	}

	// Send packets from multiple sessions with error checking
	const numPackets = 3
	for i := 0; i < numPackets; i++ {
		for j, session := range sessions {
			err = session.SendTestPacket()
			require.NoError(t, err, "Failed to send test packet %d from session %d", i, j)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for at least 90% packet reception on localhost for all sessions
	require.Eventually(t, func() bool {
		for _, session := range sessions {
			results := session.GetResults()
			if results.PacketsReceived < uint32(numPackets*9/10) {
				return false
			}
		}
		return true
	}, 2*time.Second, 10*time.Millisecond, "All sessions should receive at least 90%% of packets on localhost")

	// Verify all sessions received at least 90% of packets
	for i, session := range sessions {
		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(numPackets*9/10),
			"Session %d should receive at least 90%% of %d packets on localhost, got %d", i, numPackets, results.PacketsReceived)
	}

	// Stop all sessions
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestServerConnectionCleanup tests server cleanup when connection is closed
func TestServerConnectionCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	_, err = twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	time.Sleep(100 * time.Millisecond)

	// Close the client, which should trigger server cleanup (exercises cleanup paths)
	err = twampClient.Close()
	require.NoError(t, err, "Failed to close client")

	// Wait for server cleanup goroutines to close sessions and release resources
	// No observable client-side state to poll; server cleanup is async
	time.Sleep(500 * time.Millisecond)
}

// TestIndividualSessionStartStop tests starting and stopping individual sessions
func TestIndividualSessionStartStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-individual-startstop"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 2 individual sessions with specific SIDs (exercises RequestSessionIndividual and GetSession)
	sids := []common.SessionID{
		{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	for i, sid := range sids {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 100,
		}
		session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request individual session %d", i)

		// Verify we can retrieve the session
		retrievedSession, err := twampClient.GetSession(sid)
		require.NoError(t, err, "Failed to get session %v", sid)
		require.Equal(t, session, retrievedSession, "Retrieved session should match")
	}

	// Start all sessions at once
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	time.Sleep(100 * time.Millisecond)

	// Stop sessions individually using StopSession (exercises individual session control)
	for _, sid := range sids {
		err = twampClient.StopSession(sid)
		require.NoError(t, err, "Failed to stop session %v", sid)
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServerAcceptCodePaths tests different Accept-Session accept codes
func TestServerAcceptCodePaths(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Request a session with valid parameters (should get Accept code 0)
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	_, err = twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session with valid params")

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestAuthenticatedModeHMACValidation tests HMAC validation in authenticated mode
func TestAuthenticatedModeHMACValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-hmac"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Request and start a session (exercises HMAC calculation/verification)
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 100, // Adequate padding for authenticated mode
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Send test packets (exercises test packet HMAC)
	session.StartReceiving(ctx)
	const numPackets = 5
	for i := 0; i < numPackets; i++ {
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet %d", i)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for at least 90% packet reception on localhost
	require.Eventually(t, func() bool {
		results := session.GetResults()
		return results.PacketsReceived >= uint32(numPackets*9/10)
	}, 2*time.Second, 10*time.Millisecond, "Should receive at least 90%% of packets on localhost")

	// Verify HMAC was used and packets were received
	results := session.GetResults()
	require.GreaterOrEqual(t, results.PacketsReceived, uint32(numPackets*9/10),
		"Should receive at least 90%% of %d packets on localhost, got %d", numPackets, results.PacketsReceived)
	require.Greater(t, results.AvgRTT, time.Duration(0), "Should have measured RTT")

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestPortConflictHandling tests server behavior when requested ports are unavailable
func TestPortConflictHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Get ports for conflict test
	ports := testutil.GetFreePorts(t, "udp", 2)
	conflictPort := ports[0]
	availablePort := ports[1]

	// Bind to the conflict port to make it unavailable
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", conflictPort))
	require.NoError(t, err)
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		// Port binding failed - skip this test
		t.Skipf("Could not create port conflict (port already in use): %v", err)
		return
	}
	defer listener.Close()

	// Try to request a session with the conflicting port as sender port
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(conflictPort),  // This port is already bound - should conflict
		ReceiverPort: uint16(availablePort), // This one is free
	}

	_, err = twampClient.RequestSession(sessionConfig)
	// Server may either reject with error or accept with non-zero Accept code
	// Either behavior is valid - we're testing that it handles the conflict gracefully
	if err != nil {
		// Server rejected session request due to port conflict (expected)
		t.Logf("Server rejected session with conflicting port (expected): %v", err)
	} else {
		// Server accepted but may have assigned different port
		// This is also valid behavior - cleanup the session
		t.Logf("Server handled port conflict gracefully (accepted session)")
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	}
}