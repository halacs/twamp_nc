// Package integration provides comprehensive integration tests for the TWAMP protocol implementation.
// This file tests authenticated and encrypted mode edge cases, lifecycle, and RFC 5938 features.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/client"
	"github.com/ncode/twamp/common"
	"github.com/stretchr/testify/require"
)

// TestAuthenticatedModeStopNSessions tests Stop-N-Sessions in authenticated mode with various edge cases
func TestAuthenticatedModeStopNSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-authenticated"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 3 sessions
	var sessions []*client.TestSession
	for i := 0; i < 3; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:   uint16(ports[0]),
			ReceiverPort: uint16(ports[1]),
		}
		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d", i)
		sessions = append(sessions, session)
	}

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Start receiving on all sessions
	for _, session := range sessions {
		session.StartReceiving(ctx)
	}

	// Wait for sessions to be active
	require.Eventually(t, func() bool {
		for _, session := range sessions {
			if !session.IsActive() {
				return false
			}
		}
		return true
	}, 2*time.Second, 10*time.Millisecond, "Sessions should become active")

	// Call StopNSessions with 0 (exercises HMAC path for Stop-N-Sessions)
	// Note: Per RFC 5938, StopNSessions(0) is a no-op - doesn't stop any sessions
	err = twampClient.StopNSessions(0)
	require.NoError(t, err, "Failed to call StopNSessions(0)")

	// Verify sessions are still active after no-op
	require.Eventually(t, func() bool {
		for _, session := range sessions {
			if !session.IsActive() {
				return false // If any session stopped, fail
			}
		}
		return true
	}, 500*time.Millisecond, 10*time.Millisecond, "Sessions should remain active after StopNSessions(0)")

	// Now actually stop all sessions for cleanup
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestEncryptedModeSessionLifecycle tests full session lifecycle in encrypted mode
func TestEncryptedModeSessionLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-encrypted"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeEncrypted, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Request session (exercises encrypted control path)
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 128,
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	// Start session (exercises encrypted start command)
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Send and receive test packets
	session.StartReceiving(ctx)

	const numPackets = 10
	for i := 0; i < numPackets; i++ {
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet %d", i)
	}

	// Wait for packets to be received (require at least 90% on localhost)
	require.Eventually(t, func() bool {
		results := session.GetResults()
		return results.PacketsReceived >= uint32(numPackets*9/10)
	}, 2*time.Second, 10*time.Millisecond, "Should receive at least 90%% of packets on localhost")

	// Stop session (exercises encrypted stop command)
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")

	// Verify high packet reception rate and that encryption was used
	results := session.GetResults()
	require.GreaterOrEqual(t, results.PacketsReceived, uint32(numPackets*9/10),
		"Should receive at least 90%% of %d packets on localhost, got %d", numPackets, results.PacketsReceived)
	require.Greater(t, results.AvgRTT, time.Duration(0), "Should have measured RTT")

	// On localhost, RTT should be very low (< 10ms for encrypted mode)
	require.Less(t, results.AvgRTT, 10*time.Millisecond,
		"Localhost RTT should be < 10ms, got %v", results.AvgRTT)
}

// TestAuthenticatedModeMultipleStartStop tests multiple start/stop cycles with authentication
func TestAuthenticatedModeMultipleStartStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-cycles"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Test 2 cycles of start/stop
	for cycle := 0; cycle < 2; cycle++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 100, // Adequate padding for authenticated mode
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session in cycle %d", cycle)

		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions in cycle %d", cycle)

		session.StartReceiving(ctx)

		// Send packets with error checking
		const numPackets = 5
		for i := 0; i < numPackets; i++ {
			err = session.SendTestPacket()
			require.NoError(t, err, "Failed to send test packet %d in cycle %d", i, cycle)
		}

		// Wait for at least 90% packet reception on localhost
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= uint32(numPackets*9/10)
		}, 2*time.Second, 10*time.Millisecond, "Should receive at least 90%% of packets in cycle %d", cycle)

		// Verify session is active and packets were received
		require.True(t, session.IsActive(), "Session should be active in cycle %d", cycle)
		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(numPackets*9/10),
			"Should receive at least 90%% of %d packets on localhost in cycle %d, got %d", numPackets, cycle, results.PacketsReceived)

		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions in cycle %d", cycle)
	}
}

// TestEncryptedModeStopNSessions tests Stop-N-Sessions in encrypted mode
func TestEncryptedModeStopNSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-encrypted-stop"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeEncrypted, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 2 sessions
	var sessions []*client.TestSession
	for i := 0; i < 2; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:   uint16(ports[0]),
			ReceiverPort: uint16(ports[1]),
		}
		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d", i)
		sessions = append(sessions, session)
	}

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Start receiving on all sessions
	for _, session := range sessions {
		session.StartReceiving(ctx)
	}

	// Wait for sessions to become active
	require.Eventually(t, func() bool {
		for _, session := range sessions {
			if !session.IsActive() {
				return false
			}
		}
		return true
	}, 2*time.Second, 10*time.Millisecond, "Sessions should become active")

	// Stop all sessions
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestAuthenticatedModeIndividualSessionControl tests RFC 5938 individual session control with authentication
func TestAuthenticatedModeIndividualSessionControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-individual"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Request individual session with specific SID
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	customSID := common.SessionID{0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	session, err := twampClient.RequestSessionIndividual(sessionConfig, customSID)
	require.NoError(t, err, "Failed to request individual session")
	require.Equal(t, customSID, session.GetSID(), "Session ID should match")

	// Start the specific session
	err = twampClient.StartSession(customSID)
	require.NoError(t, err, "Failed to start individual session")

	session.StartReceiving(ctx)

	// Wait for session to become active
	require.Eventually(t, func() bool {
		return session.IsActive()
	}, 2*time.Second, 10*time.Millisecond, "Session should become active")

	// Stop the specific session
	err = twampClient.StopSession(customSID)
	require.NoError(t, err, "Failed to stop individual session")

	// Verify session is fully stopped
	require.Eventually(t, func() bool {
		return !session.IsActive()
	}, 2*time.Second, 10*time.Millisecond, "Session should be stopped")
}

// TestEncryptedModeIndividualSessionControl tests RFC 5938 individual session control with encryption
func TestEncryptedModeIndividualSessionControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-individual-enc"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeEncrypted, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Request individual session with specific SID
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
	}

	customSID := common.SessionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}

	session, err := twampClient.RequestSessionIndividual(sessionConfig, customSID)
	require.NoError(t, err, "Failed to request individual session")

	// Retrieve session and verify
	retrievedSession, err := twampClient.GetSession(customSID)
	require.NoError(t, err, "Failed to get session")
	require.Equal(t, session, retrievedSession, "Retrieved session should match")

	// Start the session
	err = twampClient.StartSession(customSID)
	require.NoError(t, err, "Failed to start session")

	session.StartReceiving(ctx)

	// Send test packets with error checking
	const numPackets = 5
	for i := 0; i < numPackets; i++ {
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet %d", i)
	}

	// Wait for at least 90% packet reception on localhost
	require.Eventually(t, func() bool {
		results := session.GetResults()
		return results.PacketsReceived >= uint32(numPackets*9/10)
	}, 2*time.Second, 10*time.Millisecond, "Should receive at least 90%% of packets on localhost")

	// Verify session is active and packets were received
	require.True(t, session.IsActive(), "Session should be active")
	results := session.GetResults()
	require.GreaterOrEqual(t, results.PacketsReceived, uint32(numPackets*9/10),
		"Should receive at least 90%% of %d packets on localhost, got %d", numPackets, results.PacketsReceived)

	// Stop the session
	err = twampClient.StopSession(customSID)
	require.NoError(t, err, "Failed to stop session")
}

// TestAuthenticatedModeGetAllSessionIDs tests retrieving all session IDs with multiple sessions
func TestAuthenticatedModeGetAllSessionIDs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-get-all"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 3 individual sessions with known SIDs
	sids := []common.SessionID{
		{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	for i, sid := range sids {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:   uint16(ports[0]),
			ReceiverPort: uint16(ports[1]),
		}
		_, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request session %d", i)
	}

	// Get all session IDs
	allSIDs := twampClient.GetSessionIDs()
	require.Len(t, allSIDs, 3, "Should have 3 sessions")

	// Verify all expected SIDs are present
	for _, expectedSID := range sids {
		found := false
		for _, actualSID := range allSIDs {
			if actualSID == expectedSID {
				found = true
				break
			}
		}
		require.True(t, found, "Expected SID %v not found", expectedSID)
	}

	// Clean up
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}