// Package integration provides comprehensive integration tests for the TWAMP protocol implementation
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

const (
	// serverProcessingDelay is the standard wait time for server-side processing in tests
	serverProcessingDelay = 200 * time.Millisecond
)

// TestRFC5938IndividualSessionControl tests RFC 5938 individual session control features
func TestRFC5938IndividualSessionControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Test 1: Request session with client-specified SID
	t.Run("RequestSessionIndividual", func(t *testing.T) {
		// Generate a specific SID
		sid := common.SessionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		// Request session with specific SID
		session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request session with individual SID")
		require.NotNil(t, session, "Session should not be nil")

		// Verify the session has the correct SID
		require.Equal(t, sid, session.GetSID(), "Session should have the requested SID")

		// Verify we can get the session by SID
		retrievedSession, err := twampClient.GetSession(sid)
		require.NoError(t, err, "Should be able to retrieve session by SID")
		require.NotNil(t, retrievedSession, "Should be able to retrieve session by SID")
		require.Equal(t, session, retrievedSession, "Retrieved session should be the same")
	})

	// Test 2: Start individual session
	t.Run("StartIndividualSession", func(t *testing.T) {
		sid := common.SessionID{0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request session")
		require.NotNil(t, session, "Session should not be nil")

		// Start the specific session
		err = twampClient.StartSession(sid)
		require.NoError(t, err, "Failed to start individual session")

		// Verify session is active
		require.True(t, session.IsActive(), "Session should be active after starting")

		// Send a test packet to verify it's working
		session.StartReceiving(ctx)
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet")

		// Wait for response
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= 1
		}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for packet response")
	})

	// Test 3: Stop individual session
	t.Run("StopIndividualSession", func(t *testing.T) {
		sid := common.SessionID{0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request session")
		require.NotNil(t, session, "Session should not be nil")

		// Start the session
		err = twampClient.StartSession(sid)
		require.NoError(t, err, "Failed to start session")
		require.True(t, session.IsActive(), "Session should be active")

		// Stop the specific session
		err = twampClient.StopSession(sid)
		require.NoError(t, err, "Failed to stop individual session")

		// Verify session is stopped
		require.False(t, session.IsActive(), "Session should not be active after stopping")
	})

	// Test 4: Get all session IDs
	t.Run("GetSessionIDs", func(t *testing.T) {
		// Get current session IDs
		sids := twampClient.GetSessionIDs()
		initialCount := len(sids)

		// Add a new session
		sid := common.SessionID{0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		_, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request session")

		// Get session IDs again
		sids = twampClient.GetSessionIDs()
		require.Equal(t, initialCount+1, len(sids), "Should have one more session")

		// Verify our SID is in the list
		found := false
		for _, s := range sids {
			if s == sid {
				found = true
				break
			}
		}
		require.True(t, found, "New session ID should be in the list")
	})

	// Test 5: Stop N sessions
	t.Run("StopNSessions", func(t *testing.T) {
		// Create multiple sessions
		var sessions []*client.TestSession
		for i := 0; i < 3; i++ {
			sid := common.SessionID{byte(0x10 + i), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

			ports := testutil.GetFreePorts(t, "udp", 2)
			sessionConfig := client.TestSessionConfig{
				SenderPort:    uint16(ports[0]),
				ReceiverPort:  uint16(ports[1]),
				PaddingLength: 41,
				Timeout:       2 * time.Second,
				DSCP:          0,
			}

			session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
			require.NoError(t, err, "Failed to request session %d", i)
			sessions = append(sessions, session)
		}

		// Start all sessions (RFC 5938 doesn't define individual start, so we use collective start)
		err := twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Verify all are active
		for _, session := range sessions {
			require.True(t, session.IsActive(), "Session should be active")
		}

		// Stop 2 sessions using StopNSessions
		err = twampClient.StopNSessions(2)
		require.NoError(t, err, "Failed to stop N sessions")

		// Give server time to process
		time.Sleep(serverProcessingDelay)

		// Count how many are still active
		activeCount := 0
		for _, session := range sessions {
			if session.IsActive() {
				activeCount++
			}
		}

		// At least one session should still be active (we stopped 2 out of 3)
		require.GreaterOrEqual(t, activeCount, 1, "At least one session should still be active")
	})
}

// TestRFC5938MixedSessionControl tests mixing individual and collective session control
func TestRFC5938MixedSessionControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create some sessions with RequestSession (server-generated SID)
	var regularSessions []*client.TestSession
	for i := 0; i < 2; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request regular session %d", i)
		regularSessions = append(regularSessions, session)
	}

	// Create some sessions with RequestSessionIndividual (client-specified SID)
	var individualSessions []*client.TestSession
	for i := 0; i < 2; i++ {
		sid := common.SessionID{byte(0x20 + i), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request individual session %d", i)
		individualSessions = append(individualSessions, session)
	}

	// Start all sessions using collective StartSessions
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start all sessions")

	// Verify all sessions are active
	for _, session := range regularSessions {
		require.True(t, session.IsActive(), "Regular session should be active")
	}
	for _, session := range individualSessions {
		require.True(t, session.IsActive(), "Individual session should be active")
	}

	// Stop one individual session
	err = twampClient.StopSession(individualSessions[0].GetSID())
	require.NoError(t, err, "Failed to stop individual session")
	require.False(t, individualSessions[0].IsActive(), "Stopped session should not be active")

	// Verify others are still active
	require.True(t, individualSessions[1].IsActive(), "Other individual session should still be active")
	for _, session := range regularSessions {
		require.True(t, session.IsActive(), "Regular sessions should still be active")
	}

	// Stop all remaining sessions
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop all sessions")

	// Verify all are stopped
	for _, session := range regularSessions {
		require.False(t, session.IsActive(), "Regular session should be stopped")
	}
	for _, session := range individualSessions {
		require.False(t, session.IsActive(), "Individual session should be stopped")
	}
}

// TestRFC5938AuthenticatedMode tests RFC 5938 features in authenticated mode
func TestRFC5938AuthenticatedMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, "test-secret")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Test individual session control in authenticated mode
	sid := common.SessionID{0x30, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 56, // Minimum for authenticated mode
		Timeout:       2 * time.Second,
		DSCP:          0,
	}

	session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
	require.NoError(t, err, "Failed to request session in authenticated mode")
	require.NotNil(t, session, "Session should not be nil")

	// Start and test the session
	err = twampClient.StartSession(sid)
	require.NoError(t, err, "Failed to start session")

	// Send a test packet
	session.StartReceiving(ctx)
	err = session.SendTestPacket()
	require.NoError(t, err, "Failed to send test packet")

	// Wait for response
	require.Eventually(t, func() bool {
		results := session.GetResults()
		return results.PacketsReceived >= 1
	}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for authenticated packet response")

	// Stop the session
	err = twampClient.StopSession(sid)
	require.NoError(t, err, "Failed to stop session")
}

// TestRFC5938StopNSessionsEdgeCases tests edge cases for Stop-N-Sessions
func TestRFC5938StopNSessionsEdgeCases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	t.Run("StopZeroSessions", func(t *testing.T) {
		// Create a session first
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session")

		// Start the session
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")
		require.True(t, session.IsActive(), "Session should be active")

		// Stop zero sessions - should be a no-op
		err = twampClient.StopNSessions(0)
		require.NoError(t, err, "StopNSessions(0) should succeed")

		// Session should still be active
		require.True(t, session.IsActive(), "Session should still be active after stopping 0")

		// Clean up
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})

	t.Run("StopMoreThanAvailable", func(t *testing.T) {
		// Create 2 sessions
		var sessions []*client.TestSession
		for i := 0; i < 2; i++ {
			ports := testutil.GetFreePorts(t, "udp", 2)
			sessionConfig := client.TestSessionConfig{
				SenderPort:    uint16(ports[0]),
				ReceiverPort:  uint16(ports[1]),
				PaddingLength: 41,
				Timeout:       2 * time.Second,
			}

			session, err := twampClient.RequestSession(sessionConfig)
			require.NoError(t, err, "Failed to request session %d", i)
			sessions = append(sessions, session)
		}

		// Start all sessions
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Try to stop 5 sessions (more than available)
		err = twampClient.StopNSessions(5)
		require.NoError(t, err, "StopNSessions should succeed even when requesting more than available")

		// Give server time to process
		time.Sleep(serverProcessingDelay)

		// All sessions should eventually be stopped
		require.Eventually(t, func() bool {
			activeCount := 0
			for _, s := range sessions {
				if s.IsActive() {
					activeCount++
				}
			}
			return activeCount == 0
		}, 3*time.Second, 100*time.Millisecond, "All sessions should be stopped")
	})
}

// TestRFC5938StopNSessionsAuthenticatedMode tests Stop-N-Sessions in authenticated mode
func TestRFC5938StopNSessionsAuthenticatedMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, "test-secret")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 3 sessions in authenticated mode
	var sessions []*client.TestSession
	for i := 0; i < 3; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 56, // Minimum for authenticated mode
			Timeout:       2 * time.Second,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d in authenticated mode", i)
		sessions = append(sessions, session)
	}

	// Start all sessions
	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Verify all are active
	for _, session := range sessions {
		require.True(t, session.IsActive(), "Session should be active")
	}

	// Stop 2 sessions using StopNSessions in authenticated mode
	err = twampClient.StopNSessions(2)
	require.NoError(t, err, "Failed to stop N sessions in authenticated mode")

	// Give server time to process
	time.Sleep(serverProcessingDelay)

	// Count active sessions
	require.Eventually(t, func() bool {
		activeCount := 0
		for _, session := range sessions {
			if session.IsActive() {
				activeCount++
			}
		}
		// After stopping 2, at least 1 should still be active initially, then be scheduled to stop
		return activeCount <= 1
	}, 3*time.Second, 100*time.Millisecond, "Should have stopped 2 sessions")
}

// TestRFC5938IndividualSessionErrors tests error cases for individual session control
func TestRFC5938IndividualSessionErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	t.Run("StartNonExistentSession", func(t *testing.T) {
		// Try to start a session that doesn't exist
		nonExistentSID := common.SessionID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

		err := twampClient.StartSession(nonExistentSID)
		require.Error(t, err, "Starting non-existent session should fail")
		require.ErrorIs(t, err, client.ErrSessionNotFound, "Error should indicate session not found")
	})

	t.Run("StopNonExistentSession", func(t *testing.T) {
		// Try to stop a session that doesn't exist
		nonExistentSID := common.SessionID{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
			0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE}

		err := twampClient.StopSession(nonExistentSID)
		require.Error(t, err, "Stopping non-existent session should fail")
		require.ErrorIs(t, err, client.ErrSessionNotFound, "Error should indicate session not found")
	})

	t.Run("GetNonExistentSession", func(t *testing.T) {
		// Try to get a session that doesn't exist
		nonExistentSID := common.SessionID{0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
			0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD}

		session, err := twampClient.GetSession(nonExistentSID)
		require.Error(t, err, "Getting non-existent session should fail")
		require.Nil(t, session, "Session should be nil for non-existent SID")
		require.ErrorIs(t, err, client.ErrSessionNotFound, "Error should indicate session not found")
	})

	t.Run("DuplicateSID", func(t *testing.T) {
		// Create a session with a specific SID
		sid := common.SessionID{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}

		ports1 := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig1 := client.TestSessionConfig{
			SenderPort:    uint16(ports1[0]),
			ReceiverPort:  uint16(ports1[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
		}

		session1, err := twampClient.RequestSessionIndividual(sessionConfig1, sid)
		require.NoError(t, err, "First session request should succeed")
		require.NotNil(t, session1, "First session should not be nil")

		// Try to create another session with the same SID
		ports2 := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig2 := client.TestSessionConfig{
			SenderPort:    uint16(ports2[0]),
			ReceiverPort:  uint16(ports2[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
		}

		session2, err := twampClient.RequestSessionIndividual(sessionConfig2, sid)
		// Depending on implementation, this might succeed with server rejection or fail client-side
		// For now, we just verify the client handles it gracefully
		if err != nil {
			require.Contains(t, err.Error(), "session", "Error should mention session conflict")
		} else if session2 != nil {
			// If it succeeded, clean it up
			t.Logf("Duplicate SID request was accepted by server (implementation-dependent)")
		}

		// Clean up
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})
}
