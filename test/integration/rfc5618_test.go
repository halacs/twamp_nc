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

// TestRFC5618MixedSecurityMode tests RFC 5618 Mixed Security Mode (bit 3)
// Mixed mode uses encrypted/authenticated control protocol with unauthenticated test protocol
func TestRFC5618MixedSecurityMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test 1: Mixed mode with encrypted control
	t.Run("MixedWithEncrypted", func(t *testing.T) {
		// Server supports mixed mode with encrypted base
		serverMode := common.ModeMixed | common.ModeEncrypted
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Request session - control messages should be encrypted, test packets should be unauthenticated
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 144, // Use encrypted mode padding for control
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session in mixed mode")
		require.NotNil(t, session, "Session should not be nil")

		// Start sessions
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Send test packets
		session.StartReceiving(ctx)
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet")

		// Wait for response
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= 1
		}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for test packet response")

		// Verify packet was received
		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(1), "Should have received test packet")

		// Stop sessions
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})

	// Test 2: Mixed mode with authenticated control
	t.Run("MixedWithAuthenticated", func(t *testing.T) {
		// Server supports mixed mode with authenticated base
		serverMode := common.ModeMixed | common.ModeAuthenticated
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret-auth")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Request session - control messages should be authenticated (HMAC), test packets should be unauthenticated
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 56, // Minimum for authenticated control mode
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session in mixed authenticated mode")
		require.NotNil(t, session, "Session should not be nil")

		// Start sessions
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Send test packets (should be unauthenticated despite authenticated control)
		session.StartReceiving(ctx)
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet")

		// Wait for response
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= 1
		}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for test packet response")

		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(1), "Should have received test packet")

		// Stop sessions
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})
}

// TestRFC5618MixedWithRFC6038 tests RFC 5618 Mixed Security Mode combined with RFC 6038 features
func TestRFC5618MixedWithRFC6038(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test 1: Mixed mode with reflect octets
	t.Run("MixedWithReflectOctets", func(t *testing.T) {
		// Server supports mixed encrypted + reflect octets
		serverMode := common.ModeMixed | common.ModeEncrypted | common.ModeReflectOctets
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Request session with specific padding
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 200, // Use larger padding to test reflection
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session in mixed mode with reflect octets")
		require.NotNil(t, session, "Session should not be nil")

		// Start sessions
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Send test packets - should be reflected back with same padding
		session.StartReceiving(ctx)
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet")

		// Wait for response
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= 1
		}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for reflected packet")

		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(1), "Should have received reflected packet")

		// Stop sessions
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})

	// Test 2: Mixed mode with symmetrical size
	t.Run("MixedWithSymmetricalSize", func(t *testing.T) {
		// Server supports mixed authenticated + symmetrical size
		serverMode := common.ModeMixed | common.ModeAuthenticated | common.ModeSymmetricalSize
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Request session
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 150, // Test symmetrical size behavior
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session in mixed mode with symmetrical size")
		require.NotNil(t, session, "Session should not be nil")

		// Start sessions
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Send test packets - reflector should match sender packet size
		session.StartReceiving(ctx)
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet")

		// Wait for response
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= 1
		}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for symmetrical size packet")

		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(1), "Should have received symmetrical size packet")

		// Stop sessions
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})

	// Test 3: Mixed mode with both RFC 6038 features
	t.Run("MixedWithBothRFC6038Features", func(t *testing.T) {
		// Server supports mixed encrypted + reflect octets + symmetrical size
		serverMode := common.ModeMixed | common.ModeEncrypted | common.ModeReflectOctets | common.ModeSymmetricalSize
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Request session
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 300, // Test both features together
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session in mixed mode with all RFC 6038 features")
		require.NotNil(t, session, "Session should not be nil")

		// Start sessions
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Send test packets
		session.StartReceiving(ctx)
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet")

		// Wait for response
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= 1
		}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for packet")

		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(1), "Should have received packet")

		// Stop sessions
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})
}

// TestRFC5618IndividualSessionControl tests RFC 5618 mixed mode with RFC 5938 individual session control
func TestRFC5618IndividualSessionControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test mixed mode with individual session control
	t.Run("MixedModeWithIndividualSessions", func(t *testing.T) {
		serverMode := common.ModeMixed | common.ModeEncrypted
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Request individual session with specific SID
		sid := common.SessionID{0x50, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 144, // Use encrypted mode padding
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSessionIndividual(sessionConfig, sid)
		require.NoError(t, err, "Failed to request individual session in mixed mode")
		require.NotNil(t, session, "Session should not be nil")
		require.Equal(t, sid, session.GetSID(), "Session should have requested SID")

		// Start session
		err = twampClient.StartSession(sid)
		require.NoError(t, err, "Failed to start individual session")

		// Send test packet
		session.StartReceiving(ctx)
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet")

		// Wait for response
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= 1
		}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for packet")

		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(1), "Should have received packet")

		// Stop individual session
		err = twampClient.StopSession(sid)
		require.NoError(t, err, "Failed to stop individual session")
	})
}

// TestRFC5618ModeNegotiation tests mode negotiation for RFC 5618 mixed mode
func TestRFC5618ModeNegotiation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test 1: RFC 5618 violation - Mixed mode with unauthenticated control MUST be rejected
	t.Run("MixedWithUnauthenticatedRejected", func(t *testing.T) {
		// Per RFC 5618 Section 3.1, mixed mode MUST use authenticated or encrypted control protocol
		// ModeMixed | ModeUnauthenticated (0x09) is invalid and should be rejected
		invalidMode := common.ModeMixed | common.ModeUnauthenticated

		// Server advertises the invalid mode combination
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(invalidMode), "")
		defer cleanup()

		// Attempt to connect - should fail
		// Both client and server validate this per RFC 5618 Section 3.1
		// The server may close the connection, or the client may detect the violation
		err := twampClient.Connect(ctx)
		require.Error(t, err, "Connect MUST fail for ModeMixed | ModeUnauthenticated per RFC 5618 Section 3.1")

		// Verify it's not a timeout or unrelated error
		require.NotContains(t, err.Error(), "timeout", "Should not be a timeout error")
		require.NotContains(t, err.Error(), "connection refused", "Should not be connection refused")
	})

	// Test 2: Server doesn't support mixed mode
	t.Run("ServerDoesNotSupportMixed", func(t *testing.T) {
		// Server only supports standard encrypted mode (no mixed bit)
		serverMode := common.ModeEncrypted
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server - should succeed and use standard encrypted mode
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Request session - should work with standard encrypted mode
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 144,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session")
		require.NotNil(t, session, "Session should not be nil")
	})

	// Test 2: Multiple sessions in mixed mode
	t.Run("MultipleMixedModeSessions", func(t *testing.T) {
		serverMode := common.ModeMixed | common.ModeAuthenticated
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Create multiple sessions
		var sessions []*client.TestSession
		for i := 0; i < 3; i++ {
			ports := testutil.GetFreePorts(t, "udp", 2)
			sessionConfig := client.TestSessionConfig{
				SenderPort:    uint16(ports[0]),
				ReceiverPort:  uint16(ports[1]),
				PaddingLength: 56,
				Timeout:       2 * time.Second,
				DSCP:          0,
			}

			session, err := twampClient.RequestSession(sessionConfig)
			require.NoError(t, err, "Failed to request session %d", i)
			sessions = append(sessions, session)
		}

		// Start all sessions
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		// Test all sessions
		for i, session := range sessions {
			session.StartReceiving(ctx)
			err = session.SendTestPacket()
			require.NoError(t, err, "Failed to send packet for session %d", i)
		}

		// Wait for all responses
		for i, session := range sessions {
			require.Eventually(t, func() bool {
				results := session.GetResults()
				return results.PacketsReceived >= 1
			}, 5*time.Second, 50*time.Millisecond, "Timeout for session %d", i)
		}

		// Verify all sessions received packets
		for i, session := range sessions {
			results := session.GetResults()
			require.GreaterOrEqual(t, results.PacketsReceived, uint32(1), "Session %d should have received packet", i)
		}

		// Stop all sessions
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})
}

// TestRFC5618Performance tests performance of mixed security mode
func TestRFC5618Performance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test performance with multiple packets in mixed mode
	t.Run("MixedModePerformance", func(t *testing.T) {
		serverMode := common.ModeMixed | common.ModeEncrypted
		_, twampClient, cleanup := setupServerAndClient(t, ctx, common.Mode(serverMode), "test-secret")
		defer cleanup()

		// Connect to server
		err := twampClient.Connect(ctx)
		require.NoError(t, err, "Failed to connect")

		// Create session
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 100, // Moderate padding for performance test
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session")
		require.NotNil(t, session, "Session should not be nil")

		// Start session
		err = twampClient.StartSessions()
		require.NoError(t, err, "Failed to start sessions")

		session.StartReceiving(ctx)

		// Send multiple test packets
		numPackets := 20
		for i := 0; i < numPackets; i++ {
			err = session.SendTestPacket()
			require.NoError(t, err, "Failed to send packet %d", i)
			time.Sleep(10 * time.Millisecond) // Small delay between packets
		}

		// Wait for all responses
		require.Eventually(t, func() bool {
			results := session.GetResults()
			return results.PacketsReceived >= uint32(numPackets)
		}, 10*time.Second, 50*time.Millisecond, "Timeout waiting for all packets")

		// Verify all packets received
		results := session.GetResults()
		require.GreaterOrEqual(t, results.PacketsReceived, uint32(numPackets), "Should have received all packets")

		// Verify RTT statistics are reasonable
		require.Greater(t, results.AvgRTT, time.Duration(0), "Average RTT should be positive")
		require.GreaterOrEqual(t, results.MaxRTT, results.MinRTT, "Max RTT should be >= Min RTT")

		// Stop session
		err = twampClient.StopSessions()
		require.NoError(t, err, "Failed to stop sessions")
	})
}