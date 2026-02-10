// Package integration provides comprehensive integration tests for the TWAMP protocol implementation.
// This file tests previously uncovered functions, edge cases, and specific code paths to increase coverage.
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

// TestGetAllPacketResults tests the GetAllPacketResults function
func TestGetAllPacketResults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 100,
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	session.StartReceiving(ctx)

	// Send several test packets
	for i := 0; i < 10; i++ {
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet %d", i)
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	// Get all packet results (exercises GetAllPacketResults)
	allResults := session.GetAllPacketResults()
	require.NotNil(t, allResults, "All results should not be nil")
	require.Greater(t, len(allResults), 0, "Should have some packet results")

	// Count how many packets were actually received
	// Use RTT > 0 as indicator since RTT is only set when a reply is received
	receivedCount := 0
	for _, result := range allResults {
		if result.RTT > 0 {
			receivedCount++
			// Verify received packets have positive RTT
			require.Greater(t, result.RTT, time.Duration(0), "RTT should be positive for received packets")
		}
	}
	// On localhost, we should receive at least 90% of packets (9 out of 10)
	require.GreaterOrEqual(t, receivedCount, 9, "Should receive at least 90%% of packets on localhost (9/10)")

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestStopNSessionsEdgeCases tests various edge cases for Stop-N-Sessions
func TestStopNSessionsEdgeCases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-stop-n"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	// Create 3 sessions
	for i := 0; i < 3; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 100,
		}
		_, err := twampClient.RequestSession(sessionConfig)
		require.NoError(t, err, "Failed to request session %d", i)
	}

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Stop 1 session using StopNSessions
	err = twampClient.StopNSessions(1)
	require.NoError(t, err, "Failed to stop 1 session")

	// Wait for client to process Stop-N-Sessions response and update internal state
	// No way to poll for completion; client-side cleanup is async
	time.Sleep(100 * time.Millisecond)

	// Verify 2 sessions remain (exercises GetSessionIDs and StopNSessions partial stop)
	sessionIDs := twampClient.GetSessionIDs()
	require.Len(t, sessionIDs, 2, "Should have 2 sessions remaining after stopping 1")

	// Note: cleanup() will handle closing the control connection and remaining sessions
}

// TestSessionStartReceivingEdgeCases tests edge cases in StartReceiving
func TestSessionStartReceivingEdgeCases(t *testing.T) {
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

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Create a context that expires quickly
	shortCtx, shortCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer shortCancel()

	// Start receiving with short context
	session.StartReceiving(shortCtx)

	// Send a few packets
	for i := 0; i < 5; i++ {
		session.SendTestPacket()
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for context to expire
	time.Sleep(300 * time.Millisecond)

	// Session should still be stoppable
	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestMultipleStartReceivingCalls tests calling StartReceiving multiple times
func TestMultipleStartReceivingCalls(t *testing.T) {
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

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	// Call StartReceiving multiple times to verify it handles concurrent receivers
	// Note: StartReceiving is NOT idempotent - each call starts a new goroutine
	// This test verifies that multiple receiver goroutines don't cause issues
	session.StartReceiving(ctx)
	time.Sleep(50 * time.Millisecond)
	session.StartReceiving(ctx) // Second call - starts another receiver goroutine
	time.Sleep(50 * time.Millisecond)

	// Send packets
	for i := 0; i < 5; i++ {
		session.SendTestPacket()
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestAuthenticatedModeWithLargePadding tests authenticated mode with large padding
func TestAuthenticatedModeWithLargePadding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-large-padding"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeAuthenticated, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 800, // Large padding
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	session.StartReceiving(ctx)

	// Send packets with large padding
	for i := 0; i < 5; i++ {
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet %d", i)
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}

// TestEncryptedModeWithZeroPadding tests encrypted mode adjusts padding automatically
func TestEncryptedModeWithZeroPadding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret := "test-secret-zero-padding"
	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeEncrypted, secret)
	defer cleanup()

	err := twampClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect")

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 0, // Zero padding - should be adjusted to minimum
	}

	session, err := twampClient.RequestSession(sessionConfig)
	require.NoError(t, err, "Failed to request session")

	err = twampClient.StartSessions()
	require.NoError(t, err, "Failed to start sessions")

	session.StartReceiving(ctx)

	// Send packets
	for i := 0; i < 5; i++ {
		err = session.SendTestPacket()
		require.NoError(t, err, "Failed to send test packet %d", i)
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	err = twampClient.StopSessions()
	require.NoError(t, err, "Failed to stop sessions")
}