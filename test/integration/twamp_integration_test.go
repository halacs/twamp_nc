// Package integration provides comprehensive integration tests for the TWAMP protocol implementation
package integration

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/client"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/server"
	"github.com/stretchr/testify/require"
)

// waitForConditionWithBackoff polls a condition with exponential backoff until timeout
func waitForConditionWithBackoff(t *testing.T, timeout time.Duration, condition func() bool, msgAndArgs ...interface{}) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	backoff := 10 * time.Millisecond
	maxBackoff := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, maxBackoff)
	}

	// Log failure if message provided
	if len(msgAndArgs) > 0 {
		if len(msgAndArgs) == 1 {
			t.Logf("Condition not met within %v: %v", timeout, msgAndArgs[0])
		} else {
			format := fmt.Sprintf("Condition not met within %v: %v", timeout, msgAndArgs[0])
			t.Logf(format, msgAndArgs[1:]...)
		}
	}
	return false
}

// setupServerAndClient creates and starts a TWAMP server and returns a configured client
// It uses a cancellable context for proper resource management
func setupServerAndClient(t *testing.T, ctx context.Context, mode common.Mode, secret string) (*server.Server, *client.Client, func()) {
	serverPort := testutil.GetFreePorts(t, "tcp", 1)[0]
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	// Create server config
	serverConfig := server.ServerConfig{
		ListenAddress:  serverAddr,
		SupportedModes: mode,
	}

	// Extract base security mode (bits 0-2) to determine if authentication is needed
	securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
	baseSecurity := mode & securityMask

	// Add secret map for authenticated/encrypted modes
	if baseSecurity != common.ModeUnauthenticated {
		serverConfig.SecretMap = map[string]string{
			"test-user": secret,
		}
	}

	// Create and start server
	twampServer, err := server.NewServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	err = twampServer.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Wait for server to be ready by attempting connection
	require.Eventually(t, func() bool {
		testConn, err := net.DialTimeout("tcp", serverAddr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		testConn.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond, "Server failed to start listening")

	// Create client config
	clientConfig := client.ClientConfig{
		ServerAddress: serverAddr,
		PreferredMode: mode,
		Timeout:       5 * time.Second,
	}

	// Add authentication for authenticated/encrypted modes
	if baseSecurity != common.ModeUnauthenticated {
		clientConfig.SharedSecret = secret
		clientConfig.KeyID = "test-user"
	}

	twampClient := client.NewClient(clientConfig)

	// Cleanup function with proper error handling and reporting
	cleanup := func() {
		var cleanupErrors []error

		if err := twampClient.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("client close: %w", err))
		}

		if err := twampServer.Stop(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("server stop: %w", err))
		}

		if len(cleanupErrors) > 0 {
			t.Logf("Cleanup errors: %v", cleanupErrors)
		}
	}

	return twampServer, twampClient, cleanup
}

// TestTWAMPModes tests TWAMP functionality across all supported modes using table-driven tests
func TestTWAMPModes(t *testing.T) {
	tests := []struct {
		name          string
		mode          common.Mode
		secret        string
		keyID         string
		paddingLength uint16
		description   string
	}{
		{
			name:          "Unauthenticated",
			mode:          common.ModeUnauthenticated,
			secret:        "",
			keyID:         "",
			paddingLength: 41, // RFC 5357 Section 4.2.1: minimum 41 octets for unauthenticated reflector packet
			description:   "Basic TWAMP without security",
		},
		{
			name:          "Authenticated",
			mode:          common.ModeAuthenticated,
			secret:        "test-secret-password",
			keyID:         "test-user",
			paddingLength: 56, // RFC 5357 Section 4.1.2/4.2.1: authenticated mode requires additional MBZ fields and HMAC
			description:   "TWAMP with HMAC-SHA256 authentication",
		},
		{
			name:          "Encrypted",
			mode:          common.ModeEncrypted,
			secret:        "strong-encryption-key",
			keyID:         "test-user",
			paddingLength: 144, // RFC 5357: encrypted mode with additional padding for block cipher
			description:   "TWAMP with AES-128-CBC encryption and HMAC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with timeout and cancellation
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Setup server and client
			ports := testutil.GetFreePorts(t, "udp", 1)
			serverAddr := fmt.Sprintf("127.0.0.1:%d", ports[0])

			// Create server config
			serverConfig := server.ServerConfig{
				ListenAddress:  serverAddr,
				SupportedModes: tt.mode,
			}

			// Add secret map for authenticated/encrypted modes
			if tt.mode != common.ModeUnauthenticated {
				serverConfig.SecretMap = map[string]string{
					tt.keyID: tt.secret,
				}
			}

			// Create and start server
			twampServer, err := server.NewServer(serverConfig)
			if err != nil {
				t.Fatalf("Failed to create server for %s mode: %v", tt.name, err)
			}

			err = twampServer.Start(ctx)
			if err != nil {
				t.Fatalf("Failed to start server for %s mode: %v", tt.name, err)
			}

			// Ensure proper cleanup
			defer func() {
				if stopErr := twampServer.Stop(); stopErr != nil {
					t.Logf("Failed to stop server for %s mode: %v", tt.name, stopErr)
				}
			}()

			// Wait for server to be ready
			require.Eventually(t, func() bool {
				testConn, err := net.DialTimeout("tcp", serverAddr, 100*time.Millisecond)
				if err != nil {
					return false
				}
				testConn.Close()
				return true
			}, 2*time.Second, 10*time.Millisecond, "Server failed to start listening for %s mode", tt.name)

			// Create client config
			clientConfig := client.ClientConfig{
				ServerAddress: serverAddr,
				PreferredMode: tt.mode,
				Timeout:       5 * time.Second,
			}

			// Add authentication for authenticated/encrypted modes
			if tt.mode != common.ModeUnauthenticated {
				clientConfig.SharedSecret = tt.secret
				clientConfig.KeyID = tt.keyID
			}

			twampClient := client.NewClient(clientConfig)
			defer func() {
				if closeErr := twampClient.Close(); closeErr != nil {
					t.Logf("Failed to close client for %s mode: %v", tt.name, closeErr)
				}
			}()

			// Connect to server - RFC 4656 Section 3.1: Greeting exchange
			err = twampClient.Connect(ctx)
			if err != nil {
				t.Fatalf("%s mode: Failed to connect: %v", tt.name, err)
			}

			// Request a test session - RFC 5357 Section 3.5: Request-TW-Session
			sessionPorts := testutil.GetFreePorts(t, "udp", 2)
			sessionConfig := client.TestSessionConfig{
				SenderPort:    uint16(sessionPorts[0]),
				ReceiverPort:  uint16(sessionPorts[1]),
				PaddingLength: uint32(tt.paddingLength),
				Timeout:       2 * time.Second,
				DSCP:          0, // Type-P Descriptor: DSCP=0 (default forwarding)
			}

			session, err := twampClient.RequestSession(sessionConfig)
			if err != nil {
				t.Fatalf("%s mode: Failed to request session: %v", tt.name, err)
			}

			// Start sessions
			err = twampClient.StartSessions()
			if err != nil {
				t.Fatalf("%s mode: Failed to start sessions: %v", tt.name, err)
			}

			// Start receiving responses
			session.StartReceiving(ctx)

			// Send test packets
			packetsToSend := 5
			for i := 0; i < packetsToSend; i++ {
				err = session.SendTestPacket()
				if err != nil {
					t.Errorf("%s mode: Failed to send test packet %d: %v", tt.name, i, err)
				}
			}

			// Wait for responses to arrive
			require.Eventually(t, func() bool {
				results := session.GetResults()
				return results.PacketsReceived >= uint32(packetsToSend-1) // Allow for one packet loss
			}, 5*time.Second, 50*time.Millisecond, "%s mode: Timeout waiting for test packets", tt.name)

			// Verify results
			verifySessionResults(t, session, packetsToSend, tt.name)

			// Stop sessions
			err = twampClient.StopSessions()
			if err != nil {
				t.Errorf("%s mode: Failed to stop sessions: %v", tt.name, err)
			}
		})
	}
}

// verifySessionResults validates the test session results
func verifySessionResults(t *testing.T, session *client.TestSession, packetsToSend int, modeName string) {
	results := session.GetResults()

	if results.PacketsSent != uint32(packetsToSend) {
		t.Errorf("%s mode: Expected %d packets sent, got %d", modeName, packetsToSend, results.PacketsSent)
	}

	if results.PacketsReceived == 0 {
		t.Errorf("%s mode: No packets received", modeName)
	}

	if results.PacketsLost > uint32(packetsToSend/2) {
		t.Errorf("%s mode: Too many packets lost: %d out of %d", modeName, results.PacketsLost, packetsToSend)
	}

	if results.MinRTT == 0 || results.MaxRTT == 0 || results.AvgRTT == 0 {
		t.Errorf("%s mode: RTT measurements are zero", modeName)
	}

	if results.MinRTT > results.MaxRTT {
		t.Errorf("%s mode: MinRTT (%v) is greater than MaxRTT (%v)", modeName, results.MinRTT, results.MaxRTT)
	}
}

// TestMultipleSessions tests handling of multiple concurrent test sessions
func TestMultipleSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Request multiple test sessions
	numSessions := 3
	sessions := make([]*client.TestSession, numSessions)

	for i := 0; i < numSessions; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		}

		session, err := twampClient.RequestSession(sessionConfig)
		if err != nil {
			t.Fatalf("Failed to request session %d: %v", i, err)
		}
		sessions[i] = session
	}

	// Start all sessions
	err = twampClient.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Start receiving on all sessions
	for _, session := range sessions {
		session.StartReceiving(ctx)
	}

	// Send test packets on all sessions
	packetsPerSession := 3
	for i := 0; i < packetsPerSession; i++ {
		for j, session := range sessions {
			err = session.SendTestPacket()
			if err != nil {
				t.Errorf("Failed to send packet %d on session %d: %v", i, j, err)
			}
		}
	}

	// Wait for all sessions to receive their packets
	for i, session := range sessions {
		sessionIdx := i
		sessionPtr := session
		require.Eventually(t, func() bool {
			results := sessionPtr.GetResults()
			return results.PacketsReceived >= uint32(packetsPerSession-1)
		}, 5*time.Second, 50*time.Millisecond,
			fmt.Sprintf("Timeout waiting for packets on session %d", sessionIdx))
	}

	// Verify results for each session
	for i, session := range sessions {
		results := session.GetResults()

		if results.PacketsSent != uint32(packetsPerSession) {
			t.Errorf("Session %d: Expected %d packets sent, got %d",
				i, packetsPerSession, results.PacketsSent)
		}

		if results.PacketsReceived == 0 {
			t.Errorf("Session %d: No packets received", i)
		}

		if results.MinRTT == 0 || results.MaxRTT == 0 || results.AvgRTT == 0 {
			t.Errorf("Session %d: RTT measurements are zero", i)
		}
	}

	// Stop sessions
	err = twampClient.StopSessions()
	if err != nil {
		t.Errorf("Failed to stop sessions: %v", err)
	}
}

// TestConnectionTimeout tests timeout handling during connection
func TestConnectionTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use a non-existent address to trigger timeout
	clientConfig := client.ClientConfig{
		ServerAddress: "192.0.2.1:862", // TEST-NET-1 address, should not be routable
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       1 * time.Second,
	}

	twampClient := client.NewClient(clientConfig)
	defer func() {
		if err := twampClient.Close(); err != nil {
			t.Logf("Failed to close client: %v", err)
		}
	}()

	// This should timeout
	err := twampClient.Connect(ctx)
	if err == nil {
		t.Error("Expected connection timeout error, got nil")
	}
}

// TestInvalidAuthentication tests rejection of invalid credentials
func TestInvalidAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	correctSecret := "correct-password"

	// Setup server with correct credentials
	serverPort := testutil.GetFreePorts(t, "tcp", 1)[0]
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	serverConfig := server.ServerConfig{
		ListenAddress:  serverAddr,
		SupportedModes: common.ModeAuthenticated,
		SecretMap: map[string]string{
			"test-user": correctSecret,
		},
	}

	twampServer, err := server.NewServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	err = twampServer.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := twampServer.Stop(); err != nil {
			t.Logf("Failed to stop server: %v", err)
		}
	}()

	// Wait for server to be ready by attempting connection
	require.Eventually(t, func() bool {
		testConn, err := net.DialTimeout("tcp", serverAddr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		testConn.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond, "Server failed to start listening")

	// Create a new client with wrong credentials
	wrongClient := client.NewClient(client.ClientConfig{
		ServerAddress: serverAddr,
		PreferredMode: common.ModeAuthenticated,
		SharedSecret:  "wrong-password",
		KeyID:         "test-user",
		Timeout:       2 * time.Second,
	})
	defer func() {
		if err := wrongClient.Close(); err != nil {
			t.Logf("Failed to close wrong client: %v", err)
		}
	}()

	// Connection might succeed but session request should fail
	err = wrongClient.Connect(ctx)
	if err == nil {
		// If connection succeeded, try to request a session
		ports := testutil.GetFreePorts(t, "udp", 2)
		sessionConfig := client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 56,
			Timeout:       2 * time.Second,
		}

		_, err = wrongClient.RequestSession(sessionConfig)
		if err == nil {
			t.Error("Expected authentication failure, but session was created")
		}
	}
}

// TestConcurrentClients tests multiple clients connecting to the same server
func TestConcurrentClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a server that can handle multiple clients
	serverPort := testutil.GetFreePorts(t, "tcp", 1)[0]
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	serverConfig := server.ServerConfig{
		ListenAddress:  serverAddr,
		SupportedModes: common.ModeUnauthenticated,
	}

	twampServer, err := server.NewServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	err = twampServer.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := twampServer.Stop(); err != nil {
			t.Logf("Failed to stop server: %v", err)
		}
	}()

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		testConn, err := net.DialTimeout("tcp", serverAddr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		testConn.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond, "Server failed to start listening")

	// Create multiple clients
	numClients := 5
	clients := make([]*client.Client, numClients)
	var wg sync.WaitGroup
	errChan := make(chan error, numClients*10) // Buffer for all potential errors

	for i := 0; i < numClients; i++ {
		clientConfig := client.ClientConfig{
			ServerAddress: serverAddr,
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       5 * time.Second,
		}
		clients[i] = client.NewClient(clientConfig)

		wg.Add(1)
		go func(idx int, c *client.Client) {
			defer wg.Done()
			defer func() {
				if closeErr := c.Close(); closeErr != nil {
					errChan <- fmt.Errorf("Client %d close: %w", idx, closeErr)
				}
			}()

			// Connect
			err := c.Connect(ctx)
			if err != nil {
				errChan <- fmt.Errorf("Client %d: Failed to connect: %v", idx, err)
				return
			}

			// Get dynamic ports for this client
			ports := testutil.GetFreePorts(t, "udp", 2)

			// Request session
			sessionConfig := client.TestSessionConfig{
				SenderPort:    uint16(ports[0]),
				ReceiverPort:  uint16(ports[1]),
				PaddingLength: 41,
				Timeout:       2 * time.Second,
			}

			session, err := c.RequestSession(sessionConfig)
			if err != nil {
				errChan <- fmt.Errorf("Client %d: Failed to request session: %v", idx, err)
				return
			}

			// Start session
			err = c.StartSessions()
			if err != nil {
				errChan <- fmt.Errorf("Client %d: Failed to start session: %v", idx, err)
				return
			}

			// Start receiving
			session.StartReceiving(ctx)

			// Send a few packets
			for j := 0; j < 3; j++ {
				err = session.SendTestPacket()
				if err != nil {
					errChan <- fmt.Errorf("Client %d: Failed to send packet %d: %v", idx, j, err)
				}
			}

			// Wait for responses using the helper function
			success := waitForConditionWithBackoff(t, 5*time.Second, func() bool {
				results := session.GetResults()
				return results.PacketsReceived >= 2 // Allow for one packet loss
			}, fmt.Sprintf("Client %d: waiting for packets", idx))

			if !success {
				finalResults := session.GetResults()
				errChan <- fmt.Errorf("client %d: timeout waiting for packets (received %d)", idx, finalResults.PacketsReceived)
				return
			}

			// Check results
			results := session.GetResults()
			if results.PacketsSent != 3 {
				errChan <- fmt.Errorf("Client %d: Expected 3 packets sent, got %d", idx, results.PacketsSent)
			}

			// Stop session
			err = c.StopSessions()
			if err != nil {
				errChan <- fmt.Errorf("Client %d: Failed to stop session: %v", idx, err)
			}
		}(i, clients[i])
	}

	wg.Wait()
	close(errChan)

	// Check for errors from goroutines
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	// Report all errors
	for _, err := range errors {
		t.Error(err)
	}
}

// TestDSCPValues tests different DSCP values in test sessions
func TestDSCPValues(t *testing.T) {
	// Test common DSCP values (RFC 5357: server MUST use DSCP from Type-P Descriptor)
	dscpValues := []struct {
		value uint8
		name  string
	}{
		{0x00, "BE_BestEffort"},      // CS0: Best Effort
		{0x08, "CS1_Scavenger"},       // CS1: Scavenger
		{0x0A, "AF11_LowPriority"},    // AF11: Low priority data
		{0x12, "AF21_HighPriority"},   // AF21: High priority data
		{0x1A, "AF31_Streaming"},      // AF31: Multimedia streaming
		{0x22, "AF41_Conferencing"},   // AF41: Multimedia conferencing
		{0x2E, "EF_ExpeditedForward"}, // EF: Expedited Forwarding (low latency)
		{0x30, "CS6_NetworkControl"},  // CS6: Network control
	}

	for _, dscp := range dscpValues {
		t.Run(dscp.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
			defer cleanup()

			// Connect to server
			err := twampClient.Connect(ctx)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}

			ports := testutil.GetFreePorts(t, "udp", 2)
			sessionConfig := client.TestSessionConfig{
				SenderPort:    uint16(ports[0]),
				ReceiverPort:  uint16(ports[1]),
				PaddingLength: 41,
				Timeout:       2 * time.Second,
				DSCP:          dscp.value,
			}

			session, err := twampClient.RequestSession(sessionConfig)
			if err != nil {
				t.Fatalf("Failed to request session with DSCP %d (%s): %v", dscp.value, dscp.name, err)
			}

			// Start session
			err = twampClient.StartSessions()
			if err != nil {
				t.Fatalf("Failed to start session with DSCP %d (%s): %v", dscp.value, dscp.name, err)
			}

			// Start receiving
			session.StartReceiving(ctx)

			// Send a test packet
			err = session.SendTestPacket()
			if err != nil {
				t.Errorf("Failed to send packet with DSCP %d (%s): %v", dscp.value, dscp.name, err)
			}

			// Wait for response
			require.Eventually(t, func() bool {
				results := session.GetResults()
				return results.PacketsReceived >= 1
			}, 5*time.Second, 50*time.Millisecond,
				fmt.Sprintf("Timeout waiting for DSCP %d (%s) packet", dscp.value, dscp.name))

			// Check results
			results := session.GetResults()
			if results.PacketsSent != 1 {
				t.Errorf("DSCP %d (%s): Expected 1 packet sent, got %d", dscp.value, dscp.name, results.PacketsSent)
			}

			// Stop session
			err = twampClient.StopSessions()
			if err != nil {
				t.Errorf("Failed to stop session with DSCP %d (%s): %v", dscp.value, dscp.name, err)
			}
		})
	}
}

// TestLargePackets tests handling of packets with maximum padding
func TestLargePackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Request session with large padding
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 1400, // Large padding
		Timeout:       2 * time.Second,
		DSCP:          0,
	}

	session, err := twampClient.RequestSession(sessionConfig)
	if err != nil {
		t.Fatalf("Failed to request session with large padding: %v", err)
	}

	// Start session
	err = twampClient.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Start receiving
	session.StartReceiving(ctx)

	// Send test packets
	packetsToSend := 3
	for i := 0; i < packetsToSend; i++ {
		err = session.SendTestPacket()
		if err != nil {
			t.Errorf("Failed to send large packet %d: %v", i, err)
		}
	}

	// Wait for responses
	require.Eventually(t, func() bool {
		results := session.GetResults()
		return results.PacketsReceived >= uint32(packetsToSend-1)
	}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for large packets")

	// Get results
	results := session.GetResults()

	// Verify results
	if results.PacketsSent != uint32(packetsToSend) {
		t.Errorf("Expected %d packets sent, got %d", packetsToSend, results.PacketsSent)
	}

	if results.PacketsReceived == 0 {
		t.Error("No large packets received")
	}

	// Stop session
	err = twampClient.StopSessions()
	if err != nil {
		t.Errorf("Failed to stop session: %v", err)
	}
}

// TestSessionRestart tests stopping and restarting sessions
func TestSessionRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	// Connect to server
	err := twampClient.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// First session
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig := client.TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		PaddingLength: 41,
		Timeout:       2 * time.Second,
		DSCP:          0,
	}

	session1, err := twampClient.RequestSession(sessionConfig)
	if err != nil {
		t.Fatalf("Failed to request first session: %v", err)
	}

	// Start first session
	err = twampClient.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start first session: %v", err)
	}

	session1.StartReceiving(ctx)

	// Send packets in first session
	for i := 0; i < 2; i++ {
		err = session1.SendTestPacket()
		if err != nil {
			t.Errorf("Failed to send packet in first session: %v", err)
		}
	}

	// Wait for first session packets
	require.Eventually(t, func() bool {
		results := session1.GetResults()
		return results.PacketsReceived >= 1
	}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for first session packets")

	// Stop first session
	err = twampClient.StopSessions()
	if err != nil {
		t.Errorf("Failed to stop first session: %v", err)
	}

	// Request second session with different ports - verifies cleanup completed
	ports2 := testutil.GetFreePorts(t, "udp", 2)
	sessionConfig2 := client.TestSessionConfig{
		SenderPort:    uint16(ports2[0]),
		ReceiverPort:  uint16(ports2[1]),
		PaddingLength: 41,
		Timeout:       2 * time.Second,
		DSCP:          0,
	}

	session2, err := twampClient.RequestSession(sessionConfig2)
	if err != nil {
		t.Fatalf("Failed to request second session: %v", err)
	}

	// Start second session
	err = twampClient.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start second session: %v", err)
	}

	session2.StartReceiving(ctx)

	// Send packets in second session
	for i := 0; i < 2; i++ {
		err = session2.SendTestPacket()
		if err != nil {
			t.Errorf("Failed to send packet in second session: %v", err)
		}
	}

	// Wait for second session packets
	require.Eventually(t, func() bool {
		results := session2.GetResults()
		return results.PacketsReceived >= 1
	}, 5*time.Second, 50*time.Millisecond, "Timeout waiting for second session packets")

	// Check results for both sessions
	results1 := session1.GetResults()
	if results1.PacketsSent != 2 {
		t.Errorf("First session: Expected 2 packets sent, got %d", results1.PacketsSent)
	}

	results2 := session2.GetResults()
	if results2.PacketsSent != 2 {
		t.Errorf("Second session: Expected 2 packets sent, got %d", results2.PacketsSent)
	}

	// Stop second session
	err = twampClient.StopSessions()
	if err != nil {
		t.Errorf("Failed to stop second session: %v", err)
	}
}
