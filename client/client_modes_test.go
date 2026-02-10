package client

import (
	"net"
	"testing"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
)

// TestRequestSession_AuthenticatedHMACBranch tests authenticated mode HMAC branch
func TestRequestSession_AuthenticatedHMACBranch(t *testing.T) {
	setup := setupAuthenticatedClient(t)
	defer setup.Close()

	_ = setupClientSession(t, setup.Client)

	// Verify HMAC was used
	if len(setup.Server.receivedHMACs) == 0 {
		t.Error("Expected HMAC to be received for authenticated mode")
	}
}

// TestRequestSessionIndividual_IPv6Path tests IPv6 address handling
func TestRequestSessionIndividual_IPv6Path(t *testing.T) {
	// Check if IPv6 is available
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("IPv6 not available")
	}
	conn.Close()

	setup := setupUnauthenticatedClient(t)
	defer setup.Close()

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 200)
	}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "::1", // IPv6 localhost
		PaddingLength:   64,
		Timeout:         defaultSessionConfig().Timeout,
	}

	// Request session with IPv6 - tests IPv6 path in RequestSessionIndividual
	session, err := setup.Client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Fatalf("Failed to request IPv6 session: %v", err)
	}

	if session == nil {
		t.Fatal("Session is nil")
	}
}

// TestStopNSessions_AuthenticatedMode tests StopNSessions with HMAC
func TestStopNSessions_AuthenticatedMode(t *testing.T) {
	setup := setupAuthenticatedClient(t)
	defer setup.Close()

	// Request 2 sessions
	for i := 0; i < 2; i++ {
		_ = setupClientSession(t, setup.Client)
	}

	err := setup.Client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Stop 1 session - tests HMAC path in StopNSessions
	err = setup.Client.StopNSessions(1)
	if err != nil {
		t.Fatalf("Failed to stop N sessions: %v", err)
	}

	// Verify HMAC was used
	if len(setup.Server.receivedHMACs) < 3 {
		t.Errorf("Expected at least 3 HMACs, got %d", len(setup.Server.receivedHMACs))
	}
}

// TestGetSessionIDs_Multiple tests GetSessionIDs with multiple sessions
func TestGetSessionIDs_Multiple(t *testing.T) {
	setup := setupUnauthenticatedClient(t)
	defer setup.Close()

	// Request 3 sessions
	for i := 0; i < 3; i++ {
		_ = setupClientSession(t, setup.Client)
	}

	// Get all session IDs
	sids := setup.Client.GetSessionIDs()
	if len(sids) != 3 {
		t.Errorf("Expected 3 session IDs, got %d", len(sids))
	}
}

// TestClose_NilConnection tests Close with nil connection
func TestClose_NilConnection(t *testing.T) {
	client := NewClient(ClientConfig{})

	// Close without connecting (conn is nil)
	err := client.Close()
	if err != nil {
		t.Errorf("Close with nil connection should not error: %v", err)
	}
}

// TestNegotiateMode_ModeCombinations tests various mode combinations
func TestNegotiateMode_ModeCombinations(t *testing.T) {
	tests := []struct {
		name            string
		serverModes     common.Mode
		clientMode      common.Mode
		expectedMode    common.Mode
		needsSecret     bool
		description     string
	}{
		{
			name:         "Prefer unauthenticated when available",
			serverModes:  common.ModeUnauthenticated | common.ModeAuthenticated,
			clientMode:   common.ModeUnauthenticated,
			expectedMode: common.ModeUnauthenticated,
			needsSecret:  false,
			description:  "Client wants unauthenticated, server supports it",
		},
		{
			name:         "Fallback to authenticated",
			serverModes:  common.ModeAuthenticated | common.ModeEncrypted,
			clientMode:   common.ModeAuthenticated | common.ModeUnauthenticated,
			expectedMode: common.ModeAuthenticated,
			needsSecret:  true,
			description:  "Server doesn't support unauthenticated, use authenticated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sharedSecret, keyID string
			if tt.needsSecret {
				sharedSecret = "test-password"
				keyID = "test-user"
			}

			setup := setupClientWithServerAndClientModes(t, tt.serverModes, tt.clientMode, sharedSecret, keyID)
			defer setup.Close()

			// Extract base security mode for comparison
			securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
			clientBaseSecurity := setup.Client.mode & securityMask
			expectedBaseSecurity := tt.expectedMode & securityMask

			if clientBaseSecurity != expectedBaseSecurity {
				t.Errorf("Expected mode %d, got %d for %s",
					expectedBaseSecurity, clientBaseSecurity, tt.description)
			}
		})
	}
}

// TestServerGreeting_MarshalPath tests greeting parsing with valid data
func TestServerGreeting_MarshalPath(t *testing.T) {
	setup := setupUnauthenticatedClient(t)
	defer setup.Close()

	// Verify greeting was received and parsed
	setup.Server.mu.Lock()
	greetingSent := setup.Server.greetingSent
	setup.Server.mu.Unlock()

	if !greetingSent {
		t.Error("Server did not send greeting")
	}
}

// TestRequestSession_EncryptedHMACBranch tests encrypted mode HMAC branch
func TestRequestSession_EncryptedHMACBranch(t *testing.T) {
	setup := setupEncryptedClient(t)
	defer setup.Close()

	cfg := sessionConfig{
		PaddingLength: 144,
		Timeout:       defaultSessionConfig().Timeout,
	}
	_ = setupClientSessionWithConfig(t, setup.Client, cfg)

	// Verify HMAC was used
	if len(setup.Server.receivedHMACs) == 0 {
		t.Error("Expected HMAC to be received for encrypted mode")
	}
}

// TestStartSessions_SessionLoop tests the session starting loop
func TestStartSessions_SessionLoop(t *testing.T) {
	setup := setupUnauthenticatedClient(t)
	defer setup.Close()

	// Request 5 sessions to test the loop
	for i := 0; i < 5; i++ {
		_ = setupClientSession(t, setup.Client)
	}

	// Start all sessions - tests the loop
	err := setup.Client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify all sessions were started
	setup.Server.sessionsMu.Lock()
	startedCount := 0
	for _, session := range setup.Server.sessions {
		if session.isStarted {
			startedCount++
		}
	}
	setup.Server.sessionsMu.Unlock()

	if startedCount != 5 {
		t.Errorf("Expected 5 started sessions, got %d", startedCount)
	}
}

// TestStopSessions_MultipleSessionsLoop tests stopping multiple sessions
func TestStopSessions_MultipleSessionsLoop(t *testing.T) {
	setup := setupUnauthenticatedClient(t)
	defer setup.Close()

	// Request 5 sessions
	for i := 0; i < 5; i++ {
		_ = setupClientSession(t, setup.Client)
	}

	err := setup.Client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Stop all sessions - tests the stopping loop
	err = setup.Client.StopSessions()
	if err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}

	// Verify all sessions were cleaned up
	if len(setup.Client.currentSessions) != 0 {
		t.Errorf("Expected 0 sessions after stop, got %d", len(setup.Client.currentSessions))
	}
}

// TestNegotiateMode_ServerStartAcceptOK tests ServerStart acceptance path
func TestNegotiateMode_ServerStartAcceptOK(t *testing.T) {
	setup := setupUnauthenticatedClient(t)
	defer setup.Close()

	// Verify connection succeeded (ServerStart was accepted)
	if setup.Client.conn == nil {
		t.Error("Connection should be established")
	}
}

// TestRequestSessionIndividual_AllBranches tests all code paths
func TestRequestSessionIndividual_AllBranches(t *testing.T) {
	setup := setupUnauthenticatedClient(t)
	defer setup.Close()

	// Test with explicit timeout
	var sid1 common.SessionID
	for i := range sid1 {
		sid1[i] = byte(i + 210)
	}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         2 * defaultSessionConfig().Timeout, // Explicit longer timeout
	}

	session1, err := setup.Client.RequestSessionIndividual(sessionCfg, sid1)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}
	if session1 == nil {
		t.Fatal("Session is nil")
	}
}
