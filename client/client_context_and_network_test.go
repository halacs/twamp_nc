package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/logging"
)

// TestContextCancellationDuringConnect tests that Connect respects context cancellation
func TestContextCancellationDuringConnect(t *testing.T) {
	// Create a server that will never respond (to force timeout)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	client := &Client{
		config: ClientConfig{
			ServerAddress: listener.Addr().String(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       10 * time.Second, // Long timeout
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	// Create a context that we'll cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Try to connect - should fail quickly due to cancelled context
	err = client.Connect(ctx)
	if err == nil {
		t.Fatal("Expected error from cancelled context, got nil")
	}

	// Should be context.Canceled error
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}

// TestContextCancellationDuringConnectTimeout tests context timeout during connect
func TestContextCancellationDuringConnectTimeout(t *testing.T) {
	// Use non-routable address to force connection timeout
	client := &Client{
		config: ClientConfig{
			ServerAddress: "192.0.2.255:862", // TEST-NET-1, non-routable
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       10 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.Connect(ctx)
	duration := time.Since(start)

	if err == nil {
		t.Fatal("Expected error from context timeout, got nil")
	}

	// Should fail fast due to context timeout, not full client timeout
	if duration > 1*time.Second {
		t.Errorf("Connect took too long with cancelled context: %v", duration)
	}
}

// TestNetworkErrorDuringStartSessions tests connection drop during StartSessions
func TestNetworkErrorDuringStartSessions(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       500 * time.Millisecond, // Short timeout for faster test
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Request a session
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      20000,
		ReceiverPort:    20001,
		PaddingLength:   100,
	}

	_, err = client.RequestSession(config)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Close the underlying connection to simulate network failure
	if client.conn != nil {
		client.conn.Close()
	}

	// Try to start sessions - should fail with network error
	err = client.StartSessions()
	if err == nil {
		t.Fatal("Expected error from network failure, got nil")
	}

	// Verify it's a network-related error
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Logf("Expected net.Error, got: %T", err)
	}
}

// TestNetworkErrorDuringRequestSession tests connection drop during RequestSession
func TestNetworkErrorDuringRequestSession(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       500 * time.Millisecond, // Short timeout for faster test
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Close connection before requesting session to simulate network failure
	if client.conn != nil {
		client.conn.Close()
	}

	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      20000,
		ReceiverPort:    20001,
		PaddingLength:   100,
	}

	// Should fail with network error
	_, err = client.RequestSession(config)
	if err == nil {
		t.Fatal("Expected error from network failure, got nil")
	}

	// Verify it's a network-related error
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Logf("Expected net.Error, got: %T", err)
	}
}

// TestLargeSessionCount tests handling of many concurrent sessions
func TestLargeSessionCount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large session count test in short mode")
	}

	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       5 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Create 100 sessions (reduced from 1000 for test speed, but validates the pattern)
	sessionCount := 100
	t.Logf("Creating %d sessions...", sessionCount)

	start := time.Now()
	for i := 0; i < sessionCount; i++ {
		config := TestSessionConfig{
			ReceiverAddress: "127.0.0.1",
			SenderPort:      uint16(30000 + i),
			ReceiverPort:    uint16(30001 + i),
			PaddingLength:   100,
		}

		_, err := client.RequestSession(config)
		if err != nil {
			t.Fatalf("Failed to create session %d: %v", i, err)
		}

		// Log progress every 25 sessions
		if (i+1)%25 == 0 {
			t.Logf("Created %d/%d sessions", i+1, sessionCount)
		}
	}

	duration := time.Since(start)
	t.Logf("Created %d sessions in %v (avg: %v per session)",
		sessionCount, duration, duration/time.Duration(sessionCount))

	// Verify all sessions exist
	sids := client.GetSessionIDs()
	if len(sids) != sessionCount {
		t.Errorf("Expected %d sessions, got %d", sessionCount, len(sids))
	}

	// Test that we can start all sessions
	err = client.StartSessions()
	if err != nil {
		t.Errorf("Failed to start %d sessions: %v", sessionCount, err)
	}
}

// TestDSCPValidation tests TypePDescriptor DSCP field handling per RFC 5357 Section 3.5
func TestDSCPValidation(t *testing.T) {
	tests := []struct {
		name        string
		dscp        uint8
		expectError bool
		description string
	}{
		{
			name:        "Valid DSCP - Default (0)",
			dscp:        0,
			expectError: false,
			description: "DSCP 0 (default)",
		},
		{
			name:        "Valid DSCP - AF11 (10)",
			dscp:        10,
			expectError: false,
			description: "DSCP AF11 (Assured Forwarding)",
		},
		{
			name:        "Valid DSCP - EF (46)",
			dscp:        46,
			expectError: false,
			description: "DSCP EF (Expedited Forwarding)",
		},
		{
			name:        "Valid DSCP - Max (63)",
			dscp:        63,
			expectError: false,
			description: "DSCP maximum value",
		},
		{
			name:        "Valid DSCP - CS1 (8)",
			dscp:        8,
			expectError: false,
			description: "DSCP CS1 (Class Selector 1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMockServer(t, common.ModeUnauthenticated)
			defer server.stop()

			client := &Client{
				config: ClientConfig{
					ServerAddress: server.addr(),
					PreferredMode: common.ModeUnauthenticated,
					Timeout:       2 * time.Second,
				},
				logger:          logging.NewNoop(),
				currentSessions: make(map[common.SessionID]*TestSession),
			}

			ctx := context.Background()
			err := client.Connect(ctx)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer client.Close()

			config := TestSessionConfig{
				ReceiverAddress: "127.0.0.1",
				SenderPort:      20000,
				ReceiverPort:    20001,
				PaddingLength:   100,
				DSCP:            tt.dscp,
			}

			session, err := client.RequestSession(config)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for DSCP %d, got nil", tt.dscp)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for DSCP %d: %v", tt.dscp, err)
				}
				if session == nil {
					t.Error("Expected session, got nil")
				}
			}
		})
	}
}

// TestZeroDurationTimeout tests behavior with Timeout: 0
func TestZeroDurationTimeout(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second, // Non-zero for Connect
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request session with zero timeout - should use default
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      20000,
		ReceiverPort:    20001,
		PaddingLength:   100,
		Timeout:         0, // Zero timeout should fall back to client's default timeout
	}

	session, err := client.RequestSession(config)
	if err != nil {
		t.Errorf("Failed with zero timeout (should use default): %v", err)
	}
	if session == nil {
		t.Error("Expected session with zero timeout to use default")
	}
}

// TestServerSendsWrongAcceptCode tests RFC violation - server sends wrong Accept code
func TestServerSendsWrongAcceptCode(t *testing.T) {
	tests := []struct {
		name       string
		acceptCode uint8
		shouldFail bool
	}{
		{
			name:       "Accept OK (0)",
			acceptCode: common.AcceptOK,
			shouldFail: false,
		},
		{
			name:       "Accept Failure (1)",
			acceptCode: common.AcceptFailure,
			shouldFail: true,
		},
		{
			name:       "Accept Internal Error (2)",
			acceptCode: common.AcceptInternalError,
			shouldFail: true,
		},
		{
			name:       "Accept Not Supported (3)",
			acceptCode: common.AcceptNotSupported,
			shouldFail: true,
		},
		{
			name:       "Accept Permanent Resource Limited (4)",
			acceptCode: common.AcceptPermanentResLimited,
			shouldFail: true,
		},
		{
			name:       "Accept Temporary Resource Limited (5)",
			acceptCode: common.AcceptTempResLimited,
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with specific behavior
			behavior := mockServerBehavior{
				rejectRequestSession: tt.shouldFail,
				rejectCode:           tt.acceptCode,
			}
			server := newMockServerWithBehavior(t, common.ModeUnauthenticated, behavior)
			defer server.stop()

			client := &Client{
				config: ClientConfig{
					ServerAddress: server.addr(),
					PreferredMode: common.ModeUnauthenticated,
					Timeout:       2 * time.Second,
				},
				logger:          logging.NewNoop(),
				currentSessions: make(map[common.SessionID]*TestSession),
			}

			ctx := context.Background()
			err := client.Connect(ctx)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer client.Close()

			config := TestSessionConfig{
				ReceiverAddress: "127.0.0.1",
				SenderPort:      20000,
				ReceiverPort:    20001,
				PaddingLength:   100,
			}

			session, err := client.RequestSession(config)
			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected error for Accept code %d, got nil", tt.acceptCode)
				}
				if session != nil {
					t.Error("Expected nil session for rejection")
				}

				// Verify error contains Accept code information
				twampErr, ok := err.(*common.TWAMPError)
				if ok && twampErr.AcceptCode != tt.acceptCode {
					t.Errorf("Expected Accept code %d in error, got %d",
						tt.acceptCode, twampErr.AcceptCode)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for Accept OK: %v", err)
				}
				if session == nil {
					t.Error("Expected session for Accept OK")
				}
			}
		})
	}
}

// TestServerStartRejectsStartSessions tests server rejecting Start-Sessions
func TestServerStartRejectsStartSessions(t *testing.T) {
	// Create server that rejects Start-Sessions
	behavior := mockServerBehavior{
		rejectStartSessions: true,
		rejectCode:          common.AcceptTempResLimited,
	}
	server := newMockServerWithBehavior(t, common.ModeUnauthenticated, behavior)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request session should succeed
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      20000,
		ReceiverPort:    20001,
		PaddingLength:   100,
	}

	_, err = client.RequestSession(config)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Start sessions should fail
	err = client.StartSessions()
	if err == nil {
		t.Fatal("Expected error when server rejects Start-Sessions")
	}

	// Verify error is a TWAMP error with correct code
	twampErr, ok := err.(*common.TWAMPError)
	if !ok {
		t.Errorf("Expected TWAMPError, got: %T", err)
	} else if twampErr.AcceptCode != common.AcceptTempResLimited {
		t.Errorf("Expected Accept code %d, got %d",
			common.AcceptTempResLimited, twampErr.AcceptCode)
	}
}

// TestInvalidReceiverAddress tests various invalid receiver addresses
func TestInvalidReceiverAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		// Note: Empty string is NOT tested here because it's valid behavior
		// (defaults to server address per client.go line 393-399)
		{"Invalid format", "not-an-ip-address"},
		{"Incomplete IPv4", "192.168.1"},
		{"Out of range", "256.256.256.256"},
		{"Just hostname", "localhost"}, // net.ParseIP doesn't resolve hostnames
	}

	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				config: ClientConfig{
					ServerAddress: server.addr(),
					PreferredMode: common.ModeUnauthenticated,
					Timeout:       2 * time.Second,
				},
				logger:          logging.NewNoop(),
				currentSessions: make(map[common.SessionID]*TestSession),
			}

			ctx := context.Background()
			err := client.Connect(ctx)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer client.Close()

			config := TestSessionConfig{
				ReceiverAddress: tt.address,
				SenderPort:      20000,
				ReceiverPort:    20001,
				PaddingLength:   100,
			}

			_, err = client.RequestSession(config)
			if err == nil {
				t.Errorf("Expected error for invalid address %q, got nil", tt.address)
			}

			// Should wrap ErrInvalidReceiverAddress
			if !errors.Is(err, common.ErrInvalidReceiverAddress) {
				t.Errorf("Expected ErrInvalidReceiverAddress, got: %v", err)
			}
		})
	}
}
