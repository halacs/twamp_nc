package client

import (
	"context"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/logging"
)

// TestConnectWithDefaultPort tests connecting when server address has no port
func TestConnectWithDefaultPort(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Extract just the host from the server address (remove port)
	host := "127.0.0.1"

	client := &Client{
		config: ClientConfig{
			ServerAddress: host, // No port specified - should default to 862
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()

	// This will try to connect to 127.0.0.1:862 which won't work,
	// but it tests the port defaulting code path
	err := client.Connect(ctx)
	// We expect an error since we're not actually listening on :862
	if err == nil {
		t.Fatal("Expected connection error, got nil")
	}
}

// TestRequestSessionIndividualWithMixedMode tests RequestSessionIndividual with mixed security mode
func TestRequestSessionIndividualWithMixedMode(t *testing.T) {
	// Test with mixed mode (authenticated control, unauthenticated test)
	mode := common.Mode(common.ModeMixed | common.ModeAuthenticated)
	server := newMockServer(t, mode)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: mode,
			SharedSecret:  "test-password",
			KeyID:         "test-user",
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

	// Request an individual session
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      20000,
		ReceiverPort:    20001,
		PaddingLength:   100,
	}

	sid := common.SessionID{0x01, 0x02, 0x03, 0x04}
	session, err := client.RequestSessionIndividual(config, sid)
	if err != nil {
		t.Fatalf("Failed to request individual session: %v", err)
	}
	if session == nil {
		t.Fatal("Expected session, got nil")
	}
}

// TestRequestSessionIndividualDuplicateSID tests error when requesting with duplicate SID
func TestRequestSessionIndividualDuplicateSID(t *testing.T) {
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
	}

	sid := common.SessionID{0x01, 0x02, 0x03, 0x04}

	// Request first session
	_, err = client.RequestSessionIndividual(config, sid)
	if err != nil {
		t.Fatalf("Failed to request first session: %v", err)
	}

	// Try to request with same SID - should fail
	_, err = client.RequestSessionIndividual(config, sid)
	if err == nil {
		t.Fatal("Expected error for duplicate SID, got nil")
	}
}

// TestRequestSessionWithIPv6 tests RequestSession with IPv6 address
func TestRequestSessionWithIPv6(t *testing.T) {
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

	// Request session with IPv6 address
	config := TestSessionConfig{
		ReceiverAddress: "::1", // IPv6 localhost
		SenderPort:      20000,
		ReceiverPort:    20001,
		PaddingLength:   100,
	}

	session, err := client.RequestSession(config)
	if err != nil {
		t.Fatalf("Failed to request session with IPv6: %v", err)
	}
	if session == nil {
		t.Fatal("Expected session, got nil")
	}
}

// TestRequestSessionPaddingAdjustment tests padding adjustment for different modes using RequestSession
func TestRequestSessionPaddingAdjustment(t *testing.T) {
	tests := []struct {
		name           string
		mode           common.Mode
		inputPadding   uint32
		sharedSecret   string
	}{
		{
			name:         "Authenticated mode with small padding",
			mode:         common.ModeAuthenticated,
			inputPadding: 10, // Too small - should be adjusted to 56
			sharedSecret: "test-password",
		},
		{
			name:         "Encrypted mode with small padding",
			mode:         common.ModeEncrypted,
			inputPadding: 50, // Too small - should be adjusted to 56
			sharedSecret: "test-password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMockServer(t, tt.mode)
			defer server.stop()

			client := &Client{
				config: ClientConfig{
					ServerAddress: server.addr(),
					PreferredMode: tt.mode,
					SharedSecret:  tt.sharedSecret,
					KeyID:         "test-user",
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
				PaddingLength:   tt.inputPadding,
			}

			// Use RequestSession instead of RequestSessionIndividual
			session, err := client.RequestSession(config)
			if err != nil {
				t.Fatalf("Failed to request session: %v", err)
			}
			if session == nil {
				t.Fatal("Expected session, got nil")
			}
		})
	}
}

// TestRequestSessionDefaultReceiverAddress tests using default receiver address
func TestRequestSessionDefaultReceiverAddress(t *testing.T) {
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

	// Request session without specifying ReceiverAddress (should default to server host)
	config := TestSessionConfig{
		ReceiverAddress: "", // Empty - should use server address
		SenderPort:      20000,
		ReceiverPort:    20001,
		PaddingLength:   100,
	}

	session, err := client.RequestSession(config)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}
	if session == nil {
		t.Fatal("Expected session, got nil")
	}
}

// TestStopNSessionsWithMultiple tests StopNSessions with N > 1
func TestStopNSessionsWithMultiple(t *testing.T) {
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

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		config := TestSessionConfig{
			ReceiverAddress: "127.0.0.1",
			SenderPort:      uint16(20000 + i),
			ReceiverPort:    uint16(20001 + i),
			PaddingLength:   100,
		}

		_, err := client.RequestSession(config)
		if err != nil {
			t.Fatalf("Failed to request session %d: %v", i, err)
		}
	}

	// Stop 2 sessions
	err = client.StopNSessions(2)
	if err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}
}

// TestCloseWithNoConnection tests Close when connection is nil
func TestCloseWithNoConnection(t *testing.T) {
	client := &Client{
		conn:            nil, // No connection
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          logging.NewNoop(),
	}

	err := client.Close()
	if err != nil {
		t.Errorf("Expected successful close with nil connection, got error: %v", err)
	}
}

// TestStartSessionWithIndividualSession tests StartSession on individually requested session
func TestStartSessionWithIndividualSession(t *testing.T) {
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

	// Request an individual session
	// Use port 31000+ to avoid conflicts with:
	// - Ephemeral port range (32768-60999 on Linux)
	// - Common service ports (0-1024)
	// - Other test suites (20000-29999)
	// - Server test port allocation (30000)
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      31000,
		ReceiverPort:    31001,
		PaddingLength:   100,
	}

	sid := common.SessionID{0x01, 0x02, 0x03, 0x04}
	session, err := client.RequestSessionIndividual(config, sid)
	if err != nil {
		t.Fatalf("Failed to request individual session: %v", err)
	}
	if session == nil {
		t.Fatal("Expected session, got nil")
	}

	// Start the specific session
	err = client.StartSession(sid)
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
}

// TestStartSessionNotFound tests error when starting non-existent session
func TestStartSessionNotFound(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          logging.NewNoop(),
	}

	sid := common.SessionID{0x01, 0x02, 0x03, 0x04}
	err := client.StartSession(sid)
	if err == nil {
		t.Fatal("Expected error for non-existent session, got nil")
	}
}

// TestStopNSessionsWithIndividualSessions tests StopNSessions with individual sessions
func TestStopNSessionsWithIndividualSessions(t *testing.T) {
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

	// Create multiple individual sessions
	for i := 0; i < 3; i++ {
		config := TestSessionConfig{
			ReceiverAddress: "127.0.0.1",
			SenderPort:      uint16(20000 + i),
			ReceiverPort:    uint16(20001 + i),
			PaddingLength:   100,
		}

		sid := common.SessionID{byte(i), 0, 0, 0}
		_, err := client.RequestSessionIndividual(config, sid)
		if err != nil {
			t.Fatalf("Failed to request session %d: %v", i, err)
		}
	}

	// Stop 2 sessions
	err = client.StopNSessions(2)
	if err != nil {
		t.Fatalf("Failed to stop N sessions: %v", err)
	}
}
