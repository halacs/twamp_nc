package client

import (
	"context"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
)

// testClientSetup encapsulates a client and mock server for testing
type testClientSetup struct {
	Client *Client
	Server *mockServer
	ctx    context.Context
}

// Close tears down the test setup
func (tcs *testClientSetup) Close() {
	if tcs.Client != nil {
		tcs.Client.Close()
	}
	if tcs.Server != nil {
		tcs.Server.stop()
	}
}

// setupUnauthenticatedClient creates a client connected to a mock server in unauthenticated mode
func setupUnauthenticatedClient(t *testing.T) *testClientSetup {
	t.Helper()
	return setupClientWithMode(t, common.ModeUnauthenticated, "", "")
}

// setupAuthenticatedClient creates a client connected to a mock server in authenticated mode
func setupAuthenticatedClient(t *testing.T) *testClientSetup {
	t.Helper()
	return setupClientWithMode(t, common.ModeAuthenticated, "test-password", "test-user")
}

// setupEncryptedClient creates a client connected to a mock server in encrypted mode
func setupEncryptedClient(t *testing.T) *testClientSetup {
	t.Helper()
	return setupClientWithMode(t, common.ModeEncrypted, "test-password", "test-user")
}

// setupClientWithMode creates a client connected to a mock server with specified mode
func setupClientWithMode(t *testing.T, mode common.Mode, sharedSecret, keyID string) *testClientSetup {
	t.Helper()

	server := newMockServer(t, mode)

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: mode,
		SharedSecret:  sharedSecret,
		KeyID:         keyID,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		server.stop()
		t.Fatalf("Failed to connect: %v", err)
	}

	return &testClientSetup{
		Client: client,
		Server: server,
		ctx:    ctx,
	}
}

// setupClientWithServerAndClientModes creates a client with different server and client modes
// Used for testing mode negotiation where server supports different modes than client prefers
func setupClientWithServerAndClientModes(t *testing.T, serverModes, clientMode common.Mode, sharedSecret, keyID string) *testClientSetup {
	t.Helper()

	server := newMockServer(t, serverModes)

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: clientMode,
		SharedSecret:  sharedSecret,
		KeyID:         keyID,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		server.stop()
		t.Fatalf("Failed to connect: %v", err)
	}

	return &testClientSetup{
		Client: client,
		Server: server,
		ctx:    ctx,
	}
}

// setupClientWithBehavior creates a client connected to a mock server with custom behavior
func setupClientWithBehavior(t *testing.T, mode common.Mode, behavior mockServerBehavior, sharedSecret, keyID string) *testClientSetup {
	t.Helper()

	server := newMockServerWithBehavior(t, mode, behavior)

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: mode,
		SharedSecret:  sharedSecret,
		KeyID:         keyID,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		server.stop()
		t.Fatalf("Failed to connect: %v", err)
	}

	return &testClientSetup{
		Client: client,
		Server: server,
		ctx:    ctx,
	}
}

// sessionConfig holds session configuration parameters
type sessionConfig struct {
	PaddingLength uint32
	Timeout       time.Duration
	DSCP          uint8
}

// defaultSessionConfig returns a session config with common defaults
func defaultSessionConfig() sessionConfig {
	return sessionConfig{
		PaddingLength: 64,
		Timeout:       1 * time.Second,
		DSCP:          0,
	}
}

// setupClientSession requests a session from the client with default configuration
func setupClientSession(t *testing.T, client *Client) *TestSession {
	t.Helper()
	return setupClientSessionWithConfig(t, client, defaultSessionConfig())
}

// setupClientSessionWithConfig requests a session from the client with custom configuration
func setupClientSessionWithConfig(t *testing.T, client *Client, cfg sessionConfig) *TestSession {
	t.Helper()

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   cfg.PaddingLength,
		Timeout:         cfg.Timeout,
		DSCP:            cfg.DSCP,
	}

	session, err := client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	return session
}

// setupTestSession creates a test session directly (without client/server) in unauthenticated mode
func setupTestSession(t *testing.T) *TestSession {
	t.Helper()
	return setupTestSessionWithMode(t, common.ModeUnauthenticated, 64)
}

// setupTestSessionWithMode creates a test session directly with specified mode and padding
func setupTestSessionWithMode(t *testing.T, mode common.Mode, paddingLength uint32) *TestSession {
	t.Helper()

	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   paddingLength,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	var keys *crypto.TWAMPKeys
	if mode != common.ModeUnauthenticated {
		keys = createTestKeys()
	}

	session, err := NewTestSession(config, sid, mode, keys)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	return session
}

// createTestKeys creates a set of test crypto keys for authenticated/encrypted modes
func createTestKeys() *crypto.TWAMPKeys {
	keys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16),
		HMACKey:  make([]byte, 32),
		ClientIV: make([]byte, 16),
		ServerIV: make([]byte, 16),
	}
	for i := range keys.AESKey {
		keys.AESKey[i] = byte(i)
	}
	for i := range keys.HMACKey {
		keys.HMACKey[i] = byte(i + 16)
	}
	for i := range keys.ClientIV {
		keys.ClientIV[i] = byte(i + 48)
	}
	for i := range keys.ServerIV {
		keys.ServerIV[i] = byte(i + 64)
	}
	return keys
}

// setupSessionWithStart creates a test session and starts it
func setupSessionWithStart(t *testing.T, mode common.Mode, paddingLength uint32) *TestSession {
	t.Helper()
	session := setupTestSessionWithMode(t, mode, paddingLength)
	err := session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	t.Cleanup(func() {
		session.Stop()
	})
	return session
}
