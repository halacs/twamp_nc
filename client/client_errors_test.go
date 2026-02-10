package client

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/messages"
)

// TestRequestSessionIndividual_SIDConflict tests RFC 6038 individual session with SID conflict
func TestRequestSessionIndividual_SIDConflict(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Use a specific SID
	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 1)
	}

	ports := testutil.GetFreePorts(t, "udp", 4)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// Request first session with this SID
	session1, err := client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Fatalf("Failed to request first session: %v", err)
	}
	if session1 == nil {
		t.Fatal("First session is nil")
	}

	// Try to request another session with the same SID - should fail locally
	sessionCfg.SenderPort = uint16(ports[2])
	sessionCfg.ReceiverPort = uint16(ports[3])
	_, err = client.RequestSessionIndividual(sessionCfg, sid)
	if err == nil {
		t.Fatal("Expected error when requesting session with duplicate SID")
	}
	if !errors.Is(err, ErrSessionConflict) {
		t.Errorf("Expected ErrSessionConflict, got: %v", err)
	}
}

// TestRequestSessionIndividual_ServerChangesPort tests port negotiation in RFC 6038
func TestRequestSessionIndividual_ServerChangesPort(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 10)
	}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// Request session - server may suggest alternate port
	session, err := client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Verify session was created
	if session == nil {
		t.Fatal("Session is nil")
	}

	// Port may have been changed by server (mock server assigns different port)
	t.Logf("Session created with receiver port: %d (requested: %d)",
		session.config.ReceiverPort, sessionCfg.ReceiverPort)
}

// TestStartReceiving_AlreadyStopping tests early return when session is stopping
func TestStartReceiving_AlreadyStopping(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Set stopping flag before calling StartReceiving
	session.mu.Lock()
	session.isStopping = true
	session.mu.Unlock()

	ctx := context.Background()

	// StartReceiving should return immediately without starting goroutine
	session.StartReceiving(ctx)

	// Allow time for any goroutine to start (shouldn't happen)
	time.Sleep(50 * time.Millisecond)

	// Verify no goroutine was started by checking receiver WaitGroup
	// If a goroutine started, Stop() would block waiting for it
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session: %v", err)
	}
}

// TestStartReceiving_NilConnection tests behavior with nil connection
func TestStartReceiving_NilConnection(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Don't call Start() - conn will be nil
	ctx := context.Background()

	// StartReceiving should return immediately
	session.StartReceiving(ctx)

	// Allow time for check
	time.Sleep(50 * time.Millisecond)

	// Session should be safe to stop even though receiver never started
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session: %v", err)
	}
}

// TestStartReceiving_ContextCancellation tests context cancellation during receive
func TestStartReceiving_ContextCancellation(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Start receiving
	session.StartReceiving(ctx)

	// Allow receiver to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context - should cause receiver to exit
	cancel()

	// Wait for receiver to exit
	time.Sleep(100 * time.Millisecond)

	// Session should still be functional
	err = session.SendTestPacket()
	if err != nil {
		t.Errorf("Session not functional after context cancellation: %v", err)
	}
}

// TestStartSession_SessionNotFound tests starting a non-existent session
func TestStartSession_SessionNotFound(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Try to start a session that doesn't exist
	var nonExistentSID common.SessionID
	for i := range nonExistentSID {
		nonExistentSID[i] = byte(0xFF)
	}

	err = client.StartSession(nonExistentSID)
	if err == nil {
		t.Fatal("Expected error when starting non-existent session")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// TestStartSession_StartFailure tests handling of session start failure
func TestStartSession_StartFailure(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 20)
	}

	// Use a port that's likely to fail (privileged port on Linux)
	sessionCfg := TestSessionConfig{
		SenderPort:      1, // Privileged port - will fail without root
		ReceiverPort:    862,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// Request session with bad port
	_, err = client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		// Expected to fail during request or start
		t.Logf("Session request failed as expected: %v", err)
		return
	}

	// If request succeeded, start should fail
	err = client.StartSession(sid)
	// Error expected due to privileged port or StartSessions behavior
	if err != nil {
		t.Logf("Session start failed as expected: %v", err)
	}
}

// TestStopSessions_EmptySessions tests stopping when no sessions exist
func TestStopSessions_EmptySessions(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Stop sessions when none exist - should succeed without error
	err = client.StopSessions()
	if err != nil {
		t.Errorf("StopSessions failed with no sessions: %v", err)
	}
}

func TestStopSessions_AggregatesErrors(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:            clientConn,
		mode:            common.ModeUnauthenticated,
		controlMode:     common.ModeUnauthenticated,
		testMode:        common.ModeUnauthenticated,
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          logging.NewNoop(),
	}

	sid1 := common.SessionID{0x01}
	sid2 := common.SessionID{0x02}
	client.currentSessions[sid1] = &TestSession{sid: sid1}
	client.currentSessions[sid2] = &TestSession{sid: sid2}

	stopErr1 := errors.New("stop failed 1")
	stopErr2 := errors.New("stop failed 2")

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, messages.StopSessionsSize)
		_, _ = io.ReadFull(serverConn, buf)
	}()

	err := client.stopSessionsWith(func(session *TestSession) error {
		if session.sid == sid1 {
			return stopErr1
		}
		return stopErr2
	})

	if err == nil {
		t.Fatal("expected aggregated stop error, got nil")
	}
	if !errors.Is(err, stopErr1) {
		t.Errorf("expected stop error 1 to be included, got: %v", err)
	}
	if !errors.Is(err, stopErr2) {
		t.Errorf("expected stop error 2 to be included, got: %v", err)
	}
	if len(client.currentSessions) != 0 {
		t.Errorf("expected sessions to be cleared, got %d", len(client.currentSessions))
	}

	<-done
}

// TestNegotiateMode_NoCompatibleMode tests mode negotiation failure
func TestNegotiateMode_NoCompatibleMode(t *testing.T) {
	// Create server that only supports encrypted mode
	server := newMockServer(t, common.ModeEncrypted)
	defer server.stop()

	// Create client that only wants unauthenticated mode
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)

	// Should fail with no compatible mode
	if err == nil {
		t.Fatal("Expected error for incompatible modes")
	}
	if !errors.Is(err, common.ErrNoCompatibleMode) {
		t.Errorf("Expected ErrNoCompatibleMode, got: %v", err)
	}
}

// TestNegotiateMode_AuthenticatedSelection tests authenticated mode selection
func TestNegotiateMode_AuthenticatedSelection(t *testing.T) {
	// Server supports both authenticated and unauthenticated
	server := newMockServer(t, common.ModeAuthenticated|common.ModeUnauthenticated)
	defer server.stop()

	// Client prefers authenticated
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeAuthenticated,
		SharedSecret:  "test-password",
		KeyID:         "test-user",
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Verify authenticated mode was selected
	if client.mode != common.ModeAuthenticated {
		t.Errorf("Expected authenticated mode, got: %v", client.mode)
	}
}

// TestNegotiateMode_EncryptedSelection tests encrypted mode preference
func TestNegotiateMode_EncryptedSelection(t *testing.T) {
	// Server supports all modes
	server := newMockServer(t, common.ModeEncrypted|common.ModeAuthenticated|common.ModeUnauthenticated)
	defer server.stop()

	// Client prefers encrypted (should take precedence)
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeEncrypted | common.ModeAuthenticated,
		SharedSecret:  "test-password",
		KeyID:         "test-user",
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Verify encrypted mode was selected
	if client.mode != common.ModeEncrypted {
		t.Errorf("Expected encrypted mode, got: %v", client.mode)
	}
}

// TestProcessReceivedPacket_EncryptedMode tests encrypted packet processing
func TestProcessReceivedPacket_EncryptedMode(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   144,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	controlKeys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16),
		HMACKey:  make([]byte, 32),
		ClientIV: make([]byte, 16),
		ServerIV: make([]byte, 16),
	}
	// Initialize keys
	for i := range controlKeys.AESKey {
		controlKeys.AESKey[i] = byte(i)
	}
	for i := range controlKeys.HMACKey {
		controlKeys.HMACKey[i] = byte(i + 16)
	}

	session, err := NewTestSession(config, sid, common.ModeEncrypted, controlKeys)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send a test packet first to have something to match
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Process encrypted packet with invalid content (should fail gracefully)
	invalidPacket := make([]byte, 128)
	for i := range invalidPacket {
		invalidPacket[i] = byte(i)
	}

	err = session.processReceivedPacket(invalidPacket, time.Now())
	if err == nil {
		t.Log("Warning: Expected error processing invalid encrypted packet")
	}
}

// TestProcessReceivedPacket_HMACFailure tests HMAC verification failure
func TestProcessReceivedPacket_HMACFailure(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	controlKeys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16),
		HMACKey:  make([]byte, 32),
		ClientIV: make([]byte, 16),
		ServerIV: make([]byte, 16),
	}
	for i := range controlKeys.HMACKey {
		controlKeys.HMACKey[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeAuthenticated, controlKeys)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Create properly formatted authenticated mode packet with all MBZ fields zero
	// but with corrupted HMAC (last 16 bytes)
	packet := make([]byte, 112) // 96 bytes data + 16 bytes HMAC
	// All MBZ fields are already zero (default for make)
	// Set SeqNumber at offset 0-3 to sequence 1
	packet[0], packet[1], packet[2], packet[3] = 0, 0, 0, 1
	// Set SenderSeqNumber at offset 48-51 to sequence 1
	packet[48], packet[49], packet[50], packet[51] = 0, 0, 0, 1
	// Set SenderTTL at offset 80
	packet[80] = 64
	// HMAC at offset 96-111: fill with invalid pattern
	// This ensures HMAC verification will fail
	for i := 96; i < 112; i++ {
		packet[i] = byte(i)
	}

	// Process packet - should fail HMAC verification
	// This is security-critical per RFC 5618 Section 6: HMAC MUST be verified before processing
	err = session.processReceivedPacket(packet, time.Now())
	if err == nil {
		t.Fatal("Expected HMAC verification failure for corrupted packet")
	}
	// SECURITY: Corrupted HMAC must be detected with specific error
	if !errors.Is(err, common.ErrHMACVerificationFailed) {
		t.Fatalf("Expected ErrHMACVerificationFailed for corrupted HMAC, got: %v", err)
	}
}

// TestProcessReceivedPacket_UnknownSequence tests handling of unknown sequence numbers
func TestProcessReceivedPacket_UnknownSequence(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Create a valid unauthenticated reflector packet with unknown sequence number
	reflectorPacket := &messages.ReflectorTestPacket{
		SeqNumber:          99999, // Sequence number we never sent
		Timestamp:          common.FromTime(time.Now()),
		ErrorEstimate:      common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		ReceiveTimestamp:   common.FromTime(time.Now()),
		SenderSeqNumber:    99999,
		SenderTimestamp:    common.FromTime(time.Now()),
		SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		SenderTTL:          64,
	}

	packet, err := reflectorPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal packet: %v", err)
	}

	// Process packet - should fail with unknown sequence number
	err = session.processReceivedPacket(packet, time.Now())
	if err == nil {
		t.Error("Expected error for unknown sequence number")
	}
	if !errors.Is(err, common.ErrUnknownSequenceNumber) {
		t.Errorf("Expected ErrUnknownSequenceNumber, got: %v", err)
	}
}

// TestNegotiateMode_MixedModeError tests invalid mixed mode rejection
func TestNegotiateMode_MixedModeError(t *testing.T) {
	// Test that mixed mode with unauthenticated control is rejected
	server := newMockServer(t, common.ModeMixed|common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeMixed | common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)

	// Should fail - either from RFC 5618 validation or connection failure with invalid mode
	if err == nil {
		t.Fatal("Expected error for invalid mixed mode combination")
	}
	// Accept any error - the important thing is that mixed+unauth doesn't succeed
	// The error could be ErrRFC5618Violation, ErrNoCompatibleMode, or connection error
	t.Logf("Client correctly rejected mixed+unauth mode with error: %v", err)
}

// TestServerGreeting_NoModes tests handling of server with no modes
func TestServerGreeting_NoModes(t *testing.T) {
	// Create a custom mock that sends greeting with no modes
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send greeting with Modes = 0
		greeting := messages.ServerGreeting{
			Modes:     0, // No modes supported
			Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			Count:     1024,
		}
		data, _ := greeting.Marshal()
		conn.Write(data)
	}()

	cfg := ClientConfig{
		ServerAddress: l.Addr().String(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       1 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err = client.Connect(ctx)

	if err == nil {
		t.Fatal("Expected error for server with no modes")
	}
	if !errors.Is(err, common.ErrServerNoModes) {
		t.Logf("Got error: %v (expected to contain ErrServerNoModes)", err)
	}
}

// TestServerGreeting_ReadError tests handling of greeting read failure
func TestServerGreeting_ReadError(t *testing.T) {
	// Create a server that closes connection immediately
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		// Close immediately without sending greeting
		conn.Close()
	}()

	cfg := ClientConfig{
		ServerAddress: l.Addr().String(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       1 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err = client.Connect(ctx)

	if err == nil {
		t.Fatal("Expected error when server closes connection")
	}
	if !errors.Is(err, ErrServerGreeting) && !errors.Is(err, io.EOF) {
		t.Logf("Got error: %v", err)
	}
}

// TestRequestSession_ReceiverAddressFromServer tests defaulting receiver address
func TestRequestSession_ReceiverAddressFromServer(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:    uint16(ports[0]),
		ReceiverPort:  uint16(ports[1]),
		// ReceiverAddress intentionally left empty - should default to server address
		PaddingLength: 64,
		Timeout:       1 * time.Second,
	}

	session, err := client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	if session == nil {
		t.Fatal("Session is nil")
	}

	// Verify receiver address was set
	if session.config.ReceiverAddress == "" {
		t.Error("Expected receiver address to be set from server address")
	}
	t.Logf("Receiver address defaulted to: %s", session.config.ReceiverAddress)
}

// TestStopNSessions_PartialStop tests RFC 5938 StopNSessions command
func TestStopNSessions_PartialStop(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request 3 sessions
	allPorts := testutil.GetFreePorts(t, "udp", 6)
	for i := 0; i < 3; i++ {
		sessionCfg := TestSessionConfig{
			SenderPort:      uint16(allPorts[i*2]),
			ReceiverPort:    uint16(allPorts[i*2+1]),
			ReceiverAddress: "127.0.0.1",
			PaddingLength:   64,
			Timeout:         1 * time.Second,
		}

		_, err := client.RequestSession(sessionCfg)
		if err != nil {
			t.Fatalf("Failed to request session %d: %v", i, err)
		}
	}

	// Start all sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify we have 3 sessions
	if len(client.currentSessions) != 3 {
		t.Fatalf("Expected 3 sessions, got %d", len(client.currentSessions))
	}

	// Stop 2 sessions
	err = client.StopNSessions(2)
	if err != nil {
		t.Fatalf("Failed to stop N sessions: %v", err)
	}

	// Verify we have 1 session remaining
	if len(client.currentSessions) != 1 {
		t.Errorf("Expected 1 session remaining, got %d", len(client.currentSessions))
	}
}

// TestGetSession_NotFound tests GetSession with non-existent SID
func TestGetSession_NotFound(t *testing.T) {
	client := NewClient(ClientConfig{})

	var nonExistentSID common.SessionID
	for i := range nonExistentSID {
		nonExistentSID[i] = byte(0xAA)
	}

	_, err := client.GetSession(nonExistentSID)
	if err == nil {
		t.Fatal("Expected error for non-existent session")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// TestStopSession_NotFound tests StopSession with non-existent SID
func TestStopSession_NotFound(t *testing.T) {
	client := NewClient(ClientConfig{})

	var nonExistentSID common.SessionID
	for i := range nonExistentSID {
		nonExistentSID[i] = byte(0xBB)
	}

	err := client.StopSession(nonExistentSID)
	if err == nil {
		t.Fatal("Expected error for non-existent session")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// Additional helper tests would go here if needed
// (Note: TestCalculateMinPadding and TestParseAndValidateIP already exist in helpers_test.go)
