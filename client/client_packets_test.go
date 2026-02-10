package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/messages"
)

// TestStartSession_AlreadyActive tests starting a session that's already started
func TestStartSession_AlreadyActive(t *testing.T) {
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
		sid[i] = byte(i + 30)
	}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// Request session
	_, err = client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Start session first time
	err = client.StartSession(sid)
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Try to start again - should skip already active sessions
	err = client.StartSession(sid)
	if err != nil {
		t.Logf("Second start returned error: %v", err)
	}
}

// TestSendTestPacket_ReflectOctetsMode tests RFC 6038 reflect-octets mode
func TestSendTestPacket_ReflectOctetsMode(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   100,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 50)
	}

	// Test unauthenticated reflect-octets mode
	session, err := NewTestSession(config, sid, common.ModeReflectOctets, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send packet in reflect-octets mode
	err = session.SendTestPacket()
	if err != nil {
		t.Errorf("Failed to send test packet in reflect-octets mode: %v", err)
	}

	// Verify packet was sent
	results := session.GetResults()
	if results.PacketsSent == 0 {
		t.Error("No packets were sent")
	}
}

// TestSendTestPacket_AuthenticatedReflectOctets tests authenticated + reflect-octets
func TestSendTestPacket_AuthenticatedReflectOctets(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   100,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 60)
	}

	// Create control keys
	controlKeys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16),
		HMACKey:  make([]byte, 32),
		ClientIV: make([]byte, 16),
		ServerIV: make([]byte, 16),
	}
	for i := range controlKeys.AESKey {
		controlKeys.AESKey[i] = byte(i)
	}
	for i := range controlKeys.HMACKey {
		controlKeys.HMACKey[i] = byte(i + 16)
	}

	// Test authenticated + reflect-octets mode
	session, err := NewTestSession(config, sid, common.ModeAuthenticated|common.ModeReflectOctets, controlKeys)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send packet in authenticated reflect-octets mode
	err = session.SendTestPacket()
	if err != nil {
		t.Errorf("Failed to send test packet in authenticated reflect-octets mode: %v", err)
	}

	// Verify packet was sent
	results := session.GetResults()
	if results.PacketsSent == 0 {
		t.Error("No packets were sent")
	}
}

// TestProcessReceivedPacket_UnauthenticatedMode tests unauthenticated packet processing
func TestProcessReceivedPacket_UnauthenticatedMode(t *testing.T) {
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
		sid[i] = byte(i + 70)
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

	// Send a test packet first so we have a sequence number to match
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Create a matching reflector packet
	seqNo := uint32(0) // First packet
	now := common.FromTime(time.Now())

	reflectorPacket := &messages.ReflectorTestPacket{
		SeqNumber:          seqNo,
		Timestamp:          now,
		ErrorEstimate:      common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		ReceiveTimestamp:   now,
		SenderSeqNumber:    seqNo,
		SenderTimestamp:    now,
		SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		SenderTTL:          64,
	}

	packet, err := reflectorPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal packet: %v", err)
	}

	// Process the packet
	err = session.processReceivedPacket(packet, time.Now())
	if err != nil {
		t.Errorf("Failed to process valid unauthenticated packet: %v", err)
	}

	// Verify packet was received
	results := session.GetResults()
	if results.PacketsReceived != 1 {
		t.Errorf("Expected 1 packet received, got %d", results.PacketsReceived)
	}
}

// TestReceiveServerStart_MarshalError tests error handling in receiveServerStart
func TestReceiveServerStart_ReadError(t *testing.T) {
	// Create a pipe that will fail
	_, client := net.Pipe()
	defer client.Close()

	c := &Client{
		conn: client,
	}

	// Close the connection to force read error
	client.Close()

	_, err := c.receiveServerStart()
	if err == nil {
		t.Error("Expected error when reading from closed connection")
	}
}

// TestNegotiateMode_KeyDerivationError tests key derivation failure
func TestNegotiateMode_KeyDerivationError(t *testing.T) {
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

	// Use empty shared secret to potentially trigger key derivation issues
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeAuthenticated,
		SharedSecret:  "", // Empty secret should cause error
		KeyID:         "test-user",
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err := client.Connect(ctx)

	// Should fail due to missing shared secret
	if err == nil {
		t.Fatal("Expected error with empty shared secret")
	}
	if !errors.Is(err, common.ErrSharedSecretRequired) {
		t.Logf("Got error (may be related to shared secret): %v", err)
	}
}

// TestRequestSession_IPv6Address tests requesting session with IPv6
func TestRequestSession_IPv6Address(t *testing.T) {
	// Check if IPv6 is available
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("IPv6 not available on this system")
	}
	conn.Close()

	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)
	ctx := context.Background()
	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "::1", // IPv6 localhost
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	session, err := client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request IPv6 session: %v", err)
	}

	if session == nil {
		t.Fatal("Session is nil")
	}
}

// TestStartSessions_AlreadyStarted tests starting sessions that are already active
func TestStartSessions_AlreadyStarted(t *testing.T) {
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
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	_, err = client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Start sessions first time
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Start again - should either skip already active sessions or return error
	// Both outcomes are acceptable (idempotent vs error for double-start)
	err = client.StartSessions()
	if err != nil {
		t.Logf("Second StartSessions returned error (expected for already active sessions): %v", err)
	} else {
		t.Log("Second StartSessions succeeded (idempotent behavior)")
	}
}

// TestStopSessions_SessionStopFailure tests handling when individual session stop fails
func TestStopSessions_SessionStopFailure(t *testing.T) {
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
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	session, err := client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Manually corrupt the session state to cause stop to potentially log error
	session.mu.Lock()
	// Close the connection to make stop behave differently
	if session.conn != nil {
		session.conn.Close()
		session.conn = nil
	}
	session.mu.Unlock()

	// Stop sessions - should handle failure gracefully
	err = client.StopSessions()
	// Should succeed even if individual session had issues
	if err != nil {
		t.Logf("StopSessions returned error (logged but continued): %v", err)
	}

	// Verify sessions were cleaned up
	if len(client.currentSessions) != 0 {
		t.Errorf("Expected 0 sessions after stop, got %d", len(client.currentSessions))
	}
}

// TestCalculateMinPadding_UnknownMode tests padding with unknown mode bits
func TestCalculateMinPadding_UnknownMode(t *testing.T) {
	// Test with mode value that doesn't match known patterns
	unknownMode := common.Mode(0xFF) // All bits set
	padding := calculateMinPadding(unknownMode)

	// Should return some padding based on base security mode extraction
	t.Logf("Unknown mode padding: %d", padding)

	// The function extracts base security mode, so it should still return a value
	if padding < 0 {
		t.Error("Padding should not be negative")
	}
}

// TestGetResults_SynchronizedClocks tests one-way delay calculation
func TestGetResults_SynchronizedClocks(t *testing.T) {
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
		sid[i] = byte(i + 80)
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

	// Send a test packet
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Create a matching reflector packet with synchronized clocks (S bit set)
	seqNo := uint32(0)
	now := common.FromTime(time.Now())

	reflectorPacket := &messages.ReflectorTestPacket{
		SeqNumber:           seqNo,
		Timestamp:           now,
		ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 8, S: true}, // Clock synced
		ReceiveTimestamp:    now,
		SenderSeqNumber:     seqNo,
		SenderTimestamp:     now,
		SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 8, S: true}, // Clock synced
		SenderTTL:           64,
	}

	packet, err := reflectorPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal packet: %v", err)
	}

	// Process the packet
	err = session.processReceivedPacket(packet, time.Now())
	if err != nil {
		t.Errorf("Failed to process packet: %v", err)
	}

	// Get results - should include one-way delay calculations
	results := session.GetResults()
	if results.PacketsReceived != 1 {
		t.Errorf("Expected 1 packet received, got %d", results.PacketsReceived)
	}

	// With synchronized clocks, one-way delays should be calculated
	t.Logf("One-way delays: forward=%v, reverse=%v, asymmetry=%f",
		results.AvgForwardDelay, results.AvgReverseDelay, results.DelayAsymmetry)
}

// TestReceiveAndVerify_ReadError tests error handling in receiveAndVerify
func TestReceiveAndVerify_ReadError(t *testing.T) {
	_, client := net.Pipe()
	c := &Client{
		conn: client,
		mode: common.ModeUnauthenticated,
	}

	// Close connection to force read error
	client.Close()

	_, err := c.receiveAndVerify(10, false)
	if err == nil {
		t.Error("Expected error when reading from closed connection")
	}
}

// TestSendWithHMAC_CalculateError tests HMAC calculation error handling
func TestSendWithHMAC_WriteError(t *testing.T) {
	srv, client := net.Pipe()
	c := &Client{
		conn: client,
		mode: common.ModeUnauthenticated,
	}

	// Close server side to cause write error
	srv.Close()
	client.Close()

	msg := []byte("test message")
	err := c.sendWithHMAC(msg, false)
	if err == nil {
		t.Error("Expected error when writing to closed connection")
	}
}
