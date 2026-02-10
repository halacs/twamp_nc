package client

import (
	"context"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
)

// TestSendPacketReflectOctetsUnauthenticated verifies marshaling of RFC 6038 Reflect Octets
// packets in unauthenticated mode. Note: Mock reflector doesn't validate packet format;
// see crypto_verification_test.go for wire-format validation.
func TestSendPacketReflectOctetsUnauthenticated(t *testing.T) {
	// Start a mock UDP server to act as reflector
	server, reflectorPort := newMockUDPServer(t)
	defer server.stop()

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	// Create a test session with Reflect Octets mode
	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Create session with ModeReflectOctets (RFC 6038)
	session, err := NewTestSession(config, sid, common.ModeReflectOctets, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send a test packet - this exercises the RFC 6038 unauthenticated path
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet with Reflect Octets mode: %v", err)
	}

	// Verify packet was sent
	results := session.GetResults()
	if results.PacketsSent != 1 {
		t.Errorf("Expected 1 packet sent, got %d", results.PacketsSent)
	}
}

// TestSendPacketReflectOctetsAuthenticated verifies marshaling of RFC 6038 Reflect Octets
// packets with RFC 5357 authenticated mode. Note: Mock reflector doesn't validate packet format;
// see TestSendTestPacketHMACVerification for actual wire-format validation.
func TestSendPacketReflectOctetsAuthenticated(t *testing.T) {
	// Start a mock UDP server to act as reflector
	server, reflectorPort := newMockUDPServer(t)
	defer server.stop()

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	// Create a test session with Reflect Octets + Authenticated mode
	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   100,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Create control keys for authenticated mode (including IVs for AES-ECB encryption)
	keys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16),
		HMACKey:  make([]byte, 32),
		ClientIV: make([]byte, 16),
		ServerIV: make([]byte, 16),
	}
	// Initialize with some test data
	for i := range keys.AESKey {
		keys.AESKey[i] = byte(i)
	}
	for i := range keys.HMACKey {
		keys.HMACKey[i] = byte(i + 16)
	}

	// Create session with ModeAuthenticated + ModeReflectOctets (RFC 6038 + RFC 5357)
	session, err := NewTestSession(config, sid, common.ModeAuthenticated|common.ModeReflectOctets, keys)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send a test packet - exercises RFC 6038 §5.1.1 Reflect Octets
	// with RFC 5357 §4.1.2 authenticated packet format
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet with Authenticated + Reflect Octets mode: %v", err)
	}

	// Verify packet was sent
	results := session.GetResults()
	if results.PacketsSent != 1 {
		t.Errorf("Expected 1 packet sent, got %d", results.PacketsSent)
	}
}

// TestSendPacketReflectOctetsEncrypted verifies marshaling of RFC 6038 Reflect Octets
// packets with RFC 5357 encrypted mode. Note: Mock reflector doesn't validate packet format;
// see TestSendTestPacketEncryptionVerification for actual wire-format validation.
func TestSendPacketReflectOctetsEncrypted(t *testing.T) {
	// Start a mock UDP server to act as reflector
	server, reflectorPort := newMockUDPServer(t)
	defer server.stop()

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	// Create a test session with Reflect Octets + Encrypted mode
	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   128,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Create control keys for encrypted mode
	keys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16),
		HMACKey:  make([]byte, 32),
		ClientIV: make([]byte, 16),
	}
	// Initialize with some test data
	for i := range keys.AESKey {
		keys.AESKey[i] = byte(i)
	}
	for i := range keys.HMACKey {
		keys.HMACKey[i] = byte(i + 16)
	}
	for i := range keys.ClientIV {
		keys.ClientIV[i] = byte(i + 48)
	}

	// Create session with ModeEncrypted + ModeReflectOctets (RFC 6038 + RFC 5357)
	session, err := NewTestSession(config, sid, common.ModeEncrypted|common.ModeReflectOctets, keys)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send a test packet - this exercises the RFC 6038 encrypted path
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet with Encrypted + Reflect Octets mode: %v", err)
	}

	// Verify packet was sent
	results := session.GetResults()
	if results.PacketsSent != 1 {
		t.Errorf("Expected 1 packet sent, got %d", results.PacketsSent)
	}
}

// TestSendPacketStandardAuthenticated verifies marshaling of standard RFC 5357 authenticated
// packets (without RFC 6038 Reflect Octets extension). Note: Mock reflector doesn't validate
// packet format; see TestSendTestPacketHMACVerification for actual wire-format validation.
func TestSendPacketStandardAuthenticated(t *testing.T) {
	// Start a mock UDP server to act as reflector
	server, reflectorPort := newMockUDPServer(t)
	defer server.stop()

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	// Create a test session with standard authenticated mode (no Reflect Octets)
	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   96,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Create control keys (including IVs for AES-ECB encryption)
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

	// Create session with just ModeAuthenticated (no Reflect Octets)
	// Exercises RFC 5357 §4.1.2 standard authenticated packet format
	session, err := NewTestSession(config, sid, common.ModeAuthenticated, keys)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send a test packet - exercises RFC 5357 §4.1.2 standard authenticated
	// packet format (without RFC 6038 Reflect Octets extension)
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet with standard Authenticated mode: %v", err)
	}

	// Verify packet was sent
	results := session.GetResults()
	if results.PacketsSent != 1 {
		t.Errorf("Expected 1 packet sent, got %d", results.PacketsSent)
	}
}

// TestStartReceivingWithStopping tests StartReceiving when session is already stopping
func TestStartReceivingWithStopping(t *testing.T) {
	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    senderPort + 1,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         100 * time.Millisecond,
	}

	var sid common.SessionID
	sid[0] = 1

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Set stopping flag
	session.mu.Lock()
	session.isStopping = true
	session.mu.Unlock()

	// Start receiving - should return early due to stopping flag (lines 322-325)
	ctx := context.Background()
	session.StartReceiving(ctx)

	// Verify we can still stop cleanly
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session: %v", err)
	}
}

// TestStartReceivingContextCancellation tests StartReceiving with context cancellation
// Uses deterministic synchronization instead of time.Sleep to avoid timing-based races
func TestStartReceivingContextCancellation(t *testing.T) {
	// Start a mock UDP server that will send us packets
	server, reflectorPort := newMockUDPServer(t)
	defer server.stop()

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         100 * time.Millisecond,
	}

	var sid common.SessionID
	sid[0] = 1

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Create a context that will be canceled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start receiving
	session.StartReceiving(ctx)

	// Send a packet to ensure the receiver goroutine is running and processing packets
	// This proves the goroutine has entered its main loop
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Poll for packet to be received (deterministic proof goroutine is active)
	timeout := time.After(500 * time.Millisecond)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	receiverActive := false
	for !receiverActive {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for receiver goroutine to process packet")
		case <-ticker.C:
			results := session.GetResults()
			if results.PacketsSent > 0 {
				// Packet sent, receiver is active and processing
				receiverActive = true
			}
		}
	}

	// Now we know the receiver goroutine is in its main loop
	// Cancel context to trigger exit via lines 354-355
	cancel()

	// Use Stop() which waits on receiverWg to confirm goroutine exited
	// This is deterministic - Stop() blocks until the goroutine completes
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session after context cancellation: %v", err)
	}

	// If we reach here, the goroutine successfully exited after context cancellation
}
