package client

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/messages"
)

// TestSendTestPacketHMACVerification verifies that HMAC is correctly calculated and placed in authenticated packets
func TestSendTestPacketHMACVerification(t *testing.T) {
	// Create a UDP receiver to capture the packet
	receiverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve receiver address: %v", err)
	}

	receiverConn, err := net.ListenUDP("udp", receiverAddr)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiverConn.Close()

	receiverPort := uint16(receiverConn.LocalAddr().(*net.UDPAddr).Port)

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    receiverPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   100,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 1)
	}

	// Create control keys for authenticated mode
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

	// Create session with authenticated mode
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

	// Send a test packet - this should calculate HMAC and encrypt first 16 bytes
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Receive the packet on our capturing receiver
	receiverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := receiverConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to receive packet: %v", err)
	}

	encryptedPacket := buf[:n]

	// Verify packet is at least the authenticated packet minimum size
	// Per RFC 5357 §4.1.2: authenticated packet = 32 bytes (header) + 16 bytes (HMAC)
	if len(encryptedPacket) < messages.SenderTestPacketAuthMinSize {
		t.Fatalf("Authenticated packet too small: %d bytes (minimum %d)", len(encryptedPacket), messages.SenderTestPacketAuthMinSize)
	}

	// Derive the test session keys (same as the session would)
	testAESKey, testHMACKey, err := crypto.DeriveTestSessionKeys(keys.AESKey, keys.HMACKey, sid)
	if err != nil {
		t.Fatalf("Failed to derive test session keys: %v", err)
	}

	// Decrypt the first 16 bytes (authenticated mode uses AES-ECB)
	decryptedPacket, err := crypto.DecryptTWAMPTestPacket(testAESKey, keys.ClientIV, encryptedPacket, true)
	if err != nil {
		t.Fatalf("Failed to decrypt packet: %v", err)
	}

	// Per RFC 5357 §4.2.1: In authenticated mode, HMAC covers first 16 bytes
	// and is placed at bytes 32-47 in sender packets
	expectedHMAC, err := crypto.CalculateHMAC(testHMACKey, decryptedPacket[:16])
	if err != nil {
		t.Fatalf("Failed to calculate expected HMAC: %v", err)
	}

	// Extract the HMAC from the packet (bytes 32-47, not encrypted)
	actualHMAC := encryptedPacket[32:48]

	// Verify HMAC matches
	if !bytes.Equal(expectedHMAC, actualHMAC) {
		t.Errorf("HMAC mismatch!\nExpected: %x\nActual:   %x", expectedHMAC, actualHMAC)
	}

	// Additional verification: unmarshal the decrypted packet to verify structure
	var authPacket messages.SenderTestPacketAuth
	err = authPacket.Unmarshal(decryptedPacket)
	if err != nil {
		t.Fatalf("Failed to unmarshal authenticated packet: %v", err)
	}

	// Verify sequence number is 0 (first packet)
	if authPacket.SeqNumber != 0 {
		t.Errorf("Expected sequence number 0, got %d", authPacket.SeqNumber)
	}
}

// TestSendTestPacketEncryptionVerification verifies that packets are actually encrypted in encrypted mode
func TestSendTestPacketEncryptionVerification(t *testing.T) {
	// Create a UDP receiver to capture the packet
	receiverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve receiver address: %v", err)
	}

	receiverConn, err := net.ListenUDP("udp", receiverAddr)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}
	defer receiverConn.Close()

	receiverPort := uint16(receiverConn.LocalAddr().(*net.UDPAddr).Port)

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    receiverPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   128,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 1)
	}

	// Create control keys for encrypted mode
	keys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16),
		HMACKey:  make([]byte, 32),
		ClientIV: make([]byte, 16),
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

	// Create session with encrypted mode
	session, err := NewTestSession(config, sid, common.ModeEncrypted, keys)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send a test packet - this should encrypt the packet
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Receive the packet on our capturing receiver
	receiverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := receiverConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Failed to receive packet: %v", err)
	}

	encryptedPacket := buf[:n]

	// For SENDER packets in encrypted mode:
	// - Header is 32 bytes, HMAC at bytes 32-47
	// - HMAC covers first 32 bytes (header up to HMAC position)
	// - First 32 bytes are encrypted with AES-CBC (two blocks)
	const senderHMACOffset = 32
	const hmacSize = 16
	const encryptedPortionSize = 32

	// Verify packet is large enough for encrypted mode
	// Minimum encrypted packet size is 32 (encrypted portion) + 16 (HMAC) = 48 bytes
	minEncryptedPacketSize := encryptedPortionSize + hmacSize
	if len(encryptedPacket) < minEncryptedPacketSize {
		t.Fatalf("Encrypted packet too small: %d bytes (minimum %d)", len(encryptedPacket), minEncryptedPacketSize)
	}

	// Derive the test session keys
	testAESKey, testHMACKey, err := crypto.DeriveTestSessionKeys(keys.AESKey, keys.HMACKey, sid)
	if err != nil {
		t.Fatalf("Failed to derive test session keys: %v", err)
	}

	// First, decrypt the packet to get the plaintext
	// (In encrypted mode, encryption happens AFTER HMAC calculation over plaintext)
	decryptedPacket, err := crypto.DecryptTWAMPTestPacket(testAESKey, keys.ClientIV, encryptedPacket, false)
	if err != nil {
		t.Fatalf("Failed to decrypt packet: %v", err)
	}

	// Verify the encrypted bytes are different from decrypted bytes
	// (proves encryption actually happened)
	// Compare first 16 bytes of encrypted block to decrypted
	if bytes.Equal(encryptedPacket[:16], decryptedPacket[:16]) {
		t.Error("Encrypted packet bytes match decrypted bytes - encryption may not have occurred!")
	}

	// Verify HMAC is correct. For sender packets:
	// - HMAC covers first 32 bytes (header up to HMAC position)
	// - HMAC is at bytes 32-47 (not encrypted)
	expectedHMAC, err := crypto.CalculateHMAC(testHMACKey, decryptedPacket[:senderHMACOffset])
	if err != nil {
		t.Fatalf("Failed to calculate expected HMAC: %v", err)
	}

	// Extract HMAC from the DECRYPTED packet (bytes 32-47 are encrypted in encrypted mode)
	actualHMAC := decryptedPacket[senderHMACOffset : senderHMACOffset+hmacSize]

	// Verify HMAC matches
	if !bytes.Equal(expectedHMAC, actualHMAC) {
		t.Errorf("HMAC mismatch in encrypted packet!\nExpected: %x\nActual:   %x", expectedHMAC, actualHMAC)
	}

	// Verify decrypted packet can be unmarshaled
	var authPacket messages.SenderTestPacketAuth
	err = authPacket.Unmarshal(decryptedPacket)
	if err != nil {
		t.Fatalf("Failed to unmarshal decrypted packet: %v", err)
	}

	// Verify the decrypted packet has valid structure (sequence number should be 0)
	if authPacket.SeqNumber != 0 {
		t.Errorf("Expected sequence number 0 in decrypted packet, got %d", authPacket.SeqNumber)
	}
}

// TestProcessReceivedPacketInvalidHMAC tests HMAC verification failure handling
func TestProcessReceivedPacketInvalidHMAC(t *testing.T) {
	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    senderPort + 1,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   100,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 1)
	}

	// Create control keys
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

	// Create session with authenticated mode
	session, err := NewTestSession(config, sid, common.ModeAuthenticated, keys)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Create a valid authenticated reflector packet
	reflectorPacket := &messages.ReflectorTestPacketAuth{
		SeqNumber:           5, // Sequence number we haven't sent
		Timestamp:           common.Now(),
		ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
		ReceiveTimestamp:    common.Now(),
		SenderSeqNumber:     0,
		SenderTimestamp:     common.Now(),
		SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
		SenderTTL:           64,
		PaddingSize:         20,
	}

	// Marshal the packet
	packet, err := reflectorPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal reflector packet: %v", err)
	}

	// Calculate proper HMAC (covering first 16 bytes for authenticated mode)
	hmac, err := crypto.CalculateHMAC(session.sessionKeys.TestHMACKey, packet[:16])
	if err != nil {
		t.Fatalf("Failed to calculate HMAC: %v", err)
	}
	copy(packet[96:112], hmac)

	// Encrypt the first 16 bytes (authenticated mode uses AES-ECB)
	packet, err = crypto.EncryptTWAMPTestPacket(
		session.sessionKeys.TestAESKey,
		session.sessionKeys.ServerIV,
		packet,
		true, // isAuthenticated = true
	)
	if err != nil {
		t.Fatalf("Failed to encrypt packet: %v", err)
	}

	// Now corrupt the HMAC field (bytes 96-111 in authenticated reflector packet)
	// Per RFC 5357 §4.2.1, HMAC is at bytes 96-111 in the reflector packet
	// This should cause HMAC verification to fail
	for i := 96; i < 112 && i < len(packet); i++ {
		packet[i] ^= 0xFF // Flip all bits
	}

	// Try to process the packet with invalid HMAC
	// This should fail HMAC verification per RFC 5357 §4.1.2
	err = session.processReceivedPacket(packet, time.Now())
	if err == nil {
		t.Fatal("Expected processReceivedPacket to fail with invalid HMAC, but it succeeded")
	}

	// Verify the error indicates HMAC verification failure (not just a parse error)
	errMsg := err.Error()
	if !strings.Contains(errMsg, "HMAC") && !strings.Contains(errMsg, "verification") {
		t.Errorf("Expected HMAC verification error, got: %v", err)
	}
}
