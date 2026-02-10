package client

import (
	"context"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/messages"
)

// TestSendTestPacket_EncryptedMode tests sending in encrypted mode
func TestSendTestPacket_EncryptedMode(t *testing.T) {
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
		sid[i] = byte(i + 220)
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

	session, err := NewTestSession(config, sid, common.ModeEncrypted, controlKeys)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send multiple packets to test encrypted mode path
	for i := 0; i < 5; i++ {
		err = session.SendTestPacket()
		if err != nil {
			t.Errorf("Failed to send test packet %d in encrypted mode: %v", i, err)
		}
	}

	results := session.GetResults()
	if results.PacketsSent != 5 {
		t.Errorf("Expected 5 packets sent, got %d", results.PacketsSent)
	}
}

// TestSendTestPacket_EncryptedReflectOctets tests encrypted + reflect-octets
func TestSendTestPacket_EncryptedReflectOctets(t *testing.T) {
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
		sid[i] = byte(i + 230)
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

	// Test encrypted + reflect-octets mode
	session, err := NewTestSession(config, sid, common.ModeEncrypted|common.ModeReflectOctets, controlKeys)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send packet - tests encrypted + reflect-octets path
	err = session.SendTestPacket()
	if err != nil {
		t.Errorf("Failed to send test packet in encrypted reflect-octets mode: %v", err)
	}

	results := session.GetResults()
	if results.PacketsSent == 0 {
		t.Error("No packets were sent")
	}
}

// TestStartReceiving_TimeoutLoop tests the timeout loop in StartReceiving
func TestStartReceiving_TimeoutLoop(t *testing.T) {
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
		sid[i] = byte(i + 240)
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

	// Start receiving with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	session.StartReceiving(ctx)

	// Wait for context to timeout
	<-ctx.Done()

	// Give receiver goroutine time to exit
	time.Sleep(100 * time.Millisecond)

	// Verify session can still be stopped cleanly
	err = session.Stop()
	if err != nil {
		t.Errorf("Failed to stop session after timeout: %v", err)
	}
}

// TestProcessReceivedPacket_Authenticated tests authenticated packet processing
func TestProcessReceivedPacket_Authenticated(t *testing.T) {
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
		sid[i] = byte(i + 250)
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

	// Send a test packet to have a sequence number
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Create a valid authenticated reflector packet
	seqNo := uint32(0)
	now := common.FromTime(time.Now())

	reflectorPacket := &messages.ReflectorTestPacketAuth{
		SeqNumber:           seqNo,
		Timestamp:           now,
		ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		ReceiveTimestamp:    now,
		SenderSeqNumber:     seqNo,
		SenderTimestamp:     now,
		SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		SenderTTL:           64,
	}

	packet, err := reflectorPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal packet: %v", err)
	}

	// RFC 5357 Section 4.2.1: In authenticated mode, HMAC covers first 16 bytes
	// HMAC is at offset 96 for reflector packets (ReflectorTestPacketAuth)
	hmac, err := crypto.CalculateHMAC(session.sessionKeys.TestHMACKey, packet[:16])
	if err != nil {
		t.Fatalf("Failed to calculate HMAC: %v", err)
	}
	copy(packet[96:112], hmac)

	// Encrypt the packet (authenticated mode uses AES-ECB on first 16 bytes)
	packet, err = crypto.EncryptTWAMPTestPacket(
		session.sessionKeys.TestAESKey,
		session.sessionKeys.ServerIV,
		packet,
		true, // isAuthenticated = true (not encrypted mode)
	)
	if err != nil {
		t.Fatalf("Failed to encrypt packet: %v", err)
	}

	// Process the packet
	err = session.processReceivedPacket(packet, time.Now())
	if err != nil {
		t.Errorf("Failed to process valid authenticated packet: %v", err)
	}

	// Verify packet was received
	results := session.GetResults()
	if results.PacketsReceived != 1 {
		t.Errorf("Expected 1 packet received, got %d", results.PacketsReceived)
	}
}

// TestProcessReceivedPacket_EncryptedValid tests valid encrypted packet processing
func TestProcessReceivedPacket_EncryptedValid(t *testing.T) {
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
		sid[i] = byte(i + 5)
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

	session, err := NewTestSession(config, sid, common.ModeEncrypted, controlKeys)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Send a test packet to have a sequence number
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Create a valid encrypted reflector packet
	seqNo := uint32(0)
	now := common.FromTime(time.Now())

	reflectorPacket := &messages.ReflectorTestPacketAuth{
		SeqNumber:           seqNo,
		Timestamp:           now,
		ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		ReceiveTimestamp:    now,
		SenderSeqNumber:     seqNo,
		SenderTimestamp:     now,
		SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		SenderTTL:           64,
	}

	packet, err := reflectorPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal packet: %v", err)
	}

	// Calculate and add HMAC
	hmac, err := crypto.CalculateHMAC(session.sessionKeys.TestHMACKey, packet[:96])
	if err != nil {
		t.Fatalf("Failed to calculate HMAC: %v", err)
	}
	copy(packet[96:112], hmac)

	// Encrypt the reflector packet
	encryptedPacket, err := crypto.EncryptTWAMPReflectorTestPacket(
		session.sessionKeys.TestAESKey,
		session.sessionKeys.ServerIV,
		packet,
		false,
	)
	if err != nil {
		t.Fatalf("Failed to encrypt packet: %v", err)
	}

	// Process the encrypted packet
	err = session.processReceivedPacket(encryptedPacket, time.Now())
	if err != nil {
		t.Errorf("Failed to process valid encrypted packet: %v", err)
	}

	// Verify packet was received
	results := session.GetResults()
	if results.PacketsReceived != 1 {
		t.Errorf("Expected 1 packet received, got %d", results.PacketsReceived)
	}
}

// TestNegotiateMode_ClientIVGeneration tests ClientIV generation
func TestNegotiateMode_ClientIVGeneration(t *testing.T) {
	server := newMockServer(t, common.ModeEncrypted)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeEncrypted,
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

	// Verify ClientIV was generated
	if len(client.keyDerivation.ClientIV) != 16 {
		t.Errorf("Expected ClientIV length 16, got %d", len(client.keyDerivation.ClientIV))
	}

	// Verify ClientIV is not all zeros
	allZero := true
	for _, b := range client.keyDerivation.ClientIV {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("ClientIV should not be all zeros")
	}
}

// TestStartSession_Error tests error from session.Start()
func TestStartSession_SessionStartError(t *testing.T) {
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
		sid[i] = byte(i + 15)
	}

	// Request session with a port that will cause issues on start
	sessionCfg := TestSessionConfig{
		SenderPort:      1, // Privileged port - will fail without root
		ReceiverPort:    862,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// This should fail during request or start
	_, err = client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Logf("Request failed as expected with invalid port: %v", err)
		return
	}

	// If request succeeded, start should fail
	err = client.StartSession(sid)
	if err != nil {
		t.Logf("Start failed as expected: %v", err)
	}
}

// TestStart_DSCPSetError tests DSCP setting error path
func TestStart_DSCPSetError(t *testing.T) {
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
		DSCP:            63, // Max valid DSCP value
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 25)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Start session with DSCP - may fail or succeed depending on platform
	err = session.Start()
	if err != nil {
		t.Logf("Start with DSCP failed (platform-dependent): %v", err)
	} else {
		session.Stop()
	}
}

// TestGetResults_Jitter tests jitter calculation
func TestGetResults_Jitter(t *testing.T) {
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
		sid[i] = byte(i + 35)
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

	// Send multiple packets with simulated responses to test jitter calculation
	for i := 0; i < 10; i++ {
		err = session.SendTestPacket()
		if err != nil {
			t.Fatalf("Failed to send test packet %d: %v", i, err)
		}

		// Simulate receiving response
		seqNo := uint32(i)
		now := common.FromTime(time.Now())

		reflectorPacket := &messages.ReflectorTestPacket{
			SeqNumber:           seqNo,
			Timestamp:           now,
			ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
			ReceiveTimestamp:    now,
			SenderSeqNumber:     seqNo,
			SenderTimestamp:     now,
			SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
			SenderTTL:           64,
		}

		packet, err := reflectorPacket.Marshal()
		if err != nil {
			continue
		}

		// Add slight delay variation to create jitter
		time.Sleep(time.Duration(i) * time.Millisecond)

		session.processReceivedPacket(packet, time.Now())
	}

	// Get results - should include jitter calculation
	results := session.GetResults()
	if results.PacketsReceived > 1 {
		// Jitter should be calculated for multiple packets
		t.Logf("RTT Variation (jitter): %v", results.RTTVariation)
		// Don't assert specific value as it depends on timing, just verify it was calculated
	}
}
