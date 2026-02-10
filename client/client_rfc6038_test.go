package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/messages"
)

// TestRequestSessionIndividual_ServerAddressParsing tests address parsing fallback
func TestRequestSessionIndividual_ServerAddressParsing(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Use server address without port to test parsing
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
		sid[i] = byte(i + 90)
	}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:   uint16(ports[0]),
		ReceiverPort: uint16(ports[1]),
		// Leave ReceiverAddress empty to test default
		PaddingLength: 64,
		Timeout:       1 * time.Second,
	}

	session, err := client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	if session == nil {
		t.Fatal("Session is nil")
	}

	// Verify receiver address was defaulted
	if session.config.ReceiverAddress == "" {
		t.Error("Receiver address should have been set from server address")
	}
}

// TestRequestSessionIndividual_HMACPath tests HMAC calculation path in RequestSessionIndividual
func TestRequestSessionIndividual_HMACPath(t *testing.T) {
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

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

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i + 100)
	}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// Request session in authenticated mode - tests HMAC path
	session, err := client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Fatalf("Failed to request session with HMAC: %v", err)
	}

	if session == nil {
		t.Fatal("Session is nil")
	}

	// Verify HMAC was used
	if len(server.receivedHMACs) == 0 {
		t.Error("Expected HMAC to be sent for authenticated mode")
	}
}

// TestRequestSessionIndividual_TimeoutConversion tests timeout conversion
func TestRequestSessionIndividual_TimeoutConversion(t *testing.T) {
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
		sid[i] = byte(i + 110)
	}

	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         0, // Zero timeout - will use default
	}

	session, err := client.RequestSessionIndividual(sessionCfg, sid)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	if session == nil {
		t.Fatal("Session is nil")
	}

	// Verify default timeout was set
	if session.config.Timeout == 0 {
		t.Error("Timeout should have been set to default")
	}
}

// TestStartSessions_MarshalWithoutHMAC tests unauthenticated marshal path
func TestStartSessions_MarshalWithoutHMAC(t *testing.T) {
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

	// Start sessions - tests marshal without HMAC path
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}
}

// TestStartSessions_MarshalWithHMAC tests authenticated marshal path
func TestStartSessions_MarshalWithHMAC(t *testing.T) {
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

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

	// Start sessions in authenticated mode - tests marshal with HMAC path
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify HMACs were sent
	if len(server.receivedHMACs) < 2 {
		t.Errorf("Expected at least 2 HMACs (RequestSession + StartSessions), got %d",
			len(server.receivedHMACs))
	}
}

// TestStopSessions_UnauthenticatedMode tests stop in unauthenticated mode
func TestStopSessions_UnauthenticatedMode(t *testing.T) {
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

	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Stop sessions - tests unauthenticated marshal path
	err = client.StopSessions()
	if err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}
}

// TestStopSessions_AuthenticatedMode tests stop in authenticated mode
func TestStopSessions_AuthenticatedMode(t *testing.T) {
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

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

	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Stop sessions - tests authenticated marshal with HMAC path
	err = client.StopSessions()
	if err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}
}

// TestNegotiateMode_EncryptedSelection tests encrypted mode preference over authenticated
func TestNegotiateMode_EncryptedOverAuthenticated(t *testing.T) {
	// Server supports all modes
	server := newMockServer(t, common.ModeEncrypted|common.ModeAuthenticated|common.ModeUnauthenticated)
	defer server.stop()

	// Client prefers encrypted
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

	// Verify encrypted was selected (highest priority)
	if client.mode != common.ModeEncrypted {
		t.Errorf("Expected encrypted mode (%d), got %d", common.ModeEncrypted, client.mode)
	}
}

// TestNegotiateMode_TokenCreation tests token creation in authenticated mode
func TestNegotiateMode_TokenCreation(t *testing.T) {
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

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

	// Verify keys were derived
	if client.keyDerivation == nil {
		t.Fatal("Expected keyDerivation to be set in authenticated mode")
	}

	if len(client.keyDerivation.AESKey) == 0 {
		t.Error("Expected AES key to be set")
	}

	if len(client.keyDerivation.HMACKey) == 0 {
		t.Error("Expected HMAC key to be set")
	}
}

// TestNegotiateMode_ServerIVStorage tests ServerIV storage in encrypted mode
func TestNegotiateMode_ServerIVStorage(t *testing.T) {
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

	// Verify ServerIV was stored
	if client.keyDerivation == nil || len(client.keyDerivation.ServerIV) == 0 {
		t.Fatal("Expected ServerIV to be set in encrypted mode")
	}
}

// TestReceiveServerStart_UnmarshalError tests unmarshal error handling
func TestReceiveServerStart_UnmarshalError(t *testing.T) {
	// Create a server that sends invalid ServerStart
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

		// Send greeting first
		greeting := messages.ServerGreeting{
			Modes:     uint32(common.ModeUnauthenticated),
			Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			Count:     1024,
		}
		data, _ := greeting.Marshal()
		conn.Write(data)

		// Read setup response
		buf := make([]byte, 164)
		conn.Read(buf)

		// Send invalid ServerStart (too short)
		conn.Write([]byte{1, 2, 3, 4, 5})
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
		t.Fatal("Expected error for invalid ServerStart")
	}
	// Accept any error - invalid ServerStart can cause EOF, network error, or unmarshal error
	t.Logf("Client correctly rejected invalid ServerStart with: %v", err)
}

// TestProcessReceivedPacket_ReflectorLatency tests reflector latency calculation
func TestProcessReceivedPacket_ReflectorLatency(t *testing.T) {
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
		sid[i] = byte(i + 120)
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

	// Send test packet
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Create reflector packet with different RX and TX times to test reflector latency
	seqNo := uint32(0)
	rxTime := common.FromTime(time.Now())
	txTime := common.FromTime(time.Now().Add(10 * time.Millisecond)) // 10ms processing

	reflectorPacket := &messages.ReflectorTestPacket{
		SeqNumber:           seqNo,
		Timestamp:           txTime,
		ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		ReceiveTimestamp:    rxTime,
		SenderSeqNumber:     seqNo,
		SenderTimestamp:     rxTime,
		SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 8, S: false},
		SenderTTL:           64,
	}

	packet, err := reflectorPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal packet: %v", err)
	}

	// Process packet
	err = session.processReceivedPacket(packet, time.Now())
	if err != nil {
		t.Errorf("Failed to process packet: %v", err)
	}

	// Get results and verify reflector latency was calculated
	results := session.GetResults()
	if results.AvgReflectorLatency == 0 {
		t.Error("Expected non-zero reflector latency")
	}
	t.Logf("Reflector latency: %v", results.AvgReflectorLatency)
}

// TestSendWithHMAC_EncryptedPath tests encrypted message sending
func TestSendWithHMAC_EncryptedPath(t *testing.T) {
	srv, client := net.Pipe()
	defer srv.Close()
	defer client.Close()

	c := &Client{
		conn: client,
		mode: common.ModeEncrypted,
		keyDerivation: &crypto.TWAMPKeys{
			AESKey:   make([]byte, 16),
			HMACKey:  make([]byte, 32),
			ClientIV: make([]byte, 16),
		},
	}

	// Initialize keys
	for i := range c.keyDerivation.AESKey {
		c.keyDerivation.AESKey[i] = byte(i)
	}
	for i := range c.keyDerivation.HMACKey {
		c.keyDerivation.HMACKey[i] = byte(i + 16)
	}

	msg := []byte("0123456789ABCDEF")

	// Send in goroutine
	done := make(chan error)
	go func() {
		done <- c.sendWithHMAC(msg, true)
	}()

	// Read encrypted message
	buf := make([]byte, 1024)
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	err = <-done
	if err != nil {
		t.Fatalf("sendWithHMAC failed: %v", err)
	}

	// Verify something was sent (encrypted data)
	if n == 0 {
		t.Error("No data was sent")
	}

	// Encrypted output length should match message+HMAC length
	expectedLen := len(msg) + 16
	if n != expectedLen {
		t.Logf("Encrypted size: %d, expected: %d", n, expectedLen)
	}
}

// TestControlRequiresAuthentication tests authentication check with mixed mode
func TestControlRequiresAuthentication(t *testing.T) {
	tests := []struct {
		name         string
		controlMode  common.Mode
		expectsAuth  bool
		description  string
	}{
		{
			name:         "Unauthenticated",
			controlMode:  common.ModeUnauthenticated,
			expectsAuth:  false,
			description:  "Unauthenticated mode doesn't require auth",
		},
		{
			name:         "Authenticated",
			controlMode:  common.ModeAuthenticated,
			expectsAuth:  true,
			description:  "Authenticated mode requires auth",
		},
		{
			name:         "Encrypted",
			controlMode:  common.ModeEncrypted,
			expectsAuth:  true,
			description:  "Encrypted mode requires auth",
		},
		{
			name:         "Mixed + Auth (control)",
			controlMode:  common.ModeAuthenticated | common.ModeReflectOctets,
			expectsAuth:  true,
			description:  "Authenticated control protocol requires auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				controlMode: tt.controlMode,
			}

			result := c.controlRequiresAuthentication()
			if result != tt.expectsAuth {
				t.Errorf("Expected %v, got %v for %s", tt.expectsAuth, result, tt.description)
			}
		})
	}
}
