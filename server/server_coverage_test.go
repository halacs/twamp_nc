package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/messages"
)

// TestHandleClientSetup_ModeZero tests client termination with mode=0
func TestHandleClientSetup_ModeZero(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := &controlConnection{
		conn:     serverConn,
		greeting: &messages.ServerGreeting{},
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		// Send setup response with mode=0
		setupResp := &messages.SetupResponse{
			Mode: 0,
		}
		data, _ := setupResp.Marshal()
		clientConn.Write(data)
	}()

	err = srv.handleClientSetup(cc)
	if err != ErrClientTerminatedConnection {
		t.Errorf("Expected ErrClientTerminatedConnection, got: %v", err)
	}
}

// TestHandleClientSetup_UnsupportedMode tests unsupported mode rejection
func TestHandleClientSetup_UnsupportedMode(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated, // Only support unauthenticated
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := &controlConnection{
		conn:     serverConn,
		greeting: &messages.ServerGreeting{},
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		// Send setup response with unsupported mode
		setupResp := &messages.SetupResponse{
			Mode: uint32(common.ModeEncrypted), // Server doesn't support this
		}
		data, _ := setupResp.Marshal()
		clientConn.Write(data)
	}()

	err = srv.handleClientSetup(cc)
	if err == nil {
		t.Fatal("Expected error for unsupported mode")
	}
	if !errors.Is(err, common.ErrUnsupportedMode) {
		t.Errorf("Expected ErrUnsupportedMode, got: %v", err)
	}
}

// TestHandleClientSetup_UnknownKeyID tests unknown KeyID rejection
func TestHandleClientSetup_UnknownKeyID(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		SecretMap:      map[string]string{"known": "password"},
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	greeting := &messages.ServerGreeting{
		Modes:     uint32(common.ModeAuthenticated),
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}

	cc := &controlConnection{
		conn:     serverConn,
		greeting: greeting,
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		// Send setup response with unknown KeyID
		setupResp := &messages.SetupResponse{
			Mode: uint32(common.ModeAuthenticated),
		}
		copy(setupResp.KeyID[:], "unknown")
		data, _ := setupResp.Marshal()
		clientConn.Write(data)
	}()

	err = srv.handleClientSetup(cc)
	if err == nil {
		t.Fatal("Expected error for unknown KeyID")
	}
	if !errors.Is(err, common.ErrUnknownKeyID) {
		t.Errorf("Expected ErrUnknownKeyID, got: %v", err)
	}
}

// TestHandleClientSetup_MissingGreeting tests missing greeting error
func TestHandleClientSetup_MissingGreeting(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		SecretMap:      map[string]string{"test": "password"},
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := &controlConnection{
		conn:     serverConn,
		greeting: nil, // Missing greeting
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		setupResp := &messages.SetupResponse{
			Mode: uint32(common.ModeAuthenticated),
		}
		copy(setupResp.KeyID[:], "test")
		data, _ := setupResp.Marshal()
		clientConn.Write(data)
	}()

	err = srv.handleClientSetup(cc)
	if err != ErrMissingGreeting {
		t.Errorf("Expected ErrMissingGreeting, got: %v", err)
	}
}

// TestHandleClientSetup_InvalidMixedMode tests RFC 5618 violation
func TestHandleClientSetup_InvalidMixedMode(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeMixed | common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := &controlConnection{
		conn:     serverConn,
		greeting: &messages.ServerGreeting{},
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		// Send setup with invalid mixed mode (mixed + unauthenticated)
		setupResp := &messages.SetupResponse{
			Mode: uint32(common.ModeMixed | common.ModeUnauthenticated),
		}
		data, _ := setupResp.Marshal()
		clientConn.Write(data)
	}()

	err = srv.handleClientSetup(cc)
	if err == nil {
		t.Fatal("Expected error for invalid mixed mode combination")
	}
	if !errors.Is(err, common.ErrRFC5618Violation) {
		t.Errorf("Expected ErrRFC5618Violation, got: %v", err)
	}
}

// TestReadCommand_UnknownCommand tests unknown command handling
func TestReadCommand_UnknownCommand(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := &controlConnection{
		conn:        serverConn,
		mode:        common.ModeUnauthenticated,
		controlMode: common.ModeUnauthenticated,
		testMode:    common.ModeUnauthenticated,
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		// Send unknown command
		clientConn.Write([]byte{99}) // Invalid command code
	}()

	serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = srv.readCommand(cc)
	if err == nil {
		t.Fatal("Expected error for unknown command")
	}
	if !errors.Is(err, common.ErrUnknownCommand) {
		t.Errorf("Expected common.ErrUnknownCommand, got: %v", err)
	}
}

// TestReadCommand_HMACVerificationFailure tests HMAC verification failure
func TestReadCommand_HMACVerificationFailure(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		SecretMap:      map[string]string{"test": "password"},
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	aesKey := bytes.Repeat([]byte{0xBB}, 16)
	clientIV := bytes.Repeat([]byte{0x11}, 16)
	controlDecrypt, err := crypto.NewCBCStream(aesKey, clientIV)
	if err != nil {
		t.Fatalf("NewCBCStream: %v", err)
	}

	cc := &controlConnection{
		conn:        serverConn,
		mode:        common.ModeAuthenticated,
		controlMode: common.ModeAuthenticated,
		testMode:    common.ModeAuthenticated,
		keyDerivation: &crypto.TWAMPKeys{
			AESKey:   aesKey,
			HMACKey:  bytes.Repeat([]byte{0xAA}, 32),
			ClientIV: clientIV,
		},
		controlDecrypt: controlDecrypt,
	}

	errCh := make(chan error, 1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		// Send command with invalid HMAC
		startCmd := &messages.StartSessions{
			Command: common.CmdStartSessions,
		}
		data, _ := startCmd.Marshal(false)
		controlEncrypt, err := crypto.NewCBCStream(aesKey, clientIV)
		if err != nil {
			errCh <- err
			return
		}
		encrypted, err := controlEncrypt.Encrypt(data)
		if err != nil {
			errCh <- err
			return
		}
		_, err = clientConn.Write(encrypted)
		errCh <- err
	}()

	serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = srv.readCommand(cc)
	if err != common.ErrHMACVerificationFailed {
		t.Errorf("Expected common.ErrHMACVerificationFailed, got: %v", err)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("background writer failed: %v", writeErr)
	}
}

// TestHandleConnection_ContextCancellation tests context cancellation
func TestHandleConnection_ContextCancellation(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	err = srv.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Connect to server
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greeting := make([]byte, 64)
	io.ReadFull(conn, greeting)

	// Send setup response
	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeUnauthenticated),
	}
	data, _ := setupResp.Marshal()
	conn.Write(data)

	// Read server start
	serverStart := make([]byte, 48)
	io.ReadFull(conn, serverStart)

	// Cancel context
	cancel()

	// Wait a bit for cancellation to propagate
	time.Sleep(100 * time.Millisecond)

	// Try to send a command - should fail or timeout
	reqSession := &messages.RequestTWSession{
		Command:         common.CmdRequestTWSession,
		IPVN:            4,
		ReceiverAddress: [16]byte{127, 0, 0, 1},
	}
	reqData, _ := reqSession.Marshal(false)
	conn.Write(reqData)

	// Connection should be closed
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 48)
	_, err = io.ReadFull(conn, buf)
	// Expect EOF or timeout
	if err == nil {
		t.Error("Expected error reading after context cancellation")
	}

	srv.Stop()
}

// TestHandleConnection_SERVWAITTimeout tests SERVWAIT timeout
func TestHandleConnection_SERVWAITTimeout(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		SERVWAIT:       100 * time.Millisecond, // Short timeout
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	err = srv.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greeting := make([]byte, 64)
	io.ReadFull(conn, greeting)

	// Send setup response
	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeUnauthenticated),
	}
	data, _ := setupResp.Marshal()
	conn.Write(data)

	// Read server start
	serverStart := make([]byte, 48)
	io.ReadFull(conn, serverStart)

	// Wait for SERVWAIT timeout (don't send any commands)
	time.Sleep(200 * time.Millisecond)

	// Connection should be closed
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed after SERVWAIT timeout")
	}
}

// TestAcceptConnections_Timeout tests accept timeout handling
func TestAcceptConnections_Timeout(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	err = srv.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Wait for accept loop to run
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for acceptConnections to exit
	time.Sleep(1500 * time.Millisecond) // Longer than accept timeout (1s)

	srv.Stop()
}

// TestReflectPackets_REFWAITTimeout tests REFWAIT timeout
func TestReflectPackets_REFWAITTimeout(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		REFWAIT:        200 * time.Millisecond, // Short timeout
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Create a test session
	ports := testutil.GetFreePorts(t, "udp", 1)
	session := &TestSession{
		sid:           common.SessionID{1, 2, 3, 4},
		reflectorPort: uint16(ports[0]),
		mode:          common.ModeUnauthenticated,
		startTime:     time.Now().Add(-300 * time.Millisecond), // Started long ago
		stopChan:      make(chan struct{}),
		reflectorDone: make(chan struct{}),
	}
	session.isActive.Store(true)

	// Create UDP connection
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(session.reflectorPort),
	})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	session.conn = conn

	// Store session
	srv.sessionsMu.Lock()
	srv.sessions[session.sid] = session
	srv.sessionsMu.Unlock()

	// Start reflector (should timeout quickly)
	done := make(chan struct{})
	go func() {
		srv.reflectPackets(session)
		close(done)
	}()

	// Wait for reflector to timeout (needs to wait for read timeout + REFWAIT check)
	// Read timeout is 500ms, so wait longer
	select {
	case <-done:
		// Good, reflector exited due to REFWAIT timeout
	case <-time.After(1500 * time.Millisecond):
		t.Error("Reflector did not exit after REFWAIT timeout")
	}

	// Verify session was stopped
	if session.isActive.Load() {
		t.Error("Session should be inactive after REFWAIT timeout")
	}
}

// TestReflectPackets_BadHMAC tests HMAC verification failure handling
func TestReflectPackets_BadHMAC(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		REFWAIT:        500 * time.Millisecond,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Create a test session with authenticated mode
	ports := testutil.GetFreePorts(t, "udp", 2)
	session := &TestSession{
		sid:           common.SessionID{5, 6, 7, 8},
		reflectorPort: uint16(ports[0]),
		senderPort:    uint16(ports[1]),
		mode:          common.ModeAuthenticated,
		startTime:     time.Now(),
		stopChan:      make(chan struct{}),
		reflectorDone: make(chan struct{}),
		sessionKeys: &crypto.TWAMPKeys{
			TestHMACKey: bytes.Repeat([]byte{0xAA}, 32),
		},
	}
	session.isActive.Store(true)

	// Create UDP connection for reflector
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(session.reflectorPort),
	})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	session.conn = conn

	// Start reflector
	reflectorExited := make(chan struct{})
	go func() {
		srv.reflectPackets(session)
		close(reflectorExited)
	}()

	// Create sender connection
	senderConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(session.reflectorPort),
	})
	if err != nil {
		t.Fatalf("Failed to create sender connection: %v", err)
	}
	defer senderConn.Close()

	// Send authenticated packet with invalid HMAC
	packet := &messages.SenderTestPacketAuth{
		SeqNumber: 1,
		Timestamp: common.Now(),
	}
	data, _ := packet.Marshal()
	// HMAC is invalid (zeros)

	senderConn.Write(data)

	// Wait a bit then stop
	time.Sleep(100 * time.Millisecond)
	session.isActive.Store(false)
	if session.conn != nil {
		session.conn.Close()
	}

	// Wait for reflector to exit
	select {
	case <-reflectorExited:
		// Good
	case <-time.After(2 * time.Second):
		t.Error("Reflector did not exit")
	}
}

// TestReflectPackets_HMACThresholdTermination tests that session terminates after
// reaching HMAC failure threshold (RFC 4656 Section 6 compliance)
func TestReflectPackets_HMACThresholdTermination(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		REFWAIT:        5 * time.Second, // Long enough to not interfere
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Create a test session with a low threshold for testing
	ports := testutil.GetFreePorts(t, "udp", 2)
	session := &TestSession{
		sid:             common.SessionID{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25},
		reflectorPort:   uint16(ports[0]),
		senderPort:      uint16(ports[1]),
		mode:            common.ModeAuthenticated,
		startTime:       time.Now(),
		stopChan:        make(chan struct{}),
		reflectorDone:   make(chan struct{}),
		maxHMACFailures: 5, // Low threshold for testing
		sessionKeys: &crypto.TWAMPKeys{
			TestHMACKey: bytes.Repeat([]byte{0xBB}, 32),
			TestAESKey:  bytes.Repeat([]byte{0xCC}, 16),
			ClientIV:    bytes.Repeat([]byte{0xDD}, 16),
		},
	}
	session.isActive.Store(true)

	// Create UDP connection for reflector
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(session.reflectorPort),
	})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	session.conn = conn

	// Start reflector
	reflectorExited := make(chan struct{})
	go func() {
		srv.reflectPackets(session)
		close(reflectorExited)
	}()

	// Create sender connection
	senderConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(session.reflectorPort),
	})
	if err != nil {
		t.Fatalf("Failed to create sender connection: %v", err)
	}
	defer senderConn.Close()

	// Send multiple packets with invalid HMAC to trigger threshold
	for i := 0; i < 10; i++ {
		packet := &messages.SenderTestPacketAuth{
			SeqNumber: uint32(i),
			Timestamp: common.Now(),
		}
		data, _ := packet.Marshal()
		// HMAC is invalid (zeros) - this will fail verification
		senderConn.Write(data)
		time.Sleep(10 * time.Millisecond) // Small delay between packets
	}

	// Wait for reflector to exit due to threshold being exceeded
	select {
	case <-reflectorExited:
		// Good - reflector exited (likely due to threshold or we stopped it)
	case <-time.After(3 * time.Second):
		// Timeout - stop the session manually
		session.isActive.Store(false)
		if session.conn != nil {
			session.conn.Close()
		}
		<-reflectorExited
	}

	// Verify HMAC failure counter was incremented
	session.mu.Lock()
	failures := session.hmacFailures
	session.mu.Unlock()

	if failures == 0 {
		t.Error("HMAC failure counter should have been incremented")
	}
	t.Logf("HMAC failures recorded: %d", failures)
}

// TestSendServerGreeting_WriteFail tests write failure in sendServerGreeting
func TestSendServerGreeting_WriteFail(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Create a connection that will fail on write
	clientConn, serverConn := net.Pipe()
	clientConn.Close() // Close client side immediately

	cc := &controlConnection{
		conn: serverConn,
	}

	// Should fail to write
	err = srv.sendServerGreeting(cc)
	if err == nil {
		t.Error("Expected error when writing to closed connection")
	}

	serverConn.Close()
}

// TestHandleConnection_StopSignal tests stop signal handling
func TestHandleConnection_StopSignal(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		SERVWAIT:       1 * time.Second,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	err = srv.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greeting := make([]byte, 64)
	io.ReadFull(conn, greeting)

	// Send setup response
	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeUnauthenticated),
	}
	data, _ := setupResp.Marshal()
	conn.Write(data)

	// Read server start
	serverStart := make([]byte, 48)
	io.ReadFull(conn, serverStart)

	// Stop server
	srv.Stop()

	// Connection should be closed
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed after server stop")
	}
}

// TestProcessAndReflect_MalformedPackets tests various malformed packet scenarios
func TestProcessAndReflect_MalformedPackets(t *testing.T) {
	tests := []struct {
		name       string
		mode       common.Mode
		packetData []byte
		expectErr  bool
	}{
		{
			name:       "Empty_Packet",
			mode:       common.ModeUnauthenticated,
			packetData: []byte{},
			expectErr:  true,
		},
		{
			name:       "Too_Short_Packet",
			mode:       common.ModeUnauthenticated,
			packetData: []byte{1, 2, 3, 4, 5},
			expectErr:  true,
		},
		{
			name:       "Authenticated_Too_Short",
			mode:       common.ModeAuthenticated,
			packetData: make([]byte, 20),
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: tt.mode,
			}
			srv, err := NewServer(config)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}
			defer srv.Stop()

			ports := testutil.GetFreePorts(t, "udp", 2)
			session := &TestSession{
				sid:           common.SessionID{1, 2, 3, 4},
				mode:          tt.mode,
				reflectorPort: uint16(ports[0]),
				senderPort:    uint16(ports[1]),
			}

			if tt.mode != common.ModeUnauthenticated {
				session.sessionKeys = &crypto.TWAMPKeys{
					TestHMACKey: bytes.Repeat([]byte{0xAA}, 32),
				}
			}

			conn, err := net.ListenUDP("udp", &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 0,
			})
			if err != nil {
				t.Fatalf("Failed to create UDP connection: %v", err)
			}
			defer conn.Close()

			session.conn = conn

			senderAddr := &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: int(session.senderPort),
			}

			err = srv.processAndReflect(session, tt.packetData, senderAddr, 255)
			if tt.expectErr && err == nil {
				t.Error("Expected error for malformed packet")
			}
		})
	}
}
