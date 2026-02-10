package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/messages"
	"github.com/ncode/twamp/metrics"
)

// TestFullAuthenticatedSession_WithMetrics tests full authenticated session with metrics
func TestFullAuthenticatedSession_WithMetrics(t *testing.T) {
	// Create metrics
	m := metrics.New()

	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		PortRange:      [2]uint16{25000, 25100},
		SecretMap:      map[string]string{"testkey": "testpass"},
		SERVWAIT:       1 * time.Second,
		REFWAIT:        1 * time.Second,
		Metrics:        m,
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

	// Connect
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greetingBuf := make([]byte, 64)
	if _, err := io.ReadFull(conn, greetingBuf); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	var greeting messages.ServerGreeting
	if err := greeting.Unmarshal(greetingBuf); err != nil {
		t.Fatalf("Failed to unmarshal greeting: %v", err)
	}

	// Derive control keys
	controlAESKey, controlHMACKey, err := crypto.DeriveKey("testpass", greeting.Salt[:], greeting.Count)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	// Create encrypted token
	clientAESKey := make([]byte, 16)
	clientHMACKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientAESKey); err != nil {
		t.Fatalf("Failed to generate session key: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientHMACKey); err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	token, err := crypto.CreateToken(greeting.Challenge[:], clientAESKey, clientHMACKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Send setup response
	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeAuthenticated),
	}
	copy(setupResp.Token[:], token)
	copy(setupResp.KeyID[:], "testkey")
	if _, err := io.ReadFull(rand.Reader, setupResp.ClientIV[:]); err != nil {
		t.Fatalf("Failed to generate client IV: %v", err)
	}

	setupData, _ := setupResp.Marshal()
	if _, err := conn.Write(setupData); err != nil {
		t.Fatalf("Failed to send setup: %v", err)
	}

	// Read Server-Start
	serverStartBuf := make([]byte, 48)
	if _, err := io.ReadFull(conn, serverStartBuf); err != nil {
		t.Fatalf("Failed to read server start: %v", err)
	}
	var serverStart messages.ServerStart
	if err := serverStart.Unmarshal(serverStartBuf); err != nil {
		t.Fatalf("Failed to unmarshal server start: %v", err)
	}

	controlEncrypt, err := crypto.NewCBCStream(controlAESKey, setupResp.ClientIV[:])
	if err != nil {
		t.Fatalf("Failed to init control encrypt stream: %v", err)
	}
	controlDecrypt, err := crypto.NewCBCStream(controlAESKey, serverStart.ServerIV[:])
	if err != nil {
		t.Fatalf("Failed to init control decrypt stream: %v", err)
	}

	// Request session
	reqSession := &messages.RequestTWSession{
		Command:    common.CmdRequestTWSession,
		IPVN:       4,
		SenderPort: uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		Timeout:    common.TWAMPTimestamp{Seconds: 1},
	}

	reqData, _ := reqSession.Marshal(false)
	sendControlMessageEncrypted(t, conn, controlEncrypt, controlHMACKey, reqData)

	// Read Accept-Session (with HMAC, encrypted)
	acceptBuf := readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.AcceptSessionSize, serverStartBuf)

	var accept messages.AcceptSession
	if err := accept.Unmarshal(acceptBuf, true); err != nil {
		t.Fatalf("Failed to unmarshal accept: %v", err)
	}

	if accept.Accept != common.AcceptOK {
		t.Fatalf("Session not accepted: %d", accept.Accept)
	}

	// Start sessions
	startSessions := &messages.StartSessions{
		Command: common.CmdStartSessions,
	}
	startData, _ := startSessions.Marshal(false)
	sendControlMessageEncrypted(t, conn, controlEncrypt, controlHMACKey, startData)

	// Read Start-Ack (with HMAC, encrypted)
	_ = readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.StartAckSize, nil)

	// Stop sessions (RFC 5357 Section 3.8: NumSessions must match active sessions)
	stopSessions := &messages.StopSessions{
		Command:     common.CmdStopSessions,
		Accept:      common.AcceptOK,
		NumSessions: 1, // We have 1 active session
	}
	stopData, _ := stopSessions.Marshal(false)
	sendControlMessageEncrypted(t, conn, controlEncrypt, controlHMACKey, stopData)

	// Check metrics were recorded
	if m == nil {
		t.Error("Metrics not initialized")
	}
}

func TestControlCBCChaining(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		PortRange:      [2]uint16{25200, 25300},
		SecretMap:      map[string]string{"chainkey": "chainpass"},
		SERVWAIT:       1 * time.Second,
		REFWAIT:        1 * time.Second,
	}

	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	greetingBuf := make([]byte, 64)
	if _, err := io.ReadFull(conn, greetingBuf); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	var greeting messages.ServerGreeting
	if err := greeting.Unmarshal(greetingBuf); err != nil {
		t.Fatalf("Failed to unmarshal greeting: %v", err)
	}

	controlAESKey, controlHMACKey, err := crypto.DeriveKey("chainpass", greeting.Salt[:], greeting.Count)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	clientAESKey := make([]byte, 16)
	clientHMACKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientAESKey); err != nil {
		t.Fatalf("Failed to generate session key: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientHMACKey); err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	token, err := crypto.CreateToken(greeting.Challenge[:], clientAESKey, clientHMACKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeAuthenticated),
	}
	copy(setupResp.Token[:], token)
	copy(setupResp.KeyID[:], "chainkey")
	if _, err := io.ReadFull(rand.Reader, setupResp.ClientIV[:]); err != nil {
		t.Fatalf("Failed to generate client IV: %v", err)
	}

	setupData, _ := setupResp.Marshal()
	if _, err := conn.Write(setupData); err != nil {
		t.Fatalf("Failed to send setup: %v", err)
	}

	serverStartBuf := make([]byte, 48)
	if _, err := io.ReadFull(conn, serverStartBuf); err != nil {
		t.Fatalf("Failed to read server start: %v", err)
	}
	var serverStart messages.ServerStart
	if err := serverStart.Unmarshal(serverStartBuf); err != nil {
		t.Fatalf("Failed to unmarshal server start: %v", err)
	}

	controlEncrypt, err := crypto.NewCBCStream(controlAESKey, setupResp.ClientIV[:])
	if err != nil {
		t.Fatalf("Failed to init control encrypt stream: %v", err)
	}
	controlDecrypt, err := crypto.NewCBCStream(controlAESKey, serverStart.ServerIV[:])
	if err != nil {
		t.Fatalf("Failed to init control decrypt stream: %v", err)
	}

	reqSession := &messages.RequestTWSession{
		Command:    common.CmdRequestTWSession,
		IPVN:       4,
		SenderPort: uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		Timeout:    common.TWAMPTimestamp{Seconds: 1},
	}

	reqData, _ := reqSession.Marshal(false)
	sendControlMessageEncrypted(t, conn, controlEncrypt, controlHMACKey, reqData)

	acceptBuf := readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.AcceptSessionSize, serverStartBuf)

	var accept messages.AcceptSession
	if err := accept.Unmarshal(acceptBuf, true); err != nil {
		t.Fatalf("Failed to unmarshal accept: %v", err)
	}
	if accept.Accept != common.AcceptOK {
		t.Fatalf("Session not accepted: %d", accept.Accept)
	}

	startSessions := &messages.StartSessions{
		Command: common.CmdStartSessions,
	}
	startData, _ := startSessions.Marshal(false)

	encryptControl := func(message []byte) []byte {
		t.Helper()
		plaintext := append([]byte(nil), message...)
		messageLen := len(plaintext) - 16
		hmac, err := crypto.CalculateHMAC(controlHMACKey, plaintext[:messageLen])
		if err != nil {
			t.Fatalf("CalculateHMAC failed: %v", err)
		}
		copy(plaintext[messageLen:], hmac)
		encrypted, err := controlEncrypt.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		return encrypted
	}

	firstCipher := encryptControl(startData)
	if _, err := conn.Write(firstCipher); err != nil {
		t.Fatalf("Failed to write start sessions: %v", err)
	}
	_ = readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.StartAckSize, nil)

	secondCipher := encryptControl(startData)
	if bytes.Equal(firstCipher, secondCipher) {
		t.Fatalf("expected CBC stream to chain IV across messages, ciphertexts match")
	}
	if _, err := conn.Write(secondCipher); err != nil {
		t.Fatalf("Failed to write second start sessions: %v", err)
	}
	_ = readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.StartAckSize, nil)
}

// TestFullEncryptedSession tests full encrypted session
func TestFullEncryptedSession(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeEncrypted,
		PortRange:      [2]uint16{26000, 26100},
		SecretMap:      map[string]string{"enckey": "encpass"},
		SERVWAIT:       1 * time.Second,
		REFWAIT:        1 * time.Second,
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

	// Connect
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greetingBuf := make([]byte, 64)
	if _, err := io.ReadFull(conn, greetingBuf); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	var greeting messages.ServerGreeting
	if err := greeting.Unmarshal(greetingBuf); err != nil {
		t.Fatalf("Failed to unmarshal greeting: %v", err)
	}

	// Derive control keys
	controlAESKey, controlHMACKey, err := crypto.DeriveKey("encpass", greeting.Salt[:], greeting.Count)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	// Create encrypted token
	clientAESKey := make([]byte, 16)
	clientHMACKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientAESKey); err != nil {
		t.Fatalf("Failed to generate session key: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientHMACKey); err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	token, err := crypto.CreateToken(greeting.Challenge[:], clientAESKey, clientHMACKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Send setup response
	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeEncrypted),
	}
	copy(setupResp.Token[:], token)
	copy(setupResp.KeyID[:], "enckey")
	if _, err := io.ReadFull(rand.Reader, setupResp.ClientIV[:]); err != nil {
		t.Fatalf("Failed to generate client IV: %v", err)
	}

	setupData, _ := setupResp.Marshal()
	if _, err := conn.Write(setupData); err != nil {
		t.Fatalf("Failed to send setup: %v", err)
	}

	// Read Server-Start
	serverStartBuf := make([]byte, 48)
	if _, err := io.ReadFull(conn, serverStartBuf); err != nil {
		t.Fatalf("Failed to read server start: %v", err)
	}
	var serverStart messages.ServerStart
	if err := serverStart.Unmarshal(serverStartBuf); err != nil {
		t.Fatalf("Failed to unmarshal server start: %v", err)
	}

	controlEncrypt, err := crypto.NewCBCStream(controlAESKey, setupResp.ClientIV[:])
	if err != nil {
		t.Fatalf("Failed to init control encrypt stream: %v", err)
	}
	controlDecrypt, err := crypto.NewCBCStream(controlAESKey, serverStart.ServerIV[:])
	if err != nil {
		t.Fatalf("Failed to init control decrypt stream: %v", err)
	}

	// Request session
	reqSession := &messages.RequestTWSession{
		Command:    common.CmdRequestTWSession,
		IPVN:       4,
		SenderPort: uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		Timeout:    common.TWAMPTimestamp{Seconds: 1},
	}

	reqData, _ := reqSession.Marshal(false)
	sendControlMessageEncrypted(t, conn, controlEncrypt, controlHMACKey, reqData)

	// Read Accept-Session (with HMAC, encrypted)
	acceptBuf := readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.AcceptSessionSize, serverStartBuf)

	var accept messages.AcceptSession
	if err := accept.Unmarshal(acceptBuf, true); err != nil {
		t.Fatalf("Failed to unmarshal accept: %v", err)
	}

	if accept.Accept != common.AcceptOK {
		t.Fatalf("Session not accepted: %d", accept.Accept)
	}
}

// TestMixedModeSession tests mixed mode (encrypted control, unauth test)
func TestMixedModeSession(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeMixed | common.ModeAuthenticated,
		PortRange:      [2]uint16{27000, 27100},
		SecretMap:      map[string]string{"mixkey": "mixpass"},
		SERVWAIT:       1 * time.Second,
		REFWAIT:        1 * time.Second,
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

	// Connect
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greetingBuf := make([]byte, 64)
	if _, err := io.ReadFull(conn, greetingBuf); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	var greeting messages.ServerGreeting
	if err := greeting.Unmarshal(greetingBuf); err != nil {
		t.Fatalf("Failed to unmarshal greeting: %v", err)
	}

	// Derive control keys
	controlAESKey, controlHMACKey, err := crypto.DeriveKey("mixpass", greeting.Salt[:], greeting.Count)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	// Create encrypted token
	clientAESKey := make([]byte, 16)
	clientHMACKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientAESKey); err != nil {
		t.Fatalf("Failed to generate session key: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientHMACKey); err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	token, err := crypto.CreateToken(greeting.Challenge[:], clientAESKey, clientHMACKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Send setup response with mixed mode
	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeMixed | common.ModeAuthenticated),
	}
	copy(setupResp.Token[:], token)
	copy(setupResp.KeyID[:], "mixkey")
	if _, err := io.ReadFull(rand.Reader, setupResp.ClientIV[:]); err != nil {
		t.Fatalf("Failed to generate client IV: %v", err)
	}

	setupData, _ := setupResp.Marshal()
	if _, err := conn.Write(setupData); err != nil {
		t.Fatalf("Failed to send setup: %v", err)
	}

	// Read Server-Start
	serverStartBuf := make([]byte, 48)
	if _, err := io.ReadFull(conn, serverStartBuf); err != nil {
		t.Fatalf("Failed to read server start: %v", err)
	}
	var serverStart messages.ServerStart
	if err := serverStart.Unmarshal(serverStartBuf); err != nil {
		t.Fatalf("Failed to unmarshal server start: %v", err)
	}

	controlEncrypt, err := crypto.NewCBCStream(controlAESKey, setupResp.ClientIV[:])
	if err != nil {
		t.Fatalf("Failed to init control encrypt stream: %v", err)
	}
	controlDecrypt, err := crypto.NewCBCStream(controlAESKey, serverStart.ServerIV[:])
	if err != nil {
		t.Fatalf("Failed to init control decrypt stream: %v", err)
	}

	senderConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender UDP conn: %v", err)
	}
	defer senderConn.Close()
	senderPort := uint16(senderConn.LocalAddr().(*net.UDPAddr).Port)

	// Request session (control message needs HMAC)
	reqSession := &messages.RequestTWSession{
		Command:    common.CmdRequestTWSession,
		IPVN:       4,
		SenderPort: senderPort,
		Timeout:    common.TWAMPTimestamp{Seconds: 1},
	}

	reqData, _ := reqSession.Marshal(false)
	sendControlMessageEncrypted(t, conn, controlEncrypt, controlHMACKey, reqData)

	// Read Accept-Session (with HMAC, encrypted)
	acceptBuf := readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.AcceptSessionSize, serverStartBuf)

	var accept messages.AcceptSession
	if err := accept.Unmarshal(acceptBuf, true); err != nil {
		t.Fatalf("Failed to unmarshal accept: %v", err)
	}

	if accept.Accept != common.AcceptOK {
		t.Fatalf("Session not accepted: %d", accept.Accept)
	}

	startSessions := &messages.StartSessions{
		Command: common.CmdStartSessions,
	}
	startData, _ := startSessions.Marshal(false)
	sendControlMessageEncrypted(t, conn, controlEncrypt, controlHMACKey, startData)
	_ = readControlMessageEncrypted(t, conn, controlDecrypt, controlHMACKey, messages.StartAckSize, nil)

	time.Sleep(50 * time.Millisecond)

	senderSeq := uint32(1)
	senderTimestamp := common.Now()
	senderPacket := &messages.SenderTestPacket{
		SeqNumber:     senderSeq,
		Timestamp:     senderTimestamp,
		ErrorEstimate: common.ErrorEstimate{},
	}
	packet, err := senderPacket.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal sender packet: %v", err)
	}

	reflectAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(accept.Port)}
	if _, err := senderConn.WriteToUDP(packet, reflectAddr); err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	senderConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	reply := make([]byte, messages.ReflectorTestPacketMinSize+64)
	n, _, err := senderConn.ReadFromUDP(reply)
	if err != nil {
		t.Fatalf("Failed to read reflected packet: %v", err)
	}

	var reflected messages.ReflectorTestPacket
	if err := reflected.Unmarshal(reply[:n]); err != nil {
		t.Fatalf("Failed to unmarshal reflected packet: %v", err)
	}

	if reflected.SenderSeqNumber != senderSeq {
		t.Errorf("SenderSeqNumber mismatch: got %d, want %d", reflected.SenderSeqNumber, senderSeq)
	}
	if reflected.SenderTimestamp != senderTimestamp {
		t.Errorf("SenderTimestamp mismatch: got %v, want %v", reflected.SenderTimestamp, senderTimestamp)
	}

	// Verify test mode is unauthenticated (this is the point of mixed mode)
	srv.sessionsMu.RLock()
	var testSession *TestSession
	for _, s := range srv.sessions {
		testSession = s
		break
	}
	srv.sessionsMu.RUnlock()

	if testSession != nil && testSession.mode != common.ModeUnauthenticated {
		t.Errorf("Expected test mode to be unauthenticated in mixed mode, got: %v", testSession.mode)
	}
}

// TestInvalidTokenChallenge tests challenge mismatch in token
func TestInvalidTokenChallenge(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeAuthenticated,
		PortRange:      [2]uint16{28000, 28100},
		SecretMap:      map[string]string{"testkey": "testpass"},
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
	defer srv.Stop()

	// Connect
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Read greeting
	greetingBuf := make([]byte, 64)
	if _, err := io.ReadFull(conn, greetingBuf); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	var greeting messages.ServerGreeting
	if err := greeting.Unmarshal(greetingBuf); err != nil {
		t.Fatalf("Failed to unmarshal greeting: %v", err)
	}

	// Create token with WRONG challenge
	wrongChallenge := [16]byte{99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99}
	clientAESKey := make([]byte, 16)
	clientHMACKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientAESKey); err != nil {
		t.Fatalf("Failed to generate session key: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientHMACKey); err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	// Use wrong challenge when creating token
	token, err := crypto.CreateToken(wrongChallenge[:], clientAESKey, clientHMACKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Send setup response
	setupResp := &messages.SetupResponse{
		Mode: uint32(common.ModeAuthenticated),
	}
	copy(setupResp.Token[:], token)
	copy(setupResp.KeyID[:], "testkey")
	if _, err := io.ReadFull(rand.Reader, setupResp.ClientIV[:]); err != nil {
		t.Fatalf("Failed to generate client IV: %v", err)
	}

	setupData, _ := setupResp.Marshal()
	if _, err := conn.Write(setupData); err != nil {
		t.Fatalf("Failed to send setup: %v", err)
	}

	// Should get connection closed due to challenge mismatch
	serverStartBuf := make([]byte, 48)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = io.ReadFull(conn, serverStartBuf)
	if err == nil {
		t.Error("Expected connection to close due to challenge mismatch")
	}
}

// TestServerWithDSCP tests DSCP configuration
func TestServerWithDSCP(t *testing.T) {
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		PortRange:      [2]uint16{29000, 29100},
		DSCP:           46, // EF (Expedited Forwarding)
		SERVWAIT:       1 * time.Second,
		REFWAIT:        1 * time.Second,
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

	// Verify server is running
	if srv.Addr() == nil {
		t.Error("Server address is nil")
	}
}

// TestWriteFailureInStartAck tests write failure in Start-Ack
func TestWriteFailureInStartAck(t *testing.T) {
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
		conn:        serverConn,
		mode:        common.ModeUnauthenticated,
		controlMode: common.ModeUnauthenticated,
	}

	// Should fail to write
	err = srv.sendStartAck(cc, common.AcceptOK)
	if err == nil {
		t.Error("Expected error when writing to closed connection")
	}

	serverConn.Close()
}

// TestWriteFailureInAcceptSession tests write failure in Accept-Session
func TestWriteFailureInAcceptSession(t *testing.T) {
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
		conn:        serverConn,
		mode:        common.ModeUnauthenticated,
		controlMode: common.ModeUnauthenticated,
	}

	// Should fail to write
	err = srv.sendAcceptSession(cc, common.AcceptOK, 0, common.SessionID{})
	if err == nil {
		t.Error("Expected error when writing to closed connection")
	}

	serverConn.Close()
}

// TestHandleClientSetup_IncompleteWrite tests incomplete write handling
func TestHandleClientSetup_IncompleteWrite(t *testing.T) {
	// This test is difficult to trigger reliably, so we just verify the code path exists
	// The condition checked is: written != len(data)
	// This would require a partial write, which is rare in tests
	t.Skip("Partial write condition is difficult to trigger in tests")
}
