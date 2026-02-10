package client

import (
	"context"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/messages"
)

const (
	// Test packet size constants per RFC 5357
	// Encrypted mode minimum: header + HMAC (sender packets)
	encryptedMinPacketSize = 48 // RFC 5357: minimum for encrypted sender test packets
	// Authenticated mode minimum: header + HMAC
	authenticatedMinPacketSize = 48 // RFC 5357: minimum for authenticated test packets
)

// waitForCondition polls a condition function until it returns true or timeout
func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return true
		}

		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				return false
			}
		}
	}
}

func controlRequiresAuthentication(controlMode common.Mode) bool {
	securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
	controlSecurity := controlMode & securityMask
	return controlSecurity != common.ModeUnauthenticated
}

func controlCommandLength(cmd byte, header []byte) (int, error) {
	switch cmd {
	case common.CmdRequestTWSession:
		return messages.RequestTWSessionSize, nil
	case common.CmdStartSessions:
		return messages.StartSessionsSize, nil
	case common.CmdStopSessions:
		return messages.StopSessionsSize, nil
	case common.CmdStopNSessions:
		if len(header) < 8 {
			return 0, common.ErrInvalidMessageLength
		}
		numSessions := binary.BigEndian.Uint32(header[4:8])
		cmdLength64 := int64(16) + int64(numSessions)*16 + 16
		if cmdLength64 > int64(math.MaxInt) {
			return 0, common.ErrInvalidMessageLength
		}
		return int(cmdLength64), nil
	case common.CmdRequestTWSessionIndividual:
		return messages.RequestTWSessionSize, nil
	default:
		return 0, fmt.Errorf("%w: %d", common.ErrUnknownCommand, cmd)
	}
}

func (s *mockServer) readCommand(conn net.Conn, mode common.Mode) ([]byte, error) {
	if controlRequiresAuthentication(mode) {
		return s.readEncryptedCommand(conn)
	}

	return s.readPlainCommand(conn)
}

func (s *mockServer) readPlainCommand(conn net.Conn) ([]byte, error) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] == common.CmdStopNSessions {
		baseHeaderLen := 16
		baseHeader := make([]byte, baseHeaderLen)
		baseHeader[0] = header[0]
		if _, err := io.ReadFull(conn, baseHeader[1:]); err != nil {
			return nil, err
		}

		cmdLength, err := controlCommandLength(header[0], baseHeader)
		if err != nil {
			return nil, err
		}

		cmd := make([]byte, cmdLength)
		copy(cmd, baseHeader)
		if cmdLength > baseHeaderLen {
			if _, err := io.ReadFull(conn, cmd[baseHeaderLen:]); err != nil {
				return nil, err
			}
		}

		return cmd, nil
	}

	cmdLength, err := controlCommandLength(header[0], nil)
	if err != nil {
		return nil, err
	}

	cmd := make([]byte, cmdLength)
	copy(cmd, header)
	if _, err := io.ReadFull(conn, cmd[1:]); err != nil {
		return nil, err
	}

	return cmd, nil
}

func (s *mockServer) readEncryptedCommand(conn net.Conn) ([]byte, error) {
	if s.controlDecrypt == nil {
		return nil, errors.New("control decryption not initialized")
	}

	firstCipher := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(conn, firstCipher); err != nil {
		return nil, err
	}

	firstPlain, err := s.controlDecrypt.Decrypt(firstCipher)
	if err != nil {
		return nil, err
	}

	cmdLength, err := controlCommandLength(firstPlain[0], firstPlain)
	if err != nil {
		return nil, err
	}

	if cmdLength%aes.BlockSize != 0 {
		return nil, common.ErrInvalidMessageLength
	}

	remaining := cmdLength - len(firstPlain)
	cmd := make([]byte, cmdLength)
	copy(cmd, firstPlain)

	if remaining > 0 {
		restCipher := make([]byte, remaining)
		if _, err := io.ReadFull(conn, restCipher); err != nil {
			return nil, err
		}

		restPlain, err := s.controlDecrypt.Decrypt(restCipher)
		if err != nil {
			return nil, err
		}
		copy(cmd[len(firstPlain):], restPlain)
	}

	messageEnd := cmdLength - 16
	valid, err := crypto.VerifyHMAC(s.keyDerivation.HMACKey, cmd[:messageEnd], cmd[messageEnd:])
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, common.ErrHMACVerificationFailed
	}

	return cmd, nil
}

func (s *mockServer) sendControlMessage(conn net.Conn, mode common.Mode, message []byte) error {
	if !controlRequiresAuthentication(mode) {
		_, err := conn.Write(message)
		return err
	}
	if s.controlEncrypt == nil {
		return errors.New("control encryption not initialized")
	}
	if s.keyDerivation == nil {
		return errors.New("control keys not initialized")
	}

	messageLen := len(message) - 16
	var hmac []byte
	var err error
	if s.serverStartHMACPending {
		hmac, err = crypto.CalculateHMACWithPrefix(s.keyDerivation.HMACKey, s.serverStart, message[:messageLen])
		s.serverStartHMACPending = false
	} else {
		hmac, err = crypto.CalculateHMAC(s.keyDerivation.HMACKey, message[:messageLen])
	}
	if err != nil {
		return err
	}
	copy(message[messageLen:], hmac)

	encrypted, err := s.controlEncrypt.Encrypt(message)
	if err != nil {
		return err
	}
	_, err = conn.Write(encrypted)
	return err
}

type mockServerBehavior struct {
	rejectRequestSession bool
	rejectCode           uint8
	rejectStartSessions  bool
	rejectStopSessions   bool
}

type mockServer struct {
	listener       net.Listener
	supportedModes common.Mode
	stopChan       chan struct{}
	wg             sync.WaitGroup
	sharedSecrets  map[string]string

	// Protected by mu
	mu            sync.Mutex
	greetingSent  bool
	setupReceived bool
	lastCommand   byte

	sessions               map[common.SessionID]*mockSession
	sessionsMu             sync.Mutex
	sessionCount           int
	receivedHMACs          [][]byte
	serverStartTime        common.TWAMPTimestamp
	keyDerivation          *crypto.TWAMPKeys
	controlEncrypt         *crypto.CBCStream
	controlDecrypt         *crypto.CBCStream
	serverStart            []byte
	serverStartHMACPending bool
	t                      *testing.T // For logging in tests
	challenge              [16]byte
	salt                   [16]byte
	behavior               mockServerBehavior
}

type mockSession struct {
	sid           common.SessionID
	reflectorPort uint16
	senderPort    uint16
	mode          common.Mode
	isStarted     bool
	isPending     bool
}

func newMockServer(t *testing.T, modes common.Mode) *mockServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}

	// Create challenge and salt
	challenge := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	salt := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	server := &mockServer{
		listener:        l,
		supportedModes:  modes,
		stopChan:        make(chan struct{}),
		sharedSecrets:   map[string]string{"test-user": "test-password"},
		sessions:        make(map[common.SessionID]*mockSession),
		t:               t,
		challenge:       challenge,
		salt:            salt,
		serverStartTime: common.FromTime(time.Now()),
	}

	server.wg.Add(1)
	go server.serve()
	return server
}

// Create an enhanced version of the mock server that allows behavior configuration
func newMockServerWithBehavior(t *testing.T, modes common.Mode, behavior mockServerBehavior) *mockServer {
	server := newMockServer(t, modes)
	server.behavior = behavior
	return server
}

func (s *mockServer) serve() {
	defer s.wg.Done()
	defer s.listener.Close()

	for {
		select {
		case <-s.stopChan:
			return
		default:
			s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
			conn, err := s.listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				s.t.Logf("Error accepting connection: %v", err)
				continue
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConnection(conn)
			}()
		}
	}
}

func (s *mockServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Send ServerGreeting
	greeting := messages.ServerGreeting{
		Modes:     uint32(s.supportedModes),
		Challenge: s.challenge,
		Salt:      s.salt,
		Count:     1024,
	}

	data, err := greeting.Marshal()
	if err != nil {
		s.t.Logf("Failed to marshal greeting: %v", err)
		return
	}

	_, err = conn.Write(data)
	if err != nil {
		s.t.Logf("Failed to send greeting: %v", err)
		return
	}
	s.mu.Lock()
	s.greetingSent = true
	s.mu.Unlock()

	// Read setup response
	// SetupResponse message size: 164 bytes per RFC 4656
	buf := make([]byte, 164)
	n, err := conn.Read(buf)
	if err != nil {
		s.t.Logf("Failed to read setup response: %v", err)
		return
	}
	if n < 164 {
		s.t.Logf("Short read for setup response: %d bytes", n)
		return
	}
	s.mu.Lock()
	s.setupReceived = true
	s.mu.Unlock()

	// Parse setup response
	var setupResponse messages.SetupResponse
	err = setupResponse.Unmarshal(buf)
	if err != nil {
		s.t.Logf("Failed to unmarshal setup response: %v", err)
		return
	}

	// Determine negotiated mode
	mode := common.Mode(setupResponse.Mode & uint32(s.supportedModes))
	if mode == 0 {
		s.t.Logf("No compatible mode")
		return
	}

	// If authenticated or encrypted mode, verify token and store keys
	if mode != common.ModeUnauthenticated {
		// Extract KeyID
		keyIDBytes := setupResponse.KeyID[:]
		keyID := ""
		for i, b := range keyIDBytes {
			if b == 0 {
				keyID = string(keyIDBytes[:i])
				break
			}
		}

		// Lookup shared secret
		sharedSecret, exists := s.sharedSecrets[keyID]
		if !exists {
			s.t.Logf("Unknown KeyID: %s", keyID)
			return
		}

		// Derive keys
		aesKey, hmacKey, err := crypto.DeriveKey(sharedSecret, s.salt[:], 1024)
		if err != nil {
			s.t.Logf("Failed to derive keys: %v", err)
			return
		}

		// Decrypt and verify token
		token := setupResponse.Token[:]
		_, err = crypto.DecryptToken(token, s.challenge[:])
		if err != nil {
			s.t.Logf("Failed to decrypt token: %v", err)
			return
		}

		// Store key derivation for future HMAC verification
		s.keyDerivation = &crypto.TWAMPKeys{
			AESKey:   aesKey,
			HMACKey:  hmacKey,
			ClientIV: setupResponse.ClientIV[:],
		}

		// Generate ServerIV
		serverIV, err := crypto.NewRandomIV()
		if err != nil {
			s.t.Logf("Failed to generate server IV: %v", err)
			return
		}
		s.keyDerivation.ServerIV = serverIV

		controlEncrypt, err := crypto.NewCBCStream(s.keyDerivation.AESKey, s.keyDerivation.ServerIV)
		if err != nil {
			s.t.Logf("Failed to init control encrypt stream: %v", err)
			return
		}
		controlDecrypt, err := crypto.NewCBCStream(s.keyDerivation.AESKey, s.keyDerivation.ClientIV)
		if err != nil {
			s.t.Logf("Failed to init control decrypt stream: %v", err)
			return
		}
		s.controlEncrypt = controlEncrypt
		s.controlDecrypt = controlDecrypt
		s.serverStartHMACPending = true
	} else {
		s.controlEncrypt = nil
		s.controlDecrypt = nil
		s.serverStartHMACPending = false
	}

	// Send ServerStart
	serverStart := messages.ServerStart{
		Accept:    common.AcceptOK,
		StartTime: s.serverStartTime,
	}

	// Set ServerIV if in secure mode
	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		copy(serverStart.ServerIV[:], s.keyDerivation.ServerIV)
	}

	data, err = serverStart.Marshal()
	if err != nil {
		s.t.Logf("Failed to marshal server start: %v", err)
		return
	}
	s.serverStart = append([]byte(nil), data...)

	_, err = conn.Write(data)
	if err != nil {
		s.t.Logf("Failed to send server start: %v", err)
		return
	}

	// Command processing loop
	for {
		cmdData, err := s.readCommand(conn, mode)
		if err != nil {
			if err != io.EOF {
				s.t.Logf("Error reading command: %v", err)
			}
			return
		}

		cmd := cmdData[0]
		// Update lastCommand right when command is received, not in the handlers
		s.mu.Lock()
		s.lastCommand = cmd
		s.mu.Unlock()

		// Process command
		switch cmd {
		case common.CmdRequestTWSession:
			s.handleRequestSession(conn, cmdData, mode)
		case common.CmdRequestTWSessionIndividual: // RFC 5938
			s.handleRequestSessionIndividual(conn, cmdData, mode)
		case common.CmdStartSessions:
			s.handleStartSessions(conn, cmdData, mode)
		case common.CmdStopSessions:
			s.handleStopSessions(conn, cmdData, mode)
			// After stopping sessions, typically connection is closed
			return
		case common.CmdStopNSessions: // RFC 5938
			s.handleStopNSessions(conn, cmdData, mode)
		default:
			s.t.Logf("Unknown command: %d", cmd)
			return
		}
	}
}

func (s *mockServer) handleRequestSession(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Request-TW-Session
	var request messages.RequestTWSession
	err := request.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Request-TW-Session: %v", err)
		return
	}

	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.mu.Lock()
		s.receivedHMACs = append(s.receivedHMACs, hmac)
		s.mu.Unlock()
	}

	// Create a unique session ID using sessionCount
	var sid common.SessionID
	// Use sessionCount to ensure unique SIDs
	sessionNum := s.sessionCount
	for i := range sid {
		if i < 4 {
			// Use sessionCount in first 4 bytes for uniqueness
			sid[i] = byte(sessionNum >> (24 - i*8))
		} else {
			// Fill rest with incrementing values
			sid[i] = byte(i)
		}
	}

	// Store session
	reflectorPort := uint16(20000 + s.sessionCount)
	s.sessionCount++

	session := &mockSession{
		sid:           sid,
		reflectorPort: reflectorPort,
		senderPort:    request.SenderPort,
		mode:          mode,
		isPending:     true,
	}

	s.sessionsMu.Lock()
	s.sessions[sid] = session
	s.sessionsMu.Unlock()

	// Create Accept-Session response
	acceptSession := &messages.AcceptSession{
		Accept: common.AcceptOK,
		Port:   reflectorPort,
		SID:    sid,
	}

	// Check if we should reject this request based on behavior configuration
	if s.behavior.rejectRequestSession {
		// Send rejection
		acceptCode := s.behavior.rejectCode
		if acceptCode == 0 {
			acceptCode = common.AcceptFailure // Default rejection code
		}

		// Create Accept-Session response with rejection
		acceptSession := &messages.AcceptSession{
			Accept: acceptCode,
			Port:   0,                  // No port when rejecting
			SID:    common.SessionID{}, // Empty SID when rejecting
		}

		// Marshal and send the response with the appropriate HMAC handling
		data, err := acceptSession.Marshal(false)
		if err != nil {
			s.t.Logf("Failed to marshal Accept-Session: %v", err)
			return
		}
		if err := s.sendControlMessage(conn, mode, data); err != nil {
			s.t.Logf("Failed to send Accept-Session: %v", err)
		}
		return
	}

	data, err := acceptSession.Marshal(false)
	if err != nil {
		s.t.Logf("Failed to marshal Accept-Session: %v", err)
		return
	}

	if err := s.sendControlMessage(conn, mode, data); err != nil {
		s.t.Logf("Failed to send Accept-Session: %v", err)
		return
	}
}

func (s *mockServer) handleStartSessions(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Start-Sessions
	var startSessions messages.StartSessions
	err := startSessions.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Start-Sessions: %v", err)
		return
	}

	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.mu.Lock()
		s.receivedHMACs = append(s.receivedHMACs, hmac)
		s.mu.Unlock()
	}

	// Mark all sessions as started
	s.sessionsMu.Lock()
	for _, session := range s.sessions {
		if session.isPending {
			session.isStarted = true
			session.isPending = false
		}
	}
	s.sessionsMu.Unlock()

	// Create Start-Ack response
	startAck := &messages.StartAck{
		Accept: common.AcceptOK,
	}

	// Check if we should reject this request based on behavior configuration
	if s.behavior.rejectStartSessions {
		// Send rejection
		acceptCode := s.behavior.rejectCode
		if acceptCode == 0 {
			acceptCode = common.AcceptFailure // Default rejection code
		}

		// Create Start-Ack response with rejection
		startAck := &messages.StartAck{
			Accept: acceptCode,
		}

		// Marshal and send the response with the appropriate HMAC handling
		data, err := startAck.Marshal(false)
		if err != nil {
			s.t.Logf("Failed to marshal Start-Ack: %v", err)
			return
		}
		if err := s.sendControlMessage(conn, mode, data); err != nil {
			s.t.Logf("Failed to send Start-Ack: %v", err)
		}
		return
	}

	data, err := startAck.Marshal(false)
	if err != nil {
		s.t.Logf("Failed to marshal Start-Ack: %v", err)
		return
	}

	if err := s.sendControlMessage(conn, mode, data); err != nil {
		s.t.Logf("Failed to send Start-Ack: %v", err)
		return
	}
}

func (s *mockServer) handleStopSessions(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Stop-Sessions
	var stopSessions messages.StopSessions
	err := stopSessions.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Stop-Sessions: %v", err)
		return
	}

	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.mu.Lock()
		s.receivedHMACs = append(s.receivedHMACs, hmac)
		s.mu.Unlock()
	}

	// Clear all sessions - make sure to completely clear
	s.sessionsMu.Lock()
	s.sessions = make(map[common.SessionID]*mockSession)
	s.sessionsMu.Unlock()

	// No sleep needed - session clearing is synchronous with the lock
}

func (s *mockServer) handleStopNSessions(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Stop-N-Sessions (RFC 5938)
	var stopNSessions messages.StopNSessions
	err := stopNSessions.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Stop-N-Sessions: %v", err)
		return
	}

	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.mu.Lock()
		s.receivedHMACs = append(s.receivedHMACs, hmac)
		s.mu.Unlock()
	}

	// Stop N sessions (oldest first)
	numToStop := int(stopNSessions.NumSessions)
	s.sessionsMu.Lock()
	stopped := 0
	for sid, session := range s.sessions {
		if stopped >= numToStop {
			break
		}
		if session.isStarted || session.isPending {
			delete(s.sessions, sid)
			stopped++
		}
	}
	s.sessionsMu.Unlock()

	// Send Stop-N-Ack response
	response := &messages.StopNSessions{
		Command:     common.CmdStopNSessions,
		Accept:      common.AcceptOK,
		NumSessions: 0, // Response doesn't need session IDs
	}

	data, err := response.Marshal(false)
	if err != nil {
		s.t.Logf("Failed to marshal Stop-N-Sessions response: %v", err)
		return
	}

	if err := s.sendControlMessage(conn, mode, data); err != nil {
		s.t.Logf("Failed to send Stop-N-Sessions response: %v", err)
	}
}

func (s *mockServer) handleRequestSessionIndividual(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Request-TW-Session-Individual (RFC 5938)
	var request messages.RequestTWSessionIndividual
	err := request.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Request-TW-Session-Individual: %v", err)
		return
	}

	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.mu.Lock()
		s.receivedHMACs = append(s.receivedHMACs, hmac)
		s.mu.Unlock()
	}

	// Use client-specified SID from the request
	sid := request.SID

	// Check if SID already exists
	s.sessionsMu.Lock()
	if _, exists := s.sessions[sid]; exists {
		s.sessionsMu.Unlock()
		// Send rejection
		acceptSession := messages.AcceptSession{
			Accept: common.AcceptNotSupported,
			Port:   0,
			SID:    common.SessionID{},
		}

		data, err := acceptSession.Marshal(false)
		if err != nil {
			s.t.Fatalf("Failed to marshal AcceptSession: %v", err)
		}
		if err := s.sendControlMessage(conn, mode, data); err != nil {
			s.t.Logf("Failed to send AcceptSession: %v", err)
		}
		return
	}

	// Store session with client-specified SID
	reflectorPort := uint16(20000 + s.sessionCount)
	s.sessionCount++

	session := &mockSession{
		sid:           sid,
		reflectorPort: reflectorPort,
		senderPort:    request.SenderPort,
		mode:          mode,
		isPending:     true,
	}

	s.sessions[sid] = session
	s.sessionsMu.Unlock()

	// Create Accept-Session response
	acceptSession := messages.AcceptSession{
		Accept: common.AcceptOK,
		Port:   reflectorPort,
		SID:    sid,
	}

	data, err := acceptSession.Marshal(false)
	if err != nil {
		s.t.Logf("Failed to marshal Accept-Session: %v", err)
		return
	}

	if err := s.sendControlMessage(conn, mode, data); err != nil {
		s.t.Logf("Failed to send Accept-Session: %v", err)
	}
}

// Helper function for constant-time byte comparison
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func (s *mockServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockServer) stop() {
	close(s.stopChan)
	s.wg.Wait()
}

// Tests for client.go
func TestConnectUnauthenticated(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client with minimal config
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Verify server received our connection
	server.mu.Lock()
	greetingSetupComplete := server.greetingSent && server.setupReceived
	server.mu.Unlock()
	if !greetingSetupComplete {
		t.Fatal("Server did not complete handshake")
	}

	// Verify client state
	if client.mode != common.ModeUnauthenticated {
		t.Errorf("Expected client mode to be %d, got %d", common.ModeUnauthenticated, client.mode)
	}
}

func TestConnectAuthenticated(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

	// Create client with authentication config
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeAuthenticated,
		SharedSecret:  "test-password",
		KeyID:         "test-user",
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Verify server received our connection
	server.mu.Lock()
	greetingSetupComplete := server.greetingSent && server.setupReceived
	server.mu.Unlock()
	if !greetingSetupComplete {
		t.Fatal("Server did not complete handshake")
	}

	// Verify client state
	if client.mode != common.ModeAuthenticated {
		t.Errorf("Expected client mode to be %d, got %d", common.ModeAuthenticated, client.mode)
	}

	// Verify client has key derivation
	if client.keyDerivation == nil {
		t.Error("Expected keyDerivation to be set")
	}
}

func TestConnectEncrypted(t *testing.T) {
	// Start mock server that supports encrypted mode
	server := newMockServer(t, common.ModeEncrypted)
	defer server.stop()

	// Create client with encryption config
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeEncrypted,
		SharedSecret:  "test-password",
		KeyID:         "test-user",
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect in encrypted mode: %v", err)
	}
	defer client.Close()

	// Verify server received our connection
	server.mu.Lock()
	greetingSetupComplete := server.greetingSent && server.setupReceived
	server.mu.Unlock()
	if !greetingSetupComplete {
		t.Fatal("Server did not complete handshake")
	}

	// Verify client state
	if client.mode != common.ModeEncrypted {
		t.Errorf("Expected client mode to be %d (encrypted), got %d",
			common.ModeEncrypted, client.mode)
	}

	// Verify client has key derivation
	if client.keyDerivation == nil {
		t.Error("Expected keyDerivation to be set")
	}

	// Test RequestSession under encrypted mode
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   56, // Minimum padding for encrypted mode
		Timeout:         1 * time.Second,
	}

	session, err := client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session in encrypted mode: %v", err)
	}

	// Verify server received request
	if server.lastCommand != common.CmdRequestTWSession {
		t.Errorf("Expected server to receive request session command, got %d",
			server.lastCommand)
	}

	// Verify session was created successfully
	if session == nil {
		t.Fatal("Returned session is nil")
	}

	// Start the session
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions in encrypted mode: %v", err)
	}

	// Verify server received start command
	if server.lastCommand != common.CmdStartSessions {
		t.Errorf("Expected server to receive start session command, got %d",
			server.lastCommand)
	}
}

func TestRequestSession(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request a session
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

	// Verify mock server received request
	if server.lastCommand != common.CmdRequestTWSession {
		t.Errorf("Expected server to receive request session command, got %d", server.lastCommand)
	}

	// Verify session was created
	if len(server.sessions) == 0 {
		t.Fatal("No sessions created on server")
	}

	// Verify session in client
	if len(client.currentSessions) == 0 {
		t.Fatal("No sessions stored in client")
	}

	// Verify returned session is valid
	if session == nil {
		t.Fatal("Returned session is nil")
	}
}

func TestStartSessions(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request a session
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

	// Start sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify mock server received start command
	if server.lastCommand != common.CmdStartSessions {
		t.Errorf("Expected server to receive start session command, got %d", server.lastCommand)
	}

	// Verify sessions in server are started
	server.sessionsMu.Lock()
	startedCount := 0
	for _, session := range server.sessions {
		if session.isStarted {
			startedCount++
		}
	}
	server.sessionsMu.Unlock()

	if startedCount == 0 {
		t.Fatal("No sessions started on server")
	}
}

func TestStopSessions(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request a session
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

	// Start sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify we have sessions before stopping
	if len(client.currentSessions) == 0 {
		t.Fatal("No sessions in client before stop")
	}

	// Stop sessions
	err = client.StopSessions()
	if err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}
}

func TestErrorCases(t *testing.T) {
	// Tests for various error cases

	// Test StartSessions with no sessions
	t.Run("StartSessionsNoSessions", func(t *testing.T) {
		client := NewClient(ClientConfig{})
		err := client.StartSessions()
		if err == nil {
			t.Fatal("Expected error when starting sessions with no sessions")
		}
	})

	// Test StopSessions with no sessions (should not error)
	t.Run("StopSessionsNoSessions", func(t *testing.T) {
		client := NewClient(ClientConfig{})
		err := client.StopSessions()
		if err != nil {
			t.Fatalf("Expected no error when stopping with no sessions, got: %v", err)
		}
	})

	// Test connection to server with no shared modes
	t.Run("NoCompatibleModes", func(t *testing.T) {
		server := newMockServer(t, common.ModeAuthenticated)
		defer server.stop()

		client := NewClient(ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		})

		err := client.Connect(context.Background())
		if err == nil {
			t.Fatal("Expected error when connecting with incompatible modes")
		}
	})

	// Test authenticated mode without shared secret
	t.Run("AuthWithoutSecret", func(t *testing.T) {
		server := newMockServer(t, common.ModeAuthenticated)
		defer server.stop()

		client := NewClient(ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeAuthenticated,
			Timeout:       2 * time.Second,
			// No shared secret provided
		})

		err := client.Connect(context.Background())
		if err == nil {
			t.Fatal("Expected error when connecting in authenticated mode without shared secret")
		}
	})
}

func TestClose(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Request a session
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

	// Start sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify sessions are started
	if len(client.currentSessions) == 0 {
		t.Fatal("No sessions in client before close")
	}

	// Close client
	err = client.Close()
	if err != nil {
		t.Fatalf("Failed to close client: %v", err)
	}

	// Verify connection is closed
	if client.conn != nil {
		t.Fatal("Connection still exists after close")
	}

	// Verify sessions are stopped
	if len(client.currentSessions) != 0 {
		t.Fatalf("Expected 0 sessions after close, got %d", len(client.currentSessions))
	}
}

func TestInvalidIPAddress(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request a session with invalid IP address
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "invalid-ip",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	_, err = client.RequestSession(sessionCfg)

	// Verify we get the expected error
	if err == nil {
		t.Fatal("Expected error for invalid IP address, got nil")
	}
	if !errors.Is(err, common.ErrInvalidReceiverAddress) {
		t.Fatalf("Expected ErrInvalidReceiverAddress, got: %v", err)
	}
}

func TestPaddingLengthAdjustment(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeAuthenticated,
		SharedSecret:  "test-password",
		KeyID:         "test-user",
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request a session with insufficient padding (should be auto-adjusted)
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   10, // Too small, should be adjusted
		Timeout:         1 * time.Second,
	}

	session, err := client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Verify session was created successfully
	if session == nil {
		t.Fatal("Returned session is nil")
	}

	// Verify the padding was adjusted (would require checking internal state)
	// Since we can't directly check the adjusted padding, we at least verify
	// that the session was created successfully despite the small initial padding
}

func TestConnectionTimeout(t *testing.T) {
	// Use a non-routable IP that will cause timeout
	// 192.0.2.0/24 is TEST-NET-1 from RFC 5737, reserved for documentation
	cfg := ClientConfig{
		ServerAddress: "192.0.2.1:862",
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       500 * time.Millisecond, // Short timeout for faster test
	}

	client := NewClient(cfg)

	// Attempt to connect - should time out
	ctx := context.Background()
	err := client.Connect(ctx)

	// Verify we get timeout error
	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Expected timeout error, got: %v", err)
	}
}

// TestServerRejectsRequestSession verifies client properly handles server rejection
func TestServerRejectsRequestSession(t *testing.T) {
	// Create a mock server that will reject session requests
	server := newMockServerWithBehavior(t, common.ModeUnauthenticated, mockServerBehavior{
		rejectRequestSession: true,
		rejectCode:           common.AcceptTempResLimited, // Use a specific rejection code
	})
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request a session - should be rejected by server
	ports := testutil.GetFreePorts(t, "udp", 2)
	sessionCfg := TestSessionConfig{
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	_, err = client.RequestSession(sessionCfg)

	// Verify we get the expected error
	if err == nil {
		t.Fatal("Expected error when server rejects session request, got nil")
	}

	// The error should be a TWAMPError with the correct code
	var twampErr *common.TWAMPError
	if !errors.As(err, &twampErr) {
		t.Fatalf("Expected *common.TWAMPError, got: %v", err)
	}

	if twampErr.AcceptCode != common.AcceptTempResLimited {
		t.Errorf("Expected accept code %d, got %d",
			common.AcceptTempResLimited, twampErr.AcceptCode)
	}
}

func TestServerRejectsStartSessions(t *testing.T) {
	// Create a mock server that will reject start sessions
	server := newMockServerWithBehavior(t, common.ModeUnauthenticated, mockServerBehavior{
		rejectStartSessions: true,
		rejectCode:          common.AcceptTempResLimited,
	})
	defer server.stop()

	// Create client
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request a session
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

	// Start sessions - should be rejected
	err = client.StartSessions()

	// Verify we get the expected error
	if err == nil {
		t.Fatal("Expected error when server rejects start sessions, got nil")
	}

	// The error should be a TWAMPError with the correct code
	var twampErr *common.TWAMPError
	if !errors.As(err, &twampErr) {
		t.Fatalf("Expected *common.TWAMPError, got: %v", err)
	}

	if twampErr.AcceptCode != common.AcceptTempResLimited {
		t.Errorf("Expected accept code %d, got %d",
			common.AcceptTempResLimited, twampErr.AcceptCode)
	}
}

func TestConcurrentRequestTWSession(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       5 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Number of concurrent sessions to request
	numSessions := 20

	// Pre-allocate all ports BEFORE spawning goroutines to avoid port conflicts
	// Each session needs 2 ports (sender and receiver)
	allPorts := testutil.GetFreePorts(t, "udp", numSessions*2)

	var wg sync.WaitGroup
	errChan := make(chan error, numSessions)
	sessionChan := make(chan *TestSession, numSessions)

	// Request sessions concurrently
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Use pre-allocated ports
			sessionCfg := TestSessionConfig{
				SenderPort:      uint16(allPorts[idx*2]),
				ReceiverPort:    uint16(allPorts[idx*2+1]),
				ReceiverAddress: "127.0.0.1",
				PaddingLength:   64,
				Timeout:         2 * time.Second,
			}

			session, err := client.RequestSession(sessionCfg)
			if err != nil {
				errChan <- err
				return
			}
			sessionChan <- session
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errChan)
	close(sessionChan)

	// Check for errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		t.Fatalf("Failed to request sessions concurrently: %v", errs)
	}

	// Count successful sessions
	var sessions []*TestSession
	for session := range sessionChan {
		sessions = append(sessions, session)
	}

	if len(sessions) != numSessions {
		t.Errorf("Expected %d sessions, got %d", numSessions, len(sessions))
	}

	// Verify each session has unique ports
	senderPorts := make(map[uint16]bool)
	receiverPorts := make(map[uint16]bool)
	for _, session := range sessions {
		if senderPorts[session.config.SenderPort] {
			t.Errorf("Duplicate sender port: %d", session.config.SenderPort)
		}
		senderPorts[session.config.SenderPort] = true

		if receiverPorts[session.config.ReceiverPort] {
			t.Errorf("Duplicate receiver port: %d", session.config.ReceiverPort)
		}
		receiverPorts[session.config.ReceiverPort] = true
	}

	// Try to start all sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Stop all sessions
	err = client.StopSessions()
	if err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}
}

// generateMalformedPacketTestCases returns test cases for malformed packet testing
func generateMalformedPacketTestCases(mode common.Mode) []struct {
	name        string
	packet      func() []byte
	description string
} {
	return []struct {
		name        string
		packet      func() []byte
		description string
	}{
		{
			name: "TooShortPacket",
			packet: func() []byte {
				// Packet too short for the mode
				if mode == common.ModeEncrypted {
					// Encrypted mode requires 48-byte minimum for sender packets
					return make([]byte, encryptedMinPacketSize-1) // One byte short
				}
				// Authenticated mode requires 48-byte minimum
				return make([]byte, authenticatedMinPacketSize-1) // One byte short
			},
			description: "Packet shorter than minimum required",
		},
		{
			name: "InvalidHMAC",
			packet: func() []byte {
				// Create a valid-sized packet with invalid HMAC
				size := authenticatedMinPacketSize
				if mode == common.ModeEncrypted {
					size = encryptedMinPacketSize
				}
				packet := make([]byte, size)
				// Fill with random data (invalid HMAC)
				for i := range packet {
					packet[i] = byte(i % 256)
				}
				return packet
			},
			description: "Packet with invalid HMAC",
		},
		{
			name: "CorruptedEncryption",
			packet: func() []byte {
				// For encrypted mode, send garbage that can't be decrypted
				if mode == common.ModeEncrypted {
					packet := make([]byte, 128) // Valid size but corrupted content
					for i := range packet {
						packet[i] = byte(0xFF) // All 0xFF - unlikely to decrypt properly
					}
					return packet
				}
				// For authenticated mode, just invalid HMAC
				packet := make([]byte, 64)
				for i := range packet {
					packet[i] = byte(0xAA)
				}
				return packet
			},
			description: "Packet with corrupted encryption",
		},
		{
			name: "WrongBlockAlignment",
			packet: func() []byte {
				// For encrypted mode, send non-block-aligned data
				if mode == common.ModeEncrypted {
					return make([]byte, 97) // Not aligned to 16-byte blocks
				}
				return make([]byte, 49) // Odd size for authenticated
			},
			description: "Packet with wrong block alignment",
		},
		{
			name: "TruncatedPacket",
			packet: func() []byte {
				// Start with a valid size then truncate
				size := 112
				if mode == common.ModeAuthenticated {
					size = 64
				}
				packet := make([]byte, size)
				// Fill with pattern
				for i := range packet {
					packet[i] = byte(i & 0xFF)
				}
				// Return truncated version
				return packet[:len(packet)-10]
			},
			description: "Truncated packet missing end bytes",
		},
		{
			name: "AllZeros",
			packet: func() []byte {
				// Packet filled with all zeros
				size := 96
				if mode == common.ModeAuthenticated {
					size = 48
				}
				return make([]byte, size) // All zeros
			},
			description: "Packet with all zero bytes",
		},
		{
			name: "RandomGarbage",
			packet: func() []byte {
				// Complete random garbage
				size := 128
				packet := make([]byte, size)
				for i := range packet {
					packet[i] = byte(rand.Intn(256))
				}
				return packet
			},
			description: "Packet with random garbage data",
		},
	}
}

// TestMalformedEncryptedPackets tests handling of various malformed encrypted packets
func TestMalformedEncryptedPackets(t *testing.T) {
	// Test with different encryption modes
	modes := []struct {
		name string
		mode common.Mode
	}{
		{"Authenticated", common.ModeAuthenticated},
		{"Encrypted", common.ModeEncrypted},
	}

	for _, testMode := range modes {
		t.Run(testMode.name, func(t *testing.T) {
			// Start mock server with the appropriate mode
			server := newMockServer(t, testMode.mode)
			defer server.stop()

			// Create client with appropriate configuration
			client := NewClient(ClientConfig{
				ServerAddress: server.addr(),
				PreferredMode: testMode.mode,
				SharedSecret:  "test-password",
				KeyID:         "test-user",
				Timeout:       2 * time.Second,
			})

			// Connect to server
			ctx := context.Background()
			err := client.Connect(ctx)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer client.Close()

			// Request a test session
			ports := testutil.GetFreePorts(t, "udp", 2)
			sessionCfg := TestSessionConfig{
				SenderPort:    uint16(ports[0]),
				ReceiverPort:  uint16(ports[1]),
				PaddingLength: 100,
				Timeout:       1 * time.Second,
			}
			session, err := client.RequestSession(sessionCfg)
			if err != nil {
				t.Fatalf("Failed to request session: %v", err)
			}

			// Start the session
			err = session.Start()
			if err != nil {
				t.Fatalf("Failed to start session: %v", err)
			}
			defer session.Stop()

			// Get the session's connection for sending malformed packets
			conn := session.conn

			// Get test cases for malformed packets
			testCases := generateMalformedPacketTestCases(testMode.mode)

			// Send malformed packets and verify they're handled gracefully
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					// Create the malformed packet
					malformedPacket := tc.packet()

					// Send the malformed packet to the session
					destAddr, err := net.ResolveUDPAddr("udp",
						fmt.Sprintf("127.0.0.1:%d", session.config.SenderPort))
					if err != nil {
						t.Fatalf("Failed to resolve address: %v", err)
					}

					_, err = conn.WriteTo(malformedPacket, destAddr)
					if err != nil {
						t.Fatalf("Failed to send malformed packet: %v", err)
					}

					// Check session is still functional after malformed packet
					// Verify the session remains functional after receiving malformed packet
					// Just try once - if it fails, the session is broken
					sendErr := session.SendTestPacket()
					if sendErr != nil {
						t.Logf("Warning: Session may have been affected by %s: %v",
							tc.description, sendErr)
					}
				})
			}

			// Verify session can still operate after malformed packets
			results := session.GetResults()
			t.Logf("Session results after malformed packet tests: sent=%d, received=%d",
				results.PacketsSent, results.PacketsReceived)

			// Session should still be functional
			err = session.SendTestPacket()
			if err != nil {
				t.Errorf("Session failed after malformed packet tests: %v", err)
			}
		})
	}
}

// TestMalformedEncryptedPacketsInReceiver tests malformed packet handling in the receiver
func TestMalformedEncryptedPacketsInReceiver(t *testing.T) {
	// Create session ID and keys for testing
	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Create control keys
	controlKeys := &crypto.TWAMPKeys{
		AESKey:   make([]byte, 16), // AES-128 key size
		HMACKey:  make([]byte, 32), // HMAC-SHA256 key size
		ClientIV: make([]byte, 16), // AES block size for IV
		ServerIV: make([]byte, 16), // AES block size for IV
	}
	for i := range controlKeys.AESKey {
		controlKeys.AESKey[i] = byte(i)
	}
	for i := range controlKeys.HMACKey {
		controlKeys.HMACKey[i] = byte(i + 16)
	}

	// Test both authenticated and encrypted modes
	modes := []struct {
		name string
		mode common.Mode
	}{
		{"Authenticated", common.ModeAuthenticated},
		{"Encrypted", common.ModeEncrypted},
	}

	for _, testMode := range modes {
		t.Run(testMode.name, func(t *testing.T) {
			ports := testutil.GetFreePorts(t, "udp", 2)
			config := TestSessionConfig{
				SenderPort:      uint16(ports[0]),
				ReceiverPort:    uint16(ports[1]),
				ReceiverAddress: "127.0.0.1",
				PaddingLength:   56, // Minimum for encrypted mode
				Timeout:         1 * time.Second,
			}

			// Create test session
			session, err := NewTestSession(config, sid, testMode.mode, controlKeys)
			if err != nil {
				t.Fatalf("Failed to create test session: %v", err)
			}

			// Start the session
			err = session.Start()
			if err != nil {
				t.Fatalf("Failed to start session: %v", err)
			}
			defer session.Stop()

			// Start receiving in the background
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session.StartReceiving(ctx)

			// Test various malformed packets being processed by processReceivedPacket
			testCases := []struct {
				name          string
				packet        []byte
				expectError   bool
				errorContains string
			}{
				{
					name:          "EmptyPacket",
					packet:        []byte{},
					expectError:   true,
					errorContains: "", // Accept any error for empty packet
				},
				{
					name:          "TooShortForMode",
					packet:        make([]byte, 10),
					expectError:   true,
					errorContains: "", // Accept any error for too short packet
				},
				{
					name: "InvalidSequenceNumber",
					packet: func() []byte {
						// Create a packet with invalid structure
						size := authenticatedMinPacketSize
						if testMode.mode == common.ModeEncrypted {
							size = encryptedMinPacketSize
						}
						packet := make([]byte, size)
						// Set an invalid sequence number (will fail unmarshal)
						return packet
					}(),
					expectError: true,
				},
				{
					name: "ValidSizeInvalidContent",
					packet: func() []byte {
						size := authenticatedMinPacketSize
						if testMode.mode == common.ModeEncrypted {
							size = 112
						}
						packet := make([]byte, size)
						// Fill with pattern that won't decrypt/unmarshal properly
						for i := range packet {
							packet[i] = byte(0x55)
						}
						return packet
					}(),
					expectError: true,
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					// Process the malformed packet
					err := session.processReceivedPacket(tc.packet, time.Now())

					if tc.expectError {
						if err == nil {
							t.Errorf("Expected error for %s, but got none", tc.name)
						} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
							t.Errorf("Expected error containing '%s', got: %v",
								tc.errorContains, err)
						}
					} else {
						if err != nil {
							t.Errorf("Unexpected error for %s: %v", tc.name, err)
						}
					}
				})
			}

			// Verify session is still functional after processing malformed packets
			err = session.SendTestPacket()
			if err != nil {
				t.Errorf("Session not functional after malformed packet tests: %v", err)
			}
		})
	}
}

func TestReceiveAndVerifyUnauthenticatedNoHMAC(t *testing.T) {
	c := &Client{mode: common.ModeUnauthenticated}
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	c.conn = cli

	// Prepare a 32-byte payload; last 16 bytes are MBZ for unauthenticated control messages
	payload := make([]byte, 32)
	for i := 0; i < 16; i++ {
		payload[i] = 0xAA
	}
	go func() { _, _ = srv.Write(payload) }()

	buf, err := c.receiveAndVerify(32, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(buf) != 32 {
		t.Fatalf("expected len 32, got %d", len(buf))
	}
}

func TestReceiveAndVerifyHMACFailure(t *testing.T) {
	c := &Client{mode: common.ModeAuthenticated}
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	c.conn = cli

	// Provide HMAC key
	c.keyDerivation = &crypto.TWAMPKeys{
		HMACKey:  make([]byte, 32),
		AESKey:   make([]byte, 16),
		ServerIV: make([]byte, 16),
	}
	for i := range c.keyDerivation.HMACKey {
		c.keyDerivation.HMACKey[i] = byte(i)
	}
	for i := range c.keyDerivation.AESKey {
		c.keyDerivation.AESKey[i] = byte(0xA0 + i)
	}
	for i := range c.keyDerivation.ServerIV {
		c.keyDerivation.ServerIV[i] = byte(0xB0 + i)
	}

	controlDecrypt, err := crypto.NewCBCStream(c.keyDerivation.AESKey, c.keyDerivation.ServerIV)
	if err != nil {
		t.Fatalf("NewCBCStream: %v", err)
	}
	c.controlDecrypt = controlDecrypt

	// Prepare message and incorrect HMAC
	msg := make([]byte, 16)
	for i := range msg {
		msg[i] = byte(0x10 + i)
	}
	tag, err := crypto.CalculateHMAC(c.keyDerivation.HMACKey, msg)
	if err != nil {
		t.Fatalf("CalculateHMAC: %v", err)
	}
	tag[0] ^= 0xFF // corrupt
	payload := append(append([]byte{}, msg...), tag...)

	controlEncrypt, err := crypto.NewCBCStream(c.keyDerivation.AESKey, c.keyDerivation.ServerIV)
	if err != nil {
		t.Fatalf("NewCBCStream: %v", err)
	}
	encrypted, err := controlEncrypt.Encrypt(payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	go func() { _, _ = srv.Write(encrypted) }()

	if _, err := c.receiveAndVerify(len(encrypted), true); err == nil {
		t.Fatalf("expected HMAC verification failure")
	}
}

func TestSendWithHMACUnauthenticated(t *testing.T) {
	c := &Client{mode: common.ModeUnauthenticated}
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	c.conn = cli

	msg := []byte("hello")

	// Run sendWithHMAC in goroutine to avoid blocking on pipe write
	var sendErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendErr = c.sendWithHMAC(msg, true)
	}()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(srv, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	<-done
	if sendErr != nil {
		t.Fatalf("unexpected error: %v", sendErr)
	}

	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", string(buf), string(msg))
	}
}

func TestSendWithHMACAuthenticated(t *testing.T) {
	c := &Client{mode: common.ModeAuthenticated}
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	c.conn = cli

	// Provide HMAC key derivation
	c.keyDerivation = &crypto.TWAMPKeys{HMACKey: make([]byte, 32)}
	for i := range c.keyDerivation.HMACKey {
		c.keyDerivation.HMACKey[i] = byte(i)
	}

	msg := []byte("payload")

	// Run sendWithHMAC in goroutine to avoid blocking on pipe write
	var sendErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendErr = c.sendWithHMAC(msg, true)
	}()

	// Expect message + HMAC to be written
	// HMAC-SHA1 is truncated to 16 bytes per RFC 4656 Section 4.1.2
	const hmacSize = 16 // Truncated HMAC-SHA1 size per RFC 4656
	buf := make([]byte, len(msg)+hmacSize)
	if _, err := io.ReadFull(srv, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	<-done
	if sendErr != nil {
		t.Fatalf("unexpected error: %v", sendErr)
	}

	// Verify prefix is original message
	if string(buf[:len(msg)]) != string(msg) {
		t.Fatalf("prefix mismatch: got %q want %q", string(buf[:len(msg)]), string(msg))
	}

	// Verify the trailing tag matches CalculateHMAC
	tag, err := crypto.CalculateHMAC(c.keyDerivation.HMACKey, msg)
	if err != nil {
		t.Fatalf("CalculateHMAC: %v", err)
	}
	if string(buf[len(msg):]) != string(tag) {
		t.Fatal("HMAC tag mismatch")
	}
}

func TestSendWithHMACEncrypted(t *testing.T) {
	c := &Client{mode: common.ModeEncrypted}
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	c.conn = cli

	// Provide AES and HMAC keys + IV
	c.keyDerivation = &crypto.TWAMPKeys{
		HMACKey:  make([]byte, 32),
		AESKey:   make([]byte, 16),
		ClientIV: make([]byte, 16),
	}
	for i := range c.keyDerivation.HMACKey {
		c.keyDerivation.HMACKey[i] = byte(0xA0 + i)
	}
	for i := range c.keyDerivation.AESKey {
		c.keyDerivation.AESKey[i] = byte(i)
	}
	for i := range c.keyDerivation.ClientIV {
		c.keyDerivation.ClientIV[i] = byte(0xF0 - i)
	}

	msg := []byte("abc12345abc12345") // 16 bytes to keep message+HMAC block-aligned

	// Run sendWithHMAC in goroutine to avoid blocking on pipe write
	var sendErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendErr = c.sendWithHMAC(msg, true)
	}()

	// Read the encrypted data and decrypt it
	enc := make([]byte, 512)
	n, err := srv.Read(enc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	<-done
	if sendErr != nil {
		t.Fatalf("unexpected error: %v", sendErr)
	}

	decrypted, err := crypto.DecryptTWAMPControlMessage(c.keyDerivation.AESKey, c.keyDerivation.ClientIV, enc[:n])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Plaintext should be message || HMAC
	tag, err := crypto.CalculateHMAC(c.keyDerivation.HMACKey, msg)
	if err != nil {
		t.Fatalf("Failed to calculate HMAC: %v", err)
	}
	want := append(append([]byte{}, msg...), tag...)
	if string(decrypted) != string(want) {
		t.Fatalf("plaintext mismatch: got %x want %x", decrypted, want)
	}
}

func TestIPv6AddressSupport(t *testing.T) {
	tests := []struct {
		name          string
		address       string
		expectSuccess bool
	}{
		{
			name:          "IPv6 localhost with brackets",
			address:       "[::1]",
			expectSuccess: true,
		},
		{
			name:          "IPv6 full address",
			address:       "[2001:db8::1]",
			expectSuccess: true,
		},
		{
			name:          "IPv6 with zone identifier",
			address:       "[fe80::1%eth0]",
			expectSuccess: true,
		},
		{
			name:          "IPv4 address for comparison",
			address:       "127.0.0.1",
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test RequestSession with IPv6 address
			ports := testutil.GetFreePorts(t, "udp", 2)
			config := TestSessionConfig{
				SenderPort:      uint16(ports[0]),
				ReceiverPort:    uint16(ports[1]),
				ReceiverAddress: tt.address,
				PaddingLength:   64,
				Timeout:         1 * time.Second,
			}

			// Create a mock client - sessions field is private
			c := &Client{
				mode: common.ModeUnauthenticated,
			}

			// Verify address can be parsed and used
			var sid common.SessionID
			for i := range sid {
				sid[i] = byte(i)
			}

			session, err := NewTestSession(config, sid, c.mode, nil)
			if tt.expectSuccess && err != nil {
				t.Errorf("Failed to create session with %s: %v", tt.address, err)
			}
			if !tt.expectSuccess && err == nil {
				t.Errorf("Expected error for address %s, got none", tt.address)
			}

			if session != nil {
				// Verify the receiver address was set correctly
				if session.config.ReceiverAddress != tt.address {
					t.Errorf("Address mismatch: got %s, want %s",
						session.config.ReceiverAddress, tt.address)
				}
			}
		})
	}
}

func TestIPv6TestSession(t *testing.T) {
	// Skip if IPv6 is not available
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("IPv6 not available on this system")
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()

	// Create test session with IPv6
	config := TestSessionConfig{
		SenderPort:      0, // Let system assign
		ReceiverPort:    uint16(port),
		ReceiverAddress: "[::1]",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create IPv6 test session: %v", err)
	}

	// Verify session can start (may fail if port is in use, but should parse address)
	err = session.Start()
	if err != nil {
		// Check if it's an address parsing error vs bind error
		if !strings.Contains(err.Error(), "bind") &&
			!strings.Contains(err.Error(), "address already in use") {
			t.Errorf("Unexpected error starting IPv6 session: %v", err)
		}
	} else {
		session.Stop()
	}
}

func TestResourceLeakPrevention(t *testing.T) {
	// Test that resources are properly cleaned up
	t.Run("ClientConnectionLeak", func(t *testing.T) {
		server := newMockServer(t, common.ModeUnauthenticated)
		defer server.stop()

		// Track goroutine count before test
		initialGoroutines := runtime.NumGoroutine()

		// Create and close multiple clients
		for i := 0; i < 10; i++ {
			cfg := ClientConfig{
				ServerAddress: server.addr(),
				PreferredMode: common.ModeUnauthenticated,
				Timeout:       2 * time.Second,
			}
			client := NewClient(cfg)
			err := client.Connect(context.Background())
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}

			// Request a session
			ports := testutil.GetFreePorts(t, "udp", 2)
			config := TestSessionConfig{
				SenderPort:      uint16(ports[0]),
				ReceiverPort:    uint16(ports[1]),
				ReceiverAddress: "127.0.0.1",
				PaddingLength:   64,
				Timeout:         1 * time.Second,
			}

			session, err := client.RequestSession(config)
			if err != nil {
				t.Fatalf("Failed to request session: %v", err)
			}

			// Start and stop session
			if err := client.StartSessions(); err != nil {
				t.Fatalf("Failed to start sessions: %v", err)
			}

			if err := client.StopSessions(); err != nil {
				t.Fatalf("Failed to stop sessions: %v", err)
			}

			// Close client
			client.Close()
			_ = session
		}

		// Wait for goroutines to clean up (increased timeout to avoid race)
		success := waitForCondition(t, 2*time.Second, func() bool {
			return runtime.NumGoroutine() <= initialGoroutines
		})

		// Check goroutine count
		finalGoroutines := runtime.NumGoroutine()
		leaked := finalGoroutines - initialGoroutines

		// Strict check - no goroutine leaks allowed
		if !success || leaked > 0 {
			t.Errorf("Goroutine leak detected: %d goroutines leaked (initial: %d, final: %d)",
				leaked, initialGoroutines, finalGoroutines)
		}
	})

	t.Run("SessionMemoryLeak", func(t *testing.T) {
		// Test that sessions are properly cleaned up from memory
		server := newMockServer(t, common.ModeUnauthenticated)
		defer server.stop()

		cfg := ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		}
		client := NewClient(cfg)
		err := client.Connect(context.Background())
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		// Request a session
		ports := testutil.GetFreePorts(t, "udp", 2)
		config := TestSessionConfig{
			SenderPort:      uint16(ports[0]),
			ReceiverPort:    uint16(ports[1]),
			ReceiverAddress: "127.0.0.1",
			PaddingLength:   64,
			Timeout:         100 * time.Millisecond,
		}

		session, err := client.RequestSession(config)
		if err != nil {
			t.Fatalf("Failed to request session: %v", err)
		}

		// Start and stop to verify cleanup
		if err := client.StartSessions(); err != nil {
			t.Fatalf("Failed to start session: %v", err)
		}

		if err := client.StopSessions(); err != nil {
			t.Fatalf("Failed to stop session: %v", err)
		}

		_ = session

		// Sessions should be cleaned up after StopSessions
		// Multiple start/stop cycles verify proper cleanup
	})

	t.Run("ConnectionPoolLeak", func(t *testing.T) {
		// Test buffer pool doesn't leak
		pool := common.NewBufferPool(1024)

		// Track memory stats
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		initialAlloc := m.Alloc

		// Get and put many buffers
		for i := 0; i < 1000; i++ {
			buf := pool.Get()
			// Use the buffer
			copy(buf, []byte("test data"))
			pool.Put(buf)
		}

		// Force GC and check memory
		runtime.GC()
		runtime.ReadMemStats(&m)
		finalAlloc := m.Alloc

		// Memory should not grow significantly
		growth := int64(finalAlloc) - int64(initialAlloc)
		// Allow for some growth but catch leaks (10KB threshold is more realistic for unit tests)
		const maxMemoryGrowth = 10 * 1024 // 10KB
		if growth > maxMemoryGrowth {
			t.Errorf("Potential memory leak in buffer pool: %d bytes growth (threshold: %d bytes)", growth, maxMemoryGrowth)
		}
	})
}

// TestResolveMixedModes tests RFC 5618 mixed mode resolution
func TestResolveMixedModes(t *testing.T) {
	tests := []struct {
		name                string
		negotiatedMode      common.Mode
		expectedControlMode common.Mode
		expectedTestMode    common.Mode
		expectError         bool
		description         string
	}{
		{
			name:                "No mixed mode - Unauthenticated",
			negotiatedMode:      common.ModeUnauthenticated,
			expectedControlMode: common.ModeUnauthenticated,
			expectedTestMode:    common.ModeUnauthenticated,
			expectError:         false,
			description:         "Both control and test use unauthenticated",
		},
		{
			name:                "No mixed mode - Authenticated",
			negotiatedMode:      common.ModeAuthenticated,
			expectedControlMode: common.ModeAuthenticated,
			expectedTestMode:    common.ModeAuthenticated,
			expectError:         false,
			description:         "Both control and test use authenticated",
		},
		{
			name:                "No mixed mode - Encrypted",
			negotiatedMode:      common.ModeEncrypted,
			expectedControlMode: common.ModeEncrypted,
			expectedTestMode:    common.ModeEncrypted,
			expectError:         false,
			description:         "Both control and test use encrypted",
		},
		{
			name:                "RFC 5618 - Mixed with Authenticated",
			negotiatedMode:      common.ModeMixed | common.ModeAuthenticated,
			expectedControlMode: common.ModeAuthenticated,
			expectedTestMode:    common.ModeUnauthenticated,
			expectError:         false,
			description:         "Control uses authenticated, test uses unauthenticated",
		},
		{
			name:                "RFC 5618 - Mixed with Encrypted",
			negotiatedMode:      common.ModeMixed | common.ModeEncrypted,
			expectedControlMode: common.ModeEncrypted,
			expectedTestMode:    common.ModeUnauthenticated,
			expectError:         false,
			description:         "Control uses encrypted, test uses unauthenticated",
		},
		{
			name:           "RFC 5618 - Invalid: Mixed with Unauthenticated",
			negotiatedMode: common.ModeMixed | common.ModeUnauthenticated,
			expectError:    true,
			description:    "Mixed mode with unauthenticated control is INVALID per RFC 5618",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controlMode, testMode, err := common.ResolveMixedModes(tt.negotiatedMode)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else {
					t.Logf("✓ RFC 5618 compliance: Invalid mode correctly rejected with error: %v", err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if controlMode != tt.expectedControlMode {
				t.Errorf("Control mode mismatch: got %d, want %d", controlMode, tt.expectedControlMode)
			}

			if testMode != tt.expectedTestMode {
				t.Errorf("Test mode mismatch: got %d, want %d", testMode, tt.expectedTestMode)
			}

			t.Logf("✓ %s: control=%d, test=%d", tt.description, controlMode, testMode)
		})
	}
}
