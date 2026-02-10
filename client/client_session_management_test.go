package client

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/messages"
)

const (
	testReadDeadline = 100 * time.Millisecond
)

// TestNewTestSessionWithLogger tests NewTestSessionWithLogger with all security modes
// Table-driven test per AGENTS.md standards
func TestNewTestSessionWithLogger(t *testing.T) {
	tests := []struct {
		name              string
		mode              common.Mode
		sid               common.SessionID
		paddingLength     uint32
		keys              *crypto.TWAMPKeys
		expectAuth        bool
		expectEncrypted   bool
		expectError       bool
	}{
		{
			name:            "Unauthenticated_Mode",
			mode:            common.ModeUnauthenticated,
			sid:             common.SessionID{1, 2, 3, 4},
			paddingLength:   100,
			keys:            nil,
			expectAuth:      false,
			expectEncrypted: false,
			expectError:     false,
		},
		{
			name:          "Authenticated_Mode",
			mode:          common.ModeAuthenticated,
			sid:           common.SessionID{2, 3, 4, 5},
			paddingLength: 100,
			keys: &crypto.TWAMPKeys{
				AESKey:   bytes.Repeat([]byte{0xAA}, 16),
				HMACKey:  bytes.Repeat([]byte{0xBB}, 32),
				ClientIV: bytes.Repeat([]byte{0x01}, 16),
				ServerIV: bytes.Repeat([]byte{0x02}, 16),
			},
			expectAuth:      true,
			expectEncrypted: false,
			expectError:     false,
		},
		{
			name:          "Encrypted_Mode",
			mode:          common.ModeEncrypted,
			sid:           common.SessionID{3, 4, 5, 6},
			paddingLength: 150, // Encrypted mode needs more padding
			keys: &crypto.TWAMPKeys{
				AESKey:   bytes.Repeat([]byte{0xCC}, 16),
				HMACKey:  bytes.Repeat([]byte{0xDD}, 32),
				ClientIV: bytes.Repeat([]byte{0x01}, 16),
				ServerIV: bytes.Repeat([]byte{0x02}, 16),
			},
			expectAuth:      true,
			expectEncrypted: true,
			expectError:     false,
		},
		{
			name:          "Mixed_Authenticated_Mode",
			mode:          common.ModeMixed | common.ModeAuthenticated,
			sid:           common.SessionID{4, 5, 6, 7},
			paddingLength: 100,
			keys: &crypto.TWAMPKeys{
				AESKey:   bytes.Repeat([]byte{0xEE}, 16),
				HMACKey:  bytes.Repeat([]byte{0xFF}, 32),
				ClientIV: bytes.Repeat([]byte{0x03}, 16),
				ServerIV: bytes.Repeat([]byte{0x04}, 16),
			},
			expectAuth:      true,
			expectEncrypted: false,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := TestSessionConfig{
				SenderPort:      10000,
				ReceiverPort:    20000,
				PaddingLength:   tt.paddingLength,
				ReceiverAddress: "127.0.0.1",
				Timeout:         time.Second,
			}
			logger := logging.NewNoop()

			session, err := NewTestSessionWithLogger(config, tt.sid, tt.mode, tt.keys, logger)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if session == nil {
				t.Fatal("Session is nil")
			}

			// Verify session properties
			if !bytes.Equal(session.sid[:], tt.sid[:]) {
				t.Errorf("Session ID mismatch: got %v, want %v", session.sid, tt.sid)
			}

			if session.mode != tt.mode {
				t.Errorf("Mode mismatch: got %v, want %v", session.mode, tt.mode)
			}

			if session.isAuthenticated != tt.expectAuth {
				t.Errorf("isAuthenticated mismatch: got %v, want %v", session.isAuthenticated, tt.expectAuth)
			}

			if session.isEncrypted != tt.expectEncrypted {
				t.Errorf("isEncrypted mismatch: got %v, want %v", session.isEncrypted, tt.expectEncrypted)
			}
		})
	}
}

// TestStopNSessionsWithMultipleSessions tests StopNSessions with multiple active sessions
func TestStopNSessionsWithMultipleSessions(t *testing.T) {
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

	// Add 3 sessions with cleanup
	sessionStopChans := make([]chan struct{}, 3)
	for i := 0; i < 3; i++ {
		sid := common.SessionID{byte(i), 0, 0, 0}
		sessionStopChans[i] = make(chan struct{})
		client.currentSessions[sid] = &TestSession{
			sid:      sid,
			stopChan: sessionStopChans[i],
			logger:   logging.NewNoop(),
		}
	}

	// Cleanup: close any remaining stopChans
	defer func() {
		for _, ch := range sessionStopChans {
			select {
			case <-ch:
				// Already closed
			default:
				close(ch)
			}
		}
	}()

	// Handle server side with synchronization
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		_, err := serverConn.Read(buf)
		if err != nil {
			t.Logf("Server read error: %v", err)
		}
	}()

	// Stop 2 sessions
	err := client.StopNSessions(2)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should have 1 session left
	if len(client.currentSessions) != 1 {
		t.Errorf("Expected 1 remaining session, got %d", len(client.currentSessions))
	}

	// Wait for server goroutine to finish
	<-done
}

// TestClientCloseWithSessions tests Close() with active sessions
func TestClientCloseWithSessions(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	client := &Client{
		conn:            clientConn,
		mode:            common.ModeUnauthenticated,
		controlMode:     common.ModeUnauthenticated,
		testMode:        common.ModeUnauthenticated,
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          logging.NewNoop(),
	}

	// Add sessions with cleanup
	sessionStopChans := make([]chan struct{}, 2)
	for i := 0; i < 2; i++ {
		sid := common.SessionID{byte(i), 0, 0, 0}
		sessionStopChans[i] = make(chan struct{})
		client.currentSessions[sid] = &TestSession{
			sid:      sid,
			stopChan: sessionStopChans[i],
			logger:   logging.NewNoop(),
		}
	}

	// Cleanup: close any remaining stopChans
	defer func() {
		for _, ch := range sessionStopChans {
			select {
			case <-ch:
				// Already closed
			default:
				close(ch)
			}
		}
	}()

	// Handle server side with synchronization
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			_, err := serverConn.Read(buf)
			if err != nil {
				// Connection closed or error
				return
			}
		}
	}()

	// Close client
	err := client.Close()
	if err != nil {
		t.Errorf("Unexpected error during close: %v", err)
	}

	// All sessions should be stopped
	if len(client.currentSessions) != 0 {
		t.Errorf("Expected all sessions to be stopped, got %d remaining", len(client.currentSessions))
	}

	// Wait for server goroutine to finish
	<-done
}

// TestReceiveAndVerifyWithShortMessage tests receiveAndVerify with short messages
// Verifies that the function correctly handles EOF and partial read errors
func TestReceiveAndVerifyWithShortMessage(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
	}

	// Send short message from server with synchronization
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Write 2 bytes when client expects 10
		_, err := serverConn.Write([]byte{0x01, 0x02})
		if err != nil {
			t.Logf("Server write error: %v", err)
		}
		// Close to trigger EOF
		serverConn.Close()
	}()

	// Set timeout to avoid hanging if something goes wrong
	clientConn.SetReadDeadline(time.Now().Add(testReadDeadline))

	// Try to receive 10 bytes - should error because we only sent 2
	_, err := client.receiveAndVerify(10, false)
	if err == nil {
		t.Fatal("Expected error with short message, got none")
	}

	// Verify it's an EOF-related error from io.ReadFull
	// io.ReadFull returns io.ErrUnexpectedEOF if some bytes were read but fewer than requested
	// or io.EOF if no bytes were read
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Expected EOF-related error from io.ReadFull, got: %v", err)
	}

	// Wait for server goroutine
	<-done
}

// TestSendWithHMAC tests sendWithHMAC happy path with HMAC calculation
func TestSendWithHMAC(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
		keyDerivation: &crypto.TWAMPKeys{
			HMACKey: bytes.Repeat([]byte{0xAA}, 32),
		},
	}

	// Handle server side with synchronization
	done := make(chan struct{})
	receivedData := make([]byte, 0)
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Logf("Server read error: %v", err)
			return
		}
		receivedData = buf[:n]
	}()

	// Send with HMAC
	data := []byte("test message")
	err := client.sendWithHMAC(data, true)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Wait for server to receive
	<-done

	// Verify data was sent (should be data + HMAC)
	expectedLen := len(data) + 16 // 16-byte HMAC
	if len(receivedData) != expectedLen {
		t.Errorf("Expected %d bytes (data + HMAC), got %d", expectedLen, len(receivedData))
	}
}

// TestSendWithHMACNilKey tests sendWithHMAC error path with nil HMAC key
func TestSendWithHMACNilKey(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
		keyDerivation: &crypto.TWAMPKeys{
			HMACKey: nil, // Invalid: nil key should cause error
		},
	}

	// Handle server side with timeout (may not receive anything if HMAC calc fails early)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		// Set read deadline to avoid blocking forever if client doesn't write
		serverConn.SetReadDeadline(time.Now().Add(testReadDeadline))
		serverConn.Read(buf) // Will timeout if nothing is written, that's OK
	}()

	// Try to send with HMAC - should fail with nil key
	data := []byte("test message")
	err := client.sendWithHMAC(data, true)
	if err == nil {
		t.Error("Expected HMAC error with nil key, got none")
	}

	// Wait for server goroutine to finish or timeout
	<-done
}

// TestSendWithHMACClosedConnection tests sendWithHMAC error path with closed connection
func TestSendWithHMACClosedConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	serverConn.Close() // Close server side immediately
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
		keyDerivation: &crypto.TWAMPKeys{
			HMACKey: bytes.Repeat([]byte{0xAA}, 32),
		},
	}

	// Try to send on closed connection - should fail
	data := []byte("test message")
	err := client.sendWithHMAC(data, true)
	if err == nil {
		t.Error("Expected write error on closed connection, got none")
	}

	// Verify it's an error (type varies by implementation: net.OpError or generic error)
	if err == nil {
		t.Error("Expected error on closed connection, got none")
	}
}

// TestSendWithHMACUnauthenticatedMode tests sendWithHMAC without HMAC (unauthenticated mode)
func TestSendWithHMACUnauthenticatedMode(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
		mode:   common.ModeUnauthenticated,
	}

	// Handle server side
	done := make(chan struct{})
	receivedData := make([]byte, 0)
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Logf("Server read error: %v", err)
			return
		}
		receivedData = buf[:n]
	}()

	// Send without HMAC (addHMAC=false)
	data := []byte("test message")
	err := client.sendWithHMAC(data, false)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	<-done

	// Verify data was sent without HMAC (same length as input)
	if len(receivedData) != len(data) {
		t.Errorf("Expected %d bytes (no HMAC), got %d", len(data), len(receivedData))
	}
}

// TestRFC5938DuplicateSIDRejection tests that duplicate SIDs are rejected
func TestRFC5938DuplicateSIDRejection(t *testing.T) {
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
		config: ClientConfig{
			ServerAddress: "127.0.0.1:862",
		},
	}

	// Add a session with SID {1, 2, 3, 4}
	duplicateSID := common.SessionID{1, 2, 3, 4}
	client.currentSessions[duplicateSID] = &TestSession{
		sid:      duplicateSID,
		stopChan: make(chan struct{}),
		logger:   logging.NewNoop(),
	}
	defer close(client.currentSessions[duplicateSID].stopChan)

	// Try to create another session with the same SID
	config := TestSessionConfig{
		SenderPort:   10000,
		ReceiverPort: 20000,
	}

	_, err := client.RequestSessionIndividual(config, duplicateSID)
	if err == nil {
		t.Error("Expected error for duplicate SID, got none")
	}

	// Verify it's a session conflict error
	if !errors.Is(err, ErrSessionConflict) {
		t.Errorf("Expected ErrSessionConflict, got: %v", err)
	}
}

// TestStartSessionNonExistent tests starting a non-existent session
func TestStartSessionNonExistent(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          logging.NewNoop(),
	}

	nonExistentSID := common.SessionID{5, 6, 7, 8}
	err := client.StartSession(nonExistentSID)
	if err == nil {
		t.Error("Expected error for non-existent session, got none")
	}

	// Verify it's a session not found error
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// TestStopNSessionsMoreThanExist tests StopNSessions with count > available sessions
func TestStopNSessionsMoreThanExist(t *testing.T) {
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

	// Add 2 sessions
	sessionStopChans := make([]chan struct{}, 2)
	for i := 0; i < 2; i++ {
		sid := common.SessionID{byte(i), 0, 0, 0}
		sessionStopChans[i] = make(chan struct{})
		client.currentSessions[sid] = &TestSession{
			sid:      sid,
			stopChan: sessionStopChans[i],
			logger:   logging.NewNoop(),
		}
	}

	// Cleanup
	defer func() {
		for _, ch := range sessionStopChans {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	}()

	// Handle server side - StopNSessions sends command to server
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16384) // Large buffer for StopNSessions command
		// Set read deadline to avoid hanging
		serverConn.SetReadDeadline(time.Now().Add(testReadDeadline))
		_, err := serverConn.Read(buf)
		if err != nil {
			t.Logf("Server read error (expected): %v", err)
		}
	}()

	// Try to stop 999 sessions (more than the 2 that exist)
	// Note: This will stop all available sessions (2) and send command to server
	err := client.StopNSessions(999)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should have stopped all 2 sessions (not 999)
	if len(client.currentSessions) != 0 {
		t.Errorf("Expected 0 remaining sessions, got %d", len(client.currentSessions))
	}

	// Wait for server goroutine
	<-done
}

// TestGetSessionNonExistent tests GetSession for non-existent SID
func TestGetSessionNonExistent(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          logging.NewNoop(),
	}

	nonExistentSID := common.SessionID{9, 10, 11, 12}
	session, err := client.GetSession(nonExistentSID)
	if err == nil {
		t.Error("Expected error for non-existent session, got none")
	}

	if session != nil {
		t.Error("Expected nil session for non-existent SID")
	}

	// Verify it's a session not found error
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// TestStopSessionNonExistent tests StopSession for non-existent SID
func TestStopSessionNonExistent(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          logging.NewNoop(),
	}

	nonExistentSID := common.SessionID{13, 14, 15, 16}
	err := client.StopSession(nonExistentSID)
	if err == nil {
		t.Error("Expected error for non-existent session, got none")
	}

	// Verify it's a session not found error
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// TestReceiveServerGreetingErrorPaths tests error handling in receiveServerGreeting
func TestReceiveServerGreetingErrorPaths(t *testing.T) {
	t.Run("ConnectionClosed", func(t *testing.T) {
		// Create pipe and close server side immediately
		clientConn, serverConn := net.Pipe()
		serverConn.Close()
		defer clientConn.Close()

		client := &Client{
			conn:   clientConn,
			logger: logging.NewNoop(),
		}

		_, err := client.receiveServerGreeting()
		if err == nil {
			t.Fatal("Expected error when reading from closed connection")
		}
		if !errors.Is(err, ErrServerGreeting) {
			t.Errorf("Expected ErrServerGreeting, got: %v", err)
		}
	})

	t.Run("ServerSupportsNoModes", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		client := &Client{
			conn:   clientConn,
			logger: logging.NewNoop(),
		}

		// Send greeting with modes = 0 in goroutine
		go func() {
			greeting := &messages.ServerGreeting{
				Modes: 0, // No modes supported
			}
			// Generate random challenge and salt
			io.ReadFull(rand.Reader, greeting.Challenge[:])
			io.ReadFull(rand.Reader, greeting.Salt[:])
			greeting.Count = 1024
			data, _ := greeting.Marshal()
			serverConn.Write(data)
		}()

		_, err := client.receiveServerGreeting()
		if err == nil {
			t.Fatal("Expected error when server supports no modes")
		}
		if !errors.Is(err, common.ErrServerNoModes) {
			t.Errorf("Expected ErrServerNoModes, got: %v", err)
		}
	})

	t.Run("MalformedGreeting", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		client := &Client{
			conn:   clientConn,
			logger: logging.NewNoop(),
		}

		// Send malformed greeting in goroutine
		go func() {
			// Send only 10 bytes instead of 64
			serverConn.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
			serverConn.Close()
		}()

		_, err := client.receiveServerGreeting()
		if err == nil {
			t.Fatal("Expected error for malformed greeting")
		}
	})
}

// TestReceiveServerStartErrorPaths tests error handling in receiveServerStart
func TestReceiveServerStartErrorPaths(t *testing.T) {
	t.Run("ConnectionClosed", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		serverConn.Close()
		defer clientConn.Close()

		client := &Client{
			conn:   clientConn,
			logger: logging.NewNoop(),
		}

		_, err := client.receiveServerStart()
		if err == nil {
			t.Fatal("Expected error when reading from closed connection")
		}
		if !strings.Contains(err.Error(), "failed to read Server-Start") {
			t.Errorf("Expected 'failed to read Server-Start' error, got: %v", err)
		}
	})

	t.Run("MalformedServerStart", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		client := &Client{
			conn:   clientConn,
			logger: logging.NewNoop(),
		}

		// Send malformed ServerStart in goroutine
		go func() {
			// Send only 10 bytes instead of 48
			serverConn.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
			serverConn.Close()
		}()

		_, err := client.receiveServerStart()
		if err == nil {
			t.Fatal("Expected error for malformed ServerStart")
		}
		if !strings.Contains(err.Error(), "failed to read Server-Start") {
			t.Errorf("Expected 'failed to read Server-Start' error, got: %v", err)
		}
	})
}
