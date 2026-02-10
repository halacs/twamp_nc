package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/messages"
)

const (
	stopNSessionsHeaderSize = 16
	sessionIDSize           = 16
	hmacSize                = 16
)

// TestStopNSessions tests the StopNSessions functionality (RFC 5938)
func TestStopNSessions(t *testing.T) {
	tests := []struct {
		name        string
		numSessions uint32
		mode        common.Mode
		setupFunc   func(*Client)
		expectError bool
	}{
		{
			name:        "Stop_Zero_Sessions_Unauthenticated",
			numSessions: 0,
			mode:        common.ModeUnauthenticated,
			expectError: false,
		},
		{
			name:        "Stop_Single_Session_Unauthenticated",
			numSessions: 1,
			mode:        common.ModeUnauthenticated,
			expectError: false,
		},
		{
			name:        "Stop_Large_Session_Count_Unauthenticated",
			numSessions: 256,
			mode:        common.ModeUnauthenticated,
			expectError: false,
		},
		{
			name:        "Stop_Sessions_Authenticated",
			numSessions: 2,
			mode:        common.ModeAuthenticated,
			setupFunc: func(c *Client) {
				// Setup HMAC key for authenticated mode
				c.keyDerivation = &crypto.TWAMPKeys{
					HMACKey: bytes.Repeat([]byte{0xAA}, 32),
				}
			},
			expectError: false,
		},
		{
			name:        "Stop_Sessions_Encrypted",
			numSessions: 3,
			mode:        common.ModeEncrypted,
			setupFunc: func(c *Client) {
				// Setup keys for encrypted mode
				c.keyDerivation = &crypto.TWAMPKeys{
					HMACKey: bytes.Repeat([]byte{0xBB}, 32),
					AESKey:  bytes.Repeat([]byte{0xCC}, 16),
				}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			// Create client
			client := &Client{
				conn:            clientConn,
				mode:            tt.mode,
				controlMode:     tt.mode, // For testing, control and test modes are the same
				testMode:        tt.mode,
				currentSessions: make(map[common.SessionID]*TestSession),
				logger:          logging.NewNoop(),
				config: ClientConfig{
					ServerAddress: fmt.Sprintf("127.0.0.1:%d", testutil.GetFreePorts(t, "tcp", 1)[0]),
				},
			}

			if tt.numSessions > 0 {
				for i := uint32(0); i < tt.numSessions; i++ {
					sid := common.SessionID{byte(i + 1)}
					client.currentSessions[sid] = &TestSession{stopChan: make(chan struct{})}
				}
			}

			// Setup client if needed
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}
			if tt.mode != common.ModeUnauthenticated {
				if client.keyDerivation == nil {
					client.keyDerivation = &crypto.TWAMPKeys{}
				}
				if len(client.keyDerivation.AESKey) == 0 {
					client.keyDerivation.AESKey = bytes.Repeat([]byte{0xCC}, 16)
				}
				if len(client.keyDerivation.HMACKey) == 0 {
					client.keyDerivation.HMACKey = bytes.Repeat([]byte{0xAA}, 32)
				}
				if len(client.keyDerivation.ClientIV) == 0 {
					client.keyDerivation.ClientIV = bytes.Repeat([]byte{0x11}, 16)
				}
				controlEncrypt, err := crypto.NewCBCStream(client.keyDerivation.AESKey, client.keyDerivation.ClientIV)
				if err != nil {
					t.Fatalf("Failed to init control encrypt stream: %v", err)
				}
				client.controlEncrypt = controlEncrypt
			}

			// Handle server side in goroutine
			errChan := make(chan error, 1)
			go func() {
				// Read the stop command
				expectedSize := stopNSessionsHeaderSize + int(tt.numSessions)*sessionIDSize + hmacSize
				buf := make([]byte, expectedSize)
				n, err := io.ReadFull(serverConn, buf)
				if err != nil {
					errChan <- err
					return
				}

				// Verify command structure
				// StopNSessions: header + (NumSessions * session ID size) + HMAC
				if n < expectedSize {
					errChan <- errors.New("command too short")
					return
				}

				payload := buf[:n]
				if tt.mode != common.ModeUnauthenticated {
					controlDecrypt, err := crypto.NewCBCStream(client.keyDerivation.AESKey, client.keyDerivation.ClientIV)
					if err != nil {
						errChan <- err
						return
					}
					decrypted, err := controlDecrypt.Decrypt(payload)
					if err != nil {
						errChan <- err
						return
					}
					messageLen := len(decrypted) - 16
					ok, err := crypto.VerifyHMAC(client.keyDerivation.HMACKey, decrypted[:messageLen], decrypted[messageLen:])
					if err != nil || !ok {
						errChan <- errors.New("hmac verification failed")
						return
					}
					payload = decrypted
				}

				// Check command type
				if payload[0] != common.CmdStopNSessions {
					errChan <- errors.New("wrong command type")
					return
				}

				errChan <- nil
			}()

			// Execute StopNSessions
			err := client.StopNSessions(tt.numSessions)

			// Check error
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Wait for server side to complete
			select {
			case serverErr := <-errChan:
				if serverErr != nil && !tt.expectError {
					t.Errorf("Server side error: %v", serverErr)
				}
			case <-time.After(100 * time.Millisecond):
				if !tt.expectError {
					t.Errorf("Server did not receive command in time")
				}
			}
		})
	}
}

// TestRequestSessionIndividual tests the RequestSessionIndividual functionality (RFC 5938)
func TestRequestSessionIndividual(t *testing.T) {
	tests := []struct {
		name         string
		request      messages.RequestTWSessionIndividual
		mode         common.Mode
		setupFunc    func(*Client)
		serverAccept uint8
		expectError  bool
	}{
		{
			name: "Server_Rejects_Request",
			request: messages.RequestTWSessionIndividual{
				RequestTWSession: messages.RequestTWSession{
					Command:      common.CmdRequestTWSessionIndividual,
					IPVN:         4,
					ConfSender:   1, // Invalid configuration
					ConfReceiver: 0,
					SenderPort:   10003,
					ReceiverPort: 20003,
					SID:          common.SessionID{9, 10, 11, 12},
				},
			},
			mode:         common.ModeUnauthenticated,
			serverAccept: common.AcceptNotSupported,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			// Create client
			client := &Client{
				conn:            clientConn,
				mode:            tt.mode,
				controlMode:     tt.mode, // For testing, control and test modes are the same
				testMode:        tt.mode,
				currentSessions: make(map[common.SessionID]*TestSession),
				logger:          logging.NewNoop(),
				config: ClientConfig{
					ServerAddress: fmt.Sprintf("127.0.0.1:%d", testutil.GetFreePorts(t, "tcp", 1)[0]),
				},
			}

			// Setup client if needed
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			// Handle server side in goroutine
			go func() {
				// Read the request
				buf := make([]byte, 1024)
				n, err := serverConn.Read(buf)
				if err != nil {
					return
				}

				// Verify it's a request command
				if buf[0] != common.CmdRequestTWSessionIndividual {
					return
				}

				// Send Accept-Session response
				accept := &messages.AcceptSession{
					Accept: tt.serverAccept,
					MBZ:    0,
					Port:   20001,
				}

				// Copy SID from request - properly parse the RequestTWSessionIndividual message
				// RequestTWSession structure offsets:
				// 0: Command (1) + MBZ/IPVN (1) + ConfSender (1) + ConfReceiver (1)
				// 4: NumSlots (4) + NumPackets (4)
				// 12: SenderPort (2) + ReceiverPort (2)
				// 16: SenderAddress (16) + ReceiverAddress (16)
				// 48: SID (16 bytes)
				if n >= 64 {
					// Extract SID from the correct position
					var sid common.SessionID
					copy(sid[:], buf[48:64])
					accept.SID = sid
				}

				respData, _ := accept.Marshal(false)
				if tt.mode != common.ModeUnauthenticated && client.keyDerivation != nil {
					hmac, _ := crypto.CalculateHMAC(client.keyDerivation.HMACKey, respData[:32])
					copy(respData[32:], hmac)
				}

				serverConn.Write(respData)
			}()

			// Execute RequestSessionIndividual
			config := TestSessionConfig{
				SenderPort:   tt.request.RequestTWSession.SenderPort,
				ReceiverPort: tt.request.RequestTWSession.ReceiverPort,
			}
			session, err := client.RequestSessionIndividual(config, tt.request.RequestTWSession.SID)

			// Check error
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if session == nil {
					t.Errorf("Expected session but got nil")
				} else {
					// Verify session properties
					if !bytes.Equal(session.sid[:], tt.request.RequestTWSession.SID[:]) {
						t.Errorf("Session ID mismatch")
					}
				}
			}
		})
	}
}

// TestStartSession tests starting an individual session
func TestStartSession(t *testing.T) {
	tests := []struct {
		name        string
		sessionID   common.SessionID
		setupFunc   func(*Client)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Start_NonExistent_Session",
			sessionID:   common.SessionID{5, 6, 7, 8},
			expectError: true,
			errorMsg:    "session not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := &Client{
				currentSessions: make(map[common.SessionID]*TestSession),
			}

			// Setup client if needed
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			// Execute StartSession
			err := client.StartSession(tt.sessionID)

			// Check error
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check error message contains expected text
			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
			}
		})
	}
}

// TestStopSession tests stopping an individual session
func TestStopSession(t *testing.T) {
	tests := []struct {
		name        string
		sessionID   common.SessionID
		setupFunc   func(*Client)
		expectError bool
	}{
		{
			name:      "Stop_Active_Session",
			sessionID: common.SessionID{1, 2, 3, 4},
			setupFunc: func(c *Client) {
				c.currentSessions[common.SessionID{1, 2, 3, 4}] = &TestSession{
					sid:      common.SessionID{1, 2, 3, 4},
					stopChan: make(chan struct{}),
				}
			},
			expectError: false,
		},
		{
			name:        "Stop_NonExistent_Session",
			sessionID:   common.SessionID{5, 6, 7, 8},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := &Client{
				currentSessions: make(map[common.SessionID]*TestSession),
			}

			// Setup client if needed
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			// Execute StopSession
			err := client.StopSession(tt.sessionID)

			// Check error
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestGetSession tests retrieving a session
func TestGetSession(t *testing.T) {
	tests := []struct {
		name      string
		sessionID common.SessionID
		setupFunc func(*Client)
		expectNil bool
	}{
		{
			name:      "Get_Existing_Session",
			sessionID: common.SessionID{1, 2, 3, 4},
			setupFunc: func(c *Client) {
				c.currentSessions[common.SessionID{1, 2, 3, 4}] = &TestSession{
					sid:      common.SessionID{1, 2, 3, 4},
					stopChan: make(chan struct{}),
				}
			},
			expectNil: false,
		},
		{
			name:      "Get_NonExistent_Session",
			sessionID: common.SessionID{5, 6, 7, 8},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := &Client{
				currentSessions: make(map[common.SessionID]*TestSession),
			}

			// Setup client if needed
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			// Execute GetSession
			session, err := client.GetSession(tt.sessionID)

			// Check result
			if tt.expectNil {
				if err == nil {
					t.Errorf("Expected error for non-existent session but got none")
				}
				if session != nil {
					t.Errorf("Expected nil session but got one")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if session == nil {
					t.Errorf("Expected session but got nil")
				} else {
					// Verify it's the correct session
					if !bytes.Equal(session.sid[:], tt.sessionID[:]) {
						t.Errorf("Got wrong session ID")
					}
				}
			}
		})
	}
}

// TestGetSessionIDs tests retrieving all session IDs
func TestGetSessionIDs(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(*Client)
		expectedCount int
	}{
		{
			name:          "No_Sessions",
			expectedCount: 0,
		},
		{
			name: "Single_Session",
			setupFunc: func(c *Client) {
				c.currentSessions[common.SessionID{1, 2, 3, 4}] = &TestSession{
					sid:      common.SessionID{1, 2, 3, 4},
					stopChan: make(chan struct{}),
				}
			},
			expectedCount: 1,
		},
		{
			name: "Multiple_Sessions",
			setupFunc: func(c *Client) {
				for i := 0; i < 5; i++ {
					sid := common.SessionID{byte(i), 0, 0, 0}
					c.currentSessions[sid] = &TestSession{
						sid:      sid,
						stopChan: make(chan struct{}),
					}
				}
			},
			expectedCount: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := &Client{
				currentSessions: make(map[common.SessionID]*TestSession),
			}

			// Setup client if needed
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			// Execute GetSessionIDs
			ids := client.GetSessionIDs()

			// Check result
			if len(ids) != tt.expectedCount {
				t.Errorf("Expected %d session IDs, got %d", tt.expectedCount, len(ids))
			}

			// Verify all returned IDs exist in sessions
			for _, id := range ids {
				if _, exists := client.currentSessions[id]; !exists {
					t.Errorf("Returned session ID %v does not exist in sessions", id)
				}
			}

			// Verify all sessions are represented
			for sid := range client.currentSessions {
				found := false
				for _, id := range ids {
					if bytes.Equal(id[:], sid[:]) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Session ID %v not in returned list", sid)
				}
			}
		})
	}
}

// TestClientConnectionError tests client behavior with connection errors
func TestClientConnectionError(t *testing.T) {
	// Create mock connection that will fail
	serverConn, clientConn := net.Pipe()
	serverConn.Close() // Close server side immediately

	client := &Client{
		conn:            clientConn,
		mode:            common.ModeUnauthenticated,
		controlMode:     common.ModeUnauthenticated, // For testing, control and test modes are the same
		testMode:        common.ModeUnauthenticated,
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	// Test StopNSessions with closed connection
	err := client.StopNSessions(1)
	if err == nil {
		t.Errorf("Expected error for closed connection, got none")
	}

	clientConn.Close()
}
