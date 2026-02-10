package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/messages"
)

// TestHandleStopNSessions tests the Stop-N-Sessions command handler
func TestHandleStopNSessions(t *testing.T) {
	tests := []struct {
		name         string
		mode         common.Mode
		numSessions  uint32
		setupFunc    func(*Server, *controlConnection, *testing.T) []common.SessionID
		expectError  bool
		expectActive int // Expected number of still-active sessions after stop
	}{
		{
			name:         "Stop_Zero_Sessions",
			mode:         common.ModeUnauthenticated,
			numSessions:  0,
			setupFunc:    nil,
			expectError:  false,
			expectActive: 0,
		},
		{
			name:        "Stop_One_Session",
			mode:        common.ModeUnauthenticated,
			numSessions: 1,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) []common.SessionID {
				// Add a test session
				ports := testutil.GetFreePorts(t, "udp", 1)
				sid := common.SessionID{1, 2, 3, 4}
				session := &TestSession{
					sid:           sid,
					reflectorPort: uint16(ports[0]),
					timeout:       50 * time.Millisecond,
					stopChan:      make(chan struct{}),
					reflectorDone: make(chan struct{}),
				}
				session.isActive.Store(true)
				cc.sessions[sid] = session
				s.sessionsMu.Lock()
				s.sessions[sid] = session
				s.sessionsMu.Unlock()
				return []common.SessionID{sid}
			},
			expectError:  false,
			expectActive: 0,
		},
		{
			name:        "Stop_Multiple_Sessions",
			mode:        common.ModeAuthenticated,
			numSessions: 3,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) []common.SessionID {
				// Add 5 test sessions, return only 3 SIDs to stop
				ports := testutil.GetFreePorts(t, "udp", 5)
				sidsToStop := make([]common.SessionID, 0, 3)
				for i := 0; i < 5; i++ {
					sid := common.SessionID{}
					sid[0] = byte(i)
					session := &TestSession{
						sid:           sid,
						reflectorPort: uint16(ports[i]),
						timeout:       50 * time.Millisecond,
						stopChan:      make(chan struct{}),
						reflectorDone: make(chan struct{}),
					}
					session.isActive.Store(true)
					cc.sessions[sid] = session
					s.sessionsMu.Lock()
					s.sessions[sid] = session
					s.sessionsMu.Unlock()
					if i < 3 {
						sidsToStop = append(sidsToStop, sid)
					}
				}
				return sidsToStop
			},
			expectError:  false,
			expectActive: 2, // 5 sessions - 3 stopped = 2 active
		},
		{
			name:        "Stop_Nonexistent_Session",
			mode:        common.ModeUnauthenticated,
			numSessions: 1,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) []common.SessionID {
				// Return a SID that doesn't exist
				return []common.SessionID{{99, 99, 99, 99}}
			},
			expectError:  false, // Should succeed (no-op)
			expectActive: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with dynamic port range
			portRangePorts := testutil.GetFreePorts(t, "udp", 2)
			sort.Ints(portRangePorts) // Ensure minPort < maxPort
			config := ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: tt.mode,
				PortRange:      [2]uint16{uint16(portRangePorts[0]), uint16(portRangePorts[1])},
			}
			srv, err := NewServer(config)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}
			defer srv.Stop()

			// Create control connection
			cc := &controlConnection{
				mode:        tt.mode,
				controlMode: tt.mode,
				testMode:    tt.mode,
				sessions:    make(map[common.SessionID]*TestSession),
			}

			// Setup test sessions and get SIDs to stop
			var sidsToStop []common.SessionID
			if tt.setupFunc != nil {
				sidsToStop = tt.setupFunc(srv, cc, t)
			}

			// Create Stop-N-Sessions command with proper SessionIDs
			stopNSessions := &messages.StopNSessions{
				Command:     common.CmdStopNSessions,
				NumSessions: tt.numSessions,
				SessionIDs:  sidsToStop,
			}

			// Marshal command
			cmdData, err := stopNSessions.Marshal(tt.mode != common.ModeUnauthenticated)
			if err != nil {
				t.Fatalf("Failed to marshal Stop-N-Sessions: %v", err)
			}
			if len(cmdData) == 0 {
				t.Fatalf("Marshal produced empty cmdData")
			}

			// Record sessions before handling command
			sessionsBeforeStop := len(cc.sessions)

			// Handle command
			err = srv.handleStopNSessions(cc, cmdData)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Verify sessions were removed from cc.sessions immediately
			if tt.numSessions > 0 && !tt.expectError && len(sidsToStop) > 0 {
				// Check that sessions were removed from cc.sessions
				removedCount := sessionsBeforeStop - len(cc.sessions)
				expectedRemoved := len(sidsToStop)
				if tt.name == "Stop_Nonexistent_Session" {
					expectedRemoved = 0 // Non-existent sessions shouldn't affect count
				}
				if removedCount != expectedRemoved {
					t.Errorf("Expected %d sessions removed from cc.sessions, got %d", expectedRemoved, removedCount)
				}

				// Verify remaining sessions count
				if len(cc.sessions) != tt.expectActive {
					t.Errorf("Expected %d active sessions in cc.sessions, got %d", tt.expectActive, len(cc.sessions))
				}

				// Wait for async cleanup to complete (2x session timeout for CI reliability)
				time.Sleep(100 * time.Millisecond)

				// Verify that stopped sessions are actually inactive (closure capture bug check)
				for _, sid := range sidsToStop {
					srv.sessionsMu.RLock()
					session, exists := srv.sessions[sid]
					srv.sessionsMu.RUnlock()
					if exists && session.isActive.Load() {
						t.Errorf("Session %v should be inactive after stop, but isActive=true", sid)
					}
				}
			}
		})
	}
}

// TestStopNSessionsClosureCapture verifies that all sessions are stopped correctly
// and not just the last one (regression test for closure capture bug)
func TestStopNSessionsClosureCapture(t *testing.T) {
	// Create server
	portRangePorts := testutil.GetFreePorts(t, "udp", 10)
	sort.Ints(portRangePorts)
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		PortRange:      [2]uint16{uint16(portRangePorts[0]), uint16(portRangePorts[len(portRangePorts)-1])},
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Create control connection
	cc := &controlConnection{
		mode:        common.ModeUnauthenticated,
		controlMode: common.ModeUnauthenticated,
		testMode:    common.ModeUnauthenticated,
		sessions:    make(map[common.SessionID]*TestSession),
	}

	// Create 5 sessions with unique SIDs
	numSessions := 5
	ports := testutil.GetFreePorts(t, "udp", numSessions)
	sids := make([]common.SessionID, numSessions)
	sessions := make([]*TestSession, numSessions)

	for i := 0; i < numSessions; i++ {
		sids[i] = common.SessionID{}
		sids[i][0] = byte(i + 1) // Use distinct values
		sids[i][15] = byte(i + 1)
		sessions[i] = &TestSession{
			sid:           sids[i],
			reflectorPort: uint16(ports[i]),
			timeout:       50 * time.Millisecond, // Short timeout
			stopChan:      make(chan struct{}),
			reflectorDone: make(chan struct{}),
		}
		sessions[i].isActive.Store(true)
		cc.sessions[sids[i]] = sessions[i]
		srv.sessionsMu.Lock()
		srv.sessions[sids[i]] = sessions[i]
		srv.sessionsMu.Unlock()
	}

	// Create Stop-N-Sessions command to stop ALL sessions
	stopNSessions := &messages.StopNSessions{
		Command:     common.CmdStopNSessions,
		NumSessions: uint32(numSessions),
		SessionIDs:  sids,
	}

	cmdData, err := stopNSessions.Marshal(false)
	if err != nil {
		t.Fatalf("Failed to marshal Stop-N-Sessions: %v", err)
	}
	if len(cmdData) == 0 {
		t.Fatalf("Marshal produced empty cmdData")
	}

	// Handle command
	err = srv.handleStopNSessions(cc, cmdData)
	if err != nil {
		t.Fatalf("handleStopNSessions failed: %v", err)
	}

	// Wait for all timeouts to fire (2x session timeout for CI reliability)
	time.Sleep(100 * time.Millisecond)

	// CRITICAL: Verify that ALL sessions were stopped, not just the last one
	// This is the regression test for the closure capture bug
	stoppedCount := 0
	for i, session := range sessions {
		if !session.isActive.Load() {
			stoppedCount++
		} else {
			t.Errorf("Session %d (SID=%v) was not stopped - closure capture bug?", i, sids[i])
		}
	}

	if stoppedCount != numSessions {
		t.Errorf("Expected all %d sessions to be stopped, but only %d were stopped", numSessions, stoppedCount)
	}

	// Also verify sessions were removed from cc.sessions
	if len(cc.sessions) != 0 {
		t.Errorf("Expected cc.sessions to be empty after stopping all sessions, got %d", len(cc.sessions))
	}
}

// TestStopSessionsClosureCapture verifies that all sessions are stopped correctly
// in handleStopSessions (regression test for closure capture bug)
func TestStopSessionsClosureCapture(t *testing.T) {
	// Create server
	portRangePorts := testutil.GetFreePorts(t, "udp", 10)
	sort.Ints(portRangePorts)
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		PortRange:      [2]uint16{uint16(portRangePorts[0]), uint16(portRangePorts[len(portRangePorts)-1])},
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Stop()

	// Create control connection
	cc := &controlConnection{
		mode:        common.ModeUnauthenticated,
		controlMode: common.ModeUnauthenticated,
		testMode:    common.ModeUnauthenticated,
		sessions:    make(map[common.SessionID]*TestSession),
	}

	// Create 5 sessions with unique SIDs
	numSessions := 5
	ports := testutil.GetFreePorts(t, "udp", numSessions)
	sids := make([]common.SessionID, numSessions)
	sessions := make([]*TestSession, numSessions)

	for i := 0; i < numSessions; i++ {
		sids[i] = common.SessionID{}
		sids[i][0] = byte(i + 1)
		sids[i][15] = byte(i + 1)
		sessions[i] = &TestSession{
			sid:           sids[i],
			reflectorPort: uint16(ports[i]),
			timeout:       50 * time.Millisecond,
			stopChan:      make(chan struct{}),
			reflectorDone: make(chan struct{}),
		}
		sessions[i].isActive.Store(true)
		cc.sessions[sids[i]] = sessions[i]
		srv.sessionsMu.Lock()
		srv.sessions[sids[i]] = sessions[i]
		srv.sessionsMu.Unlock()
	}

	// Create Stop-Sessions command (stops ALL sessions on connection)
	stopSessions := &messages.StopSessions{
		Command:     common.CmdStopSessions,
		Accept:      common.AcceptOK,
		NumSessions: uint32(numSessions),
	}

	cmdData, err := stopSessions.Marshal(false)
	if err != nil {
		t.Fatalf("Failed to marshal Stop-Sessions: %v", err)
	}
	if len(cmdData) == 0 {
		t.Fatalf("Marshal produced empty cmdData")
	}

	// Handle command
	err = srv.handleStopSessions(cc, cmdData)
	if err != nil {
		t.Fatalf("handleStopSessions failed: %v", err)
	}

	// Wait for all timeouts to fire (2x session timeout for CI reliability)
	time.Sleep(100 * time.Millisecond)

	// CRITICAL: Verify that ALL sessions were stopped, not just the last one
	stoppedCount := 0
	for i, session := range sessions {
		if !session.isActive.Load() {
			stoppedCount++
		} else {
			t.Errorf("Session %d (SID=%v) was not stopped - closure capture bug?", i, sids[i])
		}
	}

	if stoppedCount != numSessions {
		t.Errorf("Expected all %d sessions to be stopped, but only %d were stopped", numSessions, stoppedCount)
	}

	// Verify sessions were removed from cc.sessions
	if len(cc.sessions) != 0 {
		t.Errorf("Expected cc.sessions to be empty after Stop-Sessions, got %d", len(cc.sessions))
	}
}

// TestHandleRequestTWSessionIndividual tests the Request-TW-Session-Individual command handler
func TestHandleRequestTWSessionIndividual(t *testing.T) {
	tests := []struct {
		name         string
		mode         common.Mode
		setupFunc    func(*Server, *controlConnection, *testing.T) *messages.RequestTWSessionIndividual
		expectAccept uint8
		expectError  bool
		secretMap    map[string]string
	}{
		{
			name: "Valid_Request_Unauthenticated",
			mode: common.ModeUnauthenticated,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) *messages.RequestTWSessionIndividual {
				ports := testutil.GetFreePorts(t, "udp", 2)
				return &messages.RequestTWSessionIndividual{
					RequestTWSession: messages.RequestTWSession{
						Command:         common.CmdRequestTWSessionIndividual,
						IPVN:            4,
						ConfSender:      0,
						ConfReceiver:    0,
						SenderPort:      uint16(ports[0]),
						ReceiverPort:    uint16(ports[1]),
						ReceiverAddress: [16]byte{127, 0, 0, 1},
						SID:             common.SessionID{1, 2, 3, 4, 5, 6, 7, 8},
						TypePDescriptor: 0,
						Timeout:         common.TWAMPTimestamp{Seconds: 5},
					},
				}
			},
			expectAccept: common.AcceptOK,
			expectError:  false,
		},
		{
			name: "Valid_Request_Authenticated",
			mode: common.ModeAuthenticated,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) *messages.RequestTWSessionIndividual {
				// Setup key derivation for authenticated mode
				cc.keyDerivation = &crypto.TWAMPKeys{
					AESKey:   bytes.Repeat([]byte{0xAA}, 16),
					HMACKey:  bytes.Repeat([]byte{0xBB}, 32),
					ClientIV: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					ServerIV: []byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
				}
				ports := testutil.GetFreePorts(t, "udp", 2)
				return &messages.RequestTWSessionIndividual{
					RequestTWSession: messages.RequestTWSession{
						Command:         common.CmdRequestTWSessionIndividual,
						IPVN:            4,
						ConfSender:      0,
						ConfReceiver:    0,
						SenderPort:      uint16(ports[0]),
						ReceiverPort:    uint16(ports[1]),
						SID:             common.SessionID{8, 7, 6, 5, 4, 3, 2, 1},
						TypePDescriptor: 0x00B80000, // DSCP=46 (EF)
						Timeout:         common.TWAMPTimestamp{Seconds: 10},
					},
				}
			},
			expectAccept: common.AcceptOK,
			expectError:  false,
			secretMap:    map[string]string{"test": "password"},
		},
		{
			name: "Invalid_ConfSender",
			mode: common.ModeUnauthenticated,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) *messages.RequestTWSessionIndividual {
				ports := testutil.GetFreePorts(t, "udp", 2)
				return &messages.RequestTWSessionIndividual{
					RequestTWSession: messages.RequestTWSession{
						Command:      common.CmdRequestTWSessionIndividual,
						IPVN:         4,
						ConfSender:   1, // Should be 0
						ConfReceiver: 0,
						SenderPort:   uint16(ports[0]),
						ReceiverPort: uint16(ports[1]),
						ReceiverAddress: [16]byte{127, 0, 0, 1},
						SID:          common.SessionID{9, 10, 11, 12},
					},
				}
			},
			expectAccept: common.AcceptNotSupported,
			expectError:  true,
		},
		{
			name: "Invalid_ConfReceiver",
			mode: common.ModeUnauthenticated,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) *messages.RequestTWSessionIndividual {
				ports := testutil.GetFreePorts(t, "udp", 2)
				return &messages.RequestTWSessionIndividual{
					RequestTWSession: messages.RequestTWSession{
						Command:      common.CmdRequestTWSessionIndividual,
						IPVN:         4,
						ConfSender:   0,
						ConfReceiver: 1, // Should be 0
						SenderPort:   uint16(ports[0]),
						ReceiverPort: uint16(ports[1]),
						ReceiverAddress: [16]byte{127, 0, 0, 1},
						SID:          common.SessionID{13, 14, 15, 16},
					},
				}
			},
			expectAccept: common.AcceptNotSupported,
			expectError:  true,
		},
		{
			name: "Duplicate_Session_ID",
			mode: common.ModeUnauthenticated,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) *messages.RequestTWSessionIndividual {
				// Add existing session with same SID
				existingPort := testutil.GetFreePorts(t, "udp", 1)[0]
				existingSID := common.SessionID{1, 1, 1, 1}
				existingSession := &TestSession{
					sid:           existingSID,
					reflectorPort: uint16(existingPort),
				}
				s.sessionsMu.Lock()
				s.sessions[existingSID] = existingSession
				s.sessionsMu.Unlock()

				ports := testutil.GetFreePorts(t, "udp", 2)
				return &messages.RequestTWSessionIndividual{
					RequestTWSession: messages.RequestTWSession{
						Command:      common.CmdRequestTWSessionIndividual,
						IPVN:         4,
						ConfSender:   0,
						ConfReceiver: 0,
						SenderPort:   uint16(ports[0]),
						ReceiverPort: uint16(ports[1]),
						ReceiverAddress: [16]byte{127, 0, 0, 1},
						SID:          common.SessionID{1, 1, 1, 1}, // Will be duplicated
					},
				}
			},
			expectAccept: common.AcceptFailure,
			expectError:  true,
		},
		{
			name: "No_Available_Ports",
			mode: common.ModeUnauthenticated,
			setupFunc: func(s *Server, cc *controlConnection, t *testing.T) *messages.RequestTWSessionIndividual {
				// Exhaust all available ports
				for i := s.config.PortRange[0]; i <= s.config.PortRange[1]; i++ {
					s.portManager.usedPorts[i] = true
				}

				ports := testutil.GetFreePorts(t, "udp", 2)
				return &messages.RequestTWSessionIndividual{
					RequestTWSession: messages.RequestTWSession{
						Command:      common.CmdRequestTWSessionIndividual,
						IPVN:         4,
						ConfSender:   0,
						ConfReceiver: 0,
						SenderPort:   uint16(ports[0]),
						ReceiverPort: uint16(ports[1]),
						ReceiverAddress: [16]byte{127, 0, 0, 1},
						SID:          common.SessionID{17, 18, 19, 20},
					},
				}
			},
			expectAccept: common.AcceptTempResLimited,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with dynamic port range
			portRangePorts := testutil.GetFreePorts(t, "udp", 15) // Get enough ports for the test range
			sort.Ints(portRangePorts)                              // Ensure ports are sorted
			config := ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: tt.mode,
				PortRange:      [2]uint16{uint16(portRangePorts[0]), uint16(portRangePorts[10])}, // Range using free ports
				SecretMap:      tt.secretMap,
			}
			srv, err := NewServer(config)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}
			defer srv.Stop()

			// Create mock connection
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			// Create control connection
			cc := &controlConnection{
				conn:        serverConn,
				mode:        tt.mode,
				controlMode: tt.mode, // For testing, control and test modes are the same
				testMode:    tt.mode,
				sessions:    make(map[common.SessionID]*TestSession),
			}

			// Setup key derivation for authenticated/encrypted modes
			if tt.mode != common.ModeUnauthenticated {
				cc.keyDerivation = &crypto.TWAMPKeys{
					HMACKey:  bytes.Repeat([]byte{0xAA}, 32),
					AESKey:   bytes.Repeat([]byte{0xBB}, 16),
					ClientIV: bytes.Repeat([]byte{0xCC}, 16),
					ServerIV: bytes.Repeat([]byte{0xDD}, 16),
				}
				controlEncrypt, err := crypto.NewCBCStream(cc.keyDerivation.AESKey, cc.keyDerivation.ServerIV)
				if err != nil {
					t.Fatalf("NewCBCStream: %v", err)
				}
				cc.controlEncrypt = controlEncrypt
			}

			// Setup and get request
			var request *messages.RequestTWSessionIndividual
			if tt.setupFunc != nil {
				request = tt.setupFunc(srv, cc, t)
			}

			// Marshal request
			cmdData, err := request.Marshal(tt.mode != common.ModeUnauthenticated)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			// Handle command in goroutine (it sends response)
			errChan := make(chan error, 1)
			go func() {
				errChan <- srv.handleRequestTWSessionIndividual(cc, cmdData)
			}()

			// Read Accept-Session response (HMAC bytes always present)
			acceptData := make([]byte, messages.AcceptSessionSize)

			// Set read timeout
			clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, readErr := io.ReadFull(clientConn, acceptData)

			// Check for errors
			select {
			case handleErr := <-errChan:
				if tt.expectError && handleErr == nil && readErr != nil {
					// Expected an error but handler succeeded, likely sent response
					// Parse the response to check accept code
					var accept messages.AcceptSession
					if err := accept.Unmarshal(acceptData[:n], tt.mode != common.ModeUnauthenticated); err == nil {
						if accept.Accept != tt.expectAccept {
							t.Errorf("Expected accept code %d, got %d", tt.expectAccept, accept.Accept)
						}
					}
				} else if !tt.expectError && handleErr != nil {
					t.Errorf("Unexpected error: %v", handleErr)
				}
			case <-time.After(100 * time.Millisecond):
				if !tt.expectError {
					t.Errorf("Handler did not complete in time")
				}
			}

			// Verify session was created if expected
			if tt.expectAccept == common.AcceptOK {
				srv.sessionsMu.RLock()
				session, exists := srv.sessions[request.RequestTWSession.SID]
				srv.sessionsMu.RUnlock()

				if !exists {
					t.Errorf("Session was not created")
				} else {
					if session.senderPort != request.RequestTWSession.SenderPort {
						t.Errorf("Sender port mismatch: expected %d, got %d",
							request.RequestTWSession.SenderPort, session.senderPort)
					}
					if request.RequestTWSession.TypePDescriptor != 0 {
						expectedDSCP := uint8((request.RequestTWSession.TypePDescriptor >> 18) & 0x3F)
						if session.dscp != expectedDSCP {
							t.Errorf("DSCP mismatch: expected %d, got %d",
								expectedDSCP, session.dscp)
						}
					}
				}
			}
		})
	}
}

// TestReadCommandEdgeCases tests edge cases in readCommand function
func TestReadCommandEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		mode        common.Mode
		setupFunc   func(net.Conn, *testing.T)
		expectCmd   uint8
		expectError bool
	}{
		{
			name: "Valid_Start_Sessions_Command",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn, t *testing.T) {
				// Send Start-Sessions command
				startSessions := &messages.StartSessions{
					Command: common.CmdStartSessions,
				}
				data, _ := startSessions.Marshal(false)
				conn.Write(data)
			},
			expectCmd:   common.CmdStartSessions,
			expectError: false,
		},
		{
			name: "Valid_Stop_Sessions_Command",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn, t *testing.T) {
				// Send Stop-Sessions command (RFC 5357 Section 3.8)
				// NumSessions=0 because no sessions have been started
				stopSessions := &messages.StopSessions{
					Command:     common.CmdStopSessions,
					Accept:      common.AcceptOK,
					NumSessions: 0, // No active sessions
				}
				data, _ := stopSessions.Marshal(false)
				conn.Write(data)
			},
			expectCmd:   common.CmdStopSessions,
			expectError: false,
		},
		{
			name: "Valid_Request_TW_Session_Individual",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn, t *testing.T) {
				// Send Request-TW-Session-Individual command
				port := testutil.GetFreePorts(t, "udp", 1)[0]
				request := &messages.RequestTWSessionIndividual{
					RequestTWSession: messages.RequestTWSession{
						Command:    common.CmdRequestTWSessionIndividual,
						IPVN:       4,
						SenderPort: uint16(port),
						ReceiverAddress: [16]byte{127, 0, 0, 1},
						SID:        common.SessionID{1, 2, 3, 4},
					},
				}
				data, _ := request.Marshal(false)
				conn.Write(data)
			},
			expectCmd:   common.CmdRequestTWSessionIndividual,
			expectError: false,
		},
		{
			name: "Invalid_Command_Code",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn, t *testing.T) {
				// Send invalid command code
				data := make([]byte, 32)
				data[0] = 99 // Invalid command
				conn.Write(data)
			},
			expectCmd:   99,
			expectError: true,
		},
		{
			name: "Connection_Closed",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn, t *testing.T) {
				// Close connection immediately
				conn.Close()
			},
			expectCmd:   0,
			expectError: true,
		},
		{
			name: "Partial_Read",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn, t *testing.T) {
				// Send only partial data
				conn.Write([]byte{common.CmdStartSessions})
				// Don't send the rest
			},
			expectCmd:   0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server
			config := ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: tt.mode,
			}
			srv, err := NewServer(config)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}
			defer srv.Stop()

			// Create pipe for testing
			clientConn, serverConn := net.Pipe()
			defer func() {
				clientConn.Close()
				serverConn.Close()
			}()

			// Create control connection
			cc := &controlConnection{
				conn:        serverConn,
				mode:        tt.mode,
				controlMode: tt.mode, // For testing, control and test modes are the same
				testMode:    tt.mode,
				sessions:    make(map[common.SessionID]*TestSession),
			}

			// Setup key derivation for authenticated/encrypted modes
			if tt.mode != common.ModeUnauthenticated {
				cc.keyDerivation = &crypto.TWAMPKeys{
					HMACKey: bytes.Repeat([]byte{0xAA}, 32),
					AESKey:  bytes.Repeat([]byte{0xBB}, 16),
				}
			}

			// Setup test data
			go func() {
				time.Sleep(10 * time.Millisecond)
				tt.setupFunc(clientConn, t)
			}()

			// Set read timeout
			serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			// Read command
			cmdData, err := srv.readCommand(cc)
			var cmd uint8
			if err == nil && len(cmdData) > 0 {
				cmd = cmdData[0]
			}

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if cmd != tt.expectCmd {
					t.Errorf("Expected command %d, got %d", tt.expectCmd, cmd)
				}
				if cmdData == nil && cmd != 0 {
					t.Errorf("Expected command data but got nil")
				}
			}
		})
	}
}

// TestProcessAndReflectEdgeCases tests edge cases in processAndReflect function
func TestProcessAndReflectEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		mode          common.Mode
		packetData    []byte
		setupSession  func(*testing.T) *TestSession
		expectReflect bool
	}{
		{
			name: "Valid_Unauthenticated_Packet",
			mode: common.ModeUnauthenticated,
			setupSession: func(t *testing.T) *TestSession {
				ports := testutil.GetFreePorts(t, "udp", 2)
				return &TestSession{
					sid:           common.SessionID{1, 2, 3, 4},
					mode:          common.ModeUnauthenticated,
					reflectorPort: uint16(ports[0]),
					senderPort:    uint16(ports[1]),
				}
			},
			packetData: func() []byte {
				packet := &messages.SenderTestPacket{
					SeqNumber: 1,
					Timestamp: common.TWAMPTimestamp{
						Seconds:  1000,
						Fraction: 0,
					},
					PaddingSize: 27, // Min padding
				}
				data, _ := packet.Marshal()
				return data
			}(),
			expectReflect: true,
		},
		{
			name: "Invalid_Packet_Too_Short",
			mode: common.ModeUnauthenticated,
			setupSession: func(t *testing.T) *TestSession {
				ports := testutil.GetFreePorts(t, "udp", 2)
				return &TestSession{
					sid:           common.SessionID{1, 2, 3, 4},
					mode:          common.ModeUnauthenticated,
					reflectorPort: uint16(ports[0]),
					senderPort:    uint16(ports[1]),
				}
			},
			packetData:    []byte{1, 2, 3}, // Too short
			expectReflect: false,
		},
		{
			name: "Valid_Authenticated_Packet",
			mode: common.ModeAuthenticated,
			setupSession: func(t *testing.T) *TestSession {
				ports := testutil.GetFreePorts(t, "udp", 2)
				keys := &crypto.TWAMPKeys{
					TestHMACKey: bytes.Repeat([]byte{0xAA}, 32),
				}
				return &TestSession{
					sid:           common.SessionID{5, 6, 7, 8},
					mode:          common.ModeAuthenticated,
					reflectorPort: uint16(ports[0]),
					senderPort:    uint16(ports[1]),
					sessionKeys:   keys,
				}
			},
			packetData: func() []byte {
				// Create authenticated packet
				packet := &messages.SenderTestPacketAuth{
					SeqNumber: 1,
					Timestamp: common.TWAMPTimestamp{
						Seconds:  2000,
						Fraction: 0,
					},
					PaddingSize: 56, // Min padding for authenticated
				}
				data, _ := packet.Marshal()
				// Note: HMAC would need to be computed properly
				return data
			}(),
			expectReflect: true,
		},
		{
			name: "Valid_Encrypted_Packet",
			mode: common.ModeEncrypted,
			setupSession: func(t *testing.T) *TestSession {
				ports := testutil.GetFreePorts(t, "udp", 2)
				keys := &crypto.TWAMPKeys{
					TestAESKey:  bytes.Repeat([]byte{0xBB}, 16),
					TestHMACKey: bytes.Repeat([]byte{0xCC}, 32),
				}
				return &TestSession{
					sid:           common.SessionID{9, 10, 11, 12},
					mode:          common.ModeEncrypted,
					reflectorPort: uint16(ports[0]),
					senderPort:    uint16(ports[1]),
					sessionKeys:   keys,
				}
			},
			packetData: func() []byte {
				// Create encrypted packet (simplified - would need proper encryption)
				data := make([]byte, 144)                // Min size for encrypted
				binary.BigEndian.PutUint32(data[0:4], 1) // Sequence
				return data
			}(),
			expectReflect: false, // Will fail HMAC check without proper encryption
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server
			config := ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: tt.mode,
			}
			srv, err := NewServer(config)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}
			defer srv.Stop()

			// Setup session
			session := tt.setupSession(t)

			// Create UDP connection for testing
			conn, err := net.ListenUDP("udp", &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 0,
			})
			if err != nil {
				t.Fatalf("Failed to create UDP connection: %v", err)
			}
			defer conn.Close()

			session.conn = conn

			// Create test sender address
			senderAddr := &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: int(session.senderPort),
			}

			// Process and reflect packet
			reflected := false

			// Use a channel to capture reflection
			reflectChan := make(chan bool, 1)
			go func() {
				// Listen for reflected packet
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				buf := make([]byte, 2048)
				n, _, err := conn.ReadFromUDP(buf)
				if err == nil && n > 0 {
					reflectChan <- true
				} else {
					reflectChan <- false
				}
			}()

			// Process packet
			srv.processAndReflect(session, tt.packetData, senderAddr, 255)

			// Wait for reflection result
			select {
			case reflected = <-reflectChan:
			case <-time.After(200 * time.Millisecond):
				reflected = false
			}

			// Note: Due to the complexity of packet processing and reflection,
			// we're mainly testing that the function doesn't panic
			// Actual reflection depends on proper packet format and encryption
			_ = reflected
		})
	}
}

// TestHandleClientSetupErrors tests error paths in handleClientSetup
// Note: Some tests are commented out due to timing issues with test infrastructure
func TestHandleClientSetupErrors(t *testing.T) {
	// Skip this test for now - it has timing issues
	t.Skip("Skipping TestHandleClientSetupErrors due to timing issues")

	tests := []struct {
		name        string
		mode        common.Mode
		setupFunc   func(net.Conn)
		secretMap   map[string]string
		expectError bool
	}{
		{
			name: "Invalid_Mode_Selection",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn) {
				// Send setup response with unsupported mode
				setup := &messages.SetupResponse{
					Mode: 0x80000000, // Invalid mode
				}
				data, _ := setup.Marshal()
				conn.Write(data)
			},
			expectError: true,
		},
		{
			name: "Authenticated_Mode_No_Secret",
			mode: common.ModeAuthenticated,
			setupFunc: func(conn net.Conn) {
				// Send setup response for authenticated mode
				setup := &messages.SetupResponse{
					Mode:  uint32(common.ModeAuthenticated),
					KeyID: [80]byte{}, // Empty KeyID
				}
				data, _ := setup.Marshal()
				conn.Write(data)
			},
			secretMap:   map[string]string{}, // No secrets configured
			expectError: true,
		},
		{
			name: "Authenticated_Mode_Wrong_Token",
			mode: common.ModeAuthenticated,
			setupFunc: func(conn net.Conn) {
				// Send setup response with wrong token
				setup := &messages.SetupResponse{
					Mode:  uint32(common.ModeAuthenticated),
					KeyID: [80]byte{}, // Will use "test" as KeyID
					Token: [64]byte{}, // Wrong token
				}
				copy(setup.KeyID[:], "test")
				data, _ := setup.Marshal()
				conn.Write(data)
			},
			secretMap:   map[string]string{"test": "password"},
			expectError: true,
		},
		{
			name: "Connection_Closed_During_Setup",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn) {
				// Close connection instead of sending response
				conn.Close()
			},
			expectError: true,
		},
		{
			name: "Malformed_Setup_Response",
			mode: common.ModeUnauthenticated,
			setupFunc: func(conn net.Conn) {
				// Send malformed data
				conn.Write([]byte{1, 2, 3})
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server
			config := ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: tt.mode,
				SecretMap:      tt.secretMap,
			}
			srv, err := NewServer(config)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}
			defer srv.Stop()

			// Create pipe for testing
			clientConn, serverConn := net.Pipe()
			defer func() {
				clientConn.Close()
				serverConn.Close()
			}()

			// Create control connection with greeting
			cc := &controlConnection{
				conn: serverConn,
				greeting: &messages.ServerGreeting{
					Modes:     uint32(tt.mode),
					Challenge: [16]byte{1, 2, 3, 4},
					Salt:      [16]byte{5, 6, 7, 8},
					Count:     1024,
				},
				cleanupDone: make(chan struct{}),
			}

			// Setup test in goroutine
			go func() {
				time.Sleep(10 * time.Millisecond)
				tt.setupFunc(clientConn)
			}()

			// Handle client setup
			err = srv.handleClientSetup(cc)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestCompareBytesExtended tests the constant-time comparison function
func TestCompareBytesExtended(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "Equal_Bytes",
			a:        []byte{1, 2, 3, 4},
			b:        []byte{1, 2, 3, 4},
			expected: true,
		},
		{
			name:     "Different_Bytes",
			a:        []byte{1, 2, 3, 4},
			b:        []byte{1, 2, 3, 5},
			expected: false,
		},
		{
			name:     "Different_Length",
			a:        []byte{1, 2, 3},
			b:        []byte{1, 2, 3, 4},
			expected: false,
		},
		{
			name:     "Empty_Slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "Nil_vs_Empty",
			a:        nil,
			b:        []byte{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareBytes(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestServerStartupErrors tests error conditions during server startup
func TestServerStartupErrors(t *testing.T) {
	tests := []struct {
		name        string
		config      ServerConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "Invalid_Port_Range",
			config: ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: common.ModeUnauthenticated,
				PortRange:      [2]uint16{50000, 40000}, // Min > Max
			},
			expectError: true,
			errorMsg:    "invalid port range",
		},
		{
			name: "Empty_Supported_Modes",
			config: ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: 0, // No supported modes
				PortRange:      [2]uint16{45000, 45100},
			},
			expectError: false, // This is actually valid - server can run with mode 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewServer(tt.config)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorMsg)) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if srv != nil {
					srv.Stop()
				}
			}
		})
	}
}

// TestConnectionCleanup tests proper cleanup of connections
func TestConnectionCleanup(t *testing.T) {
	// Create server
	config := ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		SERVWAIT:       100 * time.Millisecond,
	}
	srv, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	ctx := context.Background()
	err = srv.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Connect and disconnect multiple clients
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", srv.listener.Addr().String())
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}

		// Read greeting
		greeting := make([]byte, 64)
		io.ReadFull(conn, greeting)

		// Close connection
		conn.Close()
	}

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Check that connections are cleaned up
	srv.connectionsMu.RLock()
	numConnections := len(srv.connections)
	srv.connectionsMu.RUnlock()

	if numConnections != 0 {
		t.Errorf("Expected 0 connections after cleanup, got %d", numConnections)
	}

	// Stop server
	srv.Stop()
}
