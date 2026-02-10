// pkg/twamp/messages/control_rfc5938_test.go
// Tests for RFC 5938: Individual Session Control Feature

package messages

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
)

func TestStopNSessions_Marshal_Unmarshal(t *testing.T) {
	tests := []struct {
		name        string
		message     *StopNSessions
		includeHMAC bool
	}{
		{
			name: "StopNSessions without HMAC",
			message: &StopNSessions{
				Command:     common.CmdStopNSessions,
				Accept:      common.AcceptOK,
				NumSessions: 2,
				SessionIDs: []common.SessionID{
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
					{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},
				},
			},
			includeHMAC: false,
		},
		{
			name: "StopNSessions with HMAC",
			message: &StopNSessions{
				Command:     common.CmdStopNSessions,
				Accept:      common.AcceptOK,
				NumSessions: 3,
				SessionIDs: []common.SessionID{
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
					{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},
					{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30},
				},
				HMAC: [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
			},
			includeHMAC: true,
		},
		{
			name: "StopNSessions with zero sessions",
			message: &StopNSessions{
				Command:     common.CmdStopNSessions,
				Accept:      common.AcceptOK,
				NumSessions: 0,
				SessionIDs:  []common.SessionID{},
			},
			includeHMAC: false,
		},
		{
			name: "StopNSessions with single session",
			message: &StopNSessions{
				Command:     common.CmdStopNSessions,
				Accept:      common.AcceptFailure,
				NumSessions: 1,
				SessionIDs: []common.SessionID{
					{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
				},
			},
			includeHMAC: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.message.Marshal(tt.includeHMAC)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Calculate expected size (HMAC bytes always present)
			expectedSize := 16 + int(tt.message.NumSessions)*16 + 16

			if len(data) != expectedSize {
				t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
			}

			// Unmarshal
			result := &StopNSessions{}
			err = result.Unmarshal(data, tt.includeHMAC)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Verify fields
			if result.Command != tt.message.Command {
				t.Errorf("Command mismatch: got %d, want %d", result.Command, tt.message.Command)
			}

			if result.Accept != tt.message.Accept {
				t.Errorf("Accept mismatch: got %d, want %d", result.Accept, tt.message.Accept)
			}

			if result.NumSessions != tt.message.NumSessions {
				t.Errorf("NumSessions mismatch: got %d, want %d", result.NumSessions, tt.message.NumSessions)
			}

			if len(result.SessionIDs) != len(tt.message.SessionIDs) {
				t.Errorf("SessionIDs length mismatch: got %d, want %d", len(result.SessionIDs), len(tt.message.SessionIDs))
			}

			for i := range tt.message.SessionIDs {
				if !bytes.Equal(result.SessionIDs[i][:], tt.message.SessionIDs[i][:]) {
					t.Errorf("SessionID[%d] mismatch: got %x, want %x", i, result.SessionIDs[i], tt.message.SessionIDs[i])
				}
			}

			if tt.includeHMAC {
				if !bytes.Equal(result.HMAC[:], tt.message.HMAC[:]) {
					t.Errorf("HMAC mismatch: got %x, want %x", result.HMAC, tt.message.HMAC)
				}
			}

			// Verify MBZ fields are zero
			if result.MBZ1 != [2]byte{} {
				t.Errorf("MBZ1 not zero: %x", result.MBZ1)
			}
			if result.MBZ2 != [8]byte{} {
				t.Errorf("MBZ2 not zero: %x", result.MBZ2)
			}
		})
	}
}

func TestRequestTWSessionIndividual_Marshal_Unmarshal(t *testing.T) {
	// Generate random session ID
	var sid common.SessionID
	rand.Read(sid[:])

	tests := []struct {
		name        string
		message     *RequestTWSessionIndividual
		includeHMAC bool
	}{
		{
			name: "RequestTWSessionIndividual IPv4 without HMAC",
			message: &RequestTWSessionIndividual{
				RequestTWSession: RequestTWSession{
					Command:         common.CmdRequestTWSessionIndividual,
					IPVN:            4,
					ConfSender:      1,
					ConfReceiver:    1,
					NumSlots:        0,
					NumPackets:      0, // RFC 5357 Section 3.5: Must be zero
					SenderPort:      uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
					ReceiverPort:    uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
					SenderAddress:   [16]byte{192, 168, 1, 1},
					ReceiverAddress: [16]byte{192, 168, 1, 2},
					SID:             sid,
					PaddingLength:   100,
					StartTime:       common.Now(),
					Timeout:         common.FromTime(common.Now().ToTime().Add(10 * time.Second)),
					TypePDescriptor: 0x00000000, // Valid descriptor
				},
			},
			includeHMAC: false,
		},
		{
			name: "RequestTWSessionIndividual IPv6 with HMAC",
			message: &RequestTWSessionIndividual{
				RequestTWSession: RequestTWSession{
					Command:         common.CmdRequestTWSessionIndividual,
					IPVN:            6,
					ConfSender:      1,
					ConfReceiver:    1,
					NumSlots:        0,
					NumPackets:      0, // RFC 5357 Section 3.5: Must be zero
					SenderPort:      uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
					ReceiverPort:    uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
					SenderAddress:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
					ReceiverAddress: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
					SID:             sid,
					PaddingLength:   200,
					StartTime:       common.Now(),
					Timeout:         common.FromTime(common.Now().ToTime().Add(30 * time.Second)),
					TypePDescriptor: 0x00280000, // DSCP value 10 (0x28 >> 2)
					HMAC:            [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00},
				},
			},
			includeHMAC: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.message.Marshal(tt.includeHMAC)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Verify command byte is correct
			if data[0] != common.CmdRequestTWSessionIndividual {
				t.Errorf("Command byte incorrect: got %d, want %d", data[0], common.CmdRequestTWSessionIndividual)
			}

			// Calculate expected size
			expectedSize := 112

			if len(data) != expectedSize {
				t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
			}

			// Unmarshal
			result := &RequestTWSessionIndividual{}
			err = result.Unmarshal(data, tt.includeHMAC)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Verify command is correct
			if result.Command != common.CmdRequestTWSessionIndividual {
				t.Errorf("Command mismatch: got %d, want %d", result.Command, common.CmdRequestTWSessionIndividual)
			}

			// Verify other fields match
			if result.IPVN != tt.message.IPVN {
				t.Errorf("IPVN mismatch: got %d, want %d", result.IPVN, tt.message.IPVN)
			}

			if result.NumPackets != tt.message.NumPackets {
				t.Errorf("NumPackets mismatch: got %d, want %d", result.NumPackets, tt.message.NumPackets)
			}

			if result.SenderPort != tt.message.SenderPort {
				t.Errorf("SenderPort mismatch: got %d, want %d", result.SenderPort, tt.message.SenderPort)
			}

			if result.ReceiverPort != tt.message.ReceiverPort {
				t.Errorf("ReceiverPort mismatch: got %d, want %d", result.ReceiverPort, tt.message.ReceiverPort)
			}

			if !bytes.Equal(result.SID[:], tt.message.SID[:]) {
				t.Errorf("SID mismatch: got %x, want %x", result.SID, tt.message.SID)
			}

			if tt.includeHMAC {
				if !bytes.Equal(result.HMAC[:], tt.message.HMAC[:]) {
					t.Errorf("HMAC mismatch: got %x, want %x", result.HMAC, tt.message.HMAC)
				}
			}
		})
	}
}

func TestStopNSessions_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		includeHMAC bool
		wantErr     error
	}{
		{
			name:        "Data too short",
			data:        make([]byte, 10),
			includeHMAC: false,
			wantErr:     common.ErrInvalidMessageLength,
		},
		{
			name: "Non-zero MBZ1",
			data: func() []byte {
				data := make([]byte, 16)
				data[0] = common.CmdStopNSessions
				data[2] = 0xFF // Non-zero MBZ1
				return data
			}(),
			includeHMAC: false,
			wantErr:     common.ErrInvalidMBZ,
		},
		{
			name: "Non-zero MBZ2",
			data: func() []byte {
				data := make([]byte, 16)
				data[0] = common.CmdStopNSessions
				data[10] = 0xFF // Non-zero MBZ2
				return data
			}(),
			includeHMAC: false,
			wantErr:     common.ErrInvalidMBZ,
		},
		{
			name: "Missing session IDs",
			data: func() []byte {
				data := make([]byte, 16)
				data[0] = common.CmdStopNSessions
				data[4] = 0x00
				data[5] = 0x00
				data[6] = 0x00
				data[7] = 0x02 // NumSessions = 2 but no session ID data
				return data
			}(),
			includeHMAC: false,
			wantErr:     common.ErrInvalidMessageLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &StopNSessions{}
			err := msg.Unmarshal(tt.data, tt.includeHMAC)

			if err == nil {
				t.Errorf("Expected error %v, got nil", tt.wantErr)
			} else if err != tt.wantErr {
				t.Errorf("Error mismatch: got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRequestTWSessionIndividual_WrongCommand(t *testing.T) {
	// Create a regular RequestTWSession packet
	msg := &RequestTWSession{
		Command:         common.CmdRequestTWSession, // Wrong command
		IPVN:            4,
		NumPackets:      0, // RFC 5357 Section 3.5: Must be zero
		SenderPort:      uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		ReceiverPort:    uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		TypePDescriptor: 0x00000000,
	}

	data, err := msg.Marshal(false)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Try to unmarshal as RequestTWSessionIndividual
	individual := &RequestTWSessionIndividual{}
	err = individual.Unmarshal(data, false)

	if err == nil {
		t.Error("Expected error for wrong command, got nil")
	}
}
