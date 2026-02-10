package messages

import (
	"bytes"
	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"reflect"
	"strings"
	"testing"
)

func TestServerGreetingMarshaling(t *testing.T) {
	// Create a sample greeting
	greeting := ServerGreeting{
		Modes:     0x00000007, // All three modes supported
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}

	// Marshal
	data, err := greeting.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal into a new struct
	var parsedGreeting ServerGreeting
	err = parsedGreeting.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify fields match
	if greeting.Modes != parsedGreeting.Modes {
		t.Errorf("Modes mismatch: got %d, want %d", parsedGreeting.Modes, greeting.Modes)
	}

	if !bytes.Equal(greeting.Challenge[:], parsedGreeting.Challenge[:]) {
		t.Errorf("Challenge mismatch")
	}

	if !bytes.Equal(greeting.Salt[:], parsedGreeting.Salt[:]) {
		t.Errorf("Salt mismatch")
	}

	if greeting.Count != parsedGreeting.Count {
		t.Errorf("Count mismatch: got %d, want %d", parsedGreeting.Count, greeting.Count)
	}
}

func TestSetupResponseMarshaling(t *testing.T) {
	// Create a sample response
	response := SetupResponse{
		Mode:     0x00000001, // Unauthenticated mode
		KeyID:    [80]byte{}, // Empty in unauthenticated mode
		Token:    [64]byte{}, // Empty in unauthenticated mode
		ClientIV: [16]byte{}, // Empty in unauthenticated mode
	}

	// Marshal
	data, err := response.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal into a new struct
	var parsedResponse SetupResponse
	err = parsedResponse.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify fields match
	if response.Mode != parsedResponse.Mode {
		t.Errorf("Mode mismatch: got %d, want %d", parsedResponse.Mode, response.Mode)
	}
}

func TestServerStartRoundTrip(t *testing.T) {
	want := ServerStart{
		Accept:    common.AcceptOK,
		ServerIV:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		StartTime: common.TWAMPTimestamp{Seconds: 12, Fraction: 34},
	}
	data, err := want.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ServerStart
	if err := got.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round‑trip mismatch:\nwant %+v\n got %+v", want, got)
	}
}

func TestServerStartMBZError(t *testing.T) {
	ss := ServerStart{}
	good, _ := ss.Marshal()
	bad := append([]byte(nil), good...)
	bad[0] = 1 // first MBZ byte
	if err := ss.Unmarshal(bad); err != common.ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ, got %v", err)
	}
}

func TestAcceptSessionRoundTrip(t *testing.T) {
	sid := common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	base := AcceptSession{Accept: common.AcceptOK, Port: 862, SID: sid}

	for _, includeHMAC := range []bool{false, true} {
		as := base
		if includeHMAC {
			as.HMAC = [16]byte{0xAA, 0xBB}
		}
		data, err := as.Marshal(includeHMAC)
		if err != nil {
			t.Fatalf("marshal(%v): %v", includeHMAC, err)
		}
		var parsed AcceptSession
		if err := parsed.Unmarshal(data, includeHMAC); err != nil {
			t.Fatalf("unmarshal(%v): %v", includeHMAC, err)
		}
		if as.Accept != parsed.Accept || as.Port != parsed.Port || !bytes.Equal(as.SID[:], parsed.SID[:]) {
			t.Fatalf("mismatch includeHMAC=%v", includeHMAC)
		}
		if includeHMAC && !bytes.Equal(as.HMAC[:], parsed.HMAC[:]) {
			t.Fatalf("HMAC mismatch includeHMAC=%v", includeHMAC)
		}
	}
}

func TestAcceptSessionMBZError(t *testing.T) {
	as := AcceptSession{}
	data, _ := as.Marshal(false)
	data[1] = 0xFF // MBZ byte must be zero
	if err := as.Unmarshal(data, false); err != common.ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ, got %v", err)
	}
}

func TestStartSessionsAndAckRoundTrip(t *testing.T) {
	ss := StartSessions{Command: common.CmdStartSessions}
	data, err := ss.Marshal(false)
	if err != nil {
		t.Fatalf("marshal StartSessions: %v", err)
	}
	var parsedSS StartSessions
	if err := parsedSS.Unmarshal(data, false); err != nil {
		t.Fatalf("unmarshal StartSessions: %v", err)
	}
	if ss.Command != parsedSS.Command {
		t.Fatalf("command mismatch")
	}

	ack := StartAck{Accept: common.AcceptOK}
	dataAck, err := ack.Marshal(true)
	if err != nil {
		t.Fatalf("marshal StartAck: %v", err)
	}
	var parsedAck StartAck
	if err := parsedAck.Unmarshal(dataAck, true); err != nil {
		t.Fatalf("unmarshal StartAck: %v", err)
	}
	if ack.Accept != parsedAck.Accept || !bytes.Equal(ack.HMAC[:], parsedAck.HMAC[:]) {
		t.Fatalf("StartAck mismatch")
	}
}

func TestStopSessionsRoundTrip(t *testing.T) {
	// Test RFC 5357 Section 3.8 compliant StopSessions
	ss := StopSessions{
		Command:     common.CmdStopSessions,
		Accept:      common.AcceptOK,
		NumSessions: 5,
	}
	data, err := ss.Marshal(false)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) != StopSessionsSize {
		t.Fatalf("expected size %d, got %d", StopSessionsSize, len(data))
	}

	var parsed StopSessions
	if err := parsed.Unmarshal(data, false); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ss.Command != parsed.Command {
		t.Fatalf("Command mismatch: expected %d, got %d", ss.Command, parsed.Command)
	}
	if ss.Accept != parsed.Accept {
		t.Fatalf("Accept mismatch: expected %d, got %d", ss.Accept, parsed.Accept)
	}
	if ss.NumSessions != parsed.NumSessions {
		t.Fatalf("NumSessions mismatch: expected %d, got %d", ss.NumSessions, parsed.NumSessions)
	}
}

func TestStopSessionsRoundTripWithHMAC(t *testing.T) {
	ss := StopSessions{
		Command:     common.CmdStopSessions,
		Accept:      common.AcceptOK,
		NumSessions: 10,
		HMAC:        [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	data, err := ss.Marshal(true)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) != StopSessionsSizeAuth {
		t.Fatalf("expected size %d, got %d", StopSessionsSizeAuth, len(data))
	}

	var parsed StopSessions
	if err := parsed.Unmarshal(data, true); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ss.Command != parsed.Command {
		t.Fatalf("Command mismatch")
	}
	if ss.Accept != parsed.Accept {
		t.Fatalf("Accept mismatch")
	}
	if ss.NumSessions != parsed.NumSessions {
		t.Fatalf("NumSessions mismatch")
	}
	if !bytes.Equal(ss.HMAC[:], parsed.HMAC[:]) {
		t.Fatalf("HMAC mismatch")
	}
}

func TestStopSessionsMBZ1Error(t *testing.T) {
	ss := StopSessions{NumSessions: 1}
	data, _ := ss.Marshal(false)
	data[2] = 1 // Non-zero in MBZ1 (bytes 2-3)
	if err := ss.Unmarshal(data, false); err != common.ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ for MBZ1, got %v", err)
	}
}

func TestStopSessionsMBZ2Error(t *testing.T) {
	ss := StopSessions{NumSessions: 1}
	data, _ := ss.Marshal(false)
	data[10] = 1 // Non-zero in MBZ2 (bytes 8-15)
	if err := ss.Unmarshal(data, false); err != common.ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ for MBZ2, got %v", err)
	}
}

func TestRequestTWSessionRoundTrip(t *testing.T) {
	sid := common.SessionID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	rts := RequestTWSession{
		Command:         common.CmdRequestTWSession,
		IPVN:            4,
		ConfSender:      1,
		ConfReceiver:    1,
		NumSlots:        0, // RFC 5357 Section 3.5: Must be zero (TWAMP, not OWAMP)
		NumPackets:      0, // RFC 5357 Section 3.5: Must be zero (TWAMP, not OWAMP)
		SenderPort:      uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		ReceiverPort:    uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		SenderAddress:   [16]byte{192, 0, 2, 1},
		ReceiverAddress: [16]byte{192, 0, 2, 2},
		SID:             sid,
		PaddingLength:   0,
		StartTime:       common.TWAMPTimestamp{Seconds: 111, Fraction: 222},
		Timeout:         common.TWAMPTimestamp{Seconds: 222, Fraction: 333},
		TypePDescriptor: 0,
	}
	for _, includeHMAC := range []bool{false, true} {
		if includeHMAC {
			rts.HMAC = [16]byte{0xAA}
		}
		data, err := rts.Marshal(includeHMAC)
		if err != nil {
			t.Fatalf("marshal(%v): %v", includeHMAC, err)
		}
		var parsed RequestTWSession
		if err := parsed.Unmarshal(data, includeHMAC); err != nil {
			t.Fatalf("unmarshal(%v): %v", includeHMAC, err)
		}
		if rts.Command != parsed.Command || rts.NumSlots != parsed.NumSlots || rts.NumPackets != parsed.NumPackets {
			t.Fatalf("RequestTWSession basic fields mismatch includeHMAC=%v", includeHMAC)
		}
		if includeHMAC && !bytes.Equal(rts.HMAC[:], parsed.HMAC[:]) {
			t.Fatalf("HMAC mismatch includeHMAC=%v", includeHMAC)
		}
	}
}

func TestRequestTWSessionMBZError(t *testing.T) {
	rts := RequestTWSession{}
	data, _ := rts.Marshal(false)
	data[1] = 0x0F // Set MBZ bits in IPVN byte
	if err := rts.Unmarshal(data, false); err != common.ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ, got %v", err)
	}
}

func TestTypePDescriptorValidation(t *testing.T) {
	tests := []struct {
		name        string
		descriptor  uint32
		expectError bool
		description string
	}{
		// Valid cases - Class Selectors
		{
			name:        "Valid_DSCP_0_Default",
			descriptor:  0x00000000,
			expectError: false,
			description: "DSCP=0, Default PHB",
		},
		{
			name:        "Valid_DSCP_CS1",
			descriptor:  0x00200000, // DSCP=8 (CS1) << 18 bits
			expectError: false,
			description: "DSCP=8 (CS1 class selector)",
		},
		{
			name:        "Valid_DSCP_CS2",
			descriptor:  0x00400000, // DSCP=16 (CS2) << 18 bits
			expectError: false,
			description: "DSCP=16 (CS2 class selector)",
		},
		{
			name:        "Valid_DSCP_CS3",
			descriptor:  0x00600000, // DSCP=24 (CS3) << 18 bits
			expectError: false,
			description: "DSCP=24 (CS3 class selector)",
		},
		{
			name:        "Valid_DSCP_CS4",
			descriptor:  0x00800000, // DSCP=32 (CS4) << 18 bits
			expectError: false,
			description: "DSCP=32 (CS4 class selector)",
		},
		{
			name:        "Valid_DSCP_CS5",
			descriptor:  0x00A00000, // DSCP=40 (CS5) << 18 bits
			expectError: false,
			description: "DSCP=40 (CS5 class selector)",
		},
		{
			name:        "Valid_DSCP_CS6",
			descriptor:  0x00C00000, // DSCP=48 (CS6) << 18 bits
			expectError: false,
			description: "DSCP=48 (CS6 class selector)",
		},
		{
			name:        "Valid_DSCP_CS7",
			descriptor:  0x00E00000, // DSCP=56 (CS7) << 18 bits
			expectError: false,
			description: "DSCP=56 (CS7 class selector)",
		},
		// Valid cases - Assured Forwarding
		{
			name:        "Valid_DSCP_AF11",
			descriptor:  0x00280000, // DSCP=10 (AF11) << 18 bits
			expectError: false,
			description: "DSCP=10 (AF11 - Low Drop)",
		},
		{
			name:        "Valid_DSCP_AF21",
			descriptor:  0x00480000, // DSCP=18 (AF21) << 18 bits
			expectError: false,
			description: "DSCP=18 (AF21 - Low Drop)",
		},
		{
			name:        "Valid_DSCP_AF31",
			descriptor:  0x00680000, // DSCP=26 (AF31) << 18 bits
			expectError: false,
			description: "DSCP=26 (AF31 - Low Drop)",
		},
		{
			name:        "Valid_DSCP_AF41",
			descriptor:  0x00880000, // DSCP=34 (AF41) << 18 bits
			expectError: false,
			description: "DSCP=34 (AF41 - Low Drop)",
		},
		// Valid cases - Special
		{
			name:        "Valid_DSCP_EF",
			descriptor:  0x00B80000, // DSCP=46 (EF) << 18 bits
			expectError: false,
			description: "DSCP=46 (Expedited Forwarding)",
		},
		{
			name:        "Valid_DSCP_VOICE_ADMIT",
			descriptor:  0x00B00000, // DSCP=44 (Voice Admit) << 18 bits
			expectError: false,
			description: "DSCP=44 (Voice Admit)",
		},
		{
			name:        "Valid_DSCP_Max",
			descriptor:  0x00FC0000, // DSCP=63 << 18 bits
			expectError: false,
			description: "Maximum valid DSCP value (63)",
		},
		// Invalid cases - Byte 0 violations
		{
			name:        "Invalid_Byte0_NonZero",
			descriptor:  0xFF000000, // Byte 0 (padding) is non-zero
			expectError: true,
			description: "Byte 0 (padding) must be zero",
		},
		{
			name:        "Invalid_Byte0_SingleBit",
			descriptor:  0x01000000, // Single bit set in byte 0
			expectError: true,
			description: "Even single bit in byte 0 is invalid",
		},
		// Invalid cases - Lower 2 bits violations
		{
			name:        "Invalid_LowerBit0_Set",
			descriptor:  0x00010000, // Bit 0 of byte 1 set
			expectError: true,
			description: "Bit 0 of DSCP byte must be zero",
		},
		{
			name:        "Invalid_LowerBit1_Set",
			descriptor:  0x00020000, // Bit 1 of byte 1 set
			expectError: true,
			description: "Bit 1 of DSCP byte must be zero",
		},
		{
			name:        "Invalid_BothLowerBits_Set",
			descriptor:  0x00030000, // Both lower bits set
			expectError: true,
			description: "Lower 2 bits of DSCP byte must be zero",
		},
		{
			name:        "Invalid_ValidDSCP_WithLowerBit",
			descriptor:  0x00B90000, // DSCP=46 with bit 0 set
			expectError: true,
			description: "Valid DSCP but lower bit set",
		},
		// Invalid cases - Reserved bytes violations
		{
			name:        "Invalid_Reserved_Byte2_NonZero",
			descriptor:  0x00000100, // Byte 2 non-zero
			expectError: true,
			description: "Reserved byte 2 must be zero",
		},
		{
			name:        "Invalid_Reserved_Byte3_NonZero",
			descriptor:  0x00000001, // Byte 3 non-zero
			expectError: true,
			description: "Reserved byte 3 must be zero",
		},
		{
			name:        "Invalid_Reserved_Word_NonZero",
			descriptor:  0x0000FFFF, // Both reserved bytes non-zero
			expectError: true,
			description: "Reserved bytes 2-3 must be zero",
		},
		// Invalid cases - Multiple violations
		{
			name:        "Invalid_Multiple_Violations",
			descriptor:  0xFFFFFFFF, // All bits set
			expectError: true,
			description: "Multiple validation violations",
		},
		{
			name:        "Invalid_Padding_And_Reserved",
			descriptor:  0xFF00FFFF, // Padding and reserved non-zero
			expectError: true,
			description: "Both padding and reserved violations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTypePDescriptor(tt.descriptor)
			if tt.expectError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
			}
		})
	}
}

func TestRequestTWSessionTypePDescriptorValidation(t *testing.T) {
	// Create a valid RequestTWSession
	sid := common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	rts := RequestTWSession{
		Command:         5,
		IPVN:            4,
		ConfSender:      1,
		ConfReceiver:    1,
		NumSlots:        0, // RFC 5357 Section 3.5: Must be zero (TWAMP, not OWAMP)
		NumPackets:      0, // RFC 5357 Section 3.5: Must be zero (TWAMP, not OWAMP)
		SenderPort:      uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		ReceiverPort:    uint16(testutil.GetFreePorts(t, "udp", 1)[0]),
		SenderAddress:   [16]byte{192, 0, 2, 1},
		ReceiverAddress: [16]byte{192, 0, 2, 2},
		SID:             sid,
		PaddingLength:   0,
		StartTime:       common.TWAMPTimestamp{Seconds: 111, Fraction: 222},
		Timeout:         common.TWAMPTimestamp{Seconds: 222, Fraction: 333},
		TypePDescriptor: 0x00B80000, // Valid DSCP=46 (EF)
	}

	// Test with valid Type-P descriptor
	data, err := rts.Marshal(false)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed RequestTWSession
	if err := parsed.Unmarshal(data, false); err != nil {
		t.Fatalf("Unmarshal with valid Type-P descriptor failed: %v", err)
	}

	// Test with invalid Type-P descriptor - byte 0 non-zero
	data[84] = 0xFF // Set byte 0 of Type-P descriptor to non-zero
	err = parsed.Unmarshal(data, false)
	if err == nil {
		t.Fatalf("Expected error for non-zero byte 0, got nil")
	}
	if !strings.Contains(err.Error(), "padding byte must be zero") || !strings.Contains(err.Error(), "0xFF") {
		t.Fatalf("Expected padding byte error with value 0xFF, got %v", err)
	}

	// Test with invalid Type-P descriptor - lower 2 bits non-zero
	data[84] = 0x00 // Reset byte 0
	data[85] = 0x03 // Set lower 2 bits of byte 1
	err = parsed.Unmarshal(data, false)
	if err == nil {
		t.Fatalf("Expected error for non-zero lower bits, got nil")
	}
	if !strings.Contains(err.Error(), "DSCP field lower 2 bits must be zero") {
		t.Fatalf("Expected DSCP lower bits error message, got %v", err)
	}

	// Test with invalid Type-P descriptor - reserved bytes non-zero
	data[85] = 0xB8 // Reset to valid DSCP
	data[86] = 0xFF // Set reserved byte to non-zero
	err = parsed.Unmarshal(data, false)
	if err == nil {
		t.Fatalf("Expected error for non-zero reserved bytes, got nil")
	}
	if !strings.Contains(err.Error(), "reserved bytes must be zero") {
		t.Fatalf("Expected reserved bytes error message, got %v", err)
	}
}
