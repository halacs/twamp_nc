package messages

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestServerGreeting_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "data too short",
			data:        make([]byte, 63),
			expectError: true,
		},
		{
			name: "non-zero in first MBZ field",
			data: func() []byte {
				buf := make([]byte, 64)
				buf[5] = 1 // Non-zero in MBZ
				return buf
			}(),
			expectError: true,
		},
		{
			name: "non-zero in last MBZ field",
			data: func() []byte {
				buf := make([]byte, 64)
				buf[55] = 1 // Non-zero in last MBZ
				return buf
			}(),
			expectError: true,
		},
		{
			name: "valid greeting",
			data: func() []byte {
				buf := make([]byte, 64)
				binary.BigEndian.PutUint32(buf[12:16], 1) // Modes
				binary.BigEndian.PutUint32(buf[48:52], 1) // Count
				return buf
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sg ServerGreeting
			err := sg.Unmarshal(tt.data)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestSetupResponse_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "data too short",
			data:        make([]byte, 163),
			expectError: true,
		},
		{
			name:        "exact size",
			data:        make([]byte, 164),
			expectError: false,
		},
		{
			name:        "data too long",
			data:        make([]byte, 200),
			expectError: false, // Should still work
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sr SetupResponse
			err := sr.Unmarshal(tt.data)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestServerStart_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "data too short",
			data:        make([]byte, 47),
			expectError: true,
		},
		{
			name: "non-zero in first MBZ",
			data: func() []byte {
				buf := make([]byte, 48)
				buf[10] = 1 // Non-zero in MBZ
				return buf
			}(),
			expectError: true,
		},
		{
			name: "non-zero in last MBZ",
			data: func() []byte {
				buf := make([]byte, 48)
				buf[45] = 1 // Non-zero in last MBZ
				return buf
			}(),
			expectError: true,
		},
		{
			name: "valid start",
			data: func() []byte {
				buf := make([]byte, 48)
				buf[15] = 1 // Accept field
				return buf
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ss ServerStart
			err := ss.Unmarshal(tt.data)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestRequestTWSession_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		includeHMAC bool
		data        []byte
		expectError bool
	}{
		{
			name:        "data too short without HMAC",
			includeHMAC: false,
			data:        make([]byte, 111),
			expectError: true,
		},
		{
			name:        "data too short with HMAC",
			includeHMAC: true,
			data:        make([]byte, 111),
			expectError: true,
		},
		{
			name:        "non-zero in lower bits of IPVN byte",
			includeHMAC: false,
			data: func() []byte {
				buf := make([]byte, 112)
				buf[1] = 0x0F // Non-zero in MBZ bits
				return buf
			}(),
			expectError: true,
		},
		{
			name:        "invalid IPVN value",
			includeHMAC: false,
			data: func() []byte {
				buf := make([]byte, 112)
				buf[1] = 0x50 // IPVN = 5 (invalid)
				return buf
			}(),
			expectError: true,
		},
		{
			name:        "non-zero in MBZ3",
			includeHMAC: false,
			data: func() []byte {
				buf := make([]byte, 112)
				buf[95] = 1 // Non-zero in MBZ3
				return buf
			}(),
			expectError: true,
		},
		{
			name:        "non-zero in padding before HMAC",
			includeHMAC: false,
			data: func() []byte {
				buf := make([]byte, 112)
				buf[105] = 1 // Non-zero in padding
				return buf
			}(),
			expectError: true,
		},
		{
			name:        "valid request without HMAC",
			includeHMAC: false,
			data: func() []byte {
				buf := make([]byte, 112)
				buf[0] = 5    // Command
				buf[1] = 0x40 // IPVN = 4
				return buf
			}(),
			expectError: false,
		},
		{
			name:        "valid request with HMAC",
			includeHMAC: true,
			data: func() []byte {
				buf := make([]byte, 112)
				buf[0] = 5    // Command
				buf[1] = 0x60 // IPVN = 6
				return buf
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rts RequestTWSession
			err := rts.Unmarshal(tt.data, tt.includeHMAC)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestAcceptSession_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		includeHMAC bool
		data        []byte
		expectError bool
	}{
	{
		name:        "data too short without HMAC",
		includeHMAC: false,
		data:        make([]byte, 47),
		expectError: true,
	},
	{
		name:        "data too short with HMAC",
		includeHMAC: true,
		data:        make([]byte, 47),
		expectError: true,
	},
	{
		name:        "non-zero MBZ byte",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 48)
			buf[1] = 1 // Non-zero MBZ
			return buf
		}(),
		expectError: true,
		},
		{
		name:        "non-zero in MBZ2",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 48)
			buf[25] = 1 // Non-zero in MBZ2
			return buf
		}(),
		expectError: true,
		},
		{
		name:        "valid accept without HMAC",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 48)
			buf[0] = 0                                  // Accept = 0 (OK)
			binary.BigEndian.PutUint16(buf[2:4], 20001) // Port
			return buf
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var as AcceptSession
			err := as.Unmarshal(tt.data, tt.includeHMAC)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestStartSessions_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		includeHMAC bool
		data        []byte
		expectError bool
	}{
	{
		name:        "data too short without HMAC",
		includeHMAC: false,
		data:        make([]byte, 31),
		expectError: true,
	},
	{
		name:        "data too short with HMAC",
		includeHMAC: true,
		data:        make([]byte, 31),
		expectError: true,
	},
	{
		name:        "non-zero in MBZ",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[8] = 1 // Non-zero in MBZ
			return buf
		}(),
			expectError: true,
		},
		{
		name:        "valid start sessions",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[0] = 2 // Command
			return buf
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ss StartSessions
			err := ss.Unmarshal(tt.data, tt.includeHMAC)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestStartAck_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		includeHMAC bool
		data        []byte
		expectError bool
	}{
	{
		name:        "non-zero in MBZ",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[12] = 1 // Non-zero in MBZ
			return buf
			}(),
			expectError: true,
		},
		{
		name:        "valid start ack",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[0] = 0 // Accept
			return buf
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sa StartAck
			err := sa.Unmarshal(tt.data, tt.includeHMAC)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestStopSessions_Unmarshal_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		includeHMAC bool
		data        []byte
		expectError bool
	}{
	{
		name:        "non-zero in MBZ1",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[0] = 3 // Command
			buf[2] = 1 // Non-zero in MBZ1 (bytes 2-3)
			return buf
			}(),
			expectError: true,
		},
	{
		name:        "non-zero in MBZ2",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[0] = 3 // Command
			buf[15] = 1 // Non-zero in MBZ2 (bytes 8-15)
			return buf
			}(),
			expectError: true,
		},
	{
		name:        "valid stop sessions",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[0] = 3           // Command
			buf[1] = 0           // Accept
			binary.BigEndian.PutUint32(buf[4:8], 5) // NumSessions = 5
				return buf
			}(),
			expectError: false,
		},
		{
			name:        "valid stop sessions with HMAC",
			includeHMAC: true,
			data: func() []byte {
				buf := make([]byte, 32)
				buf[0] = 3 // Command
				buf[1] = 0 // Accept
				binary.BigEndian.PutUint32(buf[4:8], 10) // NumSessions = 10
				// HMAC at bytes 16-32
				for i := 16; i < 32; i++ {
					buf[i] = byte(i)
				}
				return buf
			}(),
			expectError: false,
		},
	{
		name:        "valid stop sessions with Accept code",
		includeHMAC: false,
		data: func() []byte {
			buf := make([]byte, 32)
			buf[0] = 3 // Command
			buf[1] = 1 // Accept = Failure
			binary.BigEndian.PutUint32(buf[4:8], 0) // NumSessions = 0 (failure case)
				return buf
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ss StopSessions
			err := ss.Unmarshal(tt.data, tt.includeHMAC)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestMarshal_WithHMAC_Coverage(t *testing.T) {
	// Test StartSessions.Marshal with HMAC
	ss := StartSessions{
		Command: 2,
		HMAC:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	data, err := ss.Marshal(true)
	if err != nil {
		t.Errorf("StartSessions.Marshal(true) error: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("StartSessions.Marshal(true) size = %d, want 32", len(data))
	}

	// Test StopSessions.Marshal with HMAC (RFC 5357 Section 3.8)
	stop := StopSessions{
		Command:     3,
		Accept:      0, // OK
		NumSessions: 5,
		HMAC:        [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	data, err = stop.Marshal(true)
	if err != nil {
		t.Errorf("StopSessions.Marshal(true) error: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("StopSessions.Marshal(true) size = %d, want 32", len(data))
	}

	// Verify NumSessions is correctly encoded at bytes 4-7 (big-endian)
	numSessions := binary.BigEndian.Uint32(data[4:8])
	if numSessions != 5 {
		t.Errorf("StopSessions NumSessions = %d, want 5", numSessions)
	}
}

// TestRequestTWSession_RFC5357_NumSlots_Validation tests RFC 5357 Section 3.5
// requirement that NumSlots MUST be zero (TWAMP, not OWAMP)
func TestRequestTWSession_RFC5357_NumSlots_Validation(t *testing.T) {
	tests := []struct {
		name        string
		numSlots    uint32
		expectError bool
	}{
		{
			name:        "NumSlots = 0 (valid)",
			numSlots:    0,
			expectError: false,
		},
		{
			name:        "NumSlots = 1 (invalid)",
			numSlots:    1,
			expectError: true,
		},
		{
			name:        "NumSlots = 100 (invalid)",
			numSlots:    100,
			expectError: true,
		},
		{
			name:        "NumSlots = MaxUint32 (invalid)",
			numSlots:    0xFFFFFFFF,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a valid base request
			buf := make([]byte, 112)
			buf[0] = 5    // Command
			buf[1] = 0x40 // IPVN = 4
			// Set NumSlots at offset 4-7
			binary.BigEndian.PutUint32(buf[4:8], tt.numSlots)
			// NumPackets at offset 8-11 (leave as 0)

			var rts RequestTWSession
			err := rts.Unmarshal(buf, false)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
			if err != nil && tt.expectError {
				// Verify it's the right error
				if err.Error() != "NumSlots must be zero per RFC 5357 Section 3.5 (TWAMP, not OWAMP)" {
					t.Errorf("Expected NumSlots error, got: %v", err)
				}
			}
		})
	}
}

// TestRequestTWSession_RFC5357_NumPackets_Validation tests RFC 5357 Section 3.5
// requirement that NumPackets MUST be zero (TWAMP, not OWAMP)
func TestRequestTWSession_RFC5357_NumPackets_Validation(t *testing.T) {
	tests := []struct {
		name        string
		numPackets  uint32
		expectError bool
	}{
		{
			name:        "NumPackets = 0 (valid)",
			numPackets:  0,
			expectError: false,
		},
		{
			name:        "NumPackets = 1 (invalid)",
			numPackets:  1,
			expectError: true,
		},
		{
			name:        "NumPackets = 1000 (invalid)",
			numPackets:  1000,
			expectError: true,
		},
		{
			name:        "NumPackets = MaxUint32 (invalid)",
			numPackets:  0xFFFFFFFF,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a valid base request
			buf := make([]byte, 112)
			buf[0] = 5    // Command
			buf[1] = 0x40 // IPVN = 4
			// NumSlots at offset 4-7 (leave as 0)
			// Set NumPackets at offset 8-11
			binary.BigEndian.PutUint32(buf[8:12], tt.numPackets)

			var rts RequestTWSession
			err := rts.Unmarshal(buf, false)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
			if err != nil && tt.expectError {
				// Verify it's the right error
				if err.Error() != "NumPackets must be zero per RFC 5357 Section 3.5 (TWAMP, not OWAMP)" {
					t.Errorf("Expected NumPackets error, got: %v", err)
				}
			}
		})
	}
}

// TestRequestTWSession_TypeP_DSCP_Validation tests that DSCP value
// extraction and validation works correctly per RFC 5357 Section 3.5
func TestRequestTWSession_TypeP_DSCP_Validation(t *testing.T) {
	tests := []struct {
		name        string
		descriptor  uint32
		expectError bool
		errorMsg    string
	}{
		{
			name: "DSCP = 0 (valid)",
			// Byte layout: [padding][DSCP|MBZ][reserved][reserved]
			// DSCP in upper 6 bits of byte 1: 0x00 << 2 = 0
			descriptor:  0x00000000,
			expectError: false,
		},
		{
			name: "DSCP = 46 (EF - valid)",
			// DSCP 46 = 0b101110 in upper 6 bits = 0xB8
			descriptor:  0x00B80000,
			expectError: false,
		},
		{
			name: "DSCP = 63 (max valid)",
			// DSCP 63 = 0b111111 in upper 6 bits = 0xFC
			descriptor:  0x00FC0000,
			expectError: false,
		},
		{
			name: "Non-zero padding byte (invalid)",
			// Byte 0 should be zero
			descriptor:  0x01000000,
			expectError: true,
			errorMsg:    "Type-P descriptor padding byte must be zero",
		},
	{
		name: "Lower 2 bits of DSCP byte set - bit 0 (invalid)",
		// Lower 2 bits of byte 1 must be zero (testing bit 0 set)
		// Byte 1 = 0x01 = 0b00000001, lower bit 0 is set
		descriptor:  0x00010000,
		expectError: true,
		errorMsg:    "Type-P descriptor DSCP field lower 2 bits must be zero",
	},
	{
		name: "Lower 2 bits of DSCP byte set - bit 1 (invalid)",
		// Lower 2 bits of byte 1 must be zero (testing bit 1 set)
		// Byte 1 = 0x02 = 0b00000010, lower bit 1 is set
		descriptor:  0x00020000,
		expectError: true,
		errorMsg:    "Type-P descriptor DSCP field lower 2 bits must be zero",
	},
	{
		name: "Lower 2 bits of DSCP byte set - both bits (invalid)",
		// Lower 2 bits of byte 1 must be zero (testing both bits set)
		// Byte 1 = 0x03 = 0b00000011, both lower bits are set
		descriptor:  0x00030000,
		expectError: true,
		errorMsg:    "Type-P descriptor DSCP field lower 2 bits must be zero",
	},
	{
		name: "Multiple violations - hits reserved check (invalid)",
		// Note: This descriptor has 0xFC in byte 1 (11111100 binary).
		// The lower 2 bits of 0xFC are 00, so lower bits check passes.
		// It fails on reserved bytes check (0x0100 in bytes 2-3).
		// Kept to verify validation order: padding -> lower bits -> reserved
		descriptor:  0x00FC0100,
		expectError: true,
		errorMsg:    "Type-P descriptor reserved bytes must be zero",
	},
		{
			name: "Reserved bytes non-zero (invalid)",
			// Bytes 2-3 must be zero
			descriptor:  0x00000001,
			expectError: true,
			errorMsg:    "Type-P descriptor reserved bytes must be zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a valid base request
			buf := make([]byte, 112)
			buf[0] = 5    // Command
			buf[1] = 0x40 // IPVN = 4
			// Set TypePDescriptor at offset 84-87
			binary.BigEndian.PutUint32(buf[84:88], tt.descriptor)

			var rts RequestTWSession
			err := rts.Unmarshal(buf, false)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
			if err != nil && tt.expectError && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, err)
				}
			}
		})
	}
}

// TestRequestTWSession_PaddingLength_Validation tests that PaddingLength
// is validated to not exceed reasonable bounds
func TestRequestTWSession_PaddingLength_Validation(t *testing.T) {
	tests := []struct {
		name          string
		paddingLength uint32
		expectError   bool
	}{
		{
			name:          "PaddingLength = 0 (valid)",
			paddingLength: 0,
			expectError:   false,
		},
		{
			name:          "PaddingLength = 100 (valid)",
			paddingLength: 100,
			expectError:   false,
		},
		{
			name:          "PaddingLength = 1500 (valid)",
			paddingLength: 1500,
			expectError:   false,
		},
		{
			name:          "PaddingLength = 2048 (max valid)",
			paddingLength: 2048,
			expectError:   false,
		},
		{
			name:          "PaddingLength = 2049 (invalid)",
			paddingLength: 2049,
			expectError:   true,
		},
		{
			name:          "PaddingLength = 65535 (invalid)",
			paddingLength: 65535,
			expectError:   true,
		},
		{
			name:          "PaddingLength = MaxUint32 (invalid)",
			paddingLength: 0xFFFFFFFF,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a valid base request
			buf := make([]byte, 112)
			buf[0] = 5    // Command
			buf[1] = 0x40 // IPVN = 4
			// Set PaddingLength at offset 64-67
			binary.BigEndian.PutUint32(buf[64:68], tt.paddingLength)

			var rts RequestTWSession
			err := rts.Unmarshal(buf, false)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
			if err != nil && tt.expectError {
				// Verify it's the right error
				if err.Error() != "PaddingLength exceeds maximum allowed" {
					t.Errorf("Expected PaddingLength error, got: %v", err)
				}
			}
		})
	}
}

// TestRequestTWSession_Combined_RFC5357_Validations tests that all
// RFC 5357 Section 3.5 validations work together correctly
func TestRequestTWSession_Combined_RFC5357_Validations(t *testing.T) {
	tests := []struct {
		name          string
		setupBuffer   func([]byte)
		expectError   bool
		expectedError string
	}{
		{
			name: "All fields valid",
			setupBuffer: func(buf []byte) {
				buf[0] = 5    // Command
				buf[1] = 0x40 // IPVN = 4
				// NumSlots = 0, NumPackets = 0 (already zero)
				// PaddingLength = 100
				binary.BigEndian.PutUint32(buf[64:68], 100)
				// TypePDescriptor with DSCP = 46 (EF)
				binary.BigEndian.PutUint32(buf[84:88], 0x00B80000)
			},
			expectError: false,
		},
		{
			name: "NumSlots non-zero fails first",
			setupBuffer: func(buf []byte) {
				buf[0] = 5    // Command
				buf[1] = 0x40 // IPVN = 4
				binary.BigEndian.PutUint32(buf[4:8], 1) // NumSlots = 1 (invalid)
			},
			expectError:   true,
			expectedError: "NumSlots must be zero",
		},
		{
			name: "NumPackets non-zero with NumSlots zero",
			setupBuffer: func(buf []byte) {
				buf[0] = 5    // Command
				buf[1] = 0x40 // IPVN = 4
				// NumSlots = 0
				binary.BigEndian.PutUint32(buf[8:12], 1) // NumPackets = 1 (invalid)
			},
			expectError:   true,
			expectedError: "NumPackets must be zero",
		},
		{
			name: "Excessive PaddingLength",
			setupBuffer: func(buf []byte) {
				buf[0] = 5    // Command
				buf[1] = 0x40 // IPVN = 4
				binary.BigEndian.PutUint32(buf[64:68], 10000) // PaddingLength too large
			},
			expectError:   true,
			expectedError: "PaddingLength exceeds maximum",
		},
		{
			name: "Invalid TypeP descriptor",
			setupBuffer: func(buf []byte) {
				buf[0] = 5    // Command
				buf[1] = 0x40 // IPVN = 4
				binary.BigEndian.PutUint32(buf[84:88], 0x01000000) // Non-zero padding byte
			},
			expectError:   true,
			expectedError: "Type-P descriptor padding byte must be zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 112)
			tt.setupBuffer(buf)

			var rts RequestTWSession
			err := rts.Unmarshal(buf, false)
			if (err != nil) != tt.expectError {
				t.Errorf("Unmarshal() error = %v, expectError = %v", err, tt.expectError)
			}
			if err != nil && tt.expectedError != "" {
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing %q, got: %v", tt.expectedError, err)
				}
			}
		})
	}
}
