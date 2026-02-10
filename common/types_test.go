package common

import (
	"fmt"
	"testing"
)

func TestAcceptCodeToString(t *testing.T) {
	tests := []struct {
		code     uint8
		expected string
	}{
		{AcceptOK, "OK"},
		{AcceptFailure, "Failure, reason unspecified"},
		{AcceptInternalError, "Internal error"},
		{AcceptNotSupported, "Some aspect of request is not supported"},
		{AcceptPermanentResLimited, "Cannot perform request due to permanent resource limitations"},
		{AcceptTempResLimited, "Cannot perform request due to temporary resource limitations"},
		{6, "Reserved accept code: 6"},     // First reserved code
		{100, "Reserved accept code: 100"}, // Mid-range reserved code
		{255, "Reserved accept code: 255"}, // Last reserved code
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("code_%d", tt.code), func(t *testing.T) {
			result := AcceptCodeToString(tt.code)
			if result != tt.expected {
				t.Errorf("AcceptCodeToString(%d) = %q, want %q", tt.code, result, tt.expected)
			}
		})
	}
}

func TestIsAcceptCodeValid(t *testing.T) {
	tests := []struct {
		code     uint8
		expected bool
	}{
		{AcceptOK, true},
		{AcceptFailure, true},
		{AcceptInternalError, true},
		{AcceptNotSupported, true},
		{AcceptPermanentResLimited, true},
		{AcceptTempResLimited, true},
		{6, true},   // Reserved but valid
		{100, true}, // Reserved but valid
		{255, true}, // Reserved but valid
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("code_%d", tt.code), func(t *testing.T) {
			result := IsAcceptCodeValid(tt.code)
			if result != tt.expected {
				t.Errorf("IsAcceptCodeValid(%d) = %v, want %v", tt.code, result, tt.expected)
			}
		})
	}
}

func TestIsAcceptCodeDefined(t *testing.T) {
	tests := []struct {
		code     uint8
		expected bool
	}{
		{AcceptOK, true},
		{AcceptFailure, true},
		{AcceptInternalError, true},
		{AcceptNotSupported, true},
		{AcceptPermanentResLimited, true},
		{AcceptTempResLimited, true},
		{6, false},   // Reserved, not defined
		{100, false}, // Reserved, not defined
		{255, false}, // Reserved, not defined
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("code_%d", tt.code), func(t *testing.T) {
			result := IsAcceptCodeDefined(tt.code)
			if result != tt.expected {
				t.Errorf("IsAcceptCodeDefined(%d) = %v, want %v", tt.code, result, tt.expected)
			}
		})
	}
}

func TestModeToString(t *testing.T) {
	tests := []struct {
		mode     Mode
		expected string
	}{
		// Basic modes
		{ModeUnauthenticated, "unauthenticated"},
		{ModeAuthenticated, "authenticated"},
		{ModeEncrypted, "encrypted"},
		{Mode(ModeMixed), "mixed"},
		{Mode(ModeReflectOctets), "reflect-octets"},
		{Mode(ModeSymmetricalSize), "symmetrical-size"},

		// Combined modes
		{Mode(ModeUnauthenticated | ModeAuthenticated), "unauthenticated+authenticated"},
		{Mode(ModeAuthenticated | ModeEncrypted), "authenticated+encrypted"},
		{Mode(ModeMixed | ModeReflectOctets), "mixed+reflect-octets"},
		{Mode(ModeReflectOctets | ModeSymmetricalSize), "reflect-octets+symmetrical-size"},
		{Mode(ModeAuthenticated | ModeReflectOctets | ModeSymmetricalSize), "authenticated+reflect-octets+symmetrical-size"},
		{Mode(ModeUnauthenticated | ModeAuthenticated | ModeEncrypted | ModeMixed | ModeReflectOctets | ModeSymmetricalSize), "unauthenticated+authenticated+encrypted+mixed+reflect-octets+symmetrical-size"},

		// Unknown mode
		{Mode(128), "unknown"},
		{Mode(0), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := ModeToString(tt.mode)
			if result != tt.expected {
				t.Errorf("ModeToString(%d) = %q, want %q", tt.mode, result, tt.expected)
			}
		})
	}
}

func TestValidateRequestedMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    Mode
		wantErr bool
	}{
		{
			name:    "unauthenticated",
			mode:    ModeUnauthenticated,
			wantErr: false,
		},
		{
			name:    "authenticated",
			mode:    ModeAuthenticated,
			wantErr: false,
		},
		{
			name:    "encrypted",
			mode:    ModeEncrypted,
			wantErr: false,
		},
		{
			name:    "mixed authenticated with extensions",
			mode:    ModeMixed | ModeAuthenticated | ModeReflectOctets | ModeSymmetricalSize,
			wantErr: false,
		},
		{
			name:    "mixed encrypted",
			mode:    ModeMixed | ModeEncrypted,
			wantErr: false,
		},
		{
			name:    "missing security bit",
			mode:    ModeReflectOctets,
			wantErr: true,
		},
		{
			name:    "multiple security bits",
			mode:    ModeAuthenticated | ModeEncrypted,
			wantErr: true,
		},
		{
			name:    "reserved bit 14 set",
			mode:    Mode(1<<14) | ModeAuthenticated,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequestedMode(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequestedMode(%d) error = %v, wantErr = %v", tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestValidateModeMask(t *testing.T) {
	tests := []struct {
		name    string
		mode    Mode
		wantErr bool
	}{
		{
			name:    "single unauthenticated",
			mode:    ModeUnauthenticated,
			wantErr: false,
		},
		{
			name:    "multiple security bits",
			mode:    ModeAuthenticated | ModeEncrypted,
			wantErr: false,
		},
		{
			name:    "mixed with authenticated",
			mode:    ModeMixed | ModeAuthenticated,
			wantErr: false,
		},
		{
			name:    "missing security bits",
			mode:    ModeReflectOctets,
			wantErr: true,
		},
		{
			name:    "reserved bit 14 set",
			mode:    Mode(1<<14) | ModeAuthenticated,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateModeMask(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateModeMask(%d) error = %v, wantErr = %v", tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestTWAMPError(t *testing.T) {
	err := NewTWAMPError(AcceptFailure, "test error")

	// Test Error method
	expected := "TWAMP error (Failure, reason unspecified): test error"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}

	// Test with different accept codes
	err2 := NewTWAMPError(AcceptInternalError, "internal error")
	expected2 := "TWAMP error (Internal error): internal error"
	if err2.Error() != expected2 {
		t.Errorf("Error() = %q, want %q", err2.Error(), expected2)
	}

	// Test with reserved accept code
	err3 := &TWAMPError{
		Message:    "unknown error",
		AcceptCode: 99,
	}
	expected3 := "TWAMP error (Reserved accept code: 99): unknown error"
	if err3.Error() != expected3 {
		t.Errorf("Error() = %q, want %q", err3.Error(), expected3)
	}
}

func TestErrorEstimate(t *testing.T) {
	// Test ToUint16
	ee := ErrorEstimate{
		Multiplier: 0x12,
		Scale:      0x34,
		S:          true,
	}

	val := ee.ToUint16()
	// Expected: S bit (0x8000) | Scale<<8 (0x3400) | Multiplier (0x12)
	expected := uint16(0x8000 | 0x3400 | 0x12)
	if val != expected {
		t.Errorf("ToUint16() = %04x, want %04x", val, expected)
	}

	// Test FromUint16
	var ee2 ErrorEstimate
	ee2.FromUint16(0xB412) // S=1, Scale=0x34, Multiplier=0x12

	if ee2.S != true {
		t.Errorf("FromUint16: S = %v, want true", ee2.S)
	}
	if ee2.Scale != 0x34 {
		t.Errorf("FromUint16: Scale = %02x, want 0x34", ee2.Scale)
	}
	if ee2.Multiplier != 0x12 {
		t.Errorf("FromUint16: Multiplier = %02x, want 0x12", ee2.Multiplier)
	}

	// Test round-trip
	ee3 := ErrorEstimate{
		Multiplier: 0xAB,
		Scale:      0x2F,
		S:          false,
	}
	val3 := ee3.ToUint16()
	var ee4 ErrorEstimate
	ee4.FromUint16(val3)

	if ee4.S != ee3.S || ee4.Scale != ee3.Scale || ee4.Multiplier != ee3.Multiplier {
		t.Errorf("Round-trip failed: got {S:%v, Scale:%02x, Mult:%02x}, want {S:%v, Scale:%02x, Mult:%02x}",
			ee4.S, ee4.Scale, ee4.Multiplier, ee3.S, ee3.Scale, ee3.Multiplier)
	}
}

func TestErrorEstimateBoundaryValues(t *testing.T) {
	tests := []struct {
		name string
		ee   ErrorEstimate
	}{
		{"all_zeros", ErrorEstimate{0, 0, false}},
		{"max_values", ErrorEstimate{0xFF, 0x3F, true}}, // 6-bit scale
		{"s_bit_only", ErrorEstimate{0, 0, true}},
		{"multiplier_max", ErrorEstimate{0xFF, 0, false}},
		{"scale_max", ErrorEstimate{0, 0x3F, false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := tt.ee.ToUint16()
			var result ErrorEstimate
			result.FromUint16(val)

			if result.S != tt.ee.S || result.Scale != tt.ee.Scale || result.Multiplier != tt.ee.Multiplier {
				t.Errorf("Round-trip failed for %s: got {S:%v, Scale:%02x, Mult:%02x}, want {S:%v, Scale:%02x, Mult:%02x}",
					tt.name, result.S, result.Scale, result.Multiplier, tt.ee.S, tt.ee.Scale, tt.ee.Multiplier)
			}
		})
	}
}

// TestSessionID_IsZero tests the IsZero method for SessionID
// RFC 5357 Section 3.5 requires SID to be zero in Request-TW-Session
func TestSessionID_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		sid      SessionID
		expected bool
	}{
		{
			name:     "all zeros",
			sid:      SessionID{},
			expected: true,
		},
		{
			name:     "explicitly zeroed",
			sid:      SessionID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: true,
		},
		{
			name:     "first byte non-zero",
			sid:      SessionID{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: false,
		},
		{
			name:     "last byte non-zero",
			sid:      SessionID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expected: false,
		},
		{
			name:     "middle byte non-zero",
			sid:      SessionID{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: false,
		},
		{
			name:     "all ones",
			sid:      SessionID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			expected: false,
		},
		{
			name:     "typical SID",
			sid:      SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.sid.IsZero()
			if result != tt.expected {
				t.Errorf("SessionID.IsZero() = %v, want %v", result, tt.expected)
			}
		})
	}
}
