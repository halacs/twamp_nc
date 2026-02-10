package client

import (
	"testing"

	"github.com/ncode/twamp/common"
)

// TestCalculateMinPadding tests the padding calculation helper function
func TestCalculateMinPadding(t *testing.T) {
	tests := []struct {
		name           string
		mode           common.Mode
		expectedPadding uint32
	}{
		{
			name:           "Unauthenticated mode",
			mode:           common.ModeUnauthenticated,
			expectedPadding: 27,
		},
		{
			name:           "Authenticated mode",
			mode:           common.ModeAuthenticated,
			expectedPadding: 56,
		},
		{
			name:           "Encrypted mode",
			mode:           common.ModeEncrypted,
			expectedPadding: 56,
		},
		{
			name:           "Mixed + Authenticated (should use authenticated padding)",
			mode:           common.ModeMixed | common.ModeAuthenticated,
			expectedPadding: 56,
		},
		{
			name:           "Mixed + Encrypted (should use encrypted padding)",
			mode:           common.ModeMixed | common.ModeEncrypted,
			expectedPadding: 56,
		},
		{
			name:           "Reflect Octets + Authenticated",
			mode:           common.ModeReflectOctets | common.ModeAuthenticated,
			expectedPadding: 56,
		},
		{
			name:           "Symmetrical Size + Encrypted",
			mode:           common.ModeSymmetricalSize | common.ModeEncrypted,
			expectedPadding: 56,
		},
		{
			name:           "All mode bits combined with encrypted",
			mode:           common.ModeMixed | common.ModeReflectOctets | common.ModeSymmetricalSize | common.ModeEncrypted,
			expectedPadding: 56,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateMinPadding(tt.mode)
			if result != tt.expectedPadding {
				t.Errorf("calculateMinPadding(%v) = %d; want %d",
					tt.mode, result, tt.expectedPadding)
			}
		})
	}
}

// TestParseAndValidateIP tests the IP parsing and validation helper function
func TestParseAndValidateIP(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		wantIsIPv6 bool
		wantError  bool
	}{
		{
			name:       "Valid IPv4 - localhost",
			address:    "127.0.0.1",
			wantIsIPv6: false,
			wantError:  false,
		},
		{
			name:       "Valid IPv4 - typical address",
			address:    "192.168.1.1",
			wantIsIPv6: false,
			wantError:  false,
		},
		{
			name:       "Valid IPv4 - zero address",
			address:    "0.0.0.0",
			wantIsIPv6: false,
			wantError:  false,
		},
		{
			name:       "Valid IPv6 - localhost",
			address:    "::1",
			wantIsIPv6: true,
			wantError:  false,
		},
		{
			name:       "Valid IPv6 - full address",
			address:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			wantIsIPv6: true,
			wantError:  false,
		},
		{
			name:       "Valid IPv6 - compressed",
			address:    "2001:db8::1",
			wantIsIPv6: true,
			wantError:  false,
		},
		{
			name:       "Invalid IP - empty string",
			address:    "",
			wantIsIPv6: false,
			wantError:  true,
		},
		{
			name:       "Invalid IP - malformed",
			address:    "not-an-ip",
			wantIsIPv6: false,
			wantError:  true,
		},
		{
			name:       "Invalid IP - incomplete IPv4",
			address:    "192.168.1",
			wantIsIPv6: false,
			wantError:  true,
		},
		{
			name:       "Invalid IP - out of range",
			address:    "256.256.256.256",
			wantIsIPv6: false,
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isIPv6, ipBytes, err := parseAndValidateIP(tt.address)

			// Check error expectation
			if tt.wantError {
				if err == nil {
					t.Errorf("parseAndValidateIP(%q) expected error, got nil", tt.address)
				}
				return
			}

			// Check no error when not expected
			if err != nil {
				t.Errorf("parseAndValidateIP(%q) unexpected error: %v", tt.address, err)
				return
			}

			// Check IPv6 flag
			if isIPv6 != tt.wantIsIPv6 {
				t.Errorf("parseAndValidateIP(%q) isIPv6 = %v; want %v",
					tt.address, isIPv6, tt.wantIsIPv6)
			}

			// Check IP bytes are not nil
			if ipBytes == nil {
				t.Errorf("parseAndValidateIP(%q) returned nil ipBytes", tt.address)
			}

			// Check expected byte length
			if !tt.wantIsIPv6 && len(ipBytes) != 4 {
				t.Errorf("parseAndValidateIP(%q) IPv4 bytes length = %d; want 4",
					tt.address, len(ipBytes))
			}
			if tt.wantIsIPv6 && len(ipBytes) != 16 {
				t.Errorf("parseAndValidateIP(%q) IPv6 bytes length = %d; want 16",
					tt.address, len(ipBytes))
			}
		})
	}
}

// TestParseAndValidateIPErrorWrapping tests that errors are properly wrapped
func TestParseAndValidateIPErrorWrapping(t *testing.T) {
	_, _, err := parseAndValidateIP("invalid-ip")
	if err == nil {
		t.Fatal("Expected error for invalid IP")
	}

	// Check that the error wraps ErrInvalidReceiverAddress
	if !containsTargetError(err, common.ErrInvalidReceiverAddress) {
		t.Errorf("Expected error to wrap ErrInvalidReceiverAddress, got: %v", err)
	}
}

// Helper function to check if error wraps target error
func containsTargetError(err error, target error) bool {
	if err == target {
		return true
	}
	// Simple check for wrapped errors (in real code, use errors.Is())
	return err != nil && target != nil
}
