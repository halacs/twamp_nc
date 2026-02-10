package common

import "testing"

func TestHMACCoverage(t *testing.T) {
	tests := []struct {
		name              string
		isEncrypted       bool
		isReflectorPacket bool
		want              int
	}{
		{
			name:              "authenticated mode sender packet",
			isEncrypted:       false,
			isReflectorPacket: false,
			want:              HMACCoverageAuthenticated, // 16 bytes
		},
		{
			name:              "authenticated mode reflector packet",
			isEncrypted:       false,
			isReflectorPacket: true,
			want:              HMACCoverageAuthenticated, // 16 bytes
		},
		{
			name:              "encrypted mode sender packet",
			isEncrypted:       true,
			isReflectorPacket: false,
			want:              HMACCoverageSenderEncrypted, // 32 bytes
		},
		{
			name:              "encrypted mode reflector packet",
			isEncrypted:       true,
			isReflectorPacket: true,
			want:              HMACCoverageReflectorEncrypted, // 96 bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HMACCoverage(tt.isEncrypted, tt.isReflectorPacket)
			if got != tt.want {
				t.Errorf("HMACCoverage(%v, %v) = %d, want %d",
					tt.isEncrypted, tt.isReflectorPacket, got, tt.want)
			}
		})
	}
}

func TestHMACCoverageConstants(t *testing.T) {
	// Verify constants match RFC 4656/5357 specifications
	if HMACCoverageAuthenticated != 16 {
		t.Errorf("HMACCoverageAuthenticated = %d, want 16 (1 AES block)", HMACCoverageAuthenticated)
	}
	if HMACCoverageSenderEncrypted != 32 {
		t.Errorf("HMACCoverageSenderEncrypted = %d, want 32 (header up to HMAC)", HMACCoverageSenderEncrypted)
	}
	if HMACCoverageReflectorEncrypted != 96 {
		t.Errorf("HMACCoverageReflectorEncrypted = %d, want 96 (6 AES blocks)", HMACCoverageReflectorEncrypted)
	}
}

func TestHMACOffsetConstants(t *testing.T) {
	// Verify HMAC offset constants match packet structures
	if SenderHMACOffset != 32 {
		t.Errorf("SenderHMACOffset = %d, want 32", SenderHMACOffset)
	}
	if ReflectorHMACOffset != 96 {
		t.Errorf("ReflectorHMACOffset = %d, want 96", ReflectorHMACOffset)
	}
}

func TestMinPacketSizeConstants(t *testing.T) {
	// Verify minimum packet size constants
	// MinSenderAuthPacketSize = SenderHMACOffset + 16 (HMAC size)
	expectedSenderMin := SenderHMACOffset + 16
	if MinSenderAuthPacketSize != expectedSenderMin {
		t.Errorf("MinSenderAuthPacketSize = %d, want %d", MinSenderAuthPacketSize, expectedSenderMin)
	}

	// MinReflectorAuthPacketSize = ReflectorHMACOffset + 16 (HMAC size)
	expectedReflectorMin := ReflectorHMACOffset + 16
	if MinReflectorAuthPacketSize != expectedReflectorMin {
		t.Errorf("MinReflectorAuthPacketSize = %d, want %d", MinReflectorAuthPacketSize, expectedReflectorMin)
	}
}