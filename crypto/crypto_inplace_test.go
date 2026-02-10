package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ncode/twamp/common"
)

func TestEncryptTWAMPTestPacketInPlace(t *testing.T) {
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	tests := []struct {
		name            string
		packetSize      int
		isAuthenticated bool
		expectError     bool
	}{
		{
			name:            "authenticated mode minimum size",
			packetSize:      48,
			isAuthenticated: true,
			expectError:     false,
		},
		{
			name:            "authenticated mode with padding",
			packetSize:      96,
			isAuthenticated: true,
			expectError:     false,
		},
		{
			name:            "encrypted mode minimum size",
			packetSize:      48,
			isAuthenticated: false,
			expectError:     false,
		},
		{
			name:            "encrypted mode with padding",
			packetSize:      96,
			isAuthenticated: false,
			expectError:     false,
		},
		{
			name:            "authenticated mode too small",
			packetSize:      47,
			isAuthenticated: true,
			expectError:     true,
		},
		{
			name:            "encrypted mode too small",
			packetSize:      47,
			isAuthenticated: false,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := make([]byte, tt.packetSize)
			rand.Read(packet)

			// Keep a copy for comparison
			original := make([]byte, len(packet))
			copy(original, packet)

			err := EncryptTWAMPTestPacketInPlace(key, iv, packet, tt.isAuthenticated)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify the packet was modified in-place
			if tt.isAuthenticated {
				// Only first 16 bytes should be encrypted
				if bytes.Equal(packet[:16], original[:16]) {
					t.Error("First 16 bytes were not encrypted")
				}
				// Rest should be unchanged
				if !bytes.Equal(packet[16:], original[16:]) {
					t.Error("Bytes after 16 were modified in authenticated mode")
				}
			} else {
				// First 32 bytes should be encrypted
				if bytes.Equal(packet[:32], original[:32]) {
					t.Error("First 32 bytes were not encrypted")
				}
				// Rest should be unchanged
				if len(packet) > 32 && !bytes.Equal(packet[32:], original[32:]) {
					t.Error("Bytes after 32 were modified in encrypted mode")
				}
			}
		})
	}
}

func TestDecryptTWAMPTestPacketInPlace(t *testing.T) {
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	tests := []struct {
		name            string
		packetSize      int
		isAuthenticated bool
		expectError     bool
	}{
		{
			name:            "authenticated mode minimum size",
			packetSize:      48,
			isAuthenticated: true,
			expectError:     false,
		},
		{
			name:            "encrypted mode minimum size",
			packetSize:      48,
			isAuthenticated: false,
			expectError:     false,
		},
		{
			name:            "authenticated mode too small",
			packetSize:      47,
			isAuthenticated: true,
			expectError:     true,
		},
		{
			name:            "encrypted mode too small",
			packetSize:      47,
			isAuthenticated: false,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original packet
			original := make([]byte, tt.packetSize)
			rand.Read(original)

			// Make a copy to encrypt
			packet := make([]byte, len(original))
			copy(packet, original)

			// Skip if we expect error
			if tt.expectError {
				err := DecryptTWAMPTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			// First encrypt it
			err := EncryptTWAMPTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Keep encrypted copy
			encrypted := make([]byte, len(packet))
			copy(encrypted, packet)

			// Now decrypt in-place
			err = DecryptTWAMPTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify it was decrypted correctly
			if tt.isAuthenticated {
				// First 16 bytes should match original
				if !bytes.Equal(packet[:16], original[:16]) {
					t.Error("First 16 bytes were not decrypted correctly")
				}
			} else {
				// First 32 bytes should match original
				if !bytes.Equal(packet[:32], original[:32]) {
					t.Error("First 32 bytes were not decrypted correctly")
				}
			}
		})
	}
}

func TestEncryptTWAMPReflectorTestPacketInPlace(t *testing.T) {
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	tests := []struct {
		name            string
		packetSize      int
		isAuthenticated bool
		expectError     bool
	}{
		{
			name:            "authenticated mode minimum size",
			packetSize:      112,
			isAuthenticated: true,
			expectError:     false,
		},
		{
			name:            "encrypted mode minimum size",
			packetSize:      112,
			isAuthenticated: false,
			expectError:     false,
		},
		{
			name:            "authenticated mode too small",
			packetSize:      111,
			isAuthenticated: true,
			expectError:     true,
		},
		{
			name:            "encrypted mode too small",
			packetSize:      111,
			isAuthenticated: false,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := make([]byte, tt.packetSize)
			rand.Read(packet)

			original := make([]byte, len(packet))
			copy(original, packet)

			err := EncryptTWAMPReflectorTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.isAuthenticated {
				if bytes.Equal(packet[:16], original[:16]) {
					t.Error("First 16 bytes were not encrypted")
				}
				if !bytes.Equal(packet[16:], original[16:]) {
					t.Error("Bytes after 16 were modified in authenticated mode")
				}
			} else {
				if bytes.Equal(packet[:96], original[:96]) {
					t.Error("First 96 bytes were not encrypted")
				}
				if len(packet) > 96 && !bytes.Equal(packet[96:], original[96:]) {
					t.Error("Bytes after 96 were modified in encrypted mode")
				}
			}
		})
	}
}

func TestDecryptTWAMPReflectorTestPacketInPlace(t *testing.T) {
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	tests := []struct {
		name            string
		packetSize      int
		isAuthenticated bool
		expectError     bool
	}{
		{
			name:            "authenticated mode minimum size",
			packetSize:      112,
			isAuthenticated: true,
			expectError:     false,
		},
		{
			name:            "encrypted mode minimum size",
			packetSize:      112,
			isAuthenticated: false,
			expectError:     false,
		},
		{
			name:            "authenticated mode too small",
			packetSize:      111,
			isAuthenticated: true,
			expectError:     true,
		},
		{
			name:            "encrypted mode too small",
			packetSize:      111,
			isAuthenticated: false,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := make([]byte, tt.packetSize)
			rand.Read(original)

			packet := make([]byte, len(original))
			copy(packet, original)

			if tt.expectError {
				err := DecryptTWAMPReflectorTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			err := EncryptTWAMPReflectorTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			err = DecryptTWAMPReflectorTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.isAuthenticated {
				if !bytes.Equal(packet[:16], original[:16]) {
					t.Error("First 16 bytes were not decrypted correctly")
				}
			} else {
				if !bytes.Equal(packet[:96], original[:96]) {
					t.Error("First 96 bytes were not decrypted correctly")
				}
			}
		})
	}
}

func TestInPlaceCryptoRoundTrip(t *testing.T) {
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	sizes := []int{48, 64, 96, 128, 256}
	modes := []bool{true, false} // authenticated, encrypted

	for _, size := range sizes {
		for _, isAuth := range modes {
			name := "encrypted"
			if isAuth {
				name = "authenticated"
			}

			// Skip invalid combinations
			if (isAuth && size < 48) || (!isAuth && size < 96) {
				continue
			}

			t.Run(name+"_size_"+string(rune(size)), func(t *testing.T) {
				// Create original packet
				original := make([]byte, size)
				rand.Read(original)

				// Make a working copy
				packet := make([]byte, size)
				copy(packet, original)

				// Encrypt in-place
				err := EncryptTWAMPTestPacketInPlace(key, iv, packet, isAuth)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}

				// Decrypt in-place
				err = DecryptTWAMPTestPacketInPlace(key, iv, packet, isAuth)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}

				// Verify round-trip
				if isAuth {
					// Only first 16 bytes go through crypto
					if !bytes.Equal(packet[:16], original[:16]) {
						t.Error("Round-trip failed for authenticated mode")
					}
				} else {
					// First 32 bytes go through crypto
					if !bytes.Equal(packet[:32], original[:32]) {
						t.Error("Round-trip failed for encrypted mode")
					}
				}
			})
		}
	}
}

func TestInPlaceCryptoErrorCases(t *testing.T) {
	tests := []struct {
		name            string
		keyLen          int
		ivLen           int
		packetSize      int
		isAuthenticated bool
		expectError     error
	}{
		{
			name:            "invalid key length",
			keyLen:          15,
			ivLen:           16,
			packetSize:      96,
			isAuthenticated: false,
			expectError:     common.ErrInvalidKeyLength,
		},
		{
			name:            "invalid IV length",
			keyLen:          16,
			ivLen:           15,
			packetSize:      96,
			isAuthenticated: false,
			expectError:     common.ErrInvalidBlockSize,
		},
		{
			name:            "packet too small for authenticated",
			keyLen:          16,
			ivLen:           16,
			packetSize:      47,
			isAuthenticated: true,
			expectError:     common.ErrInvalidBlockSize,
		},
		{
			name:            "packet too small for encrypted",
			keyLen:          16,
			ivLen:           16,
			packetSize:      47,
			isAuthenticated: false,
			expectError:     common.ErrInvalidBlockSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_encrypt", func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			iv := make([]byte, tt.ivLen)
			packet := make([]byte, tt.packetSize)

			err := EncryptTWAMPTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
			if err != tt.expectError {
				t.Errorf("Expected error %v, got %v", tt.expectError, err)
			}
		})

		t.Run(tt.name+"_decrypt", func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			iv := make([]byte, tt.ivLen)
			packet := make([]byte, tt.packetSize)

			err := DecryptTWAMPTestPacketInPlace(key, iv, packet, tt.isAuthenticated)
			if err != tt.expectError {
				t.Errorf("Expected error %v, got %v", tt.expectError, err)
			}
		})
	}
}

func BenchmarkEncryptTWAMPTestPacketInPlace(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	packet := make([]byte, 96)
	rand.Read(packet)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = EncryptTWAMPTestPacketInPlace(key, iv, packet, false)
	}
}

func BenchmarkDecryptTWAMPTestPacketInPlace(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	packet := make([]byte, 96)
	rand.Read(packet)

	// Encrypt it first
	_ = EncryptTWAMPTestPacketInPlace(key, iv, packet, false)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = DecryptTWAMPTestPacketInPlace(key, iv, packet, false)
	}
}
