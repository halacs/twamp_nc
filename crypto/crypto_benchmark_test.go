package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ncode/twamp/common"
)

// Helper function to generate random bytes for benchmarks
func generateRandomBytes(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

// Benchmark for DeriveKey using PBKDF2
func BenchmarkDeriveKey(b *testing.B) {
	secret := "test-secret-password-123"
	salt := generateRandomBytes(16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := DeriveKey(secret, salt, 1024)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark DeriveKey with different iteration counts
func BenchmarkDeriveKeyIterations(b *testing.B) {
	secret := "test-secret-password-123"
	salt := generateRandomBytes(16)

	iterations := []uint32{1024, 4096, 16384}

	for _, count := range iterations {
		b.Run(fmt.Sprintf("iterations_%d", count), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := DeriveKey(secret, salt, count)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark for CreateToken
func BenchmarkCreateToken(b *testing.B) {
	challenge := generateRandomBytes(16)
	aesKey := generateRandomBytes(16)
	hmacKey := generateRandomBytes(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CreateToken(challenge, aesKey, hmacKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for DecryptToken
func BenchmarkDecryptToken(b *testing.B) {
	challenge := generateRandomBytes(16)
	aesKey := generateRandomBytes(16)
	hmacKey := generateRandomBytes(32)

	token, err := CreateToken(challenge, aesKey, hmacKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptToken(token, challenge)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for DeriveTestSessionKeys
func BenchmarkDeriveTestSessionKeys(b *testing.B) {
	controlAESKey := generateRandomBytes(16)
	controlHMACKey := generateRandomBytes(32)
	var sid common.SessionID
	copy(sid[:], generateRandomBytes(16))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := DeriveTestSessionKeys(controlAESKey, controlHMACKey, sid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for CalculateHMAC with different message sizes
func BenchmarkCalculateHMAC(b *testing.B) {
	key := generateRandomBytes(32)

	sizes := []int{32, 96, 256, 1024, 2048}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			message := generateRandomBytes(size)
			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				_, err := CalculateHMAC(key, message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark for VerifyHMAC
func BenchmarkVerifyHMAC(b *testing.B) {
	key := generateRandomBytes(32)
	message := generateRandomBytes(96)

	expectedHMAC, err := CalculateHMAC(key, message)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(message)))

	for i := 0; i < b.N; i++ {
		valid, err := VerifyHMAC(key, message, expectedHMAC)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("HMAC verification failed")
		}
	}
}

// Benchmark for EncryptBlocks with different sizes
func BenchmarkEncryptBlocks(b *testing.B) {
	key := generateRandomBytes(16)
	iv := generateRandomBytes(16)

	sizes := []int{64, 128, 256, 512, 1024, 2048}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			plaintext := generateRandomBytes(size)
			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				_, err := EncryptBlocks(key, iv, plaintext)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark for DecryptBlocks
func BenchmarkDecryptBlocks(b *testing.B) {
	key := generateRandomBytes(16)
	iv := generateRandomBytes(16)

	sizes := []int{64, 128, 256, 512, 1024, 2048}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			plaintext := generateRandomBytes(size)
			ciphertext, err := EncryptBlocks(key, iv, plaintext)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				_, err := DecryptBlocks(key, iv, ciphertext)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark for EncryptTWAMPTestPacket
func BenchmarkEncryptTWAMPTestPacket(b *testing.B) {
	key := generateRandomBytes(16)
	iv := generateRandomBytes(16)

	// Test both authenticated and encrypted modes
	modes := []struct {
		name            string
		isAuthenticated bool
		packetSize      int
	}{
		{"authenticated_small", true, 48},
		{"authenticated_large", true, 512},
		{"encrypted_small", false, 112},
		{"encrypted_large", false, 1024},
	}

	for _, mode := range modes {
		b.Run(mode.name, func(b *testing.B) {
			packet := generateRandomBytes(mode.packetSize)
			b.ResetTimer()
			b.SetBytes(int64(mode.packetSize))

			for i := 0; i < b.N; i++ {
				_, err := EncryptTWAMPTestPacket(key, iv, packet, mode.isAuthenticated)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark for DecryptTWAMPTestPacket
func BenchmarkDecryptTWAMPTestPacket(b *testing.B) {
	key := generateRandomBytes(16)
	iv := generateRandomBytes(16)

	modes := []struct {
		name            string
		isAuthenticated bool
		packetSize      int
	}{
		{"authenticated_small", true, 48},
		{"authenticated_large", true, 512},
		{"encrypted_small", false, 112},
		{"encrypted_large", false, 1024},
	}

	for _, mode := range modes {
		b.Run(mode.name, func(b *testing.B) {
			packet := generateRandomBytes(mode.packetSize)
			encrypted, err := EncryptTWAMPTestPacket(key, iv, packet, mode.isAuthenticated)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			b.SetBytes(int64(len(encrypted)))

			for i := 0; i < b.N; i++ {
				_, err := DecryptTWAMPTestPacket(key, iv, encrypted, mode.isAuthenticated)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark for NewRandomIV
func BenchmarkNewRandomIV(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewRandomIV()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark comparing HMAC calculation vs verification
func BenchmarkHMACComparison(b *testing.B) {
	key := generateRandomBytes(32)
	message := generateRandomBytes(96)

	b.Run("Calculate", func(b *testing.B) {
		b.SetBytes(int64(len(message)))
		for i := 0; i < b.N; i++ {
			_, err := CalculateHMAC(key, message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	expectedHMAC, _ := CalculateHMAC(key, message)

	b.Run("Verify", func(b *testing.B) {
		b.SetBytes(int64(len(message)))
		for i := 0; i < b.N; i++ {
			valid, err := VerifyHMAC(key, message, expectedHMAC)
			if err != nil {
				b.Fatal(err)
			}
			if !valid {
				b.Fatal("HMAC verification failed")
			}
		}
	})
}

// Benchmark for parallel crypto operations (simulating multiple sessions)
func BenchmarkParallelCryptoOperations(b *testing.B) {
	b.Run("HMAC_Parallel", func(b *testing.B) {
		key := generateRandomBytes(32)
		message := generateRandomBytes(96)

		b.SetBytes(int64(len(message)))
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := CalculateHMAC(key, message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("Encrypt_Parallel", func(b *testing.B) {
		key := generateRandomBytes(16)
		iv := generateRandomBytes(16)
		plaintext := generateRandomBytes(256)

		b.SetBytes(int64(len(plaintext)))
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := EncryptBlocks(key, iv, plaintext)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// Benchmark complete TWAMP crypto flow (simulating real usage)
func BenchmarkCompleteTWAMPCryptoFlow(b *testing.B) {
	// Setup phase
	secret := "test-secret-password"
	salt := generateRandomBytes(16)

	// Derive keys
	aesKey, hmacKey, _ := DeriveKey(secret, salt, 1024)

	// Create session
	var sid common.SessionID
	copy(sid[:], generateRandomBytes(16))
	testAESKey, testHMACKey, _ := DeriveTestSessionKeys(aesKey, hmacKey, sid)

	// Test packet
	iv := generateRandomBytes(16)
	packet := generateRandomBytes(96)

	b.ResetTimer()
	b.SetBytes(int64(len(packet)))

	for i := 0; i < b.N; i++ {
		// Calculate HMAC for outgoing packet
		hmac, err := CalculateHMAC(testHMACKey, packet[:32])
		if err != nil {
			b.Fatal(err)
		}

		// Simulate adding HMAC to packet
		packetWithHMAC := make([]byte, len(packet))
		copy(packetWithHMAC, packet)
		copy(packetWithHMAC[32:48], hmac)

		// Encrypt packet
		encrypted, err := EncryptTWAMPTestPacket(testAESKey, iv, packetWithHMAC, false)
		if err != nil {
			b.Fatal(err)
		}

		// Decrypt packet (simulating receive)
		decrypted, err := DecryptTWAMPTestPacket(testAESKey, iv, encrypted, false)
		if err != nil {
			b.Fatal(err)
		}

		// Verify HMAC
		valid, err := VerifyHMAC(testHMACKey, decrypted[:32], decrypted[32:48])
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("HMAC verification failed")
		}
	}
}
