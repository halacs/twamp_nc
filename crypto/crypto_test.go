package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/ncode/twamp/common"
)

// Test helper functions to reduce duplication

// generateTestKeys creates test AES and HMAC keys with predictable content
func generateTestKeys(t *testing.T) (aesKey []byte, hmacKey []byte) {
	t.Helper()
	aesKey = make([]byte, 16)
	hmacKey = make([]byte, 32)
	for i := range aesKey {
		aesKey[i] = byte(i)
	}
	for i := range hmacKey {
		hmacKey[i] = byte(i + 16)
	}
	return aesKey, hmacKey
}

// generateRandomKeys creates random AES and HMAC keys for testing
func generateRandomKeys(t *testing.T) (aesKey []byte, hmacKey []byte) {
	t.Helper()
	aesKey = make([]byte, 16)
	hmacKey = make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("Failed to generate random AES key: %v", err)
	}
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatalf("Failed to generate random HMAC key: %v", err)
	}
	return aesKey, hmacKey
}

// generateTestChallenge creates a 16-byte test challenge
func generateTestChallenge(t *testing.T) []byte {
	t.Helper()
	challenge := make([]byte, 16)
	for i := range challenge {
		challenge[i] = byte(i + 1)
	}
	return challenge
}

// generateRandomChallenge creates a random 16-byte challenge
func generateRandomChallenge(t *testing.T) []byte {
	t.Helper()
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("Failed to generate random challenge: %v", err)
	}
	return challenge
}

func TestDeriveKey(t *testing.T) {
	t.Parallel()
	// Test vector
	secret := "test-password"
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	count := uint32(1024)

	aesKey, hmacKey, err := DeriveKey(secret, salt, count)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	// Verify key lengths
	if len(aesKey) != 16 {
		t.Errorf("AES key length incorrect: got %d, want 16", len(aesKey))
	}

	if len(hmacKey) != 32 {
		t.Errorf("HMAC key length incorrect: got %d, want 32", len(hmacKey))
	}

	// Verify keys are deterministic (same input produces same output)
	aesKey2, hmacKey2, err := DeriveKey(secret, salt, count)
	if err != nil {
		t.Fatalf("Failed to derive keys second time: %v", err)
	}

	if !bytes.Equal(aesKey, aesKey2) {
		t.Errorf("AES key not deterministic")
	}

	if !bytes.Equal(hmacKey, hmacKey2) {
		t.Errorf("HMAC key not deterministic")
	}
}

func TestTokenEncryptionDecryption(t *testing.T) {
	t.Parallel()
	challenge := generateTestChallenge(t)
	aesKey, hmacKey := generateTestKeys(t)

	// Create token
	token, err := CreateToken(challenge, aesKey, hmacKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Decrypt token
	contents, err := DecryptToken(token, challenge)
	if err != nil {
		t.Fatalf("Failed to decrypt token: %v", err)
	}

	// Verify token contents
	if !bytes.Equal(contents.Challenge, challenge) {
		t.Errorf("Challenge mismatch in decrypted token")
	}

	if !bytes.Equal(contents.AESKey, aesKey) {
		t.Errorf("AES key mismatch in decrypted token")
	}

	if !bytes.Equal(contents.HMACKey, hmacKey) {
		t.Errorf("HMAC key mismatch in decrypted token")
	}
}

// TestDeriveTestSessionKeys validates key lengths and deterministic output.
func TestDeriveTestSessionKeys(t *testing.T) {
	t.Parallel()
	controlAES, controlHMAC := generateRandomKeys(t)
	var sid common.SessionID
	rand.Read(sid[:])

	testAES, testHMAC, err := DeriveTestSessionKeys(controlAES, controlHMAC, sid)
	if err != nil {
		t.Fatalf("DeriveTestSessionKeys: %v", err)
	}
	if len(testAES) != 16 || len(testHMAC) != 32 {
		t.Fatalf("derived key lengths wrong")
	}
	// Same inputs should yield same outputs (deterministic)
	testAES2, testHMAC2, _ := DeriveTestSessionKeys(controlAES, controlHMAC, sid)
	if !bytes.Equal(testAES, testAES2) || !bytes.Equal(testHMAC, testHMAC2) {
		t.Fatalf("DeriveTestSessionKeys not deterministic")
	}
}

func TestHMAC(t *testing.T) {
	t.Parallel()
	_, key := generateTestKeys(t)

	message := []byte("This is a test message for HMAC calculation")

	// Calculate HMAC
	hmac1, err := CalculateHMAC(key, message)
	if err != nil {
		t.Fatalf("Failed to calculate HMAC: %v", err)
	}

	// Verify length
	if len(hmac1) != 16 {
		t.Errorf("HMAC length incorrect: got %d, want 16", len(hmac1))
	}

	// Verify HMAC is deterministic
	hmac2, err := CalculateHMAC(key, message)
	if err != nil {
		t.Fatalf("Failed to calculate HMAC second time: %v", err)
	}

	if !bytes.Equal(hmac1, hmac2) {
		t.Errorf("HMAC calculation not deterministic")
	}

	// Verify HMAC validation
	valid, err := VerifyHMAC(key, message, hmac1)
	if err != nil {
		t.Fatalf("HMAC verification failed: %v", err)
	}

	if !valid {
		t.Errorf("HMAC verification should succeed for correct HMAC")
	}

	// Modify message and verify HMAC fails
	modifiedMessage := append([]byte{}, message...)
	modifiedMessage[0] ^= 1 // Flip a bit

	valid, err = VerifyHMAC(key, modifiedMessage, hmac1)
	if err != nil {
		t.Fatalf("HMAC verification failed: %v", err)
	}

	if valid {
		t.Errorf("HMAC verification should fail for modified message")
	}
}

func TestCalculateHMACWithPrefix(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x11}, 32)
	prefix := []byte{0x01, 0x02, 0x03}
	message := []byte("twamp")

	withPrefix, err := CalculateHMACWithPrefix(key, prefix, message)
	if err != nil {
		t.Fatalf("CalculateHMACWithPrefix failed: %v", err)
	}

	combined := append(append([]byte{}, prefix...), message...)
	expected, err := CalculateHMAC(key, combined)
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}
	if !bytes.Equal(withPrefix, expected) {
		t.Fatalf("HMAC with prefix mismatch")
	}
}

func TestBlockEncryptionDecryption(t *testing.T) {
	t.Parallel()
	key, _ := generateTestKeys(t)
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(16 - i)
	}
	plaintext := []byte("This is a test message for block encryption")

	// Encrypt
	ciphertext, err := EncryptBlocks(key, iv, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptBlocks(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decryption worked
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original: got %q, want %q", decrypted, plaintext)
	}

	// Modify ciphertext and verify decryption fails or produces different result
	modifiedCiphertext := append([]byte{}, ciphertext...)
	modifiedCiphertext[0] ^= 1 // Flip a bit

	modifiedDecrypted, err := DecryptBlocks(key, iv, modifiedCiphertext)
	if err != nil {
		// It's okay if it errors due to padding issues
		return
	}

	// If it didn't error, the result should be different
	if bytes.Equal(plaintext, modifiedDecrypted) {
		t.Errorf("Decryption of modified ciphertext should not match original plaintext")
	}
}

// TestDeriveKeyRoundTrip checks DeriveKey returns expected lengths and matches
// an independent PBKDF2 call when count > 0. Also ensures count == 0 still
// returns 48 bytes without error (RFC allows it).
func TestDeriveKeyRoundTrip(t *testing.T) {
	t.Parallel()
	secret := "s3cr3t!"
	salt := make([]byte, 16)
	rand.Read(salt)

	aesKey, hmacKey, err := DeriveKey(secret, salt, 100)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	ref := pbkdf2.Key([]byte(secret), salt, 100, 48, sha1.New)
	if !bytes.Equal(aesKey, ref[:16]) || !bytes.Equal(hmacKey, ref[16:]) {
		t.Fatalf("DeriveKey output mismatch with reference implementation")
	}
	// count = 0 still OK, just different output
	if a2, h2, err := DeriveKey(secret, salt, 0); err != nil || len(a2) != 16 || len(h2) != 32 {
		t.Fatalf("DeriveKey count=0 unexpected error or sizes: %v", err)
	}
	// wrong salt length
	if _, _, err := DeriveKey(secret, salt[:15], 1); err != common.ErrInvalidSaltLen {
		t.Fatalf("DeriveKey wrong salt len should error, got %v", err)
	}
}

// TestHMACVerify exercises both success and failure paths of VerifyHMAC.
func TestHMACVerify(t *testing.T) {
	t.Parallel()
	_, key := generateRandomKeys(t)
	msg := []byte("hello twamp")
	mac, err := CalculateHMAC(key, msg)
	if err != nil {
		t.Fatalf("CalculateHMAC: %v", err)
	}
	ok, _ := VerifyHMAC(key, msg, mac)
	if !ok {
		t.Fatalf("VerifyHMAC should succeed on valid digest")
	}

	mac[0] ^= 0xFF // corrupt
	ok, _ = VerifyHMAC(key, msg, mac)
	if ok {
		t.Fatalf("VerifyHMAC should fail on corrupted digest")
	}
}

// TestEncryptDecryptBlocks round‑trips an arbitrary payload through AES‑CBC.
func TestEncryptDecryptBlocks(t *testing.T) {
	t.Parallel()
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)
	payload := []byte("Twenty‑three bytes of data")

	ct, err := EncryptBlocks(key, iv, payload)
	if err != nil {
		t.Fatalf("EncryptBlocks: %v", err)
	}
	pt, err := DecryptBlocks(key, iv, ct)
	if err != nil {
		t.Fatalf("DecryptBlocks: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("decrypt output mismatch")
	}
	// invalid key size
	if _, err := EncryptBlocks(key[:15], iv, payload); err != common.ErrInvalidKeyLength {
		t.Fatalf("expected ErrInvalidKeyLength, got %v", err)
	}
}

// TestEncryptDecryptTWAMPPacket covers both authenticated and encrypted modes.
func TestEncryptDecryptTWAMPPacket(t *testing.T) {
	t.Parallel()
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	// Need at least 48 bytes for sender encrypted mode
	packet := make([]byte, 96)
	rand.Read(packet)

	for _, auth := range []bool{true, false} {
		enc, err := EncryptTWAMPTestPacket(key, iv, packet, auth)
		if err != nil {
			t.Fatalf("EncryptTWAMPTestPacket auth=%v: %v", auth, err)
		}
		dec, err := DecryptTWAMPTestPacket(key, iv, enc, auth)
		if err != nil {
			t.Fatalf("DecryptTWAMPTestPacket auth=%v: %v", auth, err)
		}
		if !bytes.Equal(dec, packet) {
			t.Fatalf("round‑trip mismatch auth=%v", auth)
		}
	}
}

func TestEncryptDecryptTWAMPReflectorPacket(t *testing.T) {
	t.Parallel()
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	// Need at least 112 bytes for reflector packets
	packet := make([]byte, 112)
	rand.Read(packet)

	for _, auth := range []bool{true, false} {
		enc, err := EncryptTWAMPReflectorTestPacket(key, iv, packet, auth)
		if err != nil {
			t.Fatalf("EncryptTWAMPReflectorTestPacket auth=%v: %v", auth, err)
		}
		dec, err := DecryptTWAMPReflectorTestPacket(key, iv, enc, auth)
		if err != nil {
			t.Fatalf("DecryptTWAMPReflectorTestPacket auth=%v: %v", auth, err)
		}
		if !bytes.Equal(dec, packet) {
			t.Fatalf("reflector round-trip mismatch auth=%v", auth)
		}
	}
}

// TestTokenCreateDecrypt round‑trips CreateToken / DecryptToken and hits error
// paths for invalid lengths.
func TestTokenCreateDecrypt(t *testing.T) {
	t.Parallel()
	challenge := generateRandomChallenge(t)
	aesKey, hmacKey := generateRandomKeys(t)

	token, err := CreateToken(challenge, aesKey, hmacKey)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	contents, err := DecryptToken(token, challenge)
	if err != nil {
		t.Fatalf("DecryptToken: %v", err)
	}
	if !bytes.Equal(contents.Challenge, challenge) || !bytes.Equal(contents.AESKey, aesKey) || !bytes.Equal(contents.HMACKey, hmacKey) {
		t.Fatalf("token round‑trip mismatch")
	}
	// Error: wrong challenge length
	if _, err := CreateToken(challenge[:15], aesKey, hmacKey); err == nil {
		t.Fatalf("expected error on short challenge")
	}
	if _, err := DecryptToken(token, challenge[:15]); err == nil {
		t.Fatalf("expected error on decrypt with short challenge")
	}
}

// TestNewRandomIV tests the random IV generation function
func TestNewRandomIV(t *testing.T) {
	t.Parallel()
	iv, err := NewRandomIV()
	if err != nil {
		t.Fatalf("NewRandomIV failed: %v", err)
	}

	if len(iv) != aes.BlockSize {
		t.Errorf("IV length = %d, expected %d", len(iv), aes.BlockSize)
	}

	// Generate another IV and ensure they're different
	iv2, err := NewRandomIV()
	if err != nil {
		t.Fatalf("NewRandomIV failed second time: %v", err)
	}

	if bytes.Equal(iv, iv2) {
		t.Errorf("Two random IVs should not be equal")
	}

	// Check that IV is not all zeros
	allZeros := true
	for _, b := range iv {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Errorf("Random IV should not be all zeros")
	}
}

// TestEncryptTWAMPControlMessage tests the control message encryption wrapper
func TestEncryptTWAMPControlMessage(t *testing.T) {
	t.Parallel()
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	plaintext := bytes.Repeat([]byte{0xAB}, 32)

	ciphertext, err := EncryptTWAMPControlMessage(key, iv, plaintext)
	if err != nil {
		t.Fatalf("EncryptTWAMPControlMessage failed: %v", err)
	}

	// Verify it produces the same output as manual CBC encryption without padding.
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	expectedCiphertext := make([]byte, len(plaintext))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(expectedCiphertext, plaintext)
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("EncryptTWAMPControlMessage output doesn't match CBC encryption")
	}
}

// TestDecryptTWAMPControlMessage tests the control message decryption wrapper
func TestDecryptTWAMPControlMessage(t *testing.T) {
	t.Parallel()
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	plaintext := bytes.Repeat([]byte{0xCD}, 32)

	// First encrypt
	ciphertext, err := EncryptTWAMPControlMessage(key, iv, plaintext)
	if err != nil {
		t.Fatalf("EncryptTWAMPControlMessage failed: %v", err)
	}

	// Now decrypt using the wrapper
	decrypted, err := DecryptTWAMPControlMessage(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("DecryptTWAMPControlMessage failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

func TestEncryptTWAMPControlMessage_InvalidLength(t *testing.T) {
	t.Parallel()
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	plaintext := bytes.Repeat([]byte{0xEF}, 17)
	if _, err := EncryptTWAMPControlMessage(key, iv, plaintext); err == nil {
		t.Fatal("expected error for non-block-aligned control message")
	}
}

// TestEncryptTWAMPTestPacketErrorCases tests error conditions for test packet encryption
func TestEncryptTWAMPTestPacketErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		keyLen      int
		ivLen       int
		packetLen   int
		authMode    bool
		expectError bool
	}{
		{
			name:        "invalid key length",
			keyLen:      15, // Should be 16
			ivLen:       16,
			packetLen:   96,
			authMode:    false,
			expectError: true,
		},
		{
			name:        "invalid IV length",
			keyLen:      16,
			ivLen:       15, // Should be 16
			packetLen:   96,
			authMode:    false,
			expectError: true,
		},
		{
			name:        "packet too short for encrypted mode",
			keyLen:      16,
			ivLen:       16,
			packetLen:   47, // Should be at least 48
			authMode:    false,
			expectError: true,
		},
		{
			name:        "packet too short for authenticated mode",
			keyLen:      16,
			ivLen:       16,
			packetLen:   47, // Should be at least 48 per RFC 5357
			authMode:    true,
			expectError: true,
		},
		{
			name:        "valid authenticated mode minimum size",
			keyLen:      16,
			ivLen:       16,
			packetLen:   48, // RFC 5357: minimum for authenticated mode
			authMode:    true,
			expectError: false,
		},
		{
			name:        "valid encrypted mode minimum size",
			keyLen:      16,
			ivLen:       16,
			packetLen:   48,
			authMode:    false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := make([]byte, tt.keyLen)
			iv := make([]byte, tt.ivLen)
			packet := make([]byte, tt.packetLen)

			rand.Read(key)
			rand.Read(iv)
			rand.Read(packet)

			_, err := EncryptTWAMPTestPacket(key, iv, packet, tt.authMode)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestDecryptTWAMPTestPacketErrorCases tests error conditions for test packet decryption
func TestDecryptTWAMPTestPacketErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		keyLen      int
		ivLen       int
		packetLen   int
		authMode    bool
		expectError bool
	}{
		{
			name:        "invalid key length",
			keyLen:      15, // Should be 16
			ivLen:       16,
			packetLen:   96,
			authMode:    false,
			expectError: true,
		},
		{
			name:        "invalid IV length",
			keyLen:      16,
			ivLen:       15, // Should be 16
			packetLen:   96,
			authMode:    false,
			expectError: true,
		},
		{
			name:        "packet too short for encrypted mode",
			keyLen:      16,
			ivLen:       16,
			packetLen:   47, // Should be at least 48
			authMode:    false,
			expectError: true,
		},
		{
			name:        "packet too short for authenticated mode",
			keyLen:      16,
			ivLen:       16,
			packetLen:   47, // Should be at least 48 per RFC 5357
			authMode:    true,
			expectError: true,
		},
		{
			name:        "packet not aligned to block size (encrypted mode)",
			keyLen:      16,
			ivLen:       16,
			packetLen:   49, // Not a multiple of 16 but still >= 48
			authMode:    false,
			expectError: false,
		},
		{
			name:        "packet not aligned to block size (authenticated mode)",
			keyLen:      16,
			ivLen:       16,
			packetLen:   49, // Not a multiple of 16 but still >= 48
			authMode:    true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := make([]byte, tt.keyLen)
			iv := make([]byte, tt.ivLen)
			packet := make([]byte, tt.packetLen)

			rand.Read(key)
			rand.Read(iv)
			rand.Read(packet)

			_, err := DecryptTWAMPTestPacket(key, iv, packet, tt.authMode)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestDeriveTestSessionKeysErrorCases tests error conditions
func TestDeriveTestSessionKeysErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		aesKeyLen   int
		hmacKeyLen  int
		expectError bool
	}{
		{
			name:        "invalid AES key length",
			aesKeyLen:   15, // Should be 16
			hmacKeyLen:  32,
			expectError: true,
		},
		{
			name:        "invalid HMAC key length",
			aesKeyLen:   16,
			hmacKeyLen:  31, // Should be 32
			expectError: true,
		},
		{
			name:        "valid key lengths",
			aesKeyLen:   16,
			hmacKeyLen:  32,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			controlAES := make([]byte, tt.aesKeyLen)
			controlHMAC := make([]byte, tt.hmacKeyLen)
			var sid [16]byte

			rand.Read(controlAES)
			rand.Read(controlHMAC)
			rand.Read(sid[:])

			_, _, err := DeriveTestSessionKeys(controlAES, controlHMAC, sid)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestCalculateHMACErrorCases tests error conditions for HMAC calculation
func TestCalculateHMACErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		keyLen      int
		expectError bool
	}{
		{
			name:        "invalid key length",
			keyLen:      31, // Should be 32
			expectError: true,
		},
		{
			name:        "valid key length",
			keyLen:      32,
			expectError: false,
		},
		{
			name:        "empty message",
			keyLen:      32,
			expectError: false, // Empty message should still work
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := make([]byte, tt.keyLen)
			rand.Read(key)

			var message []byte
			if tt.name != "empty message" {
				message = []byte("test message")
			}

			_, err := CalculateHMAC(key, message)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestVerifyHMACErrorCases tests error conditions for HMAC verification
func TestVerifyHMACErrorCases(t *testing.T) {
	t.Parallel()
	_, validKey := generateRandomKeys(t)
	message := []byte("test message")
	validMAC, _ := CalculateHMAC(validKey, message)

	tests := []struct {
		name        string
		key         []byte
		mac         []byte
		expectError bool
		expectValid bool
	}{
		{
			name:        "invalid key length",
			key:         make([]byte, 31),
			mac:         validMAC,
			expectError: true,
			expectValid: false,
		},
		{
			name:        "invalid MAC length",
			key:         validKey,
			mac:         make([]byte, 15), // Should be 16
			expectError: true,
			expectValid: false,
		},
		{
			name:        "valid but wrong MAC",
			key:         validKey,
			mac:         make([]byte, 16), // All zeros
			expectError: false,
			expectValid: false,
		},
		{
			name:        "correct MAC",
			key:         validKey,
			mac:         validMAC,
			expectError: false,
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			valid, err := VerifyHMAC(tt.key, message, tt.mac)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if valid != tt.expectValid {
					t.Errorf("Valid = %v, expected %v", valid, tt.expectValid)
				}
			}
		})
	}
}

// TestEncryptBlocksErrorCases tests error conditions for block encryption
func TestEncryptBlocksErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		keyLen      int
		ivLen       int
		plaintext   []byte
		expectError bool
	}{
		{
			name:        "invalid key length",
			keyLen:      15,
			ivLen:       16,
			plaintext:   []byte("test"),
			expectError: true,
		},
		{
			name:        "invalid IV length",
			keyLen:      16,
			ivLen:       15,
			plaintext:   []byte("test"),
			expectError: true,
		},
		{
			name:        "empty plaintext",
			keyLen:      16,
			ivLen:       16,
			plaintext:   []byte{},
			expectError: false, // Empty should work with padding
		},
		{
			name:        "single byte plaintext",
			keyLen:      16,
			ivLen:       16,
			plaintext:   []byte{0x42},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := make([]byte, tt.keyLen)
			iv := make([]byte, tt.ivLen)
			rand.Read(key)
			rand.Read(iv)

			_, err := EncryptBlocks(key, iv, tt.plaintext)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestDecryptBlocksErrorCases tests error conditions for block decryption
func TestDecryptBlocksErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		keyLen      int
		ivLen       int
		ciphertext  []byte
		expectError bool
	}{
		{
			name:        "invalid key length",
			keyLen:      15,
			ivLen:       16,
			ciphertext:  make([]byte, 16),
			expectError: true,
		},
		{
			name:        "invalid IV length",
			keyLen:      16,
			ivLen:       15,
			ciphertext:  make([]byte, 16),
			expectError: true,
		},
		{
			name:        "ciphertext not block aligned",
			keyLen:      16,
			ivLen:       16,
			ciphertext:  make([]byte, 17), // Not a multiple of 16
			expectError: true,
		},
		{
			name:        "empty ciphertext",
			keyLen:      16,
			ivLen:       16,
			ciphertext:  []byte{},
			expectError: true,
		},
		{
			name:   "invalid padding in ciphertext",
			keyLen: 16,
			ivLen:  16,
			ciphertext: func() []byte {
				// Create ciphertext with invalid padding
				ct := make([]byte, 16)
				rand.Read(ct)
				ct[15] = 0 // Invalid padding value
				return ct
			}(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := make([]byte, tt.keyLen)
			iv := make([]byte, tt.ivLen)
			rand.Read(key)
			rand.Read(iv)

			_, err := DecryptBlocks(key, iv, tt.ciphertext)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestCreateTokenErrorCases tests error conditions for token creation
func TestCreateTokenErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		challengeLen int
		aesKeyLen    int
		hmacKeyLen   int
		expectError  bool
	}{
		{
			name:         "invalid challenge length",
			challengeLen: 15,
			aesKeyLen:    16,
			hmacKeyLen:   32,
			expectError:  true,
		},
		{
			name:         "invalid AES key length",
			challengeLen: 16,
			aesKeyLen:    15,
			hmacKeyLen:   32,
			expectError:  true,
		},
		{
			name:         "invalid HMAC key length",
			challengeLen: 16,
			aesKeyLen:    16,
			hmacKeyLen:   31,
			expectError:  true,
		},
		{
			name:         "all valid lengths",
			challengeLen: 16,
			aesKeyLen:    16,
			hmacKeyLen:   32,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			challenge := make([]byte, tt.challengeLen)
			aesKey := make([]byte, tt.aesKeyLen)
			hmacKey := make([]byte, tt.hmacKeyLen)

			rand.Read(challenge)
			rand.Read(aesKey)
			rand.Read(hmacKey)

			_, err := CreateToken(challenge, aesKey, hmacKey)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestDecryptTokenErrorCases tests error conditions for token decryption
func TestDecryptTokenErrorCases(t *testing.T) {
	t.Parallel()
	// Create a valid token first
	challenge := generateRandomChallenge(t)
	aesKey, hmacKey := generateRandomKeys(t)

	validToken, _ := CreateToken(challenge, aesKey, hmacKey)

	tests := []struct {
		name         string
		token        []byte
		challengeLen int
		expectError  bool
	}{
		{
			name:         "invalid challenge length",
			token:        validToken,
			challengeLen: 15,
			expectError:  true,
		},
		{
			name:         "token too short",
			token:        make([]byte, 63), // Should be at least 64
			challengeLen: 16,
			expectError:  true,
		},
		{
			name:         "token not block aligned",
			token:        make([]byte, 65), // Not a multiple of 16
			challengeLen: 16,
			expectError:  true,
		},
		{
			name: "corrupted token",
			token: func() []byte {
				t := make([]byte, len(validToken))
				copy(t, validToken)
				t[0] ^= 0xFF // Corrupt first byte
				return t
			}(),
			challengeLen: 16,
			expectError:  true,
		},
		{
			name:         "valid token",
			token:        validToken,
			challengeLen: 16,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testChallenge := make([]byte, tt.challengeLen)
			if tt.challengeLen == 16 {
				copy(testChallenge, challenge)
			}

			_, err := DecryptToken(tt.token, testChallenge)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestPaddingValidation tests PKCS#7 padding edge cases
func TestPaddingValidation(t *testing.T) {
	t.Parallel()
	key, _ := generateRandomKeys(t)
	iv := make([]byte, 16)
	rand.Read(iv)

	// Test various plaintext sizes to ensure padding works correctly
	sizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 127, 128, 129}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			t.Parallel()
			plaintext := make([]byte, size)
			rand.Read(plaintext)

			ciphertext, err := EncryptBlocks(key, iv, plaintext)
			if err != nil {
				t.Fatalf("EncryptBlocks failed for size %d: %v", size, err)
			}

			// Ciphertext should be padded to block size
			if len(ciphertext)%aes.BlockSize != 0 {
				t.Errorf("Ciphertext not block aligned for size %d", size)
			}

			decrypted, err := DecryptBlocks(key, iv, ciphertext)
			if err != nil {
				t.Fatalf("DecryptBlocks failed for size %d: %v", size, err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted doesn't match original for size %d", size)
			}
		})
	}
}

// TestNewRandomIVMultipleInvocations ensures uniqueness across multiple IVs
func TestNewRandomIVMultipleInvocations(t *testing.T) {
	t.Parallel()
	const numIVs = 10000
	ivs := make(map[[16]byte]bool)

	for i := 0; i < numIVs; i++ {
		iv, err := NewRandomIV()
		if err != nil {
			t.Fatalf("NewRandomIV failed on iteration %d: %v", i, err)
		}

		var key [16]byte
		copy(key[:], iv)
		if ivs[key] {
			t.Errorf("Duplicate IV generated on iteration %d", i)
		}
		ivs[key] = true
	}
}
