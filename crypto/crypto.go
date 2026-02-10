package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"

	"github.com/ncode/twamp/common"
	"golang.org/x/crypto/pbkdf2"
)

// TWAMPKeys contains all the keys needed for a TWAMP connection
type TWAMPKeys struct {
	// Control session keys
	AESKey  []byte // 16 bytes for AES-128
	HMACKey []byte // 32 bytes for HMAC-SHA1 (key size, not digest size)

	// Test session keys (derived from control keys)
	TestAESKey  []byte // 16 bytes for AES-128
	TestHMACKey []byte // 32 bytes for HMAC-SHA1 (key size, not digest size)

	// IVs
	ClientIV []byte // 16 bytes
	ServerIV []byte // 16 bytes
}

// TokenContents represents the decrypted contents of a TWAMP token
type TokenContents struct {
	Challenge []byte // 16 bytes
	AESKey    []byte // 16 bytes
	HMACKey   []byte // 32 bytes
}

// NewRandomIV generates a cryptographically secure random IV
func NewRandomIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// DeriveKey derives AES and HMAC keys from a shared secret using PBKDF2
// as specified in RFC 4656/5357
func DeriveKey(secret string, salt []byte, count uint32) ([]byte, []byte, error) {
	if len(salt) != 16 {
		return nil, nil, common.ErrInvalidSaltLen
	}

	// Use PBKDF2 with HMAC-SHA1 to derive keys
	// The output is 48 bytes: 16 for AES-128 key, 32 for HMAC-SHA1 key
	key := pbkdf2.Key([]byte(secret), salt, int(count), 16+32, sha1.New)

	aesKey := key[:16]
	hmacKey := key[16:]

	return aesKey, hmacKey, nil
}

// CreateToken encrypts session keys with the challenge as the key
// This is used by the Control-Client when responding to Server Greeting
func CreateToken(challenge []byte, aesKey, hmacKey []byte) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("challenge must be exactly 16 bytes, got %d", len(challenge))
	}
	if len(aesKey) != 16 {
		return nil, fmt.Errorf("AES key must be exactly 16 bytes, got %d", len(aesKey))
	}
	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("HMAC key must be exactly 32 bytes, got %d", len(hmacKey))
	}

	// Create 64-byte token: 16 bytes challenge + 16 bytes AES key + 32 bytes HMAC key
	plaintext := make([]byte, 64)
	copy(plaintext[0:16], challenge)
	copy(plaintext[16:32], aesKey)
	copy(plaintext[32:64], hmacKey)

	// Create AES cipher with challenge as key
	block, err := aes.NewCipher(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt using CBC with zero IV
	ciphertext := make([]byte, 64)
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// DecryptToken decrypts a token using the challenge as the key
// This is used by the Server to verify the Control-Client's token
func DecryptToken(token, challenge []byte) (*TokenContents, error) {
	if len(token) != 64 {
		return nil, fmt.Errorf("token must be exactly 64 bytes, got %d", len(token))
	}
	if len(challenge) != 16 {
		return nil, fmt.Errorf("challenge must be exactly 16 bytes, got %d", len(challenge))
	}

	// Create AES cipher with challenge as key
	block, err := aes.NewCipher(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt using CBC with zero IV
	plaintext := make([]byte, 64)
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, token)

	// Extract token contents with additional validation
	contents := &TokenContents{
		Challenge: make([]byte, 16),
		AESKey:    make([]byte, 16),
		HMACKey:   make([]byte, 32),
	}

	copy(contents.Challenge, plaintext[0:16])
	copy(contents.AESKey, plaintext[16:32])
	copy(contents.HMACKey, plaintext[32:64])

	// Verify the decrypted challenge matches the provided challenge
	if !bytes.Equal(contents.Challenge, challenge) {
		return nil, fmt.Errorf("token validation failed: challenge mismatch")
	}

	return contents, nil
}

// DeriveTestSessionKeys derives keys for a TWAMP test session from control session keys
// using the SID as specified in RFC 5357
func DeriveTestSessionKeys(controlAESKey, controlHMACKey []byte, sid common.SessionID) ([]byte, []byte, error) {
	if len(controlAESKey) != 16 {
		return nil, nil, common.ErrInvalidKeyLength
	}
	if len(controlHMACKey) != 32 {
		return nil, nil, common.ErrInvalidKeyLength
	}

	// For AES key, single-block ECB mode with SID as key
	block, err := aes.NewCipher(sid[:])
	if err != nil {
		return nil, nil, err
	}

	// Encrypt control AES key using ECB mode (single block)
	testAESKey := make([]byte, 16)
	block.Encrypt(testAESKey, controlAESKey)

	// For HMAC key, two-block CBC mode with zero IV and SID as key
	testHMACKey := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(testHMACKey, controlHMACKey)

	return testAESKey, testHMACKey, nil
}

// CalculateHMAC computes HMAC-SHA1 of a message, truncated to 16 bytes
func CalculateHMAC(key, message []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, common.ErrInvalidKeyLength
	}

	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	digest := mac.Sum(nil)

	// Truncate to 16 bytes as per RFC 4656
	return digest[:16], nil
}

// CalculateHMACWithPrefix computes HMAC-SHA1 over prefix||message, truncated to 16 bytes.
func CalculateHMACWithPrefix(key, prefix, message []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, common.ErrInvalidKeyLength
	}

	mac := hmac.New(sha1.New, key)
	if len(prefix) > 0 {
		mac.Write(prefix)
	}
	mac.Write(message)
	digest := mac.Sum(nil)

	return digest[:16], nil
}

// VerifyHMAC verifies HMAC-SHA1 of a message against provided digest
func VerifyHMAC(key, message, expectedHMAC []byte) (bool, error) {
	if len(key) != 32 {
		return false, common.ErrInvalidKeyLength
	}
	if len(expectedHMAC) != 16 {
		return false, common.ErrInvalidHMACLength
	}

	calculatedHMAC, err := CalculateHMAC(key, message)
	if err != nil {
		return false, err
	}

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal(calculatedHMAC, expectedHMAC), nil
}

// EncryptBlocks encrypts data using AES-CBC
func EncryptBlocks(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, common.ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return nil, common.ErrInvalidBlockSize
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad plaintext to block size if needed
	// PKCS#7 padding - always add padding (even for aligned blocks)
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padding == 0 {
		padding = aes.BlockSize
	}
	paddedText := make([]byte, len(plaintext)+padding)
	copy(paddedText, plaintext)
	// PKCS#7 padding
	for i := len(plaintext); i < len(paddedText); i++ {
		paddedText[i] = byte(padding)
	}
	plaintext = paddedText

	// Encrypt using CBC mode
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// DecryptBlocks decrypts data using AES-CBC
func DecryptBlocks(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, common.ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return nil, common.ErrInvalidBlockSize
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, common.ErrInvalidBlockSize
	}
	if len(ciphertext) == 0 {
		return nil, common.ErrInvalidBlockSize
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt using CBC mode
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding value: %d", padding)
	}

	// Verify all padding bytes are correct
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	plaintext = plaintext[:len(plaintext)-padding]
	return plaintext, nil
}

// EncryptTWAMPControlMessage encrypts a block-aligned TWAMP control message.
func EncryptTWAMPControlMessage(key, iv, plaintext []byte) ([]byte, error) {
	stream, err := NewCBCStream(key, iv)
	if err != nil {
		return nil, err
	}
	return stream.Encrypt(plaintext)
}

// DecryptTWAMPControlMessage decrypts a block-aligned TWAMP control message.
func DecryptTWAMPControlMessage(key, iv, ciphertext []byte) ([]byte, error) {
	stream, err := NewCBCStream(key, iv)
	if err != nil {
		return nil, err
	}
	return stream.Decrypt(ciphertext)
}

func encryptTestPacket(key, iv []byte, packet []byte, isAuthenticated, isReflector bool) ([]byte, error) {
	if len(key) != 16 {
		return nil, common.ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return nil, common.ErrInvalidBlockSize
	}

	// Create a copy to avoid modifying the original
	result := make([]byte, len(packet))
	copy(result, packet)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if isAuthenticated {
		// RFC 5357 Section 4.1.2: For authenticated mode, encrypt the first block (16 bytes)
		// The first block contains: 4 bytes sequence number + 12 bytes MBZ
		//
		// WARNING: RFC 5357 explicitly requires ECB mode for ONLY the first 16-byte block
		// in authenticated mode. Yes, ECB is cryptographically weak, but:
		// 1. It's only used for a SINGLE block (sequence number + MBZ zeros)
		// 2. The sequence number is non-repeating (monotonic counter)
		// 3. This is mandated by RFC 5357 for compatibility
		// 4. The HMAC provides the actual authentication security
		//
		// DO NOT use ECB for anything else. This is a protocol requirement, not a choice.
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			minSize = common.MinReflectorAuthPacketSize
		}
		if len(packet) < minSize {
			return nil, common.ErrInvalidBlockSize
		}

		// Encrypt the first block using ECB mode (single block only, per RFC)
		encryptedBlock := make([]byte, 16)
		block.Encrypt(encryptedBlock, packet[:16])

		// Copy encrypted block back
		copy(result[:16], encryptedBlock)
	} else {
		encryptLen := common.HMACCoverageSenderEncrypted
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			encryptLen = common.HMACCoverageReflectorEncrypted
			minSize = common.MinReflectorAuthPacketSize
		}

		if len(packet) < minSize {
			return nil, common.ErrInvalidBlockSize
		}

		// Create a zero IV as required by RFC 5357
		zeroIV := make([]byte, aes.BlockSize)

		// Use CBC mode for the required blocks with zero IV
		mode := cipher.NewCBCEncrypter(block, zeroIV)
		mode.CryptBlocks(result[:encryptLen], packet[:encryptLen])
	}

	return result, nil
}

// EncryptTWAMPTestPacket encrypts portions of a TWAMP sender test packet based on mode.
func EncryptTWAMPTestPacket(key, iv []byte, packet []byte, isAuthenticated bool) ([]byte, error) {
	return encryptTestPacket(key, iv, packet, isAuthenticated, false)
}

// EncryptTWAMPReflectorTestPacket encrypts portions of a TWAMP reflector test packet based on mode.
func EncryptTWAMPReflectorTestPacket(key, iv []byte, packet []byte, isAuthenticated bool) ([]byte, error) {
	return encryptTestPacket(key, iv, packet, isAuthenticated, true)
}

// DecryptTWAMPTestPacket decrypts portions of a TWAMP test packet based on mode
func DecryptTWAMPTestPacket(key, iv []byte, packet []byte, isAuthenticated bool) ([]byte, error) {
	return decryptTestPacket(key, iv, packet, isAuthenticated, false)
}

// DecryptTWAMPReflectorTestPacket decrypts portions of a TWAMP reflector test packet based on mode.
func DecryptTWAMPReflectorTestPacket(key, iv []byte, packet []byte, isAuthenticated bool) ([]byte, error) {
	return decryptTestPacket(key, iv, packet, isAuthenticated, true)
}

func decryptTestPacket(key, iv []byte, packet []byte, isAuthenticated, isReflector bool) ([]byte, error) {
	if len(key) != 16 {
		return nil, common.ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return nil, common.ErrInvalidBlockSize
	}

	// Create a copy to avoid modifying the original
	result := make([]byte, len(packet))
	copy(result, packet)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if isAuthenticated {
		// RFC 5357 Section 4.1.2: For authenticated mode, decrypt the first block (16 bytes)
		// The first block contains: 4 bytes sequence number + 12 bytes MBZ
		// Using AES in ECB mode for the single block
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			minSize = common.MinReflectorAuthPacketSize
		}
		if len(packet) < minSize {
			return nil, common.ErrInvalidBlockSize
		}

		// Decrypt the first block using ECB mode
		decryptedBlock := make([]byte, 16)
		block.Decrypt(decryptedBlock, packet[:16])

		// Copy decrypted block back
		copy(result[:16], decryptedBlock)
	} else {
		encryptLen := common.HMACCoverageSenderEncrypted
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			encryptLen = common.HMACCoverageReflectorEncrypted
			minSize = common.MinReflectorAuthPacketSize
		}

		if len(packet) < minSize {
			return nil, common.ErrInvalidBlockSize
		}

		// Create a zero IV as required by RFC 5357
		zeroIV := make([]byte, aes.BlockSize)

		// Use CBC mode for the required blocks with zero IV
		mode := cipher.NewCBCDecrypter(block, zeroIV)
		mode.CryptBlocks(result[:encryptLen], packet[:encryptLen])
	}

	return result, nil
}
