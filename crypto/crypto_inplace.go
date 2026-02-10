package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/ncode/twamp/common"
)

// EncryptTWAMPTestPacketInPlace encrypts a TWAMP sender test packet in-place.
func EncryptTWAMPTestPacketInPlace(key, iv []byte, packet []byte, isAuthenticated bool) error {
	return encryptTestPacketInPlace(key, iv, packet, isAuthenticated, false)
}

// EncryptTWAMPReflectorTestPacketInPlace encrypts a TWAMP reflector test packet in-place.
func EncryptTWAMPReflectorTestPacketInPlace(key, iv []byte, packet []byte, isAuthenticated bool) error {
	return encryptTestPacketInPlace(key, iv, packet, isAuthenticated, true)
}

func encryptTestPacketInPlace(key, iv []byte, packet []byte, isAuthenticated, isReflector bool) error {
	if len(key) != 16 {
		return common.ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return common.ErrInvalidBlockSize
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if isAuthenticated {
		// For authenticated mode, encrypt first block using ECB
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			minSize = common.MinReflectorAuthPacketSize
		}
		if len(packet) < minSize {
			return common.ErrInvalidBlockSize
		}

		// Encrypt in-place
		block.Encrypt(packet[:16], packet[:16])
	} else {
		encryptLen := common.HMACCoverageSenderEncrypted
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			encryptLen = common.HMACCoverageReflectorEncrypted
			minSize = common.MinReflectorAuthPacketSize
		}
		if len(packet) < minSize {
			return common.ErrInvalidBlockSize
		}

		// Create a zero IV as required by RFC 5357
		zeroIV := make([]byte, aes.BlockSize)

		// Encrypt in-place using CBC mode
		mode := cipher.NewCBCEncrypter(block, zeroIV)
		mode.CryptBlocks(packet[:encryptLen], packet[:encryptLen])
	}

	return nil
}

// DecryptTWAMPTestPacketInPlace decrypts a TWAMP sender test packet in-place.
func DecryptTWAMPTestPacketInPlace(key, iv []byte, packet []byte, isAuthenticated bool) error {
	return decryptTestPacketInPlace(key, iv, packet, isAuthenticated, false)
}

// DecryptTWAMPReflectorTestPacketInPlace decrypts a TWAMP reflector test packet in-place.
func DecryptTWAMPReflectorTestPacketInPlace(key, iv []byte, packet []byte, isAuthenticated bool) error {
	return decryptTestPacketInPlace(key, iv, packet, isAuthenticated, true)
}

func decryptTestPacketInPlace(key, iv []byte, packet []byte, isAuthenticated, isReflector bool) error {
	if len(key) != 16 {
		return common.ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return common.ErrInvalidBlockSize
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if isAuthenticated {
		// For authenticated mode, decrypt first block using ECB
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			minSize = common.MinReflectorAuthPacketSize
		}
		if len(packet) < minSize {
			return common.ErrInvalidBlockSize
		}

		// Decrypt in-place
		block.Decrypt(packet[:16], packet[:16])
	} else {
		encryptLen := common.HMACCoverageSenderEncrypted
		minSize := common.MinSenderAuthPacketSize
		if isReflector {
			encryptLen = common.HMACCoverageReflectorEncrypted
			minSize = common.MinReflectorAuthPacketSize
		}
		if len(packet) < minSize {
			return common.ErrInvalidBlockSize
		}

		// Create a zero IV as required by RFC 5357
		zeroIV := make([]byte, aes.BlockSize)

		// Decrypt in-place using CBC mode
		mode := cipher.NewCBCDecrypter(block, zeroIV)
		mode.CryptBlocks(packet[:encryptLen], packet[:encryptLen])
	}

	return nil
}
