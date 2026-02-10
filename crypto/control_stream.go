package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/ncode/twamp/common"
)

// CBCStream implements RFC 4656 Section 3.4 control-plane CBC stream encryption.
// It maintains the IV between calls, updating it to the last ciphertext block.
type CBCStream struct {
	block cipher.Block
	iv    [aes.BlockSize]byte
}

// NewCBCStream constructs a CBC stream for control-plane encryption/decryption.
func NewCBCStream(key, iv []byte) (*CBCStream, error) {
	if len(key) != 16 {
		return nil, common.ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return nil, common.ErrInvalidBlockSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := &CBCStream{block: block}
	copy(stream.iv[:], iv)
	return stream, nil
}

// Encrypt encrypts a block-aligned control message and advances the stream IV.
func (s *CBCStream) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, common.ErrInvalidBlockSize
	}

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(s.block, s.iv[:])
	mode.CryptBlocks(ciphertext, plaintext)
	copy(s.iv[:], ciphertext[len(ciphertext)-aes.BlockSize:])

	return ciphertext, nil
}

// Decrypt decrypts a block-aligned control message and advances the stream IV.
func (s *CBCStream) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, common.ErrInvalidBlockSize
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(s.block, s.iv[:])
	mode.CryptBlocks(plaintext, ciphertext)
	copy(s.iv[:], ciphertext[len(ciphertext)-aes.BlockSize:])

	return plaintext, nil
}
