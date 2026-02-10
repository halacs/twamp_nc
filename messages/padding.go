package messages

import (
	"crypto/rand"
)

// GenerateRandomPadding creates cryptographically secure random padding
func GenerateRandomPadding(size int) ([]byte, error) {
	if size <= 0 {
		return []byte{}, nil
	}

	padding := make([]byte, size)
	_, err := rand.Read(padding)
	if err != nil {
		return nil, err
	}

	return padding, nil
}

// GenerateZeroPadding creates padding filled with zeros
func GenerateZeroPadding(size int) []byte {
	if size <= 0 {
		return []byte{}
	}

	return make([]byte, size)
}

// FillRandomPadding fills the given buffer slice with cryptographically secure random data
// This avoids allocation by writing directly to the provided buffer
func FillRandomPadding(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	_, err := rand.Read(buf)
	return err
}

// FillZeroPadding fills the given buffer slice with zeros
// This is a no-op if the buffer was freshly allocated (already zeros)
// but useful when reusing buffers from a pool
func FillZeroPadding(buf []byte) {
	// Only need to clear if we're reusing a buffer
	// Fresh allocations are already zero
	for i := range buf {
		buf[i] = 0
	}
}
