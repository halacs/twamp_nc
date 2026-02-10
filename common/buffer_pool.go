package common

import (
	"sync"
)

// BufferPool manages a pool of reusable byte buffers to reduce memory allocations
// for TWAMP packet processing. The pool uses sync.Pool to efficiently manage
// buffers across goroutines.
type BufferPool struct {
	pool sync.Pool
	size int // Store the expected buffer size to properly validate on Put
}

// NewBufferPool creates a new buffer pool with the specified buffer size.
// All buffers returned from this pool will have the capacity of bufferSize.
func NewBufferPool(bufferSize int) *BufferPool {
	return &BufferPool{
		size: bufferSize,
		pool: sync.Pool{
			New: func() interface{} {
				// Create a new buffer with the specified size
				return make([]byte, bufferSize)
			},
		},
	}
}

// Get retrieves a buffer from the pool. The buffer will have the capacity
// that was specified when the pool was created. The returned buffer should
// be returned to the pool using Put() when no longer needed.
func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

// Put returns a buffer to the pool for reuse. The buffer will be reused
// in future Get() calls. It's important to not use the buffer after
// returning it to the pool.
func (bp *BufferPool) Put(buf []byte) {
	// Only return buffers with the expected capacity
	// Reset the slice length to capacity before pooling
	if cap(buf) == bp.size {
		bp.pool.Put(buf[:cap(buf)])
	}
	// Silently discard buffers that don't match our expected size
	// to prevent memory corruption from resized/reallocated buffers
}

// PacketBufferPool is a global pool for buffers used for TWAMP packet processing.
// Uses MaxTWAMPPacketSize to ensure buffers are large enough for any TWAMP packet.
var PacketBufferPool = NewBufferPool(MaxTWAMPPacketSize)
