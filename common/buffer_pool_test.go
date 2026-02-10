package common

import (
	"sync"
	"testing"
)

func TestBufferPool(t *testing.T) {
	pool := NewBufferPool(1024)
	buf := pool.Get()
	if len(buf) != 1024 {
		t.Errorf("Expected buffer length 1024, got %d", len(buf))
	}
	if cap(buf) != 1024 {
		t.Errorf("Expected buffer capacity 1024, got %d", cap(buf))
	}
	pool.Put(buf)
	buf2 := pool.Get()
	if cap(buf2) != 1024 {
		t.Errorf("Expected reused buffer capacity 1024, got %d", cap(buf2))
	}
}

func TestBufferPoolConcurrency(t *testing.T) {
	pool := NewBufferPool(512)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := pool.Get()
			if len(buf) != 512 {
				t.Errorf("Expected buffer length 512, got %d", len(buf))
			}
			buf[0] = 1
			buf[511] = 255
			pool.Put(buf)
		}()
	}
	wg.Wait()
}

func TestBufferPoolDoesNotReturnResizedBuffers(t *testing.T) {
	pool := NewBufferPool(256)
	buf := pool.Get()
	originalCap := cap(buf)
	buf = buf[:128]
	pool.Put(buf)
	buf2 := pool.Get()
	if cap(buf2) != originalCap {
		t.Errorf("Expected buffer with capacity %d, got %d", originalCap, cap(buf2))
	}
	if len(buf2) != originalCap {
		t.Errorf("Expected buffer reset to full length %d, got %d", originalCap, len(buf2))
	}
}

func TestBufferPoolDiscardsReallocatedBuffers(t *testing.T) {
	pool := NewBufferPool(256)
	buf := pool.Get()
	buf = append(buf, make([]byte, 256)...)
	pool.Put(buf)
	buf2 := pool.Get()
	if cap(buf2) != 256 {
		t.Errorf("Expected fresh buffer with capacity 256, got %d", cap(buf2))
	}
	if len(buf2) != 256 {
		t.Errorf("Expected fresh buffer with length 256, got %d", len(buf2))
	}
}

func TestPacketBufferPool(t *testing.T) {
	buf := PacketBufferPool.Get()
	if cap(buf) != MaxTWAMPPacketSize {
		t.Errorf("Expected packet buffer capacity %d, got %d", MaxTWAMPPacketSize, cap(buf))
	}
	PacketBufferPool.Put(buf)
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	pool := NewBufferPool(2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)
	}
}

func BenchmarkDirectAllocation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = make([]byte, 2048)
	}
}

func BenchmarkBufferPoolConcurrent(b *testing.B) {
	pool := NewBufferPool(2048)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get()
			if len(buf) > 0 {
				buf[0] = 1
			}
			pool.Put(buf)
		}
	})
}
