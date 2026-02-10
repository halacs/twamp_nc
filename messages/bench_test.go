package messages

import (
	"fmt"
	"testing"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
)

// Benchmarks for control message marshaling after buffer pool removal

// BenchmarkServerGreetingMarshal measures the performance of ServerGreeting marshaling
// after switching from buffer pool to direct allocation
func BenchmarkServerGreetingMarshal(b *testing.B) {
	sg := &ServerGreeting{
		Modes:     common.ModeUnauthenticated | common.ModeAuthenticated,
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data, err := sg.Marshal()
		if err != nil {
			b.Fatal(err)
		}
		_ = data
	}
}

// BenchmarkRequestTWSessionMarshal measures RequestTWSession marshaling performance
func BenchmarkRequestTWSessionMarshal(b *testing.B) {
	rts := &RequestTWSession{
		Command:         5,
		IPVN:            4,
		ConfSender:      1,
		ConfReceiver:    1,
		NumSlots:        100,
		NumPackets:      1000,
		SenderPort:      uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
		ReceiverPort:    uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
		SID:             common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		PaddingLength:   64,
		StartTime:       common.Now(),
		Timeout:         common.Now().Add(5000000000), // 5 seconds
		TypePDescriptor: 0x00B80000,                   // DSCP 46 (EF)
	}

	b.Run("WithoutHMAC", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			data, err := rts.Marshal(false)
			if err != nil {
				b.Fatal(err)
			}
			_ = data
		}
	})

	b.Run("WithHMAC", func(b *testing.B) {
		rts.HMAC = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			data, err := rts.Marshal(true)
			if err != nil {
				b.Fatal(err)
			}
			_ = data
		}
	})
}

// BenchmarkAcceptSessionMarshal measures AcceptSession marshaling performance
func BenchmarkAcceptSessionMarshal(b *testing.B) {
	as := &AcceptSession{
		Accept: 0,
		Port:   uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
		SID:    common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	b.Run("WithoutHMAC", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			data, err := as.Marshal(false)
			if err != nil {
				b.Fatal(err)
			}
			_ = data
		}
	})

	b.Run("WithHMAC", func(b *testing.B) {
		as.HMAC = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			data, err := as.Marshal(true)
			if err != nil {
				b.Fatal(err)
			}
			_ = data
		}
	})
}

// BenchmarkTypePDescriptorValidation measures the performance impact of enhanced validation
func BenchmarkTypePDescriptorValidation(b *testing.B) {
	testCases := []struct {
		name       string
		descriptor uint32
		valid      bool
	}{
		{"Valid_DSCP_0", 0x00000000, true},
		{"Valid_DSCP_46_EF", 0x00B80000, true},
		{"Invalid_PaddingByte", 0xFF000000, false},
		{"Invalid_LowerBits", 0x00030000, false},
		{"Invalid_Reserved", 0x0000FFFF, false},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				err := validateTypePDescriptor(tc.descriptor)
				if tc.valid && err != nil {
					b.Fatal("Expected valid descriptor")
				}
				if !tc.valid && err == nil {
					b.Fatal("Expected invalid descriptor")
				}
			}
		})
	}
}

// BenchmarkControlMessageUnmarshal measures unmarshaling performance
func BenchmarkControlMessageUnmarshal(b *testing.B) {
	// Prepare test data
	sg := &ServerGreeting{
		Modes:     common.ModeUnauthenticated,
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}
	data, _ := sg.Marshal()

	b.Run("ServerGreeting", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var parsed ServerGreeting
			err := parsed.Unmarshal(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// RequestTWSession
	rts := &RequestTWSession{
		Command:         5,
		IPVN:            4,
		ConfSender:      1,
		ConfReceiver:    1,
		NumSlots:        100,
		NumPackets:      1000,
		SenderPort:      uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
		ReceiverPort:    uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
		SID:             common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		PaddingLength:   64,
		StartTime:       common.Now(),
		Timeout:         common.Now(),
		TypePDescriptor: 0x00B80000,
	}
	rtsData, _ := rts.Marshal(false)

	b.Run("RequestTWSession", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var parsed RequestTWSession
			err := parsed.Unmarshal(rtsData, false)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMBZValidation measures the performance of MBZ field validation
func BenchmarkMBZValidation(b *testing.B) {
	// Create test data with various sizes
	sizes := []int{16, 32, 64, 128, 256}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := validateMBZ(data, 0, size)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkParallelMarshal tests parallel message marshaling performance
func BenchmarkParallelMarshal(b *testing.B) {
	sg := &ServerGreeting{
		Modes:     common.ModeUnauthenticated,
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			data, err := sg.Marshal()
			if err != nil {
				b.Fatal(err)
			}
			_ = data
		}
	})
}

// Comparison benchmark: Direct allocation vs theoretical buffer pool
// This shows the performance difference between approaches

type bufferPool struct{}

func (bp *bufferPool) Get(size int) []byte {
	// Simulate buffer pool - in reality this would reuse buffers
	return make([]byte, size)
}

var simulatedPool = &bufferPool{}

func BenchmarkAllocationComparison(b *testing.B) {
	size := 128 // Typical control message size

	b.Run("DirectMake", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, size)
			clear(buf) // Ensure zeroing
			_ = buf
		}
	})

	b.Run("SimulatedPool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := simulatedPool.Get(size)
			clear(buf) // Ensure zeroing
			_ = buf
			// In real pool, would return buffer here
		}
	})
}

// BenchmarkTestPacketMarshalWithPool benchmarks test packet marshaling that still uses buffer pool
func BenchmarkTestPacketMarshalWithPool(b *testing.B) {
	stp := &SenderTestPacket{
		SeqNumber: 12345,
		Timestamp: common.Now(),
		ErrorEstimate: common.ErrorEstimate{
			Multiplier: 0,
			Scale:      0,
			S:          true,
		},
		PaddingSize: 100,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data, err := stp.Marshal()
		if err != nil {
			b.Fatal(err)
		}
		// In production, this buffer would be returned to pool
		common.PacketBufferPool.Put(data)
	}
}

// BenchmarkCompleteControlFlow measures a complete control message exchange
func BenchmarkCompleteControlFlow(b *testing.B) {
	// Simulate a complete control protocol exchange
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Server greeting
		sg := &ServerGreeting{
			Modes:     common.ModeUnauthenticated,
			Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8},
			Salt:      [16]byte{8, 7, 6, 5, 4, 3, 2, 1},
			Count:     1024,
		}
		sgData, _ := sg.Marshal()

		// Setup response
		sr := &SetupResponse{
			Mode:     common.ModeUnauthenticated,
			ClientIV: [16]byte{1, 2, 3, 4, 5, 6, 7, 8},
		}
		srData, _ := sr.Marshal()

		// Server start
		ss := &ServerStart{
			Accept:    0,
			ServerIV:  [16]byte{8, 7, 6, 5, 4, 3, 2, 1},
			StartTime: common.Now(),
		}
		ssData, _ := ss.Marshal()

		// Request session
		rts := &RequestTWSession{
			Command:         5,
			IPVN:            4,
			ConfSender:      1,
			ConfReceiver:    1,
			NumSlots:        100,
			NumPackets:      1000,
			SenderPort:      uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
			ReceiverPort:    uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
			SID:             common.SessionID{1, 2, 3, 4},
			PaddingLength:   64,
			StartTime:       common.Now(),
			Timeout:         common.Now(),
			TypePDescriptor: 0x00B80000,
		}
		rtsData, _ := rts.Marshal(false)

		// Accept session
		as := &AcceptSession{
			Accept: 0,
			Port:   uint16(testutil.GetFreePorts(b, "udp", 1)[0]),
			SID:    common.SessionID{1, 2, 3, 4},
		}
		asData, _ := as.Marshal(false)

		// Use the data to prevent optimization
		_ = sgData
		_ = srData
		_ = ssData
		_ = rtsData
		_ = asData
	}
}
