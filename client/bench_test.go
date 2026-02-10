package client

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/logging"
)

// BenchmarkSendWithHMAC benchmarks the sendWithHMAC hot path in authenticated mode
func BenchmarkSendWithHMAC(b *testing.B) {
	// Setup
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
		keyDerivation: &crypto.TWAMPKeys{
			HMACKey: bytes.Repeat([]byte{0xAA}, 32),
		},
	}

	// Server side consumer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for i := 0; i < b.N; i++ {
			_, err := serverConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	data := []byte("test message for benchmarking sendWithHMAC performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := client.sendWithHMAC(data, true)
		if err != nil {
			b.Fatalf("sendWithHMAC failed: %v", err)
		}
	}
	b.StopTimer()

	<-done
}

// BenchmarkSendWithHMACUnauthenticated benchmarks sendWithHMAC in unauthenticated mode
func BenchmarkSendWithHMACUnauthenticated(b *testing.B) {
	// Setup
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
		mode:   common.ModeUnauthenticated,
	}

	// Server side consumer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for i := 0; i < b.N; i++ {
			_, err := serverConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	data := []byte("test message for benchmarking sendWithHMAC performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := client.sendWithHMAC(data, false)
		if err != nil {
			b.Fatalf("sendWithHMAC failed: %v", err)
		}
	}
	b.StopTimer()

	<-done
}

// BenchmarkCalculateHMAC benchmarks HMAC calculation separately
func BenchmarkCalculateHMAC(b *testing.B) {
	client := &Client{
		keyDerivation: &crypto.TWAMPKeys{
			HMACKey: bytes.Repeat([]byte{0xAA}, 32),
		},
	}

	data := []byte("test message for benchmarking HMAC calculation performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.calculateHMAC(data)
		if err != nil {
			b.Fatalf("calculateHMAC failed: %v", err)
		}
	}
}

// BenchmarkReceiveAndVerify benchmarks the receiveAndVerify hot path
func BenchmarkReceiveAndVerify(b *testing.B) {
	// Setup
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		logger: logging.NewNoop(),
	}

	// Server side sender
	done := make(chan struct{})
	testData := bytes.Repeat([]byte{0x42}, 64) // 64 bytes of test data
	go func() {
		defer close(done)
		for i := 0; i < b.N; i++ {
			_, err := serverConn.Write(testData)
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.receiveAndVerify(64, false)
		if err != nil {
			b.Fatalf("receiveAndVerify failed: %v", err)
		}
	}
	b.StopTimer()

	<-done
}

// BenchmarkStopNSessions benchmarks StopNSessions with varying session counts
func BenchmarkStopNSessions(b *testing.B) {
	sessionCounts := []int{1, 5, 10, 50}

	for _, count := range sessionCounts {
		b.Run(fmt.Sprintf("%d_sessions", count), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()

				// Setup client with sessions
				serverConn, clientConn := net.Pipe()
				client := &Client{
					conn:            clientConn,
					mode:            common.ModeUnauthenticated,
					controlMode:     common.ModeUnauthenticated,
					testMode:        common.ModeUnauthenticated,
					currentSessions: make(map[common.SessionID]*TestSession),
					logger:          logging.NewNoop(),
				}

				// Create sessions
				sessionChans := make([]chan struct{}, count)
				for j := 0; j < count; j++ {
					sid := common.SessionID{byte(j), byte(j >> 8), byte(j >> 16), byte(j >> 24)}
					sessionChans[j] = make(chan struct{})
					client.currentSessions[sid] = &TestSession{
						sid:      sid,
						stopChan: sessionChans[j],
						logger:   logging.NewNoop(),
					}
				}

				// Server side
				done := make(chan struct{})
				go func() {
					defer close(done)
					buf := make([]byte, 16384)
					serverConn.Read(buf)
				}()

				b.StartTimer()
				client.StopNSessions(uint32(count))
				b.StopTimer()

				<-done
				serverConn.Close()
				clientConn.Close()

				// Cleanup channels
				for _, ch := range sessionChans {
					select {
					case <-ch:
					default:
						close(ch)
					}
				}
			}
		})
	}
}
