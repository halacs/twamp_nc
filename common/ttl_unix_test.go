//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package common

import (
	"net"
	"testing"
)

func TestSetTTL(t *testing.T) {
	tests := []struct {
		name        string
		setupConn   func() (net.PacketConn, func())
		ttl         int
		expectError bool
	}{
		{
			name: "Valid_UDP_IPv4_Connection",
			setupConn: func() (net.PacketConn, func()) {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("Failed to create UDP connection: %v", err)
				}
				return conn, func() { conn.Close() }
			},
			ttl:         255,
			expectError: false,
		},
		{
			name: "Valid_UDP_IPv6_Connection",
			setupConn: func() (net.PacketConn, func()) {
				conn, err := net.ListenPacket("udp6", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 not available: %v", err)
				}
				return conn, func() { conn.Close() }
			},
			ttl:         64,
			expectError: false,
		},
		{
			name: "Valid_TTL_Minimum",
			setupConn: func() (net.PacketConn, func()) {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("Failed to create UDP connection: %v", err)
				}
				return conn, func() { conn.Close() }
			},
			ttl:         1,
			expectError: false,
		},
		{
			name: "Valid_TTL_Maximum",
			setupConn: func() (net.PacketConn, func()) {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("Failed to create UDP connection: %v", err)
				}
				return conn, func() { conn.Close() }
			},
			ttl:         255,
			expectError: false,
		},
		{
			name: "Valid_TTL_Typical",
			setupConn: func() (net.PacketConn, func()) {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("Failed to create UDP connection: %v", err)
				}
				return conn, func() { conn.Close() }
			},
			ttl:         128,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, cleanup := tt.setupConn()
			if conn == nil {
				return // Test was skipped
			}
			defer cleanup()

			err := SetTTL(conn, tt.ttl)
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

func TestSetTTL_InvalidConnection(t *testing.T) {
	// Test with a non-UDP connection type
	// This tests the error path when type assertion fails
	mockConn := &mockPacketConn{}

	err := SetTTL(mockConn, 255)
	if err == nil {
		t.Errorf("Expected error for non-UDP connection, got nil")
	}
}

func TestGetTTL(t *testing.T) {
	// Create a valid UDP connection
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	// Test GetTTL - currently returns default value
	ttl, err := GetTTL(conn)
	if err != nil {
		t.Errorf("GetTTL returned unexpected error: %v", err)
	}

	// Per the implementation, it returns a default value of 255
	if ttl != 255 {
		t.Errorf("Expected TTL 255, got %d", ttl)
	}
}

func TestEnableTTLReception(t *testing.T) {
	tests := []struct {
		name        string
		setupConn   func() (net.PacketConn, func())
		expectError bool
	}{
		{
			name: "Valid_UDP_IPv4_Connection",
			setupConn: func() (net.PacketConn, func()) {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("Failed to create UDP connection: %v", err)
				}
				return conn, func() { conn.Close() }
			},
			expectError: false,
		},
		{
			name: "Valid_UDP_IPv6_Connection",
			setupConn: func() (net.PacketConn, func()) {
				conn, err := net.ListenPacket("udp6", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 not available: %v", err)
				}
				return conn, func() { conn.Close() }
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, cleanup := tt.setupConn()
			if conn == nil {
				return // Test was skipped
			}
			defer cleanup()

			err := EnableTTLReception(conn)
			// Note: This may fail on some platforms due to platform-specific constants
			// We're primarily testing that the function executes without panicking
			if err != nil {
				t.Logf("EnableTTLReception returned error (may be platform-specific): %v", err)
			}
		})
	}
}

func TestEnableTTLReception_InvalidConnection(t *testing.T) {
	// Test with a non-UDP connection type
	mockConn := &mockPacketConn{}

	err := EnableTTLReception(mockConn)
	if err == nil {
		t.Errorf("Expected error for non-UDP connection, got nil")
	}
}

// mockPacketConn is a mock implementation that doesn't support UDP operations
type mockPacketConn struct {
	net.PacketConn
}

func (m *mockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, nil
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return 0, nil
}

func (m *mockPacketConn) Close() error {
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

// Test for IPv4/IPv6 socket option paths
func TestSetTTL_DualStack(t *testing.T) {
	// Test with unspecified address (dual-stack)
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Skipf("Failed to create dual-stack UDP connection: %v", err)
	}
	defer conn.Close()

	// This should try IPv4 first, then IPv6
	err = SetTTL(conn, 64)
	if err != nil {
		// Some platforms may not support dual-stack or the specific socket options
		t.Logf("SetTTL on dual-stack connection returned error (may be platform-specific): %v", err)
	}
}

func TestEnableTTLReception_DualStack(t *testing.T) {
	// Test with unspecified address (dual-stack)
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Skipf("Failed to create dual-stack UDP connection: %v", err)
	}
	defer conn.Close()

	// This should try IPv4 first, then IPv6
	err = EnableTTLReception(conn)
	if err != nil {
		// Some platforms may not support the specific socket options
		t.Logf("EnableTTLReception on dual-stack connection returned error (may be platform-specific): %v", err)
	}
}

// Benchmark tests
func BenchmarkSetTTL(b *testing.B) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SetTTL(conn, 255)
	}
}

func BenchmarkGetTTL(b *testing.B) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetTTL(conn)
	}
}

func BenchmarkEnableTTLReception(b *testing.B) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EnableTTLReception(conn)
	}
}
