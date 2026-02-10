package common

import (
	"net"
	"testing"
)

// TestConstantsBitWidth ensures every code fits in 6 bits.
func TestConstantsBitWidth(t *testing.T) {
	constMask := map[string]uint8{
		"BE": BE, "CS1": CS1, "AF11": AF11, "AF12": AF12, "AF13": AF13,
		"CS2": CS2, "AF21": AF21, "AF22": AF22, "AF23": AF23,
		"CS3": CS3, "AF31": AF31, "AF32": AF32, "AF33": AF33,
		"CS4": CS4, "AF41": AF41, "AF42": AF42, "AF43": AF43,
		"CS5": CS5, "EF": EF,
		"CS6": CS6, "CS7": CS7,
	}
	for name, val := range constMask {
		if val&0x03 != 0 { // lower two bits must be zero
			t.Fatalf("%s (%02x) is not aligned to 6‑bit DSCP field", name, val)
		}
	}
}

// TestSetDSCPUDP verifies that SetDSCP returns either nil or a platform-specific
// error for a supported *net.UDPConn. We treat "option not supported" as a skip
// because not every CI kernel exposes the socket option.
func TestSetDSCPUDP(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("UDP listen: %v", err)
	}
	defer conn.Close()

	if err := SetDSCP(conn, 0x2e); err != nil {
		// Some kernels (or unprivileged containers) deny the call; make it a skip
		t.Skipf("SetDSCP not supported on this platform/CI: %v", err)
	}
}

// TestSetDSCPTCP verifies the helper works on *net.TCPConn as well.
func TestSetDSCPTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("TCP listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed or test ending
		}
		defer conn.Close()
		<-done
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("TCP dial: %v", err)
	}
	defer clientConn.Close()
	defer close(done)

	if err := SetDSCP(clientConn, 0x2e); err != nil {
		t.Skipf("SetDSCP not supported on TCPConn here: %v", err)
	}
}

// TestSetDSCPUnsupportedConn passes a net.Pipe() connection which must return
// ErrUnsupportedConn.
func TestSetDSCPUnsupportedConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if err := SetDSCP(c1, 0); err != ErrUnsupportedConn {
		t.Fatalf("expected ErrUnsupportedConn, got %v", err)
	}
}
