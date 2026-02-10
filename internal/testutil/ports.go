// Package testutil provides utilities for testing TWAMP implementations
package testutil

import (
	"net"
	"testing"
)

// GetFreePorts allocates available ports for testing by binding to port 0
// and immediately closing the socket to release it.
//
// The network parameter must be "tcp" or "udp".
// The numPorts parameter specifies how many ports to allocate.
//
// WARNING: There is an inherent race between port allocation
// and usage. The OS may reassign the port before your test
// binds to it. This is rare but can cause flaky tests.
//
// This race condition exists because:
// 1. We bind to port 0 to get an available port from the OS
// 2. We close the socket to release the port
// 3. Time passes before the test actually uses the port
// 4. During this window, the OS may assign the port to another process
//
// While this race is unavoidable with this approach, it is relatively
// rare in practice because:
// - Tests typically use the port immediately after allocation
// - The OS port allocation algorithm avoids recently used ports
// - Test environments usually have low port contention
//
// For critical production code, consider these alternatives:
// - Pass the actual listener to the test instead of just the port number
// - Use a port reservation service or coordination mechanism
// - Implement retry logic with exponential backoff
// - Use Unix domain sockets instead of TCP/UDP ports where possible
func GetFreePorts(testHelper testing.TB, network string, numPorts int) []int {
	testHelper.Helper()

	if numPorts <= 0 {
		testHelper.Fatalf("Number of ports must be positive, got %d", numPorts)
		return nil
	}

	if network != "tcp" && network != "udp" {
		testHelper.Fatalf("Network must be 'tcp' or 'udp', got %q", network)
		return nil
	}

	allocatedPorts := make([]int, numPorts)

	for i := 0; i < numPorts; i++ {
		var portNumber int
		if network == "udp" {
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				testHelper.Fatalf("Failed to listen on UDP: %v", err)
			}
			portNumber = udpConn.LocalAddr().(*net.UDPAddr).Port
			udpConn.Close()
		} else {
			tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				testHelper.Fatalf("Failed to listen on TCP: %v", err)
			}
			portNumber = tcpListener.Addr().(*net.TCPAddr).Port
			tcpListener.Close()
		}
		allocatedPorts[i] = portNumber
	}

	return allocatedPorts
}
