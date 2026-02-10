package testutil

import (
	"sync"
	"testing"
)

func TestGetFreePorts(t *testing.T) {
	tests := []struct {
		name           string
		network        string
		requestedPorts int
	}{
		{"UDP single", "udp", 1},
		{"UDP multiple", "udp", 5},
		{"TCP single", "tcp", 1},
		{"TCP multiple", "tcp", 5},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			allocatedPorts := GetFreePorts(t, testCase.network, testCase.requestedPorts)

			if len(allocatedPorts) != testCase.requestedPorts {
				t.Errorf("Expected %d ports, got %d", testCase.requestedPorts, len(allocatedPorts))
			}

			// Check all ports are different
			seenPorts := make(map[int]bool)
			for _, portNumber := range allocatedPorts {
				if portNumber <= 0 || portNumber > 65535 {
					t.Errorf("Invalid port number: %d", portNumber)
				}
				if seenPorts[portNumber] {
					t.Errorf("Duplicate port: %d", portNumber)
				}
				seenPorts[portNumber] = true
			}
		})
	}
}

func TestGetSinglePort(t *testing.T) {
	// Test UDP single port
	udpPorts := GetFreePorts(t, "udp", 1)
	if len(udpPorts) != 1 {
		t.Fatalf("Expected 1 UDP port, got %d", len(udpPorts))
	}
	if udpPorts[0] <= 0 || udpPorts[0] > 65535 {
		t.Errorf("Invalid UDP port: %d", udpPorts[0])
	}

	// Test TCP single port
	tcpPorts := GetFreePorts(t, "tcp", 1)
	if len(tcpPorts) != 1 {
		t.Fatalf("Expected 1 TCP port, got %d", len(tcpPorts))
	}
	if tcpPorts[0] <= 0 || tcpPorts[0] > 65535 {
		t.Errorf("Invalid TCP port: %d", tcpPorts[0])
	}
}

func TestInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		numPorts int
	}{
		{"zero ports", "udp", 0},
		{"negative ports", "udp", -1},
		{"invalid network", "invalid", 1},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			// Create a fake testing.TB to capture the failure
			fakeTestHelper := &fakeT{}
			_ = GetFreePorts(fakeTestHelper, testCase.network, testCase.numPorts)

			if !fakeTestHelper.failed {
				t.Errorf("Expected GetFreePorts to fail with network=%q numPorts=%d", testCase.network, testCase.numPorts)
			}
		})
	}
}

func TestErrorHandling(t *testing.T) {
	// Test that the functions handle normal allocation correctly
	// The error paths (socket allocation failures) are defensive and
	// difficult to trigger in normal test environments since they require
	// OS-level failures (e.g., out of file descriptors, network stack issues)

	// Test UDP allocation works normally
	udpPorts := GetFreePorts(t, "udp", 3)
	if len(udpPorts) != 3 {
		t.Errorf("Expected 3 UDP ports, got %d", len(udpPorts))
	}

	// Test TCP allocation works normally
	tcpPorts := GetFreePorts(t, "tcp", 3)
	if len(tcpPorts) != 3 {
		t.Errorf("Expected 3 TCP ports, got %d", len(tcpPorts))
	}

	// The error conditions are defensive:
	// - net.ListenUDP fails: requires UDP stack failure
	// - net.Listen fails: requires TCP stack failure
	// These are extremely rare in test environments and testing them
	// would require complex system manipulation (e.g., exhausting file descriptors)

	t.Log("Error handling paths are defensive against OS-level failures")
}

func TestConcurrentPortAllocation(t *testing.T) {
	const numGoroutines = 10
	const portsPerGoroutine = 2

	var wg sync.WaitGroup
	portsChan := make(chan []int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ports := GetFreePorts(t, "udp", portsPerGoroutine)
			portsChan <- ports
		}()
	}

	wg.Wait()
	close(portsChan)

	// Collect all ports and check for duplicates
	allPorts := make(map[int]bool)
	totalPorts := 0
	for ports := range portsChan {
		for _, port := range ports {
			if allPorts[port] {
				t.Errorf("Concurrent allocation produced duplicate port: %d", port)
			}
			allPorts[port] = true
			totalPorts++
		}
	}

	expected := numGoroutines * portsPerGoroutine
	if totalPorts != expected {
		t.Errorf("Expected %d total ports, got %d", expected, totalPorts)
	}
}

// fakeT implements a minimal testing.TB interface for testing
type fakeT struct {
	testing.TB
	failed bool
}

func (ft *fakeT) Helper() {}

func (ft *fakeT) Fatalf(format string, args ...interface{}) {
	ft.failed = true
}

func (ft *fakeT) Logf(format string, args ...interface{}) {}
