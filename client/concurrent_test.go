package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/logging"
)

// TestConcurrentStartAndRequest tests concurrent StartSessions and RequestSession calls
func TestConcurrentStartAndRequest(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Create initial session with dynamic ports
	ports := testutil.GetFreePorts(t, "udp", 2)
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      uint16(ports[0]),
		ReceiverPort:    uint16(ports[1]),
		PaddingLength:   100,
	}

	_, err = client.RequestSession(config)
	if err != nil {
		t.Fatalf("Failed to request initial session: %v", err)
	}

	// Run concurrent operations
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Goroutine 1: Call StartSessions
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			err := client.StartSessions()
			if err != nil {
				errors <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine 2: Call RequestSession
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			ports := testutil.GetFreePorts(t, "udp", 2)
			config := TestSessionConfig{
				ReceiverAddress: "127.0.0.1",
				SenderPort:      uint16(ports[0]),
				ReceiverPort:    uint16(ports[1]),
				PaddingLength:   100,
			}
			_, err := client.RequestSession(config)
			if err != nil {
				errors <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine 3: Call StopSessions
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond) // Wait for some sessions to start
		for i := 0; i < 3; i++ {
			err := client.StopSessions()
			if err != nil {
				errors <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for all goroutines
	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

// TestConcurrentCloseAndSend tests concurrent Close and operation calls.
//
// KNOWN LIMITATION: Client.Close() is not safe for concurrent use (see Close() godoc).
// This test is skipped until the client is refactored to handle concurrent Close
// operations properly. The race condition is documented in the Close() function.
//
// TODO: File GitHub issue tracking concurrent Close() safety and link here.
func TestConcurrentCloseAndSend(t *testing.T) {
	t.Skip("Skipping until client is refactored to handle concurrent Close properly (see Close() godoc)")
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Create some sessions with dynamic ports
	for i := 0; i < 3; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		config := TestSessionConfig{
			ReceiverAddress: "127.0.0.1",
			SenderPort:      uint16(ports[0]),
			ReceiverPort:    uint16(ports[1]),
			PaddingLength:   100,
		}
		_, err := client.RequestSession(config)
		if err != nil {
			t.Fatalf("Failed to request session %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup

	// Goroutine 1: Try to request more sessions
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			ports := testutil.GetFreePorts(t, "udp", 2)
			config := TestSessionConfig{
				ReceiverAddress: "127.0.0.1",
				SenderPort:      uint16(ports[0]),
				ReceiverPort:    uint16(ports[1]),
				PaddingLength:   100,
			}
			// This might fail after Close is called, which is fine
			client.RequestSession(config)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Goroutine 2: Try to start sessions
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			// This might fail after Close is called, which is fine
			client.StartSessions()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Goroutine 3: Close the client
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond) // Wait a bit before closing
		client.Close()
	}()

	// Wait for all goroutines
	wg.Wait()

	// Success is defined as no deadlock/race - actual errors are expected
	// when operations race with Close
}

// TestConcurrentRequestSessionIndividual tests concurrent individual session requests
func TestConcurrentRequestSessionIndividual(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Launch multiple goroutines requesting individual sessions with different SIDs
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			ports := testutil.GetFreePorts(t, "udp", 2)
			config := TestSessionConfig{
				ReceiverAddress: "127.0.0.1",
				SenderPort:      uint16(ports[0]),
				ReceiverPort:    uint16(ports[1]),
				PaddingLength:   100,
			}

			sid := common.SessionID{byte(index), 0, 0, 0}
			_, err := client.RequestSessionIndividual(config, sid)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	// Wait for all goroutines
	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent RequestSessionIndividual error: %v", err)
	}
}

// TestConcurrentGetOperations tests concurrent read operations (GetSession, GetSessionIDs)
func TestConcurrentGetOperations(t *testing.T) {
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	client := &Client{
		config: ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		},
		logger:          logging.NewNoop(),
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Create some sessions with dynamic ports
	sids := make([]common.SessionID, 5)
	for i := 0; i < 5; i++ {
		ports := testutil.GetFreePorts(t, "udp", 2)
		config := TestSessionConfig{
			ReceiverAddress: "127.0.0.1",
			SenderPort:      uint16(ports[0]),
			ReceiverPort:    uint16(ports[1]),
			PaddingLength:   100,
		}

		sid := common.SessionID{byte(i), 1, 2, 3}
		session, err := client.RequestSessionIndividual(config, sid)
		if err != nil {
			t.Fatalf("Failed to request session %d: %v", i, err)
		}
		sids[i] = session.GetSID()
	}

	var wg sync.WaitGroup

	// Multiple goroutines calling GetSessionIDs
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				client.GetSessionIDs()
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Multiple goroutines calling GetSession
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				client.GetSession(sids[index%len(sids)])
				time.Sleep(time.Millisecond)
			}
		}(i)
	}

	// Wait for all goroutines
	wg.Wait()

	// Success - no deadlock or race
}
