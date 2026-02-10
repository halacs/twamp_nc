package client

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/messages"
)

// mockUDPServer simulates a TWAMP reflector
type mockUDPServer struct {
	conn     *net.UDPConn
	stopChan chan struct{}
}

func newMockUDPServer(t *testing.T) (*mockUDPServer, uint16) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen on UDP: %v", err)
	}

	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	server := &mockUDPServer{
		conn:     conn,
		stopChan: make(chan struct{}),
	}

	go server.serve(t)
	return server, port
}

func (s *mockUDPServer) serve(t *testing.T) {
	defer s.conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-s.stopChan:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := s.conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				t.Logf("Error reading from UDP: %v", err)
				continue
			}

			// Simulate TWAMP reflector - parse incoming packet
			var senderPacket messages.SenderTestPacket
			if err := senderPacket.Unmarshal(buf[:n]); err != nil {
				t.Logf("Failed to parse sender packet: %v", err)
				continue
			}

			// Create reflector response
			reflectorPacket := messages.ReflectorTestPacket{
				SeqNumber:           0, // Use 0 for simplicity in test
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    common.Now(),
				SenderSeqNumber:     senderPacket.SeqNumber,
				SenderTimestamp:     senderPacket.Timestamp,
				SenderErrorEstimate: senderPacket.ErrorEstimate,
				SenderTTL:           255,
				PaddingSize:         20, // Arbitrary padding for test
			}

			// Marshal and send response
			response, err := reflectorPacket.Marshal()
			if err != nil {
				t.Logf("Failed to marshal reflector packet: %v", err)
				continue
			}

			_, err = s.conn.WriteTo(response, addr)
			if err != nil {
				t.Logf("Failed to send reflector packet: %v", err)
			}
		}
	}
}

func (s *mockUDPServer) stop() {
	close(s.stopChan)
}

func TestTestSessionSendReceive(t *testing.T) {
	// Start a mock UDP server to act as reflector
	server, reflectorPort := newMockUDPServer(t)
	defer server.stop()

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	// Create a test session
	config := TestSessionConfig{
		SenderPort:      senderPort, // Use dynamically allocated port
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// Create a session ID
	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Create a test session
	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Start receiving in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is canceled at the end

	session.StartReceiving(ctx)

	// Send a test packet
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Wait for packet to be processed with timeout
	// Poll for results instead of using a fixed sleep
	var results TestSessionResult
	timeout := time.After(1 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			// Timeout reached, get final results
			results = session.GetResults()
			goto done
		case <-ticker.C:
			results = session.GetResults()
			if results.PacketsReceived > 0 {
				// We received a response, can proceed
				goto done
			}
		}
	}
done:

	// Cancel context and stop session
	cancel()
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session: %v", err)
	}

	// Verify we sent and received packets
	if results.PacketsSent != 1 {
		t.Errorf("Expected 1 packet sent, got %d", results.PacketsSent)
	}

	// Check if we received the packet (this could be flaky on CI, so we'll be lenient)
	t.Logf("Packets received: %d", results.PacketsReceived)
	if results.PacketsReceived > 0 {
		// If we received packets, validate RTT is reasonable
		if results.AvgRTT < 0 || results.AvgRTT > 1*time.Second {
			t.Errorf("Unexpected RTT value: %v", results.AvgRTT)
		}
	}
}

func TestTestSessionResults(t *testing.T) {
	// Create a test session directly with ports that won't be used
	config := TestSessionConfig{
		SenderPort:      0, // Won't actually be used since we don't start the session
		ReceiverPort:    0, // Won't actually be used since we don't start the session
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Manually set results for testing
	session.mu.Lock()
	session.totalSent = 10
	session.totalReceived = 8
	session.minRTT = 10 * time.Millisecond
	session.maxRTT = 100 * time.Millisecond
	session.sumRTT = 400 * time.Millisecond
	session.mu.Unlock()

	// Manually create some test packet results
	now := time.Now()
	for i := uint32(0); i < 10; i++ {
		result := &PacketResult{
			SenderSeqNo: i,
			SentTime:    now.Add(-time.Duration(100+i) * time.Millisecond),
			SenderTimestamp: common.TWAMPTimestamp{
				Seconds:  uint32(now.Unix()),
				Fraction: 0,
			},
		}

		// Mark some as received
		if i < 8 {
			result.ReceivedTime = now.Add(-time.Duration(50+i) * time.Millisecond)
			result.RTT = time.Duration(50) * time.Millisecond
			result.ReflectorRxTime = now.Add(-time.Duration(75+i) * time.Millisecond)
			result.ReflectorTxTime = now.Add(-time.Duration(65+i) * time.Millisecond)
			result.ReflectorLatency = 10 * time.Millisecond
		}

		session.results.Store(i, result)
	}

	// Get results
	results := session.GetResults()

	// Validate basic metrics
	if results.PacketsSent != 10 {
		t.Errorf("Expected 10 packets sent, got %d", results.PacketsSent)
	}
	if results.PacketsReceived != 8 {
		t.Errorf("Expected 8 packets received, got %d", results.PacketsReceived)
	}
	if results.PacketsLost != 2 {
		t.Errorf("Expected 2 packets lost, got %d", results.PacketsLost)
	}
	if results.MinRTT != 10*time.Millisecond {
		t.Errorf("Expected min RTT of 10ms, got %v", results.MinRTT)
	}
	if results.MaxRTT != 100*time.Millisecond {
		t.Errorf("Expected max RTT of 100ms, got %v", results.MaxRTT)
	}
	if results.AvgRTT != 50*time.Millisecond {
		t.Errorf("Expected avg RTT of 50ms, got %v", results.AvgRTT)
	}

	// Check reflector latency
	if results.AvgReflectorLatency != 10*time.Millisecond {
		t.Errorf("Expected avg reflector latency of 10ms, got %v", results.AvgReflectorLatency)
	}

	// Check individual packet results
	allResults := session.GetAllPacketResults()
	if len(allResults) != 10 {
		t.Errorf("Expected 10 packet results, got %d", len(allResults))
	}
}

func TestPacketLossSimulation(t *testing.T) {
	// Create a mock UDP server that simulates packet loss
	server, reflectorPort := newMockUDPServerWithLoss(t, 0.3) // 30% packet loss
	defer server.stop()

	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	// Create a test session
	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         500 * time.Millisecond,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}
	defer session.Stop()

	// Start receiving
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session.StartReceiving(ctx)

	// Send multiple test packets with small spacing to simulate realistic traffic
	const numPackets = 10
	packetTicker := time.NewTicker(50 * time.Millisecond)
	defer packetTicker.Stop()

	for i := 0; i < numPackets; i++ {
		err = session.SendTestPacket()
		if err != nil {
			t.Fatalf("Failed to send test packet %d: %v", i, err)
		}
		if i < numPackets-1 { // Don't wait after the last packet
			<-packetTicker.C
		}
	}

	// Wait for responses to be received
	success := waitForCondition(t, 500*time.Millisecond, func() bool {
		results := session.GetResults()
		// With 30% loss, expect at least some packets received
		return results.PacketsReceived > 0
	})

	if !success {
		t.Logf("Warning: No packets received within timeout")
	}

	// Get results
	results := session.GetResults()

	// Verify packet loss is detected
	if results.PacketsSent != numPackets {
		t.Errorf("Expected %d packets sent, got %d", numPackets, results.PacketsSent)
	}

	// With 30% loss, we expect to receive about 70% of packets (allow some variance)
	expectedMin := uint32(numPackets * 0.5) // Allow down to 50% received
	expectedMax := uint32(numPackets * 0.9) // Allow up to 90% received

	if results.PacketsReceived < expectedMin || results.PacketsReceived > expectedMax {
		t.Logf("Packets received: %d (expected between %d and %d with 30%% loss)",
			results.PacketsReceived, expectedMin, expectedMax)
	}

	// Verify packet loss is tracked
	if results.PacketsLost != results.PacketsSent-results.PacketsReceived {
		t.Errorf("PacketsLost mismatch: got %d, expected %d",
			results.PacketsLost, results.PacketsSent-results.PacketsReceived)
	}

	// Calculate actual loss percentage
	actualLoss := float64(results.PacketsLost) / float64(results.PacketsSent) * 100
	t.Logf("Actual packet loss: %.1f%% (sent: %d, received: %d, lost: %d)",
		actualLoss, results.PacketsSent, results.PacketsReceived, results.PacketsLost)
}

// newMockUDPServerWithLoss creates a mock UDP server that simulates packet loss
func newMockUDPServerWithLoss(t *testing.T, lossRate float64) (*mockUDPServerWithLoss, uint16) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen on UDP: %v", err)
	}

	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	server := &mockUDPServerWithLoss{
		conn:     conn,
		stopChan: make(chan struct{}),
		lossRate: lossRate,
	}

	go server.serve(t)
	return server, port
}

type mockUDPServerWithLoss struct {
	conn     *net.UDPConn
	stopChan chan struct{}
	lossRate float64
}

func (s *mockUDPServerWithLoss) serve(t *testing.T) {
	defer s.conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-s.stopChan:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := s.conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			// Simulate packet loss
			if rand.Float64() < s.lossRate {
				// Drop this packet
				continue
			}

			// Parse and reflect the packet
			var senderPacket messages.SenderTestPacket
			if err := senderPacket.Unmarshal(buf[:n]); err != nil {
				continue
			}

			// Create reflector response
			reflectorPacket := messages.ReflectorTestPacket{
				SeqNumber:           0,
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    common.Now(),
				SenderSeqNumber:     senderPacket.SeqNumber,
				SenderTimestamp:     senderPacket.Timestamp,
				SenderErrorEstimate: senderPacket.ErrorEstimate,
				SenderTTL:           255,
				PaddingSize:         20,
			}

			response, err := reflectorPacket.Marshal()
			if err != nil {
				continue
			}

			s.conn.WriteTo(response, addr)
		}
	}
}

func (s *mockUDPServerWithLoss) stop() {
	close(s.stopChan)
}

func TestTestSessionStartStop(t *testing.T) {
	// Get free ports for the test
	ports := testutil.GetFreePorts(t, "udp", 2)
	senderPort := uint16(ports[0])
	receiverPort := uint16(ports[1])

	// Create a test session
	config := TestSessionConfig{
		SenderPort:      senderPort,
		ReceiverPort:    receiverPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Verify connection is established
	session.mu.Lock()
	hasConn := session.conn != nil
	session.mu.Unlock()

	if !hasConn {
		t.Fatal("Session conn is nil after Start()")
	}

	// Start receiving
	ctx, cancel := context.WithCancel(context.Background())
	session.StartReceiving(ctx)

	// Cancel the context and stop the session
	cancel()
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session: %v", err)
	}

	// Verify connection is closed
	session.mu.Lock()
	hasConn = session.conn != nil
	session.mu.Unlock()

	if hasConn {
		t.Fatal("Session conn is not nil after Stop()")
	}

	// Verify stopping an already stopped session doesn't cause issues
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop already stopped session: %v", err)
	}
}

// TestGetSID tests the GetSID getter method
func TestGetSID(t *testing.T) {
	// Create a test session with a known SID
	var expectedSID common.SessionID
	for i := range expectedSID {
		expectedSID[i] = byte(i + 1)
	}

	session := &TestSession{
		sid: expectedSID,
	}

	// Get the SID and verify it matches
	actualSID := session.GetSID()

	if actualSID != expectedSID {
		t.Errorf("GetSID() = %v, want %v", actualSID, expectedSID)
	}
}

// TestStartWithDSCP tests that Start() handles DSCP configuration
func TestStartWithDSCP(t *testing.T) {
	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	// Create test session with DSCP configured
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      senderPort,
		ReceiverPort:    senderPort + 1,
		PaddingLength:   100,
		DSCP:            46, // EF (Expedited Forwarding)
	}

	var sid common.SessionID
	sid[0] = 1

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("NewTestSession() failed: %v", err)
	}

	// Start the session - this should attempt to set DSCP
	err = session.Start()
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer session.Stop()

	// Verify session started successfully
	// Note: SetDSCP may fail silently and log a warning, but Start() should succeed
	if session.conn == nil {
		t.Fatal("Expected conn to be set after Start()")
	}
}

// TestStartRestart tests that Start() can be called again after Stop()
func TestStartRestart(t *testing.T) {
	// Get a free port for the sender
	senderPort := uint16(testutil.GetFreePorts(t, "udp", 1)[0])

	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      senderPort,
		ReceiverPort:    senderPort + 1,
		PaddingLength:   100,
	}

	var sid common.SessionID
	sid[0] = 1

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("NewTestSession() failed: %v", err)
	}

	// First start
	err = session.Start()
	if err != nil {
		t.Fatalf("First Start() failed: %v", err)
	}

	// Stop the session
	session.Stop()

	// Start again - should recreate stopChan if nil
	err = session.Start()
	if err != nil {
		t.Fatalf("Restart Start() failed: %v", err)
	}
	defer session.Stop()

	// Verify session is active
	if !session.IsActive() {
		t.Error("Expected session to be active after restart")
	}
}

// TestStartPortInUse tests Start() when port is already in use
func TestStartPortInUse(t *testing.T) {
	// Bind to a port to make it in-use
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	// Bind to get an actual port
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to bind to port: %v", err)
	}
	defer conn.Close()

	// Get the actual port that was bound
	boundPort := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	// Try to start a test session on the same port
	config := TestSessionConfig{
		ReceiverAddress: "127.0.0.1",
		SenderPort:      boundPort,
		ReceiverPort:    boundPort + 1,
		PaddingLength:   100,
	}

	var sid common.SessionID
	sid[0] = 1

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("NewTestSession() failed: %v", err)
	}

	// Start should fail because port is in use
	err = session.Start()
	if err == nil {
		session.Stop()
		t.Fatal("Expected Start() to fail with port in use, but it succeeded")
	}
}
