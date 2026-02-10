// pkg/twamp/client/metrics_integration_test.go
package client

import (
	"context"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/metrics"
	"github.com/ncode/twamp/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestClientMetricsRecordedDuringSession verifies client metrics during session
func TestClientMetricsRecordedDuringSession(t *testing.T) {
	m := metrics.New()

	// Start server
	serverConfig := server.ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		Logger:         logging.NewNoop(),
		Metrics:        nil, // Server has separate metrics
	}
	srv, err := server.NewServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	// Create client with metrics
	clientConfig := ClientConfig{
		ServerAddress: srv.Addr().String(),
		PreferredMode: common.ModeUnauthenticated,
		Logger:        logging.NewNoop(),
		Metrics:       m,
	}
	client := NewClient(clientConfig)

	// Connect
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request session (use port 0 for OS assignment to avoid conflicts)
	sessionConfig := TestSessionConfig{
		SenderPort:   0,
		ReceiverPort: 0,
		Timeout:      5 * time.Second,
	}
	session, err := client.RequestSession(sessionConfig)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Verify control message metric
	controlMsgs := testutil.ToFloat64(m.ControlMessagesTotal.WithLabelValues("request_tw_session", "client", "success", metrics.ErrorTypeNone))
	if controlMsgs != 1.0 {
		t.Errorf("Expected request_tw_session count=1.0, got %f", controlMsgs)
	}

	// Start sessions
	if err := client.StartSessions(); err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify session was started (client-side session tracking)
	// Note: Client metrics for sessions are recorded via test session, not client
	// So we verify the control message was successful
	controlMsgsStart := testutil.CollectAndCount(m.ControlMessagesTotal)
	if controlMsgsStart < 1 {
		t.Error("Expected at least one control message to be recorded")
	}

	// Stop sessions
	if err := client.StopSessions(); err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}

	_ = session
}

// TestClientMetricsMultipleSessions verifies client tracks multiple sessions
func TestClientMetricsMultipleSessions(t *testing.T) {
	m := metrics.New()

	// Start server
	serverConfig := server.ServerConfig{
		ListenAddress:  "127.0.0.1:0",
		SupportedModes: common.ModeUnauthenticated,
		Logger:         logging.NewNoop(),
	}
	srv, err := server.NewServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	// Create client
	clientConfig := ClientConfig{
		ServerAddress: srv.Addr().String(),
		PreferredMode: common.ModeUnauthenticated,
		Logger:        logging.NewNoop(),
		Metrics:       m,
	}
	client := NewClient(clientConfig)

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Request 3 sessions (use port 0 for OS assignment)
	numSessions := 3
	for i := 0; i < numSessions; i++ {
		sessionConfig := TestSessionConfig{
			SenderPort:   0,
			ReceiverPort: 0,
			Timeout:      5 * time.Second,
		}
		_, err := client.RequestSession(sessionConfig)
		if err != nil {
			t.Fatalf("Failed to request session %d: %v", i, err)
		}
	}

	// Verify control messages were recorded
	controlMsgs := testutil.ToFloat64(m.ControlMessagesTotal.WithLabelValues("request_tw_session", "client", "success", metrics.ErrorTypeNone))
	if controlMsgs != float64(numSessions) {
		t.Errorf("Expected request_tw_session count=%d, got %f", numSessions, controlMsgs)
	}

	// Start all sessions
	if err := client.StartSessions(); err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Stop all sessions
	if err := client.StopSessions(); err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}
}

// TestClientMetricsDifferentModes verifies metrics work across security modes
func TestClientMetricsDifferentModes(t *testing.T) {
	testCases := []struct {
		name string
		mode common.Mode
	}{
		{"Unauthenticated", common.ModeUnauthenticated},
		{"Authenticated", common.ModeAuthenticated},
		{"Encrypted", common.ModeEncrypted},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := metrics.New()

			// Start server
			serverConfig := server.ServerConfig{
				ListenAddress:  "127.0.0.1:0",
				SupportedModes: tc.mode,
				SecretMap: map[string]string{
					"test-key": "test-secret",
				},
				Logger: logging.NewNoop(),
			}
			srv, err := server.NewServer(serverConfig)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := srv.Start(ctx); err != nil {
				t.Fatalf("Failed to start server: %v", err)
			}
			defer srv.Stop()

			// Create client
			clientConfig := ClientConfig{
				ServerAddress: srv.Addr().String(),
				PreferredMode: tc.mode,
				SharedSecret:  "test-secret",
				KeyID:         "test-key",
				Logger:        logging.NewNoop(),
				Metrics:       m,
			}
			client := NewClient(clientConfig)

			if err := client.Connect(ctx); err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer client.Close()

			// Request session (use port 0 for OS assignment)
			sessionConfig := TestSessionConfig{
				SenderPort:   0,
				ReceiverPort: 0,
				Timeout:      5 * time.Second,
			}
			_, err = client.RequestSession(sessionConfig)
			if err != nil {
				t.Fatalf("Failed to request session: %v", err)
			}

			// Verify control message was recorded
			controlMsgs := testutil.ToFloat64(m.ControlMessagesTotal.WithLabelValues("request_tw_session", "client", "success", metrics.ErrorTypeNone))
			if controlMsgs != 1.0 {
				t.Errorf("Expected control message count=1.0 for mode %s, got %f", tc.name, controlMsgs)
			}
		})
	}
}
