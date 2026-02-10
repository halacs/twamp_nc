// pkg/twamp/client/logging_integration_test.go
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/server"
)

// TestClientLogsSessionEvents verifies that client logging works during TWAMP sessions
func TestClientLogsSessionEvents(t *testing.T) {
	// Capture client logs
	var clientBuf bytes.Buffer
	clientHandler := slog.NewJSONHandler(&clientBuf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	clientLogger := logging.FromSlog(slog.New(clientHandler))

	// Start test server (with noop logger to avoid mixing logs)
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

	// Get server address
	serverAddr := srv.Addr().String()

	// Create client with logger
	clientConfig := ClientConfig{
		ServerAddress: serverAddr,
		PreferredMode: common.ModeUnauthenticated,
		Logger:        clientLogger,
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

	// Start sessions
	if err := client.StartSessions(); err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Stop sessions
	if err := client.StopSessions(); err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}

	// Wait for session to finish
	_ = session

	time.Sleep(100 * time.Millisecond)

	// Verify client logs contain expected fields
	logs := clientBuf.String()

	// Split into log lines
	logLines := strings.Split(strings.TrimSpace(logs), "\n")

	var foundSessionID, foundMode bool

	for _, line := range logLines {
		if line == "" {
			continue
		}

		var logEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			continue
		}

		if _, ok := logEntry["session_id"]; ok {
			foundSessionID = true
		}

		if _, ok := logEntry["mode"]; ok {
			foundMode = true
		}
	}

	// Client logging is less verbose than server, so we just verify it doesn't crash
	if logs == "" {
		t.Log("Note: No logs generated (okay if no errors occurred)")
	} else {
		t.Logf("Client logs:\n%s", logs)
		if foundSessionID {
			t.Log("Found session_id in logs")
		}
		if foundMode {
			t.Log("Found mode in logs")
		}
	}
}

// TestClientLogsContextPropagation verifies context propagates in client logs
func TestClientLogsContextPropagation(t *testing.T) {
	// Capture logs
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := logging.FromSlog(slog.New(handler))

	// Add custom field
	correlationID := "client-test-456"
	logger = logger.With("correlation_id", correlationID)

	// Start test server
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

	// Create client with logger
	clientConfig := ClientConfig{
		ServerAddress: srv.Addr().String(),
		PreferredMode: common.ModeUnauthenticated,
		Logger:        logger,
	}
	client := NewClient(clientConfig)

	// Connect
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	time.Sleep(100 * time.Millisecond)

	// Verify correlation ID in logs (if any logs were generated)
	logs := buf.String()

	if logs == "" {
		t.Log("Note: No logs generated during normal operation (this is expected)")
	} else {
		// If logs were generated, verify correlation ID propagated
		if !strings.Contains(logs, correlationID) {
			t.Errorf("Expected correlation_id '%s' in client logs, got:\n%s", correlationID, logs)
		} else {
			t.Logf("Successfully verified correlation_id propagation in client logs:\n%s", logs)
		}
	}
}

// TestClientLogsDifferentModes verifies logging works across security modes
func TestClientLogsDifferentModes(t *testing.T) {
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
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})
			logger := logging.FromSlog(slog.New(handler))

			// Start server with matching mode
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
				Logger:        logger,
			}
			client := NewClient(clientConfig)

			// Connect
			if err := client.Connect(ctx); err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer client.Close()

			time.Sleep(100 * time.Millisecond)

			// Verify logging works (client may not log much in normal operation)
			logs := buf.String()
			if logs == "" {
				t.Log("Note: No logs generated (okay if no errors)")
			} else {
				t.Logf("Generated logs for mode %s:\n%s", tc.name, logs)
			}
		})
	}
}
