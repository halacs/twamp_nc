// pkg/twamp/logging/logger_test.go
package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/ncode/twamp/common"
)

func TestLogger(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := FromSlog(slog.New(handler))

	// Test basic logging
	logger.Info("test message", "key", "value")

	// Verify JSON output
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	// Check fields
	if logEntry["msg"] != "test message" {
		t.Errorf("Expected msg='test message', got '%v'", logEntry["msg"])
	}

	if logEntry["key"] != "value" {
		t.Errorf("Expected key='value', got '%v'", logEntry["key"])
	}

	if logEntry["level"] != "INFO" {
		t.Errorf("Expected level='INFO', got '%v'", logEntry["level"])
	}
}

func TestLoggerWith(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := FromSlog(slog.New(handler))

	// Create child logger with additional context
	childLogger := logger.With("session_id", "test-123", "mode", "authenticated")
	childLogger.Info("session started")

	// Verify context is included
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	if logEntry["session_id"] != "test-123" {
		t.Errorf("Expected session_id='test-123', got '%v'", logEntry["session_id"])
	}

	if logEntry["mode"] != "authenticated" {
		t.Errorf("Expected mode='authenticated', got '%v'", logEntry["mode"])
	}
}

func TestLoggerWithContext(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := FromSlog(slog.New(handler))

	// Create context with correlation ID
	ctx := context.WithValue(context.Background(), CorrelationIDKey, "corr-456")
	contextLogger := logger.WithContext(ctx)
	contextLogger.Info("request processed")

	// Verify correlation ID is included
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	if logEntry["correlation_id"] != "corr-456" {
		t.Errorf("Expected correlation_id='corr-456', got '%v'", logEntry["correlation_id"])
	}
}

func TestWithSession(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := FromSlog(slog.New(handler))

	// Create session logger
	sessionID := common.SessionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	sessionLogger := WithSession(logger, sessionID, common.ModeAuthenticated, "192.168.1.100:862")
	sessionLogger.Info("session created")

	// Verify fields
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	expectedSID := "0102030405060708090a0b0c0d0e0f10"
	if logEntry[FieldSessionID] != expectedSID {
		t.Errorf("Expected session_id='%s', got '%v'", expectedSID, logEntry[FieldSessionID])
	}

	if logEntry[FieldMode] != "authenticated" {
		t.Errorf("Expected mode='authenticated', got '%v'", logEntry[FieldMode])
	}

	if logEntry[FieldPeerAddr] != "192.168.1.100:862" {
		t.Errorf("Expected peer_address='192.168.1.100:862', got '%v'", logEntry[FieldPeerAddr])
	}
}

func TestWithConnection(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := FromSlog(slog.New(handler))

	// Create connection logger
	connLogger := WithConnection(logger, "conn-789", "10.0.0.5:862")
	connLogger.Info("connection established")

	// Verify fields
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	if logEntry[FieldConnID] != "conn-789" {
		t.Errorf("Expected connection_id='conn-789', got '%v'", logEntry[FieldConnID])
	}

	if logEntry[FieldPeerAddr] != "10.0.0.5:862" {
		t.Errorf("Expected peer_address='10.0.0.5:862', got '%v'", logEntry[FieldPeerAddr])
	}
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		name     string
		logFunc  func(Logger, string)
		expected string
	}{
		{"debug", func(l Logger, m string) { l.Debug(m) }, "DEBUG"},
		{"info", func(l Logger, m string) { l.Info(m) }, "INFO"},
		{"warn", func(l Logger, m string) { l.Warn(m) }, "WARN"},
		{"error", func(l Logger, m string) { l.Error(m) }, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})
			logger := FromSlog(slog.New(handler))

			tt.logFunc(logger, "test message")

			var logEntry map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
				t.Fatalf("Failed to parse log output as JSON: %v", err)
			}

			if logEntry["level"] != tt.expected {
				t.Errorf("Expected level='%s', got '%v'", tt.expected, logEntry["level"])
			}
		})
	}
}

func TestNoopLogger(t *testing.T) {
	// Noop logger should not panic
	logger := NewNoop()

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	child := logger.With("key", "value")
	child.Info("child message")

	ctx := context.WithValue(context.Background(), CorrelationIDKey, "test")
	ctxLogger := logger.WithContext(ctx)
	ctxLogger.Info("context message")

	// If we got here without panicking, test passes
}

func TestDefaultLogger(t *testing.T) {
	// Get default logger (should be thread-safe lazy init)
	logger := Default()
	if logger == nil {
		t.Fatal("Default() returned nil")
	}

	// Verify it's usable
	logger.Info("test default logger", "foo", "bar")

	// Verify Default() returns same instance on subsequent calls
	logger2 := Default()
	if logger != logger2 {
		t.Error("Default() should return same instance on subsequent calls")
	}

	// Test convenience functions work with default logger
	// (These use Default() internally and write to stderr)
	Info("test info")
	Warn("test warn")
	Error("test error")
	Debug("test debug")
}

func TestTextLogger(t *testing.T) {
	// Just verify it doesn't panic
	logger := NewTextLogger(slog.LevelInfo)
	logger.Info("test text logger", "key", "value")
	logger.Debug("debug message") // Should be filtered
	logger.Warn("warning message")
	logger.Error("error message")
}

func TestWithCorrelationID(t *testing.T) {
	// Create context with correlation ID using the helper
	ctx := context.Background()
	correlationID := "test-correlation-123"

	ctx = WithCorrelationID(ctx, correlationID)

	// Verify the value can be retrieved
	retrieved := ctx.Value(CorrelationIDKey)
	if retrieved == nil {
		t.Fatal("Expected correlation ID in context, got nil")
	}

	retrievedStr, ok := retrieved.(string)
	if !ok {
		t.Fatalf("Expected string correlation ID, got %T", retrieved)
	}

	if retrievedStr != correlationID {
		t.Errorf("Expected correlation ID %q, got %q", correlationID, retrievedStr)
	}

	// Verify it works with WithContext
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := FromSlog(slog.New(handler))

	ctxLogger := logger.WithContext(ctx)
	ctxLogger.Info("test message")

	logs := buf.String()
	if !strings.Contains(logs, correlationID) {
		t.Errorf("Expected correlation ID %q in logs, got: %s", correlationID, logs)
	}
}
