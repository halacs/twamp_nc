// pkg/twamp/logging/logger.go
package logging

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"sync"

	"github.com/ncode/twamp/common"
)

// Logger defines the interface for structured logging in TWAMP
// This allows for easy testing and alternative implementations
type Logger interface {
	// Debug logs at debug level with structured fields
	Debug(msg string, args ...any)
	// Info logs at info level with structured fields
	Info(msg string, args ...any)
	// Warn logs at warn level with structured fields
	Warn(msg string, args ...any)
	// Error logs at error level with structured fields
	Error(msg string, args ...any)

	// With returns a new logger with additional context fields
	With(args ...any) Logger
	// WithContext returns a new logger with context
	WithContext(ctx context.Context) Logger
}

// slogLogger wraps log/slog.Logger to implement our Logger interface
type slogLogger struct {
	logger *slog.Logger
}

// New creates a new structured logger with the specified level
func New(level slog.Level) Logger {
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	return &slogLogger{
		logger: slog.New(handler),
	}
}

// NewTextLogger creates a new text-formatted logger (for development)
func NewTextLogger(level slog.Level) Logger {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	return &slogLogger{
		logger: slog.New(handler),
	}
}

// FromSlog wraps an existing slog.Logger
func FromSlog(logger *slog.Logger) Logger {
	return &slogLogger{logger: logger}
}

// Debug logs at debug level
func (l *slogLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

// Info logs at info level
func (l *slogLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

// Warn logs at warn level
func (l *slogLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

// Error logs at error level
func (l *slogLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

// With returns a new logger with additional context fields
func (l *slogLogger) With(args ...any) Logger {
	return &slogLogger{
		logger: l.logger.With(args...),
	}
}

// WithContext returns a new logger with context
func (l *slogLogger) WithContext(ctx context.Context) Logger {
	// Extract correlation ID from context if present
	if corrID := ctx.Value(CorrelationIDKey); corrID != nil {
		return l.With("correlation_id", corrID)
	}
	return l
}

// Context keys for logging
type contextKey string

const (
	// CorrelationIDKey is used to store correlation IDs in context
	CorrelationIDKey contextKey = "correlation_id"
)

// WithCorrelationID adds a correlation ID to the context.
// This allows external packages to properly set correlation IDs
// without direct access to the unexported contextKey type.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, CorrelationIDKey, id)
}

// Common field names for consistency across the codebase
const (
	FieldSessionID   = "session_id"
	FieldMode        = "mode"
	FieldPeerAddr    = "peer_address"
	FieldCommand     = "command"
	FieldError       = "error"
	FieldPacketSeq   = "packet_seq"
	FieldDSCP        = "dscp"
	FieldPort        = "port"
	FieldCount       = "count"
	FieldRTT         = "rtt_ms"
	FieldJitter      = "jitter_ms"
	FieldLoss        = "packet_loss"
	FieldConnID      = "connection_id"
	FieldAcceptCode  = "accept_code"
	FieldPaddingLen  = "padding_length"
	FieldSenderPort  = "sender_port"
	FieldRecvPort    = "receiver_port"
)

// WithSession returns a logger with session-related fields
func WithSession(logger Logger, sessionID common.SessionID, mode common.Mode, peerAddr string) Logger {
	return logger.With(
		FieldSessionID, hex.EncodeToString(sessionID[:]),
		FieldMode, common.ModeToString(mode),
		FieldPeerAddr, peerAddr,
	)
}

// WithConnection returns a logger with connection-related fields
func WithConnection(logger Logger, connID string, peerAddr string) Logger {
	return logger.With(
		FieldConnID, connID,
		FieldPeerAddr, peerAddr,
	)
}

// WithCommand returns a logger with command context
func WithCommand(logger Logger, command string) Logger {
	return logger.With(FieldCommand, command)
}

// WithError returns a logger with error context
func WithError(logger Logger, err error) Logger {
	return logger.With(FieldError, err)
}

// Default logger instance (info level, JSON format)
// Thread-safe lazy initialization using sync.Once
var (
	defaultLogger Logger
	loggerOnce    sync.Once
)

// Default returns the default logger (thread-safe lazy initialization)
func Default() Logger {
	loggerOnce.Do(func() {
		defaultLogger = New(slog.LevelInfo)
	})
	return defaultLogger
}

// Convenience functions using the default logger

// Debug logs at debug level using the default logger
func Debug(msg string, args ...any) {
	defaultLogger.Debug(msg, args...)
}

// Info logs at info level using the default logger
func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}

// Warn logs at warn level using the default logger
func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}

// Error logs at error level using the default logger
func Error(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}
