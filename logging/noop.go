// pkg/twamp/logging/noop.go
package logging

import "context"

// noopLogger is a logger that does nothing - useful for testing
type noopLogger struct{}

// NewNoop creates a logger that discards all logs
func NewNoop() Logger {
	return &noopLogger{}
}

func (l *noopLogger) Debug(msg string, args ...any) {}
func (l *noopLogger) Info(msg string, args ...any)  {}
func (l *noopLogger) Warn(msg string, args ...any)  {}
func (l *noopLogger) Error(msg string, args ...any) {}

func (l *noopLogger) With(args ...any) Logger {
	return l
}

func (l *noopLogger) WithContext(ctx context.Context) Logger {
	return l
}
