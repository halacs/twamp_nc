// pkg/twamp/metrics/metrics.go
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Namespace for all TWAMP metrics
const (
	namespace = "twamp"
)

// Error types for bounded error_type label (Prometheus best practice)
const (
	ErrorTypeNone             = "none"              // No error (success case)
	ErrorTypeAccept           = "accept_code"       // Non-zero accept code from server
	ErrorTypeTimeout          = "timeout"           // Timeout waiting for response
	ErrorTypeConnection       = "connection"        // Connection/network error
	ErrorTypeHMAC             = "hmac"              // HMAC verification failure
	ErrorTypeParse            = "parse"             // Message parsing error
	ErrorTypeInvalidState     = "invalid_state"     // Invalid state for operation
	ErrorTypeSessionNotFound  = "session_not_found" // Session lookup failed
	ErrorTypeInternal         = "internal"          // Internal/unexpected error
)

// Metrics holds all Prometheus metrics for TWAMP
type Metrics struct {
	// Counter metrics
	SessionsTotal        *prometheus.CounterVec
	PacketsSent          *prometheus.CounterVec
	PacketsReceived      *prometheus.CounterVec
	PacketLossTotal      *prometheus.CounterVec
	ErrorsTotal          *prometheus.CounterVec
	ControlMessagesTotal *prometheus.CounterVec

	// Gauge metrics
	ActiveSessions *prometheus.GaugeVec
	PortUsage      prometheus.Gauge

	// Histogram metrics
	RTTSeconds    *prometheus.HistogramVec
	JitterSeconds *prometheus.HistogramVec

	// Registry for this metrics instance
	registry *prometheus.Registry
}

// New creates a new Metrics instance with a custom registry
func New() *Metrics {
	reg := prometheus.NewRegistry()
	return NewWithRegistry(reg)
}

// NewWithRegistry creates a new Metrics instance with the provided registry
func NewWithRegistry(reg *prometheus.Registry) *Metrics {
	factory := promauto.With(reg)

	m := &Metrics{
		registry: reg,

		// Sessions total by mode
		SessionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "sessions_total",
				Help:      "Total number of TWAMP sessions created, labeled by mode",
			},
			[]string{"mode", "role"}, // role: client or server
		),

		// Packets sent by mode
		PacketsSent: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "packets_sent_total",
				Help:      "Total number of TWAMP test packets sent",
			},
			[]string{"mode", "role"},
		),

		// Packets received by mode
		PacketsReceived: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "packets_received_total",
				Help:      "Total number of TWAMP test packets received",
			},
			[]string{"mode", "role"},
		),

		// Packet loss by mode
		PacketLossTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "packet_loss_total",
				Help:      "Total number of lost TWAMP test packets",
			},
			[]string{"mode", "role"},
		),

		// Errors by type
		ErrorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "errors_total",
				Help:      "Total number of errors, labeled by type",
			},
			[]string{"type", "role"}, // type: hmac_failed, packet_processing, etc.
		),

		// Control messages by command
		ControlMessagesTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "control_messages_total",
				Help:      "Total number of TWAMP control messages, labeled by command and error type",
			},
			[]string{"command", "role", "status", "error_type"}, // status: success or error; error_type: bounded error categories
		),

		// Active sessions gauge
		ActiveSessions: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "active_sessions",
				Help:      "Number of currently active TWAMP sessions",
			},
			[]string{"mode", "role"},
		),

		// Port usage gauge (server only)
		PortUsage: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "port_usage",
				Help:      "Number of allocated UDP ports for test sessions",
			},
		),

		// RTT histogram with buckets optimized for network latency
		RTTSeconds: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "rtt_seconds",
				Help:      "Round-trip time histogram in seconds",
				// Buckets from 100µs to 10s: 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0
				Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0},
			},
			[]string{"mode"},
		),

		// Jitter histogram with buckets optimized for jitter measurements
		JitterSeconds: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "jitter_seconds",
				Help:      "Jitter (RTT variation) histogram in seconds",
				// Buckets from 10µs to 1s: 0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0
				Buckets: []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
			},
			[]string{"mode"},
		),
	}

	return m
}

// Registry returns the Prometheus registry for this metrics instance
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// Helper methods for common metric operations

// RecordSessionStart increments the sessions counter and active sessions gauge
func (m *Metrics) RecordSessionStart(mode, role string) {
	m.SessionsTotal.WithLabelValues(mode, role).Inc()
	m.ActiveSessions.WithLabelValues(mode, role).Inc()
}

// RecordSessionEnd decrements the active sessions gauge
func (m *Metrics) RecordSessionEnd(mode, role string) {
	m.ActiveSessions.WithLabelValues(mode, role).Dec()
}

// RecordPacketSent increments the packets sent counter
func (m *Metrics) RecordPacketSent(mode, role string) {
	m.PacketsSent.WithLabelValues(mode, role).Inc()
}

// RecordPacketReceived increments the packets received counter
func (m *Metrics) RecordPacketReceived(mode, role string) {
	m.PacketsReceived.WithLabelValues(mode, role).Inc()
}

// RecordPacketLoss increments the packet loss counter
func (m *Metrics) RecordPacketLoss(mode, role string) {
	m.PacketLossTotal.WithLabelValues(mode, role).Inc()
}

// RecordRTT observes an RTT measurement
func (m *Metrics) RecordRTT(mode string, rttSeconds float64) {
	m.RTTSeconds.WithLabelValues(mode).Observe(rttSeconds)
}

// RecordJitter observes a jitter measurement
func (m *Metrics) RecordJitter(mode string, jitterSeconds float64) {
	m.JitterSeconds.WithLabelValues(mode).Observe(jitterSeconds)
}

// RecordError increments the error counter
func (m *Metrics) RecordError(errorType, role string) {
	m.ErrorsTotal.WithLabelValues(errorType, role).Inc()
}

// RecordControlMessage increments the control message counter
// errorType should be one of the ErrorType* constants (use ErrorTypeNone for success)
func (m *Metrics) RecordControlMessage(command, role, status, errorType string) {
	m.ControlMessagesTotal.WithLabelValues(command, role, status, errorType).Inc()
}

// SetPortUsage sets the current port usage gauge
func (m *Metrics) SetPortUsage(count int) {
	m.PortUsage.Set(float64(count))
}

// Default metrics instance (uses default Prometheus registry)
// Thread-safe lazy initialization using sync.Once
var (
	defaultMetrics *Metrics
	metricsOnce    sync.Once
)

// Default returns the default metrics instance (thread-safe lazy initialization)
func Default() *Metrics {
	metricsOnce.Do(func() {
		defaultMetrics = New()
	})
	return defaultMetrics
}
