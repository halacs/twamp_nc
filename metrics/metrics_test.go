// pkg/twamp/metrics/metrics_test.go
package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.registry == nil {
		t.Error("registry is nil")
	}
	if m.SessionsTotal == nil {
		t.Error("SessionsTotal is nil")
	}
	if m.PacketsSent == nil {
		t.Error("PacketsSent is nil")
	}
	if m.PacketsReceived == nil {
		t.Error("PacketsReceived is nil")
	}
	if m.PacketLossTotal == nil {
		t.Error("PacketLossTotal is nil")
	}
	if m.ErrorsTotal == nil {
		t.Error("ErrorsTotal is nil")
	}
	if m.ControlMessagesTotal == nil {
		t.Error("ControlMessagesTotal is nil")
	}
	if m.ActiveSessions == nil {
		t.Error("ActiveSessions is nil")
	}
	if m.RTTSeconds == nil {
		t.Error("RTTSeconds is nil")
	}
	if m.JitterSeconds == nil {
		t.Error("JitterSeconds is nil")
	}
}

func TestNewWithRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewWithRegistry(reg)
	if m == nil {
		t.Fatal("NewWithRegistry() returned nil")
	}
	if m.registry != reg {
		t.Error("registry was not set correctly")
	}
}

func TestRecordSessionStart(t *testing.T) {
	m := New()
	m.RecordSessionStart("authenticated", "server")

	// Verify SessionsTotal counter was incremented
	count := testutil.ToFloat64(m.SessionsTotal.WithLabelValues("authenticated", "server"))
	if count != 1.0 {
		t.Errorf("Expected SessionsTotal=1.0, got %f", count)
	}

	// Verify ActiveSessions gauge was incremented
	active := testutil.ToFloat64(m.ActiveSessions.WithLabelValues("authenticated", "server"))
	if active != 1.0 {
		t.Errorf("Expected ActiveSessions=1.0, got %f", active)
	}
}

func TestRecordSessionEnd(t *testing.T) {
	m := New()

	// Start a session first
	m.RecordSessionStart("authenticated", "client")

	// End the session
	m.RecordSessionEnd("authenticated", "client")

	// Verify ActiveSessions gauge was decremented
	active := testutil.ToFloat64(m.ActiveSessions.WithLabelValues("authenticated", "client"))
	if active != 0.0 {
		t.Errorf("Expected ActiveSessions=0.0, got %f", active)
	}

	// SessionsTotal should still be 1
	count := testutil.ToFloat64(m.SessionsTotal.WithLabelValues("authenticated", "client"))
	if count != 1.0 {
		t.Errorf("Expected SessionsTotal=1.0, got %f", count)
	}
}

func TestRecordPacketSent(t *testing.T) {
	m := New()
	m.RecordPacketSent("authenticated", "server")
	m.RecordPacketSent("authenticated", "server")

	count := testutil.ToFloat64(m.PacketsSent.WithLabelValues("authenticated", "server"))
	if count != 2.0 {
		t.Errorf("Expected PacketsSent=2.0, got %f", count)
	}
}

func TestRecordPacketReceived(t *testing.T) {
	m := New()
	m.RecordPacketReceived("encrypted", "client")

	count := testutil.ToFloat64(m.PacketsReceived.WithLabelValues("encrypted", "client"))
	if count != 1.0 {
		t.Errorf("Expected PacketsReceived=1.0, got %f", count)
	}
}

func TestRecordPacketLoss(t *testing.T) {
	m := New()
	m.RecordPacketLoss("unauthenticated", "server")

	count := testutil.ToFloat64(m.PacketLossTotal.WithLabelValues("unauthenticated", "server"))
	if count != 1.0 {
		t.Errorf("Expected PacketLossTotal=1.0, got %f", count)
	}
}

func TestRecordRTT(t *testing.T) {
	m := New()

	// Record a few RTT measurements
	m.RecordRTT("authenticated", 0.001) // 1ms
	m.RecordRTT("authenticated", 0.002) // 2ms
	m.RecordRTT("authenticated", 0.0015) // 1.5ms

	// We can't easily verify histogram contents, but we can verify it was called
	// without panicking and that the metric exists
	count := testutil.CollectAndCount(m.RTTSeconds)
	if count == 0 {
		t.Error("RTTSeconds histogram has no metrics")
	}
}

func TestRecordJitter(t *testing.T) {
	m := New()

	m.RecordJitter("encrypted", 0.0001) // 0.1ms

	count := testutil.CollectAndCount(m.JitterSeconds)
	if count == 0 {
		t.Error("JitterSeconds histogram has no metrics")
	}
}

func TestRecordError(t *testing.T) {
	m := New()
	m.RecordError("hmac_failed", "server")

	count := testutil.ToFloat64(m.ErrorsTotal.WithLabelValues("hmac_failed", "server"))
	if count != 1.0 {
		t.Errorf("Expected ErrorsTotal=1.0, got %f", count)
	}
}

func TestRecordControlMessage(t *testing.T) {
	m := New()
	m.RecordControlMessage("server_start", "client", "success", ErrorTypeNone)
	m.RecordControlMessage("server_start", "client", "error", ErrorTypeTimeout)

	successCount := testutil.ToFloat64(m.ControlMessagesTotal.WithLabelValues("server_start", "client", "success", ErrorTypeNone))
	if successCount != 1.0 {
		t.Errorf("Expected success count=1.0, got %f", successCount)
	}

	errorCount := testutil.ToFloat64(m.ControlMessagesTotal.WithLabelValues("server_start", "client", "error", ErrorTypeTimeout))
	if errorCount != 1.0 {
		t.Errorf("Expected error count=1.0, got %f", errorCount)
	}
}

func TestSetPortUsage(t *testing.T) {
	m := New()
	m.SetPortUsage(42)

	usage := testutil.ToFloat64(m.PortUsage)
	if usage != 42.0 {
		t.Errorf("Expected PortUsage=42.0, got %f", usage)
	}

	// Update it
	m.SetPortUsage(100)
	usage = testutil.ToFloat64(m.PortUsage)
	if usage != 100.0 {
		t.Errorf("Expected PortUsage=100.0, got %f", usage)
	}
}

func TestDefaultMetrics(t *testing.T) {
	// Get default instance (thread-safe lazy init via sync.Once)
	m1 := Default()
	if m1 == nil {
		t.Fatal("Default() returned nil")
	}

	// Should return same instance on subsequent calls
	m2 := Default()
	if m1 != m2 {
		t.Error("Default() returned different instances")
	}

	// Third call should also return same instance
	m3 := Default()
	if m1 != m3 {
		t.Error("Default() returned different instance on third call")
	}
}

func TestRegistry(t *testing.T) {
	m := New()
	reg := m.Registry()
	if reg == nil {
		t.Error("Registry() returned nil")
	}
}

func TestMultipleSessionsScenario(t *testing.T) {
	m := New()

	// Start 3 authenticated sessions on server
	m.RecordSessionStart("authenticated", "server")
	m.RecordSessionStart("authenticated", "server")
	m.RecordSessionStart("authenticated", "server")

	// Verify counts
	sessionsTotal := testutil.ToFloat64(m.SessionsTotal.WithLabelValues("authenticated", "server"))
	if sessionsTotal != 3.0 {
		t.Errorf("Expected SessionsTotal=3.0, got %f", sessionsTotal)
	}

	activeSessions := testutil.ToFloat64(m.ActiveSessions.WithLabelValues("authenticated", "server"))
	if activeSessions != 3.0 {
		t.Errorf("Expected ActiveSessions=3.0, got %f", activeSessions)
	}

	// End one session
	m.RecordSessionEnd("authenticated", "server")

	activeSessions = testutil.ToFloat64(m.ActiveSessions.WithLabelValues("authenticated", "server"))
	if activeSessions != 2.0 {
		t.Errorf("Expected ActiveSessions=2.0 after ending one, got %f", activeSessions)
	}

	// SessionsTotal should remain 3
	sessionsTotal = testutil.ToFloat64(m.SessionsTotal.WithLabelValues("authenticated", "server"))
	if sessionsTotal != 3.0 {
		t.Errorf("Expected SessionsTotal=3.0 (unchanged), got %f", sessionsTotal)
	}
}

func TestMetricsLabels(t *testing.T) {
	m := New()

	// Test different mode/role combinations
	modes := []string{"unauthenticated", "authenticated", "encrypted"}
	roles := []string{"client", "server"}

	for _, mode := range modes {
		for _, role := range roles {
			m.RecordSessionStart(mode, role)
		}
	}

	// Verify all combinations were recorded
	for _, mode := range modes {
		for _, role := range roles {
			count := testutil.ToFloat64(m.SessionsTotal.WithLabelValues(mode, role))
			if count != 1.0 {
				t.Errorf("Expected count=1.0 for mode=%s role=%s, got %f", mode, role, count)
			}
		}
	}
}
