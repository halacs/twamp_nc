// pkg/twamp/metrics/server_test.go
package metrics

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	config := ServerConfig{
		Address: ":19090",
	}
	srv := NewServer(config)

	if srv == nil {
		t.Fatal("NewServer() returned nil")
	}
	if srv.config.Path != "/metrics" {
		t.Errorf("Expected default path='/metrics', got '%s'", srv.config.Path)
	}
	if srv.config.ReadTimeout != 5*time.Second {
		t.Errorf("Expected default ReadTimeout=5s, got %v", srv.config.ReadTimeout)
	}
	if srv.config.WriteTimeout != 10*time.Second {
		t.Errorf("Expected default WriteTimeout=10s, got %v", srv.config.WriteTimeout)
	}
}

func TestNewServerWithCustomPath(t *testing.T) {
	config := ServerConfig{
		Address: ":19091",
		Path:    "/custom-metrics",
	}
	srv := NewServer(config)

	if srv.config.Path != "/custom-metrics" {
		t.Errorf("Expected path='/custom-metrics', got '%s'", srv.config.Path)
	}
}

func TestServerStartStop(t *testing.T) {
	m := New()

	config := ServerConfig{
		Address:  ":19092",
		Registry: m.Registry(),
	}
	srv := NewServer(config)

	// Start the server
	if err := srv.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Verify it's running by making a request
	resp, err := http.Get("http://localhost:19092/metrics")
	if err != nil {
		t.Fatalf("Failed to fetch metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Stop the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Verify it's stopped
	time.Sleep(100 * time.Millisecond)
	_, err = http.Get("http://localhost:19092/metrics")
	if err == nil {
		t.Error("Expected error after server stopped, got nil")
	}
}

func TestServerMetricsEndpoint(t *testing.T) {
	m := New()

	// Record some metrics
	m.RecordSessionStart("authenticated", "server")
	m.RecordPacketSent("authenticated", "server")
	m.RecordRTT("authenticated", 0.001)

	config := ServerConfig{
		Address:  ":19093",
		Registry: m.Registry(),
	}
	srv := NewServer(config)

	if err := srv.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Fetch metrics
	resp, err := http.Get("http://localhost:19093/metrics")
	if err != nil {
		t.Fatalf("Failed to fetch metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)

	// Verify we have some TWAMP metrics
	expectedMetrics := []string{
		"twamp_sessions_total",
		"twamp_active_sessions",
		"twamp_packets_sent_total",
		"twamp_rtt_seconds",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(bodyStr, metric) {
			t.Errorf("Expected to find metric '%s' in response", metric)
		}
	}

	// Verify our specific recorded values are present
	if !strings.Contains(bodyStr, `twamp_sessions_total{mode="authenticated",role="server"} 1`) {
		t.Error("Expected sessions_total counter to be present")
	}

	if !strings.Contains(bodyStr, `twamp_packets_sent_total{mode="authenticated",role="server"} 1`) {
		t.Error("Expected packets_sent_total counter to be present")
	}
}

func TestServerAddress(t *testing.T) {
	config := ServerConfig{
		Address: ":19094",
	}
	srv := NewServer(config)

	if srv.Address() != ":19094" {
		t.Errorf("Expected address ':19094', got '%s'", srv.Address())
	}
}

func TestServerWithCustomTimeouts(t *testing.T) {
	config := ServerConfig{
		Address:      ":19095",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
	}
	srv := NewServer(config)

	if srv.config.ReadTimeout != 10*time.Second {
		t.Errorf("Expected ReadTimeout=10s, got %v", srv.config.ReadTimeout)
	}
	if srv.config.WriteTimeout != 20*time.Second {
		t.Errorf("Expected WriteTimeout=20s, got %v", srv.config.WriteTimeout)
	}
}

func TestMultipleStartsAndStops(t *testing.T) {
	m := New()

	config := ServerConfig{
		Address:  ":19096",
		Registry: m.Registry(),
	}

	// First run
	srv := NewServer(config)
	if err := srv.Start(); err != nil {
		t.Fatalf("Failed to start server (first time): %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server (first time): %v", err)
	}
	cancel()

	time.Sleep(100 * time.Millisecond)

	// Second run (reusing same port)
	srv2 := NewServer(config)
	if err := srv2.Start(); err != nil {
		t.Fatalf("Failed to start server (second time): %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := srv2.Stop(ctx2); err != nil {
		t.Errorf("Failed to stop server (second time): %v", err)
	}
}
