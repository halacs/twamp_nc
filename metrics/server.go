// pkg/twamp/metrics/server.go
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/ncode/twamp/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServerConfig holds configuration for the metrics HTTP server
type ServerConfig struct {
	// Address to listen on (e.g., ":9090")
	Address string
	// Path for metrics endpoint (defaults to "/metrics")
	Path string
	// ReadTimeout for HTTP server
	ReadTimeout time.Duration
	// WriteTimeout for HTTP server
	WriteTimeout time.Duration
	// Registry to expose (if nil, uses default Prometheus registry)
	Registry *prometheus.Registry
	// Logger for structured error logging (if nil, uses default logger)
	Logger logging.Logger
}

// Server is an HTTP server that exposes Prometheus metrics
type Server struct {
	config     ServerConfig
	httpServer *http.Server
	logger     logging.Logger
}

// NewServer creates a new metrics HTTP server
func NewServer(config ServerConfig) *Server {
	if config.Path == "" {
		config.Path = "/metrics"
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 5 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 10 * time.Second
	}
	if config.Logger == nil {
		config.Logger = logging.Default()
	}

	mux := http.NewServeMux()

	// Create the Prometheus handler
	var handler http.Handler
	if config.Registry != nil {
		// Use custom registry
		handler = promhttp.HandlerFor(config.Registry, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		})
	} else {
		// Use default registry
		handler = promhttp.Handler()
	}

	mux.Handle(config.Path, handler)

	httpServer := &http.Server{
		Addr:         config.Address,
		Handler:      mux,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	return &Server{
		config:     config,
		httpServer: httpServer,
		logger:     config.Logger,
	}
}

// Start starts the metrics HTTP server in a goroutine
// Returns immediately; server runs in background
func (s *Server) Start() error {
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't panic - metrics server failure shouldn't crash the app
			s.logger.Error("Metrics server error",
				logging.FieldError, err,
				"address", s.config.Address)
		}
	}()
	return nil
}

// Stop gracefully shuts down the metrics HTTP server
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Address returns the address the server is configured to listen on
func (s *Server) Address() string {
	return s.config.Address
}
