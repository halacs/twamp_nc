package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ncode/twamp/client"
)

const (
	interopComposeFile       = "test/integration/perfsonar/docker-compose.yml"
	perfsonarToolkitImage    = "ghcr.io/perfsonar/toolkit:5.0.8"
	interopDiagnosticsDirEnv = "INTEROP_DIAGNOSTICS_DIR"
)

type serviceEndpoint struct {
	Name    string
	Address string
}

type interopPhase string

const (
	phaseControl        interopPhase = "control-negotiation"
	phaseSessionSetup   interopPhase = "session-setup"
	phasePacketExchange interopPhase = "packet-exchange"
	phaseValidation     interopPhase = "validation"
)

type scenarioStep struct {
	Phase   interopPhase
	Timeout time.Duration
	Run     func(context.Context) error
}

type baselineScenarioConfig struct {
	SessionConfig      client.TestSessionConfig
	PacketsToSend      int
	MinPacketsReceived uint32
	ControlTimeout     time.Duration
	SessionTimeout     time.Duration
	PacketTimeout      time.Duration
	ValidationTimeout  time.Duration
	PhaseRetryInterval time.Duration
	DiagnosticRecorder diagnosticRecorder
}

type phaseFailureDiagnostic struct {
	Phase      interopPhase `json:"phase"`
	Message    string       `json:"message"`
	CapturedAt time.Time    `json:"captured_at"`
}

type diagnosticRecorder interface {
	Record(ctx context.Context, diagnostic phaseFailureDiagnostic) error
}

type fileDiagnosticRecorder struct {
	outputDir string
}

func newFileDiagnosticRecorder(outputDir string) diagnosticRecorder {
	return &fileDiagnosticRecorder{outputDir: outputDir}
}

func diagnosticRecorderFromEnv() diagnosticRecorder {
	dir := strings.TrimSpace(os.Getenv(interopDiagnosticsDirEnv))
	if dir == "" {
		return nil
	}
	return newFileDiagnosticRecorder(dir)
}

func (r *fileDiagnosticRecorder) Record(_ context.Context, diagnostic phaseFailureDiagnostic) error {
	if err := os.MkdirAll(r.outputDir, 0o755); err != nil {
		return fmt.Errorf("create diagnostics directory: %w", err)
	}
	diagnostic.CapturedAt = time.Now().UTC()
	content, err := json.MarshalIndent(diagnostic, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal diagnostic: %w", err)
	}
	name := fmt.Sprintf("%d-%s.json", diagnostic.CapturedAt.UnixNano(), diagnostic.Phase)
	path := filepath.Join(r.outputDir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("write diagnostic artifact: %w", err)
	}
	return nil
}

func runSteps(ctx context.Context, steps []scenarioStep) error {
	return runStepsWithRecorder(ctx, steps, nil)
}

func runStepsWithRecorder(ctx context.Context, steps []scenarioStep, recorder diagnosticRecorder) error {
	for _, step := range steps {
		phaseCtx, cancel := context.WithTimeout(ctx, step.Timeout)
		err := step.Run(phaseCtx)
		cancel()
		if err != nil {
			phaseErr := fmt.Errorf("phase %s: %w", step.Phase, err)
			if recorder != nil {
				recordErr := recorder.Record(ctx, phaseFailureDiagnostic{Phase: step.Phase, Message: phaseErr.Error()})
				if recordErr != nil {
					return errors.Join(phaseErr, fmt.Errorf("diagnostics: %w", recordErr))
				}
			}
			return phaseErr
		}
	}
	return nil
}

func runTWAMPBaselineScenario(ctx context.Context, twampClient *client.Client, cfg baselineScenarioConfig) error {
	if twampClient == nil {
		return errors.New("twamp client is required")
	}
	if cfg.PacketsToSend <= 0 {
		cfg.PacketsToSend = 3
	}
	if cfg.MinPacketsReceived == 0 {
		cfg.MinPacketsReceived = uint32(cfg.PacketsToSend - 1)
	}
	if cfg.MinPacketsReceived > uint32(cfg.PacketsToSend) {
		return fmt.Errorf("MinPacketsReceived (%d) cannot exceed PacketsToSend (%d)", cfg.MinPacketsReceived, cfg.PacketsToSend)
	}
	if cfg.ControlTimeout <= 0 {
		cfg.ControlTimeout = 3 * time.Second
	}
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = 3 * time.Second
	}
	if cfg.PacketTimeout <= 0 {
		cfg.PacketTimeout = 5 * time.Second
	}
	if cfg.ValidationTimeout <= 0 {
		cfg.ValidationTimeout = 500 * time.Millisecond
	}
	if cfg.PhaseRetryInterval <= 0 {
		cfg.PhaseRetryInterval = 50 * time.Millisecond
	}
	if cfg.DiagnosticRecorder == nil {
		cfg.DiagnosticRecorder = diagnosticRecorderFromEnv()
	}

	var session *client.TestSession

	steps := []scenarioStep{
		{
			Phase:   phaseControl,
			Timeout: cfg.ControlTimeout,
			Run: func(phaseCtx context.Context) error {
				return twampClient.Connect(phaseCtx)
			},
		},
		{
			Phase:   phaseSessionSetup,
			Timeout: cfg.SessionTimeout,
			Run: func(_ context.Context) error {
				var err error
				session, err = twampClient.RequestSession(cfg.SessionConfig)
				if err != nil {
					return err
				}
				return twampClient.StartSessions()
			},
		},
		{
			Phase:   phasePacketExchange,
			Timeout: cfg.PacketTimeout,
			Run: func(phaseCtx context.Context) error {
				session.StartReceiving(phaseCtx)
				for i := 0; i < cfg.PacketsToSend; i++ {
					if err := session.SendTestPacket(); err != nil {
						return err
					}
				}
				for {
					results := session.GetResults()
					if results.PacketsReceived >= cfg.MinPacketsReceived {
						return nil
					}
					select {
					case <-phaseCtx.Done():
						return phaseCtx.Err()
					case <-time.After(cfg.PhaseRetryInterval):
					}
				}
			},
		},
		{
			Phase:   phaseValidation,
			Timeout: cfg.ValidationTimeout,
			Run: func(_ context.Context) error {
				results := session.GetResults()
				if results.PacketsSent != uint32(cfg.PacketsToSend) {
					return fmt.Errorf("expected %d packets sent, got %d", cfg.PacketsToSend, results.PacketsSent)
				}
				if results.PacketsReceived < cfg.MinPacketsReceived {
					return fmt.Errorf("expected at least %d packets received, got %d", cfg.MinPacketsReceived, results.PacketsReceived)
				}
				if results.AvgRTT == 0 {
					return errors.New("expected non-zero average RTT")
				}
				return nil
			},
		},
	}

	err := runStepsWithRecorder(ctx, steps, cfg.DiagnosticRecorder)
	stopErr := twampClient.StopSessions()
	if err != nil {
		return err
	}
	if stopErr != nil {
		phaseErr := fmt.Errorf("phase %s: %w", phaseValidation, stopErr)
		if cfg.DiagnosticRecorder != nil {
			recordErr := cfg.DiagnosticRecorder.Record(ctx, phaseFailureDiagnostic{Phase: phaseValidation, Message: phaseErr.Error()})
			if recordErr != nil {
				return errors.Join(phaseErr, fmt.Errorf("diagnostics: %w", recordErr))
			}
		}
		return phaseErr
	}
	return nil
}

func waitForTCPReady(ctx context.Context, endpoints []serviceEndpoint, retryInterval time.Duration) error {
	if retryInterval <= 0 {
		retryInterval = 100 * time.Millisecond
	}

	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	for {
		allReady := true
		for _, endpoint := range endpoints {
			if err := probeTCP(endpoint.Address); err != nil {
				allReady = false
				break
			}
		}
		if allReady {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("services not ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func probeTCP(address string) error {
	conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err != nil {
		return err
	}
	return conn.Close()
}
