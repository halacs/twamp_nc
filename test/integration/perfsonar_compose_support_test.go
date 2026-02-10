package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncode/twamp/internal/testutil"
	"github.com/ncode/twamp/client"
	"github.com/ncode/twamp/common"
	"github.com/stretchr/testify/require"
)

type recordingSink struct {
	records []phaseFailureDiagnostic
}

type failingRecorder struct {
	err error
}

func (r *recordingSink) Record(_ context.Context, diagnostic phaseFailureDiagnostic) error {
	r.records = append(r.records, diagnostic)
	return nil
}

func (r failingRecorder) Record(_ context.Context, _ phaseFailureDiagnostic) error {
	return r.err
}

func TestWaitForTCPReadySucceeds(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	address := listener.Addr().String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { <-done })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = waitForTCPReady(ctx, []serviceEndpoint{{Name: "probe", Address: address}}, 25*time.Millisecond)
	require.NoError(t, err)
}

func TestWaitForTCPReadyTimesOut(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	err := waitForTCPReady(ctx, []serviceEndpoint{{Name: "unreachable", Address: "127.0.0.1:39999"}}, 30*time.Millisecond)
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestInteropComposeMetadata(t *testing.T) {
	t.Parallel()

	require.Equal(t, "test/integration/perfsonar/docker-compose.yml", interopComposeFile)
	require.NotEmpty(t, perfsonarToolkitImage)
	require.NotContains(t, perfsonarToolkitImage, ":latest")
}

func TestRunStepsStopsOnPhaseFailure(t *testing.T) {
	t.Parallel()

	order := make([]interopPhase, 0, 3)
	steps := []scenarioStep{
		{
			Phase:   phaseControl,
			Timeout: 500 * time.Millisecond,
			Run: func(_ context.Context) error {
				order = append(order, phaseControl)
				return nil
			},
		},
		{
			Phase:   phaseSessionSetup,
			Timeout: 500 * time.Millisecond,
			Run: func(_ context.Context) error {
				order = append(order, phaseSessionSetup)
				return errors.New("session setup failed")
			},
		},
		{
			Phase:   phasePacketExchange,
			Timeout: 500 * time.Millisecond,
			Run: func(_ context.Context) error {
				order = append(order, phasePacketExchange)
				return nil
			},
		},
	}

	err := runSteps(context.Background(), steps)
	require.Error(t, err)
	require.Equal(t, []interopPhase{phaseControl, phaseSessionSetup}, order)
	require.True(t, strings.Contains(err.Error(), "session-setup"))
}

func TestRunTWAMPBaselineScenario(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	ports := testutil.GetFreePorts(t, "udp", 2)
	cfg := baselineScenarioConfig{
		SessionConfig: client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		},
		PacketsToSend:      3,
		MinPacketsReceived: 2,
		ControlTimeout:     2 * time.Second,
		SessionTimeout:     2 * time.Second,
		PacketTimeout:      4 * time.Second,
		ValidationTimeout:  500 * time.Millisecond,
	}

	err := runTWAMPBaselineScenario(ctx, twampClient, cfg)
	require.NoError(t, err)
}

func TestRunStepsRecordsDiagnosticsOnFailure(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{}
	steps := []scenarioStep{
		{
			Phase:   phaseControl,
			Timeout: 200 * time.Millisecond,
			Run: func(_ context.Context) error {
				return errors.New("control refused")
			},
		},
	}

	err := runStepsWithRecorder(context.Background(), steps, sink)
	require.Error(t, err)
	require.Len(t, sink.records, 1)
	require.Equal(t, phaseControl, sink.records[0].Phase)
	require.True(t, strings.Contains(sink.records[0].Message, "control refused"))
	require.True(t, strings.Contains(err.Error(), "phase control-negotiation"))
}

func TestRunStepsWithRecorderPreservesRecorderErrorChain(t *testing.T) {
	t.Parallel()

	stepErr := errors.New("step failed")
	recorderErr := errors.New("diagnostics failed")
	steps := []scenarioStep{
		{
			Phase:   phaseControl,
			Timeout: 200 * time.Millisecond,
			Run: func(_ context.Context) error {
				return stepErr
			},
		},
	}

	err := runStepsWithRecorder(context.Background(), steps, failingRecorder{err: recorderErr})
	require.Error(t, err)
	require.True(t, errors.Is(err, stepErr))
	require.True(t, errors.Is(err, recorderErr))
}

func TestFileDiagnosticRecorderWritesJSONArtifact(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	recorder := newFileDiagnosticRecorder(dir)

	diagnostic := phaseFailureDiagnostic{
		Phase:   phasePacketExchange,
		Message: "packet exchange timed out",
	}

	err := recorder.Record(context.Background(), diagnostic)
	require.NoError(t, err)

	paths, globErr := filepath.Glob(filepath.Join(dir, "*.json"))
	require.NoError(t, globErr)
	require.Len(t, paths, 1)

	content, readErr := os.ReadFile(paths[0])
	require.NoError(t, readErr)
	require.Contains(t, string(content), "packet-exchange")
	require.Contains(t, string(content), "packet exchange timed out")
}

func TestDiagnosticRecorderFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(interopDiagnosticsDirEnv, dir)

	recorder := diagnosticRecorderFromEnv()
	require.NotNil(t, recorder)

	err := recorder.Record(context.Background(), phaseFailureDiagnostic{Phase: phaseValidation, Message: "validation failed"})
	require.NoError(t, err)

	paths, globErr := filepath.Glob(filepath.Join(dir, "*.json"))
	require.NoError(t, globErr)
	require.NotEmpty(t, paths)
}

func TestRunTWAMPBaselineScenarioRejectsInvalidMinPacketsReceived(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, twampClient, cleanup := setupServerAndClient(t, ctx, common.ModeUnauthenticated, "")
	defer cleanup()

	ports := testutil.GetFreePorts(t, "udp", 2)
	cfg := baselineScenarioConfig{
		SessionConfig: client.TestSessionConfig{
			SenderPort:    uint16(ports[0]),
			ReceiverPort:  uint16(ports[1]),
			PaddingLength: 41,
			Timeout:       2 * time.Second,
			DSCP:          0,
		},
		PacketsToSend:      2,
		MinPacketsReceived: 3,
		ControlTimeout:     1 * time.Second,
		SessionTimeout:     1 * time.Second,
		PacketTimeout:      500 * time.Millisecond,
		ValidationTimeout:  200 * time.Millisecond,
	}

	err := runTWAMPBaselineScenario(ctx, twampClient, cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, fmt.Sprintf("MinPacketsReceived (%d) cannot exceed PacketsToSend (%d)", cfg.MinPacketsReceived, cfg.PacketsToSend))
}
