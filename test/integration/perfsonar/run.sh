#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$ROOT_DIR"

export INTEROP_DIAGNOSTICS_DIR="${INTEROP_DIAGNOSTICS_DIR:-$ROOT_DIR/test-results/perfsonar-interop}"

go test -v ./test/integration -run '^TestWaitForTCPReadySucceeds$|^TestWaitForTCPReadyTimesOut$|^TestInteropComposeMetadata$|^TestRunStepsStopsOnPhaseFailure$|^TestRunTWAMPBaselineScenario$|^TestRunStepsRecordsDiagnosticsOnFailure$|^TestFileDiagnosticRecorderWritesJSONArtifact$|^TestDiagnosticRecorderFromEnv$'
