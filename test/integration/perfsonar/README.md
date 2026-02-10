# perfSONAR interoperability compose baseline

This directory holds the Docker Compose assets for the perfSONAR interoperability test harness.

## Pinned image baseline

- `ghcr.io/perfsonar/toolkit:5.0.8`
- `golang:1.24.2-alpine3.21`

These tags are intentionally pinned so CI results are reproducible and version drift does not silently change interoperability behavior.

## Planned usage

Later tasks in this change wire this compose stack into integration tests and CI execution.

## Local prerequisites

- Docker Engine with Docker Compose v2 (`docker compose version`)
- Go 1.24+
- Available local ports for TWAMP control and test sessions

## Local commands

```bash
# Run the dedicated interoperability target
chmod +x test/integration/perfsonar/run.sh
INTEROP_DIAGNOSTICS_DIR="$(pwd)/test-results/perfsonar-interop" test/integration/perfsonar/run.sh
```

## CI execution model

- Workflow: `.github/workflows/perfsonar-interop.yml`
- Triggering:
  - manual (`workflow_dispatch`)
  - push/PR changes touching perfSONAR interop test files
- CI sets `INTEROP_DIAGNOSTICS_DIR` to `test-results/perfsonar-interop` and uploads that directory as the `perfsonar-interop-artifacts` artifact.

## Pass/fail interpretation

- **Pass**: all targeted interoperability support tests complete successfully; no phase-level errors are reported.
- **Fail**: at least one test fails; phase-specific messages identify where failure occurred (`control-negotiation`, `session-setup`, `packet-exchange`, or `validation`).
- On failures, inspect uploaded JSON diagnostics in the CI artifact directory to identify the failing phase and error chain.

## Flake observations

- Local run observation (current change validation): targeted interoperability target passed repeatedly with no flaky failures observed.
- Regression check observation: full `go test -v ./test/integration` suite passed in the same session with no interop-related flakes.
- Threshold decision: no readiness/retry threshold changes were required based on current runs.
