# Contributing to twamp

We welcome well‑engineered, RFC‑compliant contributions. Keep changes small, focused, and production‑ready.

## Prerequisites
- Go 1.25.6 or newer
- GitHub account with a fork of this repo
- Platform(s) for testing platform‑specific code as applicable (Linux/BSD/Windows)

## Quick Start
```bash
# Fork on GitHub, then:
git clone https://github.com/<you>/twamp.git
cd twamp

# Get dependencies
go mod download

# Run tests (fast feedback)
go test ./...

# Race + coverage (CI parity)
go test -race -coverpkg=./... ./... -coverprofile=coverage.out -covermode=atomic

# View coverage
go tool cover -html=coverage.out

# Format and vet
go fmt ./...
go vet ./...
```

## Development Guidelines
- Read AGENTS.md and follow its standards strictly.
- Keep PRs small and single‑purpose; include tests and docs.
- Reference exact RFC section(s) in code comments where behavior is subtle.
- Maintain deterministic timing: use monotonic deltas for RTT; use `common.TWAMPTimestamp` helpers for NTP conversions.
- Validate message fields rigorously: lengths, MBZ=0, big‑endian encoding, padding per mode.
- Avoid allocations in hot paths; reuse `common.PacketBufferPool` buffers.
- Guard concurrency with contexts and avoid leaks; verify with `-race`.
- Keep platform differences behind build tags; provide consistent behavior and stubs.

## Commit Messages
- Subject: imperative, <= 72 chars
- Body: what and why; reference RFC section(s) when relevant

Examples:
- messages: enforce MBZ=0 in StartAck Unmarshal
- common/timestamp: use monotonic pair for RTT deltas

## Pull Requests
- Before opening a PR:
  - Tests pass locally with `-race`
  - Benchmarks added/validated if hot paths are touched (`go test -bench . -benchmem ./...`)
  - README/examples updated if APIs or behavior changed
  - RFC citations included for protocol logic
- Open the PR against `main` and ensure CI is green.

## Security Notes
- Verify HMAC before consuming dependent fields; fail closed.
- Handle AES IVs correctly; never reuse IVs in the same key context.
- Avoid logging sensitive material; clear long‑lived key buffers when appropriate.

## Questions
Open a GitHub Discussion or Issue with clear reproduction steps and environment details.
