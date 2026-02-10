# AGENTS.md

Guidance for coding agents working in `github.com/ncode/twamp`.
This repository is a Go TWAMP implementation with strict RFC semantics and strong test coverage.

## Scope and priorities

1. Keep changes small, local, and protocol-correct.
2. Preserve RFC behavior (especially MBZ fields, mode negotiation, and message sizes).
3. Treat RFC 4656, RFC 5357, RFC 5618, RFC 5938, and RFC 6038 as mandatory constraints for all protocol-affecting changes.
4. Prefer readable code over clever abstractions.
5. Add or update tests for behavior changes.
6. Never weaken security checks for convenience.

## Toolchain and environment

- Go version: `1.25.x` (module uses `go 1.25.7`).
- Module path: `github.com/ncode/twamp`.
- Main packages: `client`, `server`, `messages`, `common`, `crypto`, `metrics`, `logging`.
- Integration tests: `test/integration`.

## Build, lint, and test commands

Run from repository root.

### Dependency/bootstrap

- Download modules: `go mod download`
- Verify module files: `go mod tidy`

### Build

- Build all packages (CI build parity): `go build ./...`
- Build one package: `go build ./client`

### Lint/format/static checks

- Format all code: `go fmt ./...`
- Vet all packages: `go vet ./...`
- Optional extra strictness (if installed): `staticcheck ./...`

### Tests

- Run all tests: `go test ./...`
- Run with race detector: `go test -race ./...`
- Run with verbose output: `go test -v ./...`

### Run a single test (important)

- Single test in a package:
  - `go test ./client -run '^TestConnect$'`
- Single subtest:
  - `go test ./common -run '^TestValidateRequestedMode$/mixed_authenticated_with_extensions$'`
- Multiple matching tests by regex:
  - `go test ./server -run 'TestHandleRequest|TestStart'`
- Single package, single count (disable cache):
  - `go test ./messages -run '^TestServerGreeting_Unmarshal$' -count=1`

### Integration tests

- All integration tests: `go test -v ./test/integration`
- Single integration test:
  - `go test ./test/integration -run '^TestRFC6038' -count=1`
- perfSONAR helper script:
  - `chmod +x test/integration/perfsonar/run.sh`
  - `INTEROP_DIAGNOSTICS_DIR="$(pwd)/test-results/perfsonar-interop" test/integration/perfsonar/run.sh`

### Coverage and benchmarks

- Coverage profile (repo-wide):
  - `go test -race -coverpkg=./... ./... -coverprofile=coverage.out -covermode=atomic`
- View coverage report: `go tool cover -html=coverage.out`
- Benchmarks: `go test -bench . -benchmem ./...`

## Code style guidelines

Follow existing patterns in the touched package first.

### Imports

- Group imports in Go standard style:
  1. standard library
  2. blank line
  3. internal/external module imports
- Do not use dot imports.
- Use import aliases only when required to avoid collisions or improve clarity.

### Formatting and layout

- Always keep files `gofmt`-clean.
- Prefer small functions with clear control flow.
- Keep protocol constants near related types/functions.
- Use comments for non-obvious protocol rules or invariants, not obvious code.

### Types and data modeling

- Use domain types from `common` (e.g., `common.Mode`, `common.SessionID`, `common.TWAMPTimestamp`) instead of raw primitives when available.
- Prefer concrete types over `interface{}` unless polymorphism is needed.
- Keep zero-value behavior safe and explicit in config constructors (`NewClient`, `NewServer`).
- Use typed constants for protocol values and accept codes.

### Naming conventions

- Exported identifiers: `PascalCase` with clear domain meaning.
- Unexported identifiers: `camelCase`.
- Sentinel errors: `ErrXxx` in package-level `var` blocks.
- Constructors: `NewXxx`.
- Test names: `TestXxx`, table entries with descriptive `name` fields.

### Error handling

- Return errors; do not panic in library code.
- Wrap lower-level errors with context using `%w` (e.g., `fmt.Errorf("failed to parse greeting: %w", err)`).
- Preserve sentinel semantics so callers can use `errors.Is`.
- Prefer fail-closed behavior for auth/crypto validation.
- For combined cleanup failures, use `errors.Join` where appropriate.

### Concurrency and context

- Propagate `context.Context` through network operations.
- Respect timeouts/deadlines; avoid goroutine leaks.
- Protect shared mutable state with mutexes/atomics as existing code does.
- Validate concurrency changes with `go test -race ./...`.

### Protocol and encoding rules

- Message lengths and field offsets are strict; validate before parsing.
- Preserve big-endian encoding conventions for wire fields.
- Enforce MBZ fields (`must be zero`) on unmarshal paths.
- Keep mode negotiation logic consistent with RFC 4656/5357/5618/5938/6038 behavior already implemented.
- Treat RFC 4656/5357/5618/5938/6038 as required review checklist items before merging protocol changes.
- Cite RFC sections in comments where behavior may look surprising.

### RFC compliance checklist (required for protocol changes)

- Confirm wire sizes, offsets, and field ordering match RFC definitions before/after changes.
- Verify all MBZ fields are written as zero and rejected on parse when non-zero.
- Validate mode negotiation behavior against RFC 4656/5357 and extensions from RFC 5618/5938/6038.
- Ensure authenticated/encrypted paths verify HMAC before consuming dependent fields.
- Add or update tests that exercise protocol changes, including at least one RFC-specific regression case.

### Security-sensitive code

- Verify HMAC before using dependent authenticated fields.
- Do not log secrets, keys, IVs, or raw auth material.
- Keep key derivation and crypto stream setup paths explicit and test-covered.

## Testing guidelines

- Prefer table-driven tests for validation-heavy logic.
- Use `t.Run` for case naming and selective execution.
- Use `t.Parallel()` only when shared state and port usage are safe.
- Keep tests deterministic (avoid flaky timing assumptions).
- Add regression tests when fixing bugs.
- Existing integration tests use `testify/require`; stay consistent in that area.
