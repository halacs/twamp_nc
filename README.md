# twamp

RFC-compliant TWAMP implementation in Go for active network performance measurement with strict wire-format semantics and practical client/server APIs.

[![CI](https://github.com/ncode/twamp/actions/workflows/go.yml/badge.svg)](https://github.com/ncode/twamp/actions/workflows/go.yml)
[![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](https://go.dev/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Table of contents

- [Why twamp?](#why-twamp)
- [Implemented RFCs](#implemented-rfcs)
- [Get running in 5 minutes](#get-running-in-5-minutes)
- [Common tasks](#common-tasks)
- [Full end-to-end examples](#full-end-to-end-examples)
- [Package overview](#package-overview)
- [Testing and interop](#testing-and-interop)
- [Contributing](#contributing)
- [License](#license)

## Why twamp?

- Enforces strict protocol behavior, including field-length validation, big-endian encoding, and MBZ (must-be-zero) checks.
- Implements TWAMP control/test workflows with explicit mode handling (unauthenticated/authenticated/encrypted).
- Ships as a Go module with clear package boundaries for integration into existing systems.
- CI validates build, tests, and race detection on every PR/push to `main`.
- Includes integration interoperability assets for perfSONAR-focused verification.

## Implemented RFCs

The following RFCs are implemented in this repository. Local reference copies are vendored under `rfcs/` for stable, offline-friendly review.

| RFC | Focus area | Local reference | Canonical reference |
| --- | --- | --- | --- |
| RFC 4656 | OWAMP base protocol context used by TWAMP ecosystem | [`rfcs/rfc4656.txt`](rfcs/rfc4656.txt) | [datatracker](https://datatracker.ietf.org/doc/html/rfc4656) |
| RFC 5357 | TWAMP core protocol | [`rfcs/rfc5357.txt`](rfcs/rfc5357.txt) | [datatracker](https://datatracker.ietf.org/doc/html/rfc5357) |
| RFC 5618 | TWAMP mixed security mode | [`rfcs/rfc5618.txt`](rfcs/rfc5618.txt) | [datatracker](https://datatracker.ietf.org/doc/html/rfc5618) |
| RFC 5938 | TWAMP individual session control | [`rfcs/rfc5938.txt`](rfcs/rfc5938.txt) | [datatracker](https://datatracker.ietf.org/doc/html/rfc5938) |
| RFC 6038 | TWAMP reflect octets and symmetrical size features | [`rfcs/rfc6038.txt`](rfcs/rfc6038.txt) | [datatracker](https://datatracker.ietf.org/doc/html/rfc6038) |

## Get running in 5 minutes

Install:

```bash
go get github.com/ncode/twamp
```

Minimal client connect example:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/ncode/twamp/client"
	"github.com/ncode/twamp/common"
)

func main() {
	c := client.NewClient(client.ClientConfig{
		ServerAddress: "127.0.0.1:8620",
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       5 * time.Second,
	})

	if err := c.Connect(context.Background()); err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer c.Close()
}
```

## Common tasks

Create a client and request a test session:

```go
session, err := c.RequestSession(client.TestSessionConfig{
	SenderPort:   10000,
	ReceiverPort: 20000,
	Timeout:      2 * time.Second,
})
if err != nil {
	// handle error
}
```

Start TWAMP test sessions and receiver loop:

```go
if err := c.StartSessions(); err != nil {
	// handle error
}
session.StartReceiving(context.Background())
```

Send test packets and read results:

```go
for i := 0; i < 10; i++ {
	_ = session.SendTestPacket()
	time.Sleep(1 * time.Second)
}
results := session.GetResults()
```

Stop sessions cleanly:

```go
if err := c.StopSessions(); err != nil {
	// handle error
}
```

## Full end-to-end examples

For runnable, environment-driven flows:

- Server example: `examples/server/server.go`
- Client example: `examples/client/client.go`

These examples cover session setup, mode configuration, packet exchange, and result reporting.

## Package overview

- `client`: TWAMP control client and test-session sender APIs.
- `server`: TWAMP control server and test-session reflector APIs.
- `messages`: Wire-level message encoding/decoding primitives.
- `common`: Domain types, timestamps, DSCP, and shared protocol helpers.
- `crypto`: AES/HMAC and TWAMP key derivation utilities.
- `metrics`: Prometheus-oriented measurement helpers.
- `logging`: Structured logging abstractions.

## Testing and interop

Core verification:

```bash
go test ./...
go test -race ./...
```

Build everything:

```bash
go build ./...
```

perfSONAR interoperability assets and usage notes:

- `test/integration/perfsonar/README.md`
- `test/integration/perfsonar/run.sh`

## Contributing

See `CONTRIBUTING.md` for development workflow, verification expectations, and contribution standards.

## License

Apache-2.0. See `LICENSE`.
