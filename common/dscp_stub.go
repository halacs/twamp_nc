//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd
// +build !linux,!darwin,!freebsd,!netbsd,!openbsd

package common

func platformSetDSCP(fd uintptr, dscp uint8) error {
	return nil // silently ignore on unknown OS
}
