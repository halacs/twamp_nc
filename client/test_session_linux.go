//go:build linux
// +build linux

package client

import (
	"syscall"
	"unsafe"
)

// isClockSynchronized checks if the system clock is synchronized
func isClockSynchronized() bool {
	var timex syscall.Timex

	// SYS_ADJTIMEX returns clock status
	_, _, err := syscall.Syscall(syscall.SYS_ADJTIMEX, uintptr(unsafe.Pointer(&timex)), 0, 0)
	if err != 0 {
		return false
	}

	// Constants from linux/timex.h
	const STA_UNSYNC = 0x0040 // Clock unsynchronized

	// Return true if the UNSYNC flag is NOT set
	return (timex.Status & STA_UNSYNC) == 0
}
