//go:build linux
// +build linux

package common

import "golang.org/x/sys/unix"

func platformSetDSCP(fd uintptr, dscp uint8) error {
	tos := int(dscp << 2) // DSCP in upper 6 bits of TOS/TC field
	// Try IPv6 first (it’s allowed even on v4 sockets on modern kernels)
	if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos); err == nil {
		return nil
	}
	// Fallback to v4
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos)
}
