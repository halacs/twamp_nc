//go:build darwin || freebsd || netbsd || openbsd
// +build darwin freebsd netbsd openbsd

package common

import "golang.org/x/sys/unix"

func platformSetDSCP(fd uintptr, dscp uint8) error {
	tos := int(dscp << 2)
	if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos); err == nil {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos)
}
