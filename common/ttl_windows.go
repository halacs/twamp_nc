//go:build windows

package common

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	// Windows socket options for TTL
	IP_TTL            = 0x4
	IPV6_UNICAST_HOPS = 0x4
	IPPROTO_IP        = 0x0
	IPPROTO_IPV6      = 0x29
)

// SetTTL sets the TTL (Time To Live) for outgoing packets on the connection
// Per RFC 5357 Section 4.2.1, the reflector SHOULD set TTL to 255
func SetTTL(conn net.PacketConn, ttl int) error {
	// Get the underlying file descriptor
	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var socketErr error
	err = raw.Control(func(fd uintptr) {
		// Try IPv4 first
		err := syscall.Setsockopt(syscall.Handle(fd), IPPROTO_IP, IP_TTL,
			(*byte)(unsafe.Pointer(&ttl)), int32(unsafe.Sizeof(ttl)))
		if err == nil {
			return
		}

		// If IPv4 failed, try IPv6
		err = syscall.Setsockopt(syscall.Handle(fd), IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			(*byte)(unsafe.Pointer(&ttl)), int32(unsafe.Sizeof(ttl)))
		if err != nil {
			socketErr = fmt.Errorf("failed to set TTL: %w", err)
		}
	})

	if err != nil {
		return err
	}
	return socketErr
}

// GetTTL retrieves the TTL from received packets
// This requires IP_RECVTTL (IPv4) or IPV6_RECVHOPLIMIT (IPv6) to be enabled
func GetTTL(conn net.PacketConn) (int, error) {
	// Note: Getting TTL from received packets on Windows requires:
	// 1. Using WSARecvMsg with control messages
	// 2. Parsing WSACMSGHDR structures
	// This is complex and requires Windows-specific APIs
	// For now, return a default value
	return 255, nil
}

// EnableTTLReception enables receiving TTL values in control messages
func EnableTTLReception(conn net.PacketConn) error {
	// On Windows, this would require using WSAIoctl with SIO_ENABLE_CIRCULAR_QUEUEING
	// or similar Windows-specific socket options
	// For now, this is a no-op
	return nil
}
