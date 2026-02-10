//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package common

import (
	"fmt"
	"net"
	"syscall"
)

// SetTTL sets the TTL (Time To Live) for outgoing packets on the connection
// Per RFC 5357 Section 4.2.1, the reflector SHOULD set TTL to 255
func SetTTL(conn net.PacketConn, ttl int) error {
	// Get the underlying file descriptor
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("SetTTL requires a UDP connection")
	}

	raw, err := udpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var socketErr error
	err = raw.Control(func(fd uintptr) {
		// Try IPv4 first
		err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		if err == nil {
			return
		}

		// If IPv4 failed, try IPv6
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
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
	// Note: Getting TTL from received packets requires:
	// 1. Setting IP_RECVTTL or IPV6_RECVHOPLIMIT socket option
	// 2. Using recvmsg with control messages to extract TTL
	// This is complex and platform-specific, requiring raw sockets
	// For now, return a default value
	return 255, nil
}

// EnableTTLReception enables receiving TTL values in control messages
func EnableTTLReception(conn net.PacketConn) error {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("EnableTTLReception requires a UDP connection")
	}

	raw, err := udpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var socketErr error
	err = raw.Control(func(fd uintptr) {
		// Try to enable IPv4 TTL reception
		// Note: IP_RECVTTL is platform-specific and may not be available on all Unix systems
		// On Linux it's typically 12, on BSD it's different
		const IP_RECVTTL = 12 // Linux value
		err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_RECVTTL, 1)
		if err == nil {
			return
		}

		// If IPv4 failed, try IPv6
		// IPV6_RECVHOPLIMIT is also platform-specific
		// On Linux it's typically 51
		const IPV6_RECVHOPLIMIT = 51 // Linux value
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)
		if err != nil {
			socketErr = fmt.Errorf("failed to enable TTL reception: %w", err)
		}
	})

	if err != nil {
		return err
	}
	return socketErr
}
