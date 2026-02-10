package common

import (
	"errors"
	"net"
)

// RFC 4594 / RFC 5127 DiffServ code‑points.
// Values are already left‑shifted into the upper 6 bits of the IPv4 TOS / IPv6
// Traffic‑Class field, ready for use with IP_TOS or IPV6_TCLASS.
const (
	BE uint8 = 0x00 // Best Effort

	CS1  uint8 = 0x20 // Class Selector 1 (scavenger)
	AF11 uint8 = 0x28
	AF12 uint8 = 0x30
	AF13 uint8 = 0x38

	CS2  uint8 = 0x40 // typically OAM / low‑priority control
	AF21 uint8 = 0x48
	AF22 uint8 = 0x50
	AF23 uint8 = 0x58

	CS3  uint8 = 0x60 // call‑signalling
	AF31 uint8 = 0x68
	AF32 uint8 = 0x70
	AF33 uint8 = 0x78

	CS4  uint8 = 0x80 // real‑time multimedia
	AF41 uint8 = 0x88
	AF42 uint8 = 0x90
	AF43 uint8 = 0x98

	CS5 uint8 = 0xA0 // interactive voice (VoIP)
	EF  uint8 = 0xB8 // Expedited Forwarding – strict priority

	CS6 uint8 = 0xC0 // network control
	CS7 uint8 = 0xE0 // network control (highest)
)

var ErrUnsupportedConn = errors.New("dscp: connection type not supported")

// SetDSCP sets the Differentiated‑Services Code‑Point on an
// already‑open UDP/TCP connection. Pass the 6‑bit DSCP value
// (e.g. AF41 = 0x2a, EF = 0x2e). Returns an error if the platform
// doesn’t support it or if the socket family is not AF_INET / AF_INET6.
func SetDSCP(c net.Conn, dscp uint8) error {
	pc, ok := c.(*net.UDPConn)
	if !ok {
		if tcp, ok := c.(*net.TCPConn); ok {
			pc = (*net.UDPConn)(tcp) // both satisfy syscall.RawConn
		} else {
			return ErrUnsupportedConn
		}
	}
	raw, err := pc.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	ctrlFn := func(fd uintptr) {
		opErr = platformSetDSCP(fd, dscp)
	}
	if err := raw.Control(ctrlFn); err != nil {
		return err
	}
	return opErr
}
