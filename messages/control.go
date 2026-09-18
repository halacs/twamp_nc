package messages

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ncode/twamp/common"
)

// Message size constants as per RFC specifications
const (
	ServerGreetingSize       = 64  // RFC 4656 Section 3.1
	SetupResponseSize        = 164 // RFC 4656 Section 3.2
	ServerStartSize          = 48  // RFC 4656 Section 3.3
	RequestTWSessionSize     = 112 // RFC 5357 Section 3.5 (with HMAC)
	RequestTWSessionSizeAuth = 112 // RFC 5357 Section 3.5 (fixed length)
	AcceptSessionSize        = 48  // RFC 5357 Section 3.6 (with HMAC)
	AcceptSessionSizeAuth    = 48  // RFC 5357 Section 3.6 (fixed length)
	StartSessionsSize        = 32  // RFC 5357 Section 3.7 (with HMAC)
	StartSessionsSizeAuth    = 32  // RFC 5357 Section 3.7 (fixed length)
	StartAckSize             = 32  // RFC 5357 Section 3.8 (with HMAC)
	StartAckSizeAuth         = 32  // RFC 5357 Section 3.8 (fixed length)
	StopSessionsSize         = 32  // RFC 5357 Section 3.8 (with HMAC)
	StopSessionsSizeAuth     = 32  // RFC 5357 Section 3.8 (fixed length)
)

// validateMBZ validates that Must-Be-Zero fields are actually zero
func validateMBZ(data []byte, start, end int) error {
	for i := start; i < end; i++ {
		if data[i] != 0 {
			return common.ErrInvalidMBZ
		}
	}
	return nil
}

// validateTypePDescriptor validates the Type-P Descriptor field per RFC 5357 Section 3.5
// The 32-bit Type-P Descriptor has the following format:
//
//	Bits 0-7 (byte 0): Padding, must be zero
//	Bits 8-15 (byte 1): DSCP value in top 6 bits, lower 2 bits MBZ
//	Bits 16-31 (bytes 2-3): Reserved for future use, MBZ
func validateTypePDescriptor(descriptor uint32) error {
	// Check byte 0 (bits 24-31 when viewed as big-endian): must be zero
	if paddingByte := (descriptor >> 24) & 0xFF; paddingByte != 0 {
		return fmt.Errorf("Type-P descriptor padding byte must be zero, got 0x%02X", paddingByte)
	}

	// Check byte 1 (bits 16-23): lower 2 bits must be zero
	// The DSCP value occupies the upper 6 bits (values 0-63), lower 2 bits are MBZ
	// Note: No explicit DSCP range validation needed - the 6-bit extraction
	// via ((descriptor >> 16) & 0xFF) >> 2 mathematically guarantees 0-63 range
	if (descriptor>>16)&0x03 != 0 {
		return errors.New("Type-P descriptor DSCP field lower 2 bits must be zero")
	}

	// Check bytes 2-3 (bits 0-15): must be zero (reserved)
	if descriptor&0xFFFF != 0 {
		return errors.New("Type-P descriptor reserved bytes must be zero")
	}

	return nil
}

// ServerGreeting represents the first message in TWAMP-Control
// RFC 4656 Section 3.1 - Total size is 64 bytes
type ServerGreeting struct {
	Unused    [12]byte // Must be zeros
	Modes     uint32
	Challenge [16]byte
	Salt      [16]byte
	Count     uint32
	MBZ       [12]byte // Must be zeros
}

// Marshal converts ServerGreeting to network bytes
func (sg *ServerGreeting) Marshal() ([]byte, error) {
	buf := make([]byte, ServerGreetingSize)

	// First 12 bytes must be zeros (already zeros from make)

	// Modes (4 bytes)
	binary.BigEndian.PutUint32(buf[12:16], sg.Modes)

	// Challenge (16 bytes)
	copy(buf[16:32], sg.Challenge[:])

	// Salt (16 bytes)
	copy(buf[32:48], sg.Salt[:])

	// Count (4 bytes)
	binary.BigEndian.PutUint32(buf[48:52], sg.Count)

	// Last 12 bytes are MBZ (already zeros from make)

	return buf, nil
}

// Unmarshal parses network bytes into ServerGreeting
func (sg *ServerGreeting) Unmarshal(data []byte) error {
	if len(data) < ServerGreetingSize {
		return common.ErrInvalidMessageLength
	}

	// Check that MBZ fields are zeros
	if err := validateMBZ(data, 0, 12); err != nil {
		return err
	}

	if err := validateMBZ(data, 52, 64); err != nil {
		return err
	}

	// Extract Modes
	sg.Modes = binary.BigEndian.Uint32(data[12:16])

	// Extract Challenge
	copy(sg.Challenge[:], data[16:32])

	// Extract Salt
	copy(sg.Salt[:], data[32:48])

	// Extract Count
	sg.Count = binary.BigEndian.Uint32(data[48:52])

	return nil
}

// SetupResponse is the client's response to a ServerGreeting
type SetupResponse struct {
	Mode     uint32
	KeyID    [80]byte
	Token    [64]byte
	ClientIV [16]byte
}

// Marshal converts SetupResponse to network bytes
func (sr *SetupResponse) Marshal() ([]byte, error) {
	buf := make([]byte, SetupResponseSize)
	// No need to zero - no MBZ fields in SetupResponse

	// Mode (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], sr.Mode)

	// KeyID (80 bytes)
	copy(buf[4:84], sr.KeyID[:])

	// Token (64 bytes)
	copy(buf[84:148], sr.Token[:])

	// ClientIV (16 bytes)
	copy(buf[148:164], sr.ClientIV[:])

	return buf, nil
}

// Unmarshal parses network bytes into SetupResponse
func (sr *SetupResponse) Unmarshal(data []byte) error {
	if len(data) < SetupResponseSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Mode
	sr.Mode = binary.BigEndian.Uint32(data[0:4])

	// Extract KeyID
	copy(sr.KeyID[:], data[4:84])

	// Extract Token
	copy(sr.Token[:], data[84:148])

	// Extract ClientIV
	copy(sr.ClientIV[:], data[148:164])

	return nil
}

// ServerStart is the server's response to a SetupResponse
type ServerStart struct {
	MBZ       [15]byte // Must be zeros
	Accept    uint8
	ServerIV  [16]byte
	StartTime common.TWAMPTimestamp
	MBZ2      [8]byte // Must be zeros
}

// Marshal converts ServerStart to network bytes
func (ss *ServerStart) Marshal() ([]byte, error) {
	buf := make([]byte, ServerStartSize)

	// First 15 bytes are MBZ (already zeros from make)

	// Accept (1 byte)
	buf[15] = ss.Accept

	// ServerIV (16 bytes)
	copy(buf[16:32], ss.ServerIV[:])

	// StartTime (8 bytes)
	ss.StartTime.Marshal(buf[32:40])

	// Last 8 bytes are MBZ (already zeros from make)

	return buf, nil
}

// Unmarshal parses network bytes into ServerStart
func (ss *ServerStart) Unmarshal(data []byte) error {
	if len(data) < ServerStartSize {
		return common.ErrInvalidMessageLength
	}

	// Check that MBZ fields are zeros
	if err := validateMBZ(data, 0, 15); err != nil {
		return err
	}

	if err := validateMBZ(data, 40, 48); err != nil {
		return err
	}

	// Extract Accept
	ss.Accept = data[15]

	// Extract ServerIV
	copy(ss.ServerIV[:], data[16:32])

	// Extract StartTime
	ss.StartTime.Unmarshal(data[32:40])

	return nil
}

// RequestTWSession represents a request for a new TWAMP test session
type RequestTWSession struct {
	Command         uint8
	MBZ1            uint8 // Must be zero (upper nibble of byte 1)
	IPVN            uint8
	ConfSender      uint8
	ConfReceiver    uint8
	MBZ2            [3]byte // Deprecated: retained for compatibility; not on wire
	NumSlots        uint32
	NumPackets      uint32
	SenderPort      uint16
	ReceiverPort    uint16
	SenderAddress   [16]byte
	ReceiverAddress [16]byte
	SID             common.SessionID
	PaddingLength   uint32
	StartTime       common.TWAMPTimestamp
	Timeout         common.TWAMPTimestamp
	TypePDescriptor uint32
	MBZ3            [8]byte  // Must be zeros
	HMAC            [16]byte // HMAC or zero in unauthenticated mode
}

// Marshal converts RequestTWSession to network bytes
func (rts *RequestTWSession) Marshal(includeHMAC bool) ([]byte, error) {
	size := RequestTWSessionSize
	if includeHMAC {
		size = RequestTWSessionSizeAuth
	}

	buf := make([]byte, size)

	// Command (1 byte)
	buf[0] = rts.Command

	// MBZ, IPVN (1 byte total) - RFC 5357 Section 3.5.
	// Bits 7-4: MBZ, bits 3-0: IPVN.
	buf[1] = rts.IPVN & 0x0F

	// ConfSender (1 byte)
	buf[2] = rts.ConfSender

	// ConfReceiver (1 byte)
	buf[3] = rts.ConfReceiver

	// NumSlots (4 bytes)
	binary.BigEndian.PutUint32(buf[4:8], rts.NumSlots)

	// NumPackets (4 bytes)
	binary.BigEndian.PutUint32(buf[8:12], rts.NumPackets)

	// SenderPort (2 bytes)
	binary.BigEndian.PutUint16(buf[12:14], rts.SenderPort)

	// ReceiverPort (2 bytes)
	binary.BigEndian.PutUint16(buf[14:16], rts.ReceiverPort)

	// SenderAddress (16 bytes)
	copy(buf[16:32], rts.SenderAddress[:])

	// ReceiverAddress (16 bytes)
	copy(buf[32:48], rts.ReceiverAddress[:])

	// SID (16 bytes)
	copy(buf[48:64], rts.SID[:])

	// PaddingLength (4 bytes)
	binary.BigEndian.PutUint32(buf[64:68], rts.PaddingLength)

	// StartTime (8 bytes)
	rts.StartTime.Marshal(buf[68:76])

	// Timeout (8 bytes)
	rts.Timeout.Marshal(buf[76:84])

	// TypePDescriptor (4 bytes)
	binary.BigEndian.PutUint32(buf[84:88], rts.TypePDescriptor)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[96:112], rts.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into RequestTWSession
func (rts *RequestTWSession) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := RequestTWSessionSize
	if includeHMAC {
		minSize = RequestTWSessionSizeAuth
	}

	if len(data) < minSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Command
	rts.Command = data[0]

	// Extract MBZ, IPVN - RFC 5357 Section 3.5.
	// Bits 7-4: MBZ (must be zero), bits 3-0: IPVN.
	if data[1]&0xF0 != 0 {
		return common.ErrInvalidMBZ
	}
	rts.IPVN = data[1] & 0x0F
	if rts.IPVN != 4 && rts.IPVN != 6 {
		return common.ErrInvalidIPVN
	}

	// Extract ConfSender
	rts.ConfSender = data[2]

	// Extract ConfReceiver
	rts.ConfReceiver = data[3]

	// Extract NumSlots
	rts.NumSlots = binary.BigEndian.Uint32(data[4:8])

	// Extract NumPackets
	rts.NumPackets = binary.BigEndian.Uint32(data[8:12])

	// RFC 5357 Section 3.5: NumSlots and NumPackets are OWAMP-only fields
	// These MUST be zero in TWAMP
	if rts.NumSlots != 0 {
		return common.ErrInvalidNumSlots
	}
	if rts.NumPackets != 0 {
		return common.ErrInvalidNumPackets
	}

	// Extract SenderPort
	rts.SenderPort = binary.BigEndian.Uint16(data[12:14])

	// Extract ReceiverPort
	rts.ReceiverPort = binary.BigEndian.Uint16(data[14:16])

	// Extract SenderAddress
	copy(rts.SenderAddress[:], data[16:32])

	// Extract ReceiverAddress
	copy(rts.ReceiverAddress[:], data[32:48])

	// Extract SID
	copy(rts.SID[:], data[48:64])

	// Extract PaddingLength
	rts.PaddingLength = binary.BigEndian.Uint32(data[64:68])

	// Validate PaddingLength doesn't exceed maximum allowed
	// RFC 5357 Section 4.1.2 implies padding should be reasonable
	// Base test packet is 14 bytes (unauthenticated) or larger (authenticated/encrypted)
	// Total packet size should not exceed MaxTWAMPPacketSize
	if rts.PaddingLength > uint32(common.MaxTWAMPPacketSize) {
		return common.ErrInvalidPaddingLength
	}

	// Extract StartTime
	rts.StartTime.Unmarshal(data[68:76])

	// Extract Timeout
	rts.Timeout.Unmarshal(data[76:84])

	// Extract TypePDescriptor
	rts.TypePDescriptor = binary.BigEndian.Uint32(data[84:88])

	// Validate Type-P Descriptor per RFC 5357 Section 3.5
	// Bits 0-7 (byte 0): Padding, must be zero
	// Bits 8-15 (byte 1): DSCP value in top 6 bits, lower 2 bits MBZ
	// Bits 16-31 (bytes 2-3): Reserved for future use, MBZ
	if err := validateTypePDescriptor(rts.TypePDescriptor); err != nil {
		return err
	}

	// Validate MBZ3 bytes (88-95 for 8-byte MBZ field)
	if err := validateMBZ(data, 88, 96); err != nil {
		return err
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(rts.HMAC[:], data[96:112])
	} else if err := validateMBZ(data, 96, 112); err != nil {
		return err
	}

	return nil
}

// AcceptSession is the server's response to a RequestTWSession
type AcceptSession struct {
	Accept uint8
	MBZ    uint8
	Port   uint16
	SID    common.SessionID
	MBZ2   [12]byte // Must be zeros
	HMAC   [16]byte // Optional, based on mode
}

// Marshal converts AcceptSession to network bytes
func (as *AcceptSession) Marshal(includeHMAC bool) ([]byte, error) {
	size := AcceptSessionSize
	if includeHMAC {
		size = AcceptSessionSizeAuth
	}

	buf := make([]byte, size)

	// Accept (1 byte)
	buf[0] = as.Accept

	// MBZ (1 byte, already zeros from make)

	// Port (2 bytes)
	binary.BigEndian.PutUint16(buf[2:4], as.Port)

	// SID (16 bytes)
	copy(buf[4:20], as.SID[:])

	// MBZ (12 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[32:48], as.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into AcceptSession
func (as *AcceptSession) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := AcceptSessionSize
	if includeHMAC {
		minSize = AcceptSessionSizeAuth
	}

	if len(data) < minSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Accept
	as.Accept = data[0]

	// Extract MBZ (and validate)
	as.MBZ = data[1]
	if as.MBZ != 0 {
		return common.ErrInvalidMBZ
	}

	// Extract Port
	as.Port = binary.BigEndian.Uint16(data[2:4])

	// Extract SID
	copy(as.SID[:], data[4:20])

	// Skip MBZ bytes (20-31), but validate they're zero
	if err := validateMBZ(data, 20, 32); err != nil {
		return err
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(as.HMAC[:], data[32:48])
	} else if err := validateMBZ(data, 32, 48); err != nil {
		return err
	}

	return nil
}

// StartSessions command to start all previously requested sessions
type StartSessions struct {
	Command uint8
	MBZ     [15]byte // Must be zeros
	HMAC    [16]byte // Optional, based on mode
}

// Marshal converts StartSessions to network bytes
func (ss *StartSessions) Marshal(includeHMAC bool) ([]byte, error) {
	size := StartSessionsSize
	if includeHMAC {
		size = StartSessionsSizeAuth
	}

	buf := make([]byte, size)

	// Command (1 byte)
	buf[0] = ss.Command

	// MBZ (15 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[16:32], ss.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into StartSessions
func (ss *StartSessions) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := StartSessionsSize
	if includeHMAC {
		minSize = StartSessionsSizeAuth
	}

	if len(data) < minSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Command
	ss.Command = data[0]

	// Skip MBZ bytes (1-15), but validate they're zero
	if err := validateMBZ(data, 1, 16); err != nil {
		return err
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(ss.HMAC[:], data[16:32])
	} else if err := validateMBZ(data, 16, 32); err != nil {
		return err
	}

	return nil
}

// StartAck is the server's response to a StartSessions command
type StartAck struct {
	Accept uint8
	MBZ    [15]byte // Must be zeros
	HMAC   [16]byte // Optional, based on mode
}

// Marshal converts StartAck to network bytes
func (sa *StartAck) Marshal(includeHMAC bool) ([]byte, error) {
	size := StartAckSize
	if includeHMAC {
		size = StartAckSizeAuth
	}

	buf := make([]byte, size)

	// Accept (1 byte)
	buf[0] = sa.Accept

	// MBZ (15 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[16:32], sa.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into StartAck
func (sa *StartAck) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := StartAckSize
	if includeHMAC {
		minSize = StartAckSizeAuth
	}

	if len(data) < minSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Accept
	sa.Accept = data[0]

	// Skip MBZ bytes (1-15), but validate they're zero
	if err := validateMBZ(data, 1, 16); err != nil {
		return err
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(sa.HMAC[:], data[16:32])
	} else if err := validateMBZ(data, 16, 32); err != nil {
		return err
	}

	return nil
}

// StopSessions command to stop all running test sessions
// RFC 5357 Section 3.8
//
// Message format (32 bytes with HMAC):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|      3        |    Accept     |              MBZ              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                      Number of Sessions                       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        MBZ (8 octets)                         |
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                       HMAC (16 octets)                        |
//	...
type StopSessions struct {
	Command     uint8
	Accept      uint8    // Accept code (0 = OK, non-zero = failure)
	MBZ1        [2]byte  // Must be zeros
	NumSessions uint32   // Number of sessions to stop (MUST match active sessions)
	MBZ2        [8]byte  // Must be zeros
	HMAC        [16]byte // Optional, based on mode
}

// Marshal converts StopSessions to network bytes
// RFC 5357 Section 3.8 format:
// - Byte 0: Command (3)
// - Byte 1: Accept
// - Bytes 2-3: MBZ
// - Bytes 4-7: Number of Sessions
// - Bytes 8-15: MBZ
// - Bytes 16-31: HMAC
func (ss *StopSessions) Marshal(includeHMAC bool) ([]byte, error) {
	size := StopSessionsSize
	if includeHMAC {
		size = StopSessionsSizeAuth
	}

	buf := make([]byte, size)

	// Command (1 byte)
	buf[0] = ss.Command

	// Accept (1 byte)
	buf[1] = ss.Accept

	// MBZ1 (2 bytes) - already zeros from make

	// Number of Sessions (4 bytes, big-endian)
	binary.BigEndian.PutUint32(buf[4:8], ss.NumSessions)

	// MBZ2 (8 bytes) - already zeros from make

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[16:32], ss.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into StopSessions
// RFC 5357 Section 3.8 format:
// - Byte 0: Command (3)
// - Byte 1: Accept
// - Bytes 2-3: MBZ
// - Bytes 4-7: Number of Sessions
// - Bytes 8-15: MBZ
// - Bytes 16-31: HMAC
func (ss *StopSessions) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := StopSessionsSize
	if includeHMAC {
		minSize = StopSessionsSizeAuth
	}

	if len(data) < minSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Command
	ss.Command = data[0]

	// Extract Accept
	ss.Accept = data[1]

	// Validate MBZ1 bytes (2-3)
	if err := validateMBZ(data, 2, 4); err != nil {
		return err
	}

	// Extract Number of Sessions
	ss.NumSessions = binary.BigEndian.Uint32(data[4:8])

	// Validate MBZ2 bytes (8-15)
	if err := validateMBZ(data, 8, 16); err != nil {
		return err
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(ss.HMAC[:], data[16:32])
	} else if err := validateMBZ(data, 16, 32); err != nil {
		return err
	}

	return nil
}
