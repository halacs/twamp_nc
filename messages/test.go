package messages

import (
	"encoding/binary"

	"github.com/ncode/twamp/common"
)

// Test message size constants as per RFC 5357
const (
	SenderTestPacketMinSize        = 14  // RFC 5357 Section 4.1.2 (unauthenticated)
	SenderTestPacketAuthMinSize    = 48  // RFC 5357 Section 4.1.2 (authenticated)
	ReflectorTestPacketMinSize     = 41  // RFC 5357 Section 4.2.1 (unauthenticated)
	ReflectorTestPacketAuthMinSize = 112 // RFC 5357 Section 4.2.1 (authenticated)
)

// SenderTestPacket represents the TWAMP-Test packet sent by Session-Sender
// in Unauthenticated mode (RFC 5357 Section 4.1.2)
type SenderTestPacket struct {
	SeqNumber     uint32
	Timestamp     common.TWAMPTimestamp
	ErrorEstimate common.ErrorEstimate
	// No TTL field in sender packet - TTL is set in IP header by sender
	// The reflector will extract the TTL from the received IP header and
	// include it in the response packet as per RFC 5357 Section 4.2.1
	PaddingSize int // Not part of the packet, but size info for padding
}

// Marshal converts SenderTestPacket to network bytes
// Unauthenticated mode uses zero padding as per RFC 5357
func (stp *SenderTestPacket) Marshal() ([]byte, error) {
	// Base size + padding
	size := 14 + stp.PaddingSize
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer for MBZ fields

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], stp.SeqNumber)

	// Timestamp (8 bytes)
	stp.Timestamp.Marshal(buf[4:12])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[12:14], stp.ErrorEstimate.ToUint16())

	// Unauthenticated mode uses zero padding
	// Buffer is already zero from make(), no action needed

	return buf, nil
}

// Unmarshal parses network bytes into SenderTestPacket
func (stp *SenderTestPacket) Unmarshal(data []byte) error {
	if len(data) < SenderTestPacketMinSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Sequence Number
	stp.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Extract Timestamp
	stp.Timestamp.Unmarshal(data[4:12])

	// Extract Error Estimate
	stp.ErrorEstimate.FromUint16(binary.BigEndian.Uint16(data[12:14]))

	// Record actual padding size
	stp.PaddingSize = len(data) - SenderTestPacketMinSize

	return nil
}

// SenderTestPacketAuth represents the authenticated/encrypted version
// of the SenderTestPacket
type SenderTestPacketAuth struct {
	SeqNumber     uint32
	MBZ           [12]byte // Must be zeros
	Timestamp     common.TWAMPTimestamp
	ErrorEstimate common.ErrorEstimate
	MBZ2          [6]byte // Must be zeros
	HMAC          [16]byte
	PaddingSize   int // Not part of the packet, but size info for padding
}

// Marshal converts SenderTestPacketAuth to network bytes
func (stpa *SenderTestPacketAuth) Marshal() ([]byte, error) {
	// Base size (48) + padding
	size := 48 + stpa.PaddingSize
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer for MBZ fields

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], stpa.SeqNumber)

	// MBZ (12 bytes, already zeros from make)

	// Timestamp (8 bytes)
	stpa.Timestamp.Marshal(buf[16:24])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[24:26], stpa.ErrorEstimate.ToUint16())

	// MBZ (6 bytes, already zeros from make)

	// HMAC (16 bytes)
	copy(buf[32:48], stpa.HMAC[:])

	// Fill padding with cryptographically secure random bytes
	// Required for security in authenticated/encrypted modes
	if stpa.PaddingSize > 0 {
		if err := FillRandomPadding(buf[48:]); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

// Unmarshal parses network bytes into SenderTestPacketAuth
func (stpa *SenderTestPacketAuth) Unmarshal(data []byte) error {
	if len(data) < SenderTestPacketAuthMinSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Sequence Number
	stpa.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Validate MBZ
	if err := validateMBZ(data, 4, 16); err != nil {
		return err
	}

	// Extract Timestamp
	stpa.Timestamp.Unmarshal(data[16:24])

	// Extract Error Estimate
	stpa.ErrorEstimate.FromUint16(binary.BigEndian.Uint16(data[24:26]))

	// Validate MBZ
	if err := validateMBZ(data, 26, 32); err != nil {
		return err
	}

	// Extract HMAC
	copy(stpa.HMAC[:], data[32:48])

	// Record actual padding size
	stpa.PaddingSize = len(data) - SenderTestPacketAuthMinSize

	return nil
}

// ReflectorTestPacket represents the TWAMP-Test packet sent by Session-Reflector
// in Unauthenticated mode
type ReflectorTestPacket struct {
	SeqNumber           uint32
	Timestamp           common.TWAMPTimestamp
	ErrorEstimate       common.ErrorEstimate
	MBZ                 [2]byte // Must be zeros
	ReceiveTimestamp    common.TWAMPTimestamp
	SenderSeqNumber     uint32
	SenderTimestamp     common.TWAMPTimestamp
	SenderErrorEstimate common.ErrorEstimate
	MBZ2                [2]byte // Must be zeros
	SenderTTL           uint8
	PaddingSize         int // Not part of the packet, but size info for padding
}

// Marshal converts ReflectorTestPacket to network bytes
func (rtp *ReflectorTestPacket) Marshal() ([]byte, error) {
	// Base size (41) + padding
	size := 41 + rtp.PaddingSize
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer for MBZ fields

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], rtp.SeqNumber)

	// Timestamp (8 bytes)
	rtp.Timestamp.Marshal(buf[4:12])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[12:14], rtp.ErrorEstimate.ToUint16())

	// MBZ (2 bytes, already zeros from make)

	// Receive Timestamp (8 bytes)
	rtp.ReceiveTimestamp.Marshal(buf[16:24])

	// Sender Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[24:28], rtp.SenderSeqNumber)

	// Sender Timestamp (8 bytes)
	rtp.SenderTimestamp.Marshal(buf[28:36])

	// Sender Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[36:38], rtp.SenderErrorEstimate.ToUint16())

	// MBZ (2 bytes, already zeros from make)

	// Sender TTL (1 byte)
	buf[40] = rtp.SenderTTL

	// Unauthenticated mode uses zero padding
	// Buffer is already zero from make(), no action needed

	return buf, nil
}

// Unmarshal parses network bytes into ReflectorTestPacket
func (rtp *ReflectorTestPacket) Unmarshal(data []byte) error {
	if len(data) < ReflectorTestPacketMinSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Sequence Number
	rtp.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Extract Timestamp
	rtp.Timestamp.Unmarshal(data[4:12])

	// Extract Error Estimate
	rtp.ErrorEstimate.FromUint16(binary.BigEndian.Uint16(data[12:14]))

	// Validate MBZ
	if err := validateMBZ(data, 14, 16); err != nil {
		return err
	}

	// Extract Receive Timestamp
	rtp.ReceiveTimestamp.Unmarshal(data[16:24])

	// Extract Sender Sequence Number
	rtp.SenderSeqNumber = binary.BigEndian.Uint32(data[24:28])

	// Extract Sender Timestamp
	rtp.SenderTimestamp.Unmarshal(data[28:36])

	// Extract Sender Error Estimate
	rtp.SenderErrorEstimate.FromUint16(binary.BigEndian.Uint16(data[36:38]))

	// Validate MBZ2
	if err := validateMBZ(data, 38, 40); err != nil {
		return err
	}

	// Extract Sender TTL
	rtp.SenderTTL = data[40]

	// Record actual padding size
	rtp.PaddingSize = len(data) - ReflectorTestPacketMinSize

	return nil
}

// ReflectorTestPacketAuth represents the authenticated/encrypted version
// of the ReflectorTestPacket
type ReflectorTestPacketAuth struct {
	SeqNumber           uint32
	MBZ                 [12]byte // Must be zeros
	Timestamp           common.TWAMPTimestamp
	ErrorEstimate       common.ErrorEstimate
	MBZ2                [6]byte // Must be zeros
	ReceiveTimestamp    common.TWAMPTimestamp
	MBZ3                [8]byte // Must be zeros
	SenderSeqNumber     uint32
	MBZ4                [12]byte // Must be zeros
	SenderTimestamp     common.TWAMPTimestamp
	SenderErrorEstimate common.ErrorEstimate
	MBZ5                [6]byte // Must be zeros
	SenderTTL           uint8
	MBZ6                [15]byte // Must be zeros
	HMAC                [16]byte
	PaddingSize         int // Not part of the packet, but size info for padding
}

// Marshal converts ReflectorTestPacketAuth to network bytes
func (rtpa *ReflectorTestPacketAuth) Marshal() ([]byte, error) {
	// Base size (112) + padding (to fit auth)
	minSize := 112
	size := minSize
	if rtpa.PaddingSize > 0 {
		size = minSize + rtpa.PaddingSize
	}
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer for MBZ fields

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], rtpa.SeqNumber)

	// MBZ (12 bytes, already zeros from make)

	// Timestamp (8 bytes)
	rtpa.Timestamp.Marshal(buf[16:24])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[24:26], rtpa.ErrorEstimate.ToUint16())

	// MBZ (6 bytes, already zeros from make)

	// Receive Timestamp (8 bytes)
	rtpa.ReceiveTimestamp.Marshal(buf[32:40])

	// MBZ (8 bytes, already zeros from make)

	// Sender Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[48:52], rtpa.SenderSeqNumber)

	// MBZ (12 bytes, already zeros from make)

	// Sender Timestamp (8 bytes)
	rtpa.SenderTimestamp.Marshal(buf[64:72])

	// Sender Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[72:74], rtpa.SenderErrorEstimate.ToUint16())

	// MBZ (6 bytes, already zeros from make)

	// Sender TTL (1 byte)
	buf[80] = rtpa.SenderTTL

	// MBZ (15 bytes, already zeros from make)

	// HMAC (16 bytes)
	copy(buf[96:112], rtpa.HMAC[:])

	// Fill padding with cryptographically secure random bytes
	// Required for security in authenticated/encrypted modes
	if rtpa.PaddingSize > 0 {
		if err := FillRandomPadding(buf[112:]); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

// Unmarshal parses network bytes into ReflectorTestPacketAuth
func (rtpa *ReflectorTestPacketAuth) Unmarshal(data []byte) error {
	if len(data) < ReflectorTestPacketAuthMinSize {
		return common.ErrInvalidMessageLength
	}

	// Extract Sequence Number
	rtpa.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Validate MBZ
	if err := validateMBZ(data, 4, 16); err != nil {
		return err
	}

	// Extract Timestamp
	rtpa.Timestamp.Unmarshal(data[16:24])

	// Extract Error Estimate
	rtpa.ErrorEstimate.FromUint16(binary.BigEndian.Uint16(data[24:26]))

	// Validate MBZ
	if err := validateMBZ(data, 26, 32); err != nil {
		return err
	}

	// Extract Receive Timestamp
	rtpa.ReceiveTimestamp.Unmarshal(data[32:40])

	// Validate MBZ
	if err := validateMBZ(data, 40, 48); err != nil {
		return err
	}

	// Extract Sender Sequence Number
	rtpa.SenderSeqNumber = binary.BigEndian.Uint32(data[48:52])

	// Validate MBZ
	if err := validateMBZ(data, 52, 64); err != nil {
		return err
	}

	// Extract Sender Timestamp
	rtpa.SenderTimestamp.Unmarshal(data[64:72])

	// Extract Sender Error Estimate
	rtpa.SenderErrorEstimate.FromUint16(binary.BigEndian.Uint16(data[72:74]))

	// Validate MBZ
	if err := validateMBZ(data, 74, 80); err != nil {
		return err
	}

	// Extract Sender TTL
	rtpa.SenderTTL = data[80]

	// Validate MBZ
	if err := validateMBZ(data, 81, 96); err != nil {
		return err
	}

	// Extract HMAC
	copy(rtpa.HMAC[:], data[96:112])

	// Record actual padding size
	rtpa.PaddingSize = len(data) - ReflectorTestPacketAuthMinSize

	return nil
}
