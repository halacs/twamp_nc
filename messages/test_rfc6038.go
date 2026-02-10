// pkg/twamp/messages/test_rfc6038.go
// RFC 6038: TWAMP Reflect Octets and Symmetrical Size Features

package messages

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/ncode/twamp/common"
)

// SenderTestPacketReflectOctets represents a TWAMP-Test packet with reflect octets mode
// RFC 6038 Section 3 - Reflect Octets Feature
type SenderTestPacketReflectOctets struct {
	SeqNumber     uint32
	Timestamp     common.TWAMPTimestamp
	ErrorEstimate common.ErrorEstimate
	PaddingSize   int
	PaddingData   []byte // Actual padding content to be reflected
}

// SenderTestPacketAuthReflectOctets represents an authenticated/encrypted TWAMP-Test packet with reflect octets mode
// RFC 6038 Section 3 - Reflect Octets Feature for authenticated and encrypted modes
type SenderTestPacketAuthReflectOctets struct {
	SeqNumber     uint32
	MBZ           [12]byte // Must be zeros
	Timestamp     common.TWAMPTimestamp
	ErrorEstimate common.ErrorEstimate
	MBZ2          [6]byte  // Must be zeros
	HMAC          [16]byte // HMAC-SHA256 truncated to 16 bytes
	PaddingSize   int
	PaddingData   []byte // Actual padding content to be reflected (for authenticated/encrypted modes)
}

// Marshal converts SenderTestPacketAuthReflectOctets to network bytes
func (stpa *SenderTestPacketAuthReflectOctets) Marshal() ([]byte, error) {
	// Base size (48) + padding
	size := SenderTestPacketAuthMinSize + stpa.PaddingSize
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer for MBZ fields

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], stpa.SeqNumber)

	// MBZ (12 bytes) - already zeros

	// Timestamp (8 bytes)
	stpa.Timestamp.Marshal(buf[16:24])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[24:26], stpa.ErrorEstimate.ToUint16())

	// MBZ2 (6 bytes) - already zeros

	// HMAC (16 bytes)
	copy(buf[32:48], stpa.HMAC[:])

	// Padding with actual data (not zeros)
	if stpa.PaddingSize > 0 {
		if stpa.PaddingData != nil && len(stpa.PaddingData) >= stpa.PaddingSize {
			copy(buf[SenderTestPacketAuthMinSize:], stpa.PaddingData[:stpa.PaddingSize])
		} else {
			// Generate random padding if not provided
			if _, err := rand.Read(buf[SenderTestPacketAuthMinSize:]); err != nil {
				return nil, err
			}
		}
	}

	return buf, nil
}

// Unmarshal parses network bytes into SenderTestPacketAuthReflectOctets
func (stpa *SenderTestPacketAuthReflectOctets) Unmarshal(data []byte) error {
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

	// Validate MBZ2
	if err := validateMBZ(data, 26, 32); err != nil {
		return err
	}

	// Extract HMAC
	copy(stpa.HMAC[:], data[32:48])

	// Extract padding data
	if len(data) > SenderTestPacketAuthMinSize {
		stpa.PaddingSize = len(data) - SenderTestPacketAuthMinSize
		stpa.PaddingData = make([]byte, stpa.PaddingSize)
		copy(stpa.PaddingData, data[SenderTestPacketAuthMinSize:])
	}

	return nil
}

// Marshal converts SenderTestPacketReflectOctets to network bytes
// In reflect octets mode, padding contains data that the reflector must preserve
func (stp *SenderTestPacketReflectOctets) Marshal() ([]byte, error) {
	// Base size + padding
	size := SenderTestPacketMinSize + stp.PaddingSize
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer first

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], stp.SeqNumber)

	// Timestamp (8 bytes)
	stp.Timestamp.Marshal(buf[4:12])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[12:SenderTestPacketMinSize], stp.ErrorEstimate.ToUint16())

	// Padding with actual data (not zeros)
	if stp.PaddingSize > 0 {
		if stp.PaddingData != nil && len(stp.PaddingData) >= stp.PaddingSize {
			copy(buf[SenderTestPacketMinSize:], stp.PaddingData[:stp.PaddingSize])
		} else {
			// Generate random padding if not provided
			if _, err := rand.Read(buf[SenderTestPacketMinSize:]); err != nil {
				return nil, err
			}
		}
	}

	return buf, nil
}

// Unmarshal parses network bytes into SenderTestPacketReflectOctets
func (stp *SenderTestPacketReflectOctets) Unmarshal(data []byte) error {
	if len(data) < SenderTestPacketMinSize {
		return common.ErrInvalidMessageLength
	}

	// Sequence Number (4 bytes)
	stp.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Timestamp (8 bytes)
	stp.Timestamp.Unmarshal(data[4:12])

	// Error Estimate (2 bytes)
	ee := uint16(0)
	ee = binary.BigEndian.Uint16(data[12:SenderTestPacketMinSize])
	stp.ErrorEstimate.FromUint16(ee)

	// Extract padding data
	if len(data) > SenderTestPacketMinSize {
		stp.PaddingSize = len(data) - SenderTestPacketMinSize
		stp.PaddingData = make([]byte, stp.PaddingSize)
		copy(stp.PaddingData, data[SenderTestPacketMinSize:])
	}

	return nil
}

// ReflectorTestPacketReflectOctets represents a reflector packet with reflect octets mode
// RFC 6038 Section 3 - Reflect Octets Feature
type ReflectorTestPacketReflectOctets struct {
	SeqNumber           uint32
	Timestamp           common.TWAMPTimestamp
	ErrorEstimate       common.ErrorEstimate
	MBZ1                uint16
	ReceiveTimestamp    common.TWAMPTimestamp
	SenderSeqNumber     uint32
	SenderTimestamp     common.TWAMPTimestamp
	SenderErrorEstimate common.ErrorEstimate
	MBZ2                uint16
	SenderTTL           uint8
	ReflectedPadding    []byte // Padding data copied from sender
}

// ReflectorTestPacketAuthReflectOctets represents an authenticated/encrypted reflector packet with reflect octets mode
// RFC 6038 Section 3 - Reflect Octets Feature for authenticated and encrypted modes
type ReflectorTestPacketAuthReflectOctets struct {
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
	MBZ6                [3]byte  // Must be zeros for padding
	HMAC                [16]byte // HMAC-SHA256 truncated to 16 bytes
	ReflectedPadding    []byte   // Padding data copied from sender
}

// Marshal converts ReflectorTestPacketAuthReflectOctets to network bytes
func (rtpa *ReflectorTestPacketAuthReflectOctets) Marshal() ([]byte, error) {
	// Base size (112) + reflected padding
	size := ReflectorTestPacketAuthMinSize + len(rtpa.ReflectedPadding)
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer for MBZ fields

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], rtpa.SeqNumber)

	// MBZ (12 bytes) - already zeros

	// Timestamp (8 bytes)
	rtpa.Timestamp.Marshal(buf[16:24])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[24:26], rtpa.ErrorEstimate.ToUint16())

	// MBZ2 (6 bytes) - already zeros

	// Receive Timestamp (8 bytes)
	rtpa.ReceiveTimestamp.Marshal(buf[32:40])

	// MBZ3 (8 bytes) - already zeros

	// Sender Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[48:52], rtpa.SenderSeqNumber)

	// MBZ4 (12 bytes) - already zeros

	// Sender Timestamp (8 bytes)
	rtpa.SenderTimestamp.Marshal(buf[64:72])

	// Sender Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[72:74], rtpa.SenderErrorEstimate.ToUint16())

	// MBZ5 (6 bytes) - already zeros

	// Sender TTL (1 byte)
	buf[80] = rtpa.SenderTTL

	// MBZ6 (3 bytes) - already zeros for padding

	// HMAC placeholder (16 bytes) - to be calculated by crypto layer
	copy(buf[96:112], rtpa.HMAC[:])

	// Reflected padding (copy from sender)
	if len(rtpa.ReflectedPadding) > 0 {
		copy(buf[ReflectorTestPacketAuthMinSize:], rtpa.ReflectedPadding)
	}

	return buf, nil
}

// Marshal converts ReflectorTestPacketReflectOctets to network bytes
// In reflect octets mode, padding is copied from the sender packet
func (rtp *ReflectorTestPacketReflectOctets) Marshal() ([]byte, error) {
	// Base size + reflected padding
	size := ReflectorTestPacketMinSize + len(rtp.ReflectedPadding)
	buf := common.PacketBufferPool.Get()[:size]
	clear(buf) // Zero the buffer first

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], rtp.SeqNumber)

	// Timestamp (8 bytes)
	rtp.Timestamp.Marshal(buf[4:12])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[12:SenderTestPacketMinSize], rtp.ErrorEstimate.ToUint16())

	// MBZ1 (2 bytes, already zero)

	// Receive Timestamp (8 bytes)
	rtp.ReceiveTimestamp.Marshal(buf[16:24])

	// Sender Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[24:28], rtp.SenderSeqNumber)

	// Sender Timestamp (8 bytes)
	rtp.SenderTimestamp.Marshal(buf[28:36])

	// Sender Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[36:38], rtp.SenderErrorEstimate.ToUint16())

	// MBZ2 (2 bytes, already zero)

	// Sender TTL (1 byte)
	buf[40] = rtp.SenderTTL

	// Reflected padding (copy from sender)
	if len(rtp.ReflectedPadding) > 0 {
		copy(buf[ReflectorTestPacketMinSize:], rtp.ReflectedPadding)
	}

	return buf, nil
}

// Unmarshal parses network bytes into ReflectorTestPacketReflectOctets
func (rtp *ReflectorTestPacketReflectOctets) Unmarshal(data []byte) error {
	if len(data) < ReflectorTestPacketMinSize {
		return common.ErrInvalidMessageLength
	}

	// Sequence Number (4 bytes)
	rtp.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Timestamp (8 bytes)
	rtp.Timestamp.Unmarshal(data[4:12])

	// Error Estimate (2 bytes)
	ee := binary.BigEndian.Uint16(data[12:SenderTestPacketMinSize])
	rtp.ErrorEstimate.FromUint16(ee)

	// MBZ1 (2 bytes)
	rtp.MBZ1 = binary.BigEndian.Uint16(data[SenderTestPacketMinSize:16])
	if rtp.MBZ1 != 0 {
		return common.ErrInvalidMBZ
	}

	// Receive Timestamp (8 bytes)
	rtp.ReceiveTimestamp.Unmarshal(data[16:24])

	// Sender Sequence Number (4 bytes)
	rtp.SenderSeqNumber = binary.BigEndian.Uint32(data[24:28])

	// Sender Timestamp (8 bytes)
	rtp.SenderTimestamp.Unmarshal(data[28:36])

	// Sender Error Estimate (2 bytes)
	senderEE := binary.BigEndian.Uint16(data[36:38])
	rtp.SenderErrorEstimate.FromUint16(senderEE)

	// MBZ2 (2 bytes)
	rtp.MBZ2 = binary.BigEndian.Uint16(data[38:40])
	if rtp.MBZ2 != 0 {
		return common.ErrInvalidMBZ
	}

	// Sender TTL (1 byte)
	rtp.SenderTTL = data[40]

	// Extract reflected padding
	if len(data) > ReflectorTestPacketMinSize {
		rtp.ReflectedPadding = make([]byte, len(data)-ReflectorTestPacketMinSize)
		copy(rtp.ReflectedPadding, data[ReflectorTestPacketMinSize:])
	}

	return nil
}

// CalculateSymmetricalPadding calculates the padding needed for symmetrical size mode
// RFC 6038 Section 4 - Symmetrical Size Feature
func CalculateSymmetricalPadding(senderPacketSize int) int {
	// Reflector packet minimum size is ReflectorTestPacketMinSize bytes (unauthenticated)
	// Sender packet minimum size is SenderTestPacketMinSize bytes (unauthenticated)
	// To make them symmetrical, reflector needs padding of:
	// senderPacketSize - ReflectorTestPacketMinSize (if sender is larger than ReflectorTestPacketMinSize)
	// Otherwise, reflector uses no padding

	if senderPacketSize > ReflectorTestPacketMinSize {
		return senderPacketSize - ReflectorTestPacketMinSize
	}
	return 0
}

// CalculateSymmetricalPaddingAuth calculates padding for authenticated mode
// RFC 6038 Section 4 - Symmetrical Size Feature
func CalculateSymmetricalPaddingAuth(senderPacketSize int) int {
	// Reflector packet minimum size is ReflectorTestPacketAuthMinSize bytes (authenticated)
	// Sender packet minimum size is 48 bytes (authenticated)
	// To make them symmetrical, reflector needs padding of:
	// senderPacketSize - ReflectorTestPacketAuthMinSize (if sender is larger than ReflectorTestPacketAuthMinSize)
	// Otherwise, reflector uses no padding

	if senderPacketSize > ReflectorTestPacketAuthMinSize {
		return senderPacketSize - ReflectorTestPacketAuthMinSize
	}
	return 0
}

// CreateRFC6038SymmetricalReflectorPacket creates a reflector packet with symmetrical size
// RFC 6038 Section 4 - This ensures both directions have equal-sized packets
func CreateRFC6038SymmetricalReflectorPacket(senderPacket *SenderTestPacket, senderPacketSize int) *ReflectorTestPacket {
	paddingSize := CalculateSymmetricalPadding(senderPacketSize)

	return &ReflectorTestPacket{
		SenderSeqNumber:     senderPacket.SeqNumber,
		SenderTimestamp:     senderPacket.Timestamp,
		SenderErrorEstimate: senderPacket.ErrorEstimate,
		PaddingSize:         paddingSize,
	}
}

// CreateRFC6038ReflectOctetsReflectorPacket creates a reflector packet with reflected padding
// RFC 6038 Section 3 - This preserves the sender's padding content
func CreateRFC6038ReflectOctetsReflectorPacket(senderPacket *SenderTestPacketReflectOctets) *ReflectorTestPacketReflectOctets {
	return &ReflectorTestPacketReflectOctets{
		SenderSeqNumber:     senderPacket.SeqNumber,
		SenderTimestamp:     senderPacket.Timestamp,
		SenderErrorEstimate: senderPacket.ErrorEstimate,
		ReflectedPadding:    senderPacket.PaddingData,
	}
}
