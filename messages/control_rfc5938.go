// pkg/twamp/messages/control_rfc5938.go
// RFC 5938: Individual Session Control Feature for TWAMP

package messages

import (
	"encoding/binary"
	"fmt"

	"github.com/ncode/twamp/common"
)

// StopNSessions command to stop specific test sessions
// RFC 5938 Section 3.4 - Individual Session Control
type StopNSessions struct {
	Command     uint8
	Accept      uint8
	MBZ1        [2]byte
	NumSessions uint32 // Number of sessions to stop
	MBZ2        [8]byte
	SessionIDs  []common.SessionID // Variable length array of session IDs
	HMAC        [16]byte           // Optional, based on mode
}

// Marshal converts StopNSessions to network bytes
func (sns *StopNSessions) Marshal(includeHMAC bool) ([]byte, error) {
	// Base size: 16 bytes + (NumSessions * 16 bytes for SIDs)
	size := 16 + int(sns.NumSessions)*16 + 16

	buf := make([]byte, size)

	// Command (1 byte)
	buf[0] = sns.Command

	// Accept (1 byte)
	buf[1] = sns.Accept

	// MBZ1 (2 bytes, already zeros)

	// NumSessions (4 bytes)
	binary.BigEndian.PutUint32(buf[4:8], sns.NumSessions)

	// MBZ2 (8 bytes, already zeros)

	// SessionIDs (NumSessions * 16 bytes)
	offset := 16
	for i := uint32(0); i < sns.NumSessions && i < uint32(len(sns.SessionIDs)); i++ {
		copy(buf[offset:offset+16], sns.SessionIDs[i][:])
		offset += 16
	}

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[offset:offset+16], sns.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into StopNSessions
func (sns *StopNSessions) Unmarshal(data []byte, includeHMAC bool) error {
	// Minimum size check
	if len(data) < 16 {
		return common.ErrInvalidMessageLength
	}

	// Extract Command
	sns.Command = data[0]

	// Extract Accept
	sns.Accept = data[1]

	// Validate MBZ1
	if err := validateMBZ(data, 2, 4); err != nil {
		return err
	}
	copy(sns.MBZ1[:], data[2:4])

	// Extract NumSessions
	sns.NumSessions = binary.BigEndian.Uint32(data[4:8])

	// Validate MBZ2
	if err := validateMBZ(data, 8, 16); err != nil {
		return err
	}
	copy(sns.MBZ2[:], data[8:16])

	// Calculate expected size
	expectedSize := 16 + int(sns.NumSessions)*16 + 16

	if len(data) < expectedSize {
		return common.ErrInvalidMessageLength
	}

	// Extract SessionIDs
	sns.SessionIDs = make([]common.SessionID, sns.NumSessions)
	offset := 16
	for i := uint32(0); i < sns.NumSessions; i++ {
		copy(sns.SessionIDs[i][:], data[offset:offset+16])
		offset += 16
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(sns.HMAC[:], data[offset:offset+16])
	} else if err := validateMBZ(data, offset, offset+16); err != nil {
		return err
	}

	return nil
}

// RequestTWSessionIndividual requests a new two-way test session with individual control
// RFC 5938 Section 3.1 - Individual Session Control Feature
type RequestTWSessionIndividual struct {
	RequestTWSession // Embed the base request structure
}

// Marshal converts RequestTWSessionIndividual to network bytes
func (rtsi *RequestTWSessionIndividual) Marshal(includeHMAC bool) ([]byte, error) {
	// First marshal as regular RequestTWSession
	buf, err := rtsi.RequestTWSession.Marshal(includeHMAC)
	if err != nil {
		return nil, err
	}

	// Change the command byte to CmdRequestTWSessionIndividual
	buf[0] = common.CmdRequestTWSessionIndividual

	return buf, nil
}

// Unmarshal parses network bytes into RequestTWSessionIndividual
func (rtsi *RequestTWSessionIndividual) Unmarshal(data []byte, includeHMAC bool) error {
	// First unmarshal as regular RequestTWSession
	if err := rtsi.RequestTWSession.Unmarshal(data, includeHMAC); err != nil {
		return err
	}

	// Verify the command is correct
	if rtsi.Command != common.CmdRequestTWSessionIndividual {
		return fmt.Errorf("invalid command for RequestTWSessionIndividual: expected %d, got %d",
			common.CmdRequestTWSessionIndividual, rtsi.Command)
	}

	return nil
}
