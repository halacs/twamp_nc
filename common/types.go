package common

import (
	"errors"
	"fmt"
	"time"
)

// TWAMP protocol constants
const (
	// Mode values
	ModeUnauthenticated = 1
	ModeAuthenticated   = 2
	ModeEncrypted       = 4

	// Accept values from RFC 4656 Section 3.3 and RFC 5357
	AcceptOK                  = 0
	AcceptFailure             = 1
	AcceptInternalError       = 2
	AcceptNotSupported        = 3
	AcceptPermanentResLimited = 4
	AcceptTempResLimited      = 5
	// Accept codes 6-255 are reserved for future use per RFC 4656/5357
	// These should be treated as "Unknown" but not necessarily as errors
	AcceptReservedMin = 6
	AcceptReservedMax = 255

	// Command numbers
	CmdRequestTWSession = 5
	CmdStartSessions    = 2
	CmdStopSessions     = 3

	// RFC 5938: Individual Session Control commands
	CmdStopNSessions              = 4 // RFC 5938 Section 3.4
	CmdRequestTWSessionIndividual = 6 // RFC 5938 Section 3.1

	// RFC 6038: Reflect Octets and Symmetrical Size modes
	// RFC 5938 reserves bit value 16 for Individual Session Control.
	// RFC 6038 assigns the following values:
	//   32: Reflect Octets
	//   64: Symmetrical Size
	ModeReflectOctets   = 32 // RFC 6038 Section 4.1 / IANA registry
	ModeSymmetricalSize = 64 // RFC 6038 Section 4.1 / IANA registry

	// RFC 5618: Mixed Security Mode
	ModeMixed = 8 // RFC 5618 Section 3

	// Default timeouts
	DefaultSERVWAIT = 900 * time.Second
	DefaultREFWAIT  = 900 * time.Second
	DefaultTimeout  = 3 * time.Second

	// MaxTWAMPPacketSize is the maximum size of a TWAMP test packet
	// This accounts for the maximum padding that can be added per RFC 5357
	MaxTWAMPPacketSize = 2048
)

// AcceptCodeToString converts an Accept code to a human-readable string
// Per RFC 4656/5357, codes 0-5 are defined, 6-255 are reserved for future use
func AcceptCodeToString(code uint8) string {
	switch code {
	case AcceptOK:
		return "OK"
	case AcceptFailure:
		return "Failure, reason unspecified"
	case AcceptInternalError:
		return "Internal error"
	case AcceptNotSupported:
		return "Some aspect of request is not supported"
	case AcceptPermanentResLimited:
		return "Cannot perform request due to permanent resource limitations"
	case AcceptTempResLimited:
		return "Cannot perform request due to temporary resource limitations"
	default:
		if code >= AcceptReservedMin && code <= AcceptReservedMax {
			return fmt.Sprintf("Reserved accept code: %d", code)
		}
		// This shouldn't happen as uint8 max is 255, but kept for completeness
		return fmt.Sprintf("Unknown accept code: %d", code)
	}
}

// IsAcceptCodeValid checks if an accept code is valid per RFC specifications.
//
// IMPORTANT: This function ALWAYS returns true because per RFC 4656/5357,
// all uint8 values (0-255) are valid accept codes. This is NOT a bug.
// - Codes 0-5 have defined meanings (OK, Failure, Internal Error, etc.)
// - Codes 6-255 are reserved for future use but are still valid codes
//
// To check if a code has a defined meaning, use IsAcceptCodeDefined() instead.
func IsAcceptCodeValid(code uint8) bool {
	// Per RFC: All values 0-255 are valid accept codes
	// This always returns true intentionally
	return true
}

// IsAcceptCodeDefined checks if an accept code has a defined meaning
// Returns true for codes 0-5, false for reserved codes 6-255
func IsAcceptCodeDefined(code uint8) bool {
	return code <= AcceptTempResLimited
}

// Common error definitions used across TWAMP packages
var (
	// Message validation errors
	ErrInvalidMessageLength   = errors.New("invalid message length")
	ErrInvalidMBZ             = errors.New("non-zero value in MBZ field")
	ErrInvalidTypePDescriptor = errors.New("invalid Type-P descriptor: reserved bits must be zero")
	ErrInvalidNumSlots        = errors.New("NumSlots must be zero per RFC 5357 Section 3.5 (TWAMP, not OWAMP)")
	ErrInvalidNumPackets      = errors.New("NumPackets must be zero per RFC 5357 Section 3.5 (TWAMP, not OWAMP)")
	ErrInvalidPaddingLength   = errors.New("PaddingLength exceeds maximum allowed")
	ErrInvalidIPVN            = errors.New("invalid IP version (IPVN)")

	// Connection errors
	ErrNoCompatibleMode     = errors.New("no compatible mode available")
	ErrServerNoModes        = errors.New("server doesn't support any mode")
	ErrSharedSecretRequired = errors.New("shared secret required for secure modes")
	ErrRFC5618Violation     = errors.New("RFC 5618 violation: mixed mode requires authenticated or encrypted control protocol")
	ErrUnsupportedMode      = errors.New("unsupported mode")
	ErrUnknownKeyID         = errors.New("unknown KeyID")
	ErrInvalidModeCombo     = errors.New("invalid mode combination")
	ErrUnknownCommand       = errors.New("unknown command")

	// Session errors
	ErrNoSessionsToStart      = errors.New("no sessions to start")
	ErrInvalidReceiverAddress = errors.New("invalid receiver address")
	ErrNoAvailablePorts       = errors.New("no available ports in range")
	ErrInvalidPortRange       = errors.New("invalid port range")

	// Security errors
	ErrHMACVerificationFailed = errors.New("HMAC verification failed")
	ErrUnknownSequenceNumber  = errors.New("received response for unknown sequence number")

	// Crypto errors
	ErrInvalidKeyLength  = errors.New("invalid key length")
	ErrInvalidBlockSize  = errors.New("invalid block size")
	ErrInvalidHMACLength = errors.New("invalid HMAC length")
	ErrInvalidSaltLen    = errors.New("invalid salt length")
)

// Mode represents TWAMP test modes
type Mode uint32

// ModeToString function to convert mode to string
func ModeToString(mode Mode) string {
	// Handle combined modes
	var modes []string

	if mode&Mode(ModeUnauthenticated) != 0 {
		modes = append(modes, "unauthenticated")
	}
	if mode&Mode(ModeAuthenticated) != 0 {
		modes = append(modes, "authenticated")
	}
	if mode&Mode(ModeEncrypted) != 0 {
		modes = append(modes, "encrypted")
	}
	if mode&Mode(ModeMixed) != 0 {
		modes = append(modes, "mixed")
	}
	if mode&Mode(ModeReflectOctets) != 0 {
		modes = append(modes, "reflect-octets")
	}
	if mode&Mode(ModeSymmetricalSize) != 0 {
		modes = append(modes, "symmetrical-size")
	}

	if len(modes) == 0 {
		return "unknown"
	}

	if len(modes) == 1 {
		return modes[0]
	}

	// Join multiple modes with "+"
	result := modes[0]
	for i := 1; i < len(modes); i++ {
		result += "+" + modes[i]
	}
	return result
}

// ValidateRequestedMode enforces that a negotiated mode has exactly one base
// security bit set and does not include reserved/unsupported bits.
func ValidateRequestedMode(mode Mode) error {
	const reservedModeBit14 Mode = 1 << 14

	if mode&reservedModeBit14 != 0 {
		return ErrInvalidModeCombo
	}

	securityMask := Mode(ModeUnauthenticated | ModeAuthenticated | ModeEncrypted)
	securityBits := mode & securityMask
	if securityBits == 0 || securityBits&(securityBits-1) != 0 {
		return ErrInvalidModeCombo
	}

	return nil
}

// ResolveMixedModes separates mixed security mode into control and test modes per RFC 5618 Section 3.1.
// It returns an error when mixed mode is combined with unauthenticated control protocol.
func ResolveMixedModes(negotiatedMode Mode) (controlMode Mode, testMode Mode, err error) {
	if err := ValidateRequestedMode(negotiatedMode); err != nil {
		return 0, 0, err
	}

	// Check if RFC 5618 Mixed Security Mode is active (bit 3).
	if negotiatedMode&ModeMixed != 0 {
		// Extract the base security mode (bits 0-2) and preserve other mode bits.
		securityMask := Mode(ModeUnauthenticated | ModeAuthenticated | ModeEncrypted)
		otherModes := negotiatedMode &^ (securityMask | ModeMixed)
		baseSecurityMode := negotiatedMode & securityMask

		// RFC 5618 Section 3.1: Mixed mode MUST use authenticated or encrypted control protocol.
		if baseSecurityMode == ModeUnauthenticated {
			return 0, 0, ErrRFC5618Violation
		}

		// Control protocol uses the base security mode + other mode bits.
		controlMode = baseSecurityMode | otherModes
		// Test protocol uses unauthenticated mode + other mode bits.
		testMode = ModeUnauthenticated | otherModes

		return controlMode, testMode, nil
	}

	// No mixed mode - both control and test use the same mode.
	return negotiatedMode, negotiatedMode, nil
}

// ValidateModeMask validates a mode mask used for configuration or capabilities.
// It allows multiple base security bits but requires at least one to be set.
func ValidateModeMask(mode Mode) error {
	const reservedModeBit14 Mode = 1 << 14

	if mode&reservedModeBit14 != 0 {
		return ErrInvalidModeCombo
	}

	securityMask := Mode(ModeUnauthenticated | ModeAuthenticated | ModeEncrypted)
	if mode&securityMask == 0 {
		return ErrInvalidModeCombo
	}

	return nil
}

// ErrorEstimate represents the TWAMP error estimate field
type ErrorEstimate struct {
	Multiplier uint8
	Scale      uint8
	S          bool // Sync bit
}

// ToUint16 converts ErrorEstimate to its uint16 wire representation
func (ee ErrorEstimate) ToUint16() uint16 {
	val := uint16(ee.Multiplier)
	val |= uint16(ee.Scale) << 8
	if ee.S {
		val |= 1 << 15 // Set the S bit (high bit of first byte)
	}
	return val
}

// FromUint16 parses a uint16 into an ErrorEstimate
func (ee *ErrorEstimate) FromUint16(val uint16) {
	ee.S = (val & 0x8000) != 0        // Extract S bit
	ee.Scale = uint8(val>>8) & 0x3F   // Extract Scale (6 bits)
	ee.Multiplier = uint8(val & 0xFF) // Extract Multiplier
}

// SessionID represents a TWAMP session identifier (16 octets)
type SessionID [16]byte

// IsZero returns true if the SessionID is all zeros.
// RFC 5357 Section 3.5: SID in Request-TW-Session MUST be set to 0.
// Note: SID validation failures are communicated via TWAMP protocol Accept codes,
// not Go errors (see server.go handleRequestTWSession).
func (sid SessionID) IsZero() bool {
	return sid == SessionID{}
}

// TWAMPError represents an error in the TWAMP protocol
type TWAMPError struct {
	AcceptCode uint8
	Message    string
}

// Error implements the error interface
func (e *TWAMPError) Error() string {
	return fmt.Sprintf("TWAMP error (%s): %s",
		AcceptCodeToString(e.AcceptCode),
		e.Message)
}

// NewTWAMPError creates a new TWAMP error
func NewTWAMPError(code uint8, msg string) *TWAMPError {
	return &TWAMPError{
		AcceptCode: code,
		Message:    msg,
	}
}
