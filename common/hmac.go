package common

// HMAC coverage constants for TWAMP test packets per RFC 4656/5357.
// These define how many bytes are covered by the HMAC in different modes.
const (
	// HMACCoverageAuthenticated is the HMAC coverage for authenticated mode.
	// Per RFC 4656 Section 4.1.2, HMAC covers first 16 bytes (1 AES block).
	HMACCoverageAuthenticated = 16

	// HMACCoverageSenderEncrypted is the HMAC coverage for sender packets in encrypted mode.
	// Per RFC 5357 Section 4.2.1, covers header up to HMAC position (32 bytes).
	HMACCoverageSenderEncrypted = 32

	// HMACCoverageReflectorEncrypted is the HMAC coverage for reflector packets in encrypted mode.
	// Per RFC 5357 Section 4.2.1, covers first 96 bytes (6 AES blocks).
	HMACCoverageReflectorEncrypted = 96

	// SenderHMACOffset is the byte offset where HMAC starts in sender packets.
	// Sender packet structure (SenderTestPacketAuth):
	// - Bytes 0-31: Header (SeqNo, MBZ, Timestamp, ErrorEstimate, MBZ2)
	// - Bytes 32-47: HMAC
	// - Bytes 48+: Padding
	SenderHMACOffset = 32

	// ReflectorHMACOffset is the byte offset where HMAC starts in reflector packets.
	// Reflector packet structure (ReflectorTestPacketAuth):
	// - Bytes 0-95: Header (SeqNo, MBZ, timestamps, etc.)
	// - Bytes 96-111: HMAC
	// - Bytes 112+: Padding
	ReflectorHMACOffset = 96

	// MinSenderAuthPacketSize is the minimum size for authenticated sender packets.
	MinSenderAuthPacketSize = SenderHMACOffset + 16 // 48 bytes

	// MinReflectorAuthPacketSize is the minimum size for authenticated reflector packets.
	MinReflectorAuthPacketSize = ReflectorHMACOffset + 16 // 112 bytes
)

// HMACCoverage returns the number of bytes covered by HMAC for a given packet type.
// Per RFC 4656/5357:
// - Authenticated mode: HMAC covers first 16 bytes (1 AES block) for both packet types
// - Encrypted mode (sender): HMAC covers first 32 bytes (header up to HMAC position)
// - Encrypted mode (reflector): HMAC covers first 96 bytes (6 AES blocks)
func HMACCoverage(isEncrypted, isReflectorPacket bool) int {
	if !isEncrypted {
		return HMACCoverageAuthenticated
	}
	if isReflectorPacket {
		return HMACCoverageReflectorEncrypted
	}
	return HMACCoverageSenderEncrypted
}