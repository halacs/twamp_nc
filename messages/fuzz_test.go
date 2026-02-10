package messages

import (
	"testing"
)

// FuzzServerGreeting fuzzes ServerGreeting unmarshaling
func FuzzServerGreeting(f *testing.F) {
	// Seed corpus with valid examples
	f.Add(make([]byte, ServerGreetingSize)) // All zeros

	// Valid greeting with modes
	validGreeting := make([]byte, ServerGreetingSize)
	validGreeting[15] = 0x01 // Mode unauthenticated
	f.Add(validGreeting)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &ServerGreeting{}
		// Don't fail the test on expected errors - fuzzing is about finding panics
		_ = msg.Unmarshal(data)
	})
}

// FuzzSetupResponse fuzzes SetupResponse unmarshaling
func FuzzSetupResponse(f *testing.F) {
	// Seed corpus
	f.Add(make([]byte, SetupResponseSize))

	validResp := make([]byte, SetupResponseSize)
	validResp[3] = 0x01 // Mode unauthenticated
	f.Add(validResp)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &SetupResponse{}
		_ = msg.Unmarshal(data)
	})
}

// FuzzServerStart fuzzes ServerStart unmarshaling
func FuzzServerStart(f *testing.F) {
	// Seed corpus
	f.Add(make([]byte, ServerStartSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &ServerStart{}
		_ = msg.Unmarshal(data)
	})
}

// FuzzRequestTWSession fuzzes RequestTWSession unmarshaling
func FuzzRequestTWSession(f *testing.F) {
	// Seed corpus without HMAC
	f.Add(false, make([]byte, RequestTWSessionSize))

	// Valid request with some fields set
	validReq := make([]byte, RequestTWSessionSize)
	validReq[0] = 5 // Command
	f.Add(false, validReq)

	// With HMAC
	f.Add(true, make([]byte, RequestTWSessionSizeAuth))

	f.Fuzz(func(t *testing.T, includeHMAC bool, data []byte) {
		msg := &RequestTWSession{}
		_ = msg.Unmarshal(data, includeHMAC)
	})
}

// FuzzAcceptSession fuzzes AcceptSession unmarshaling
func FuzzAcceptSession(f *testing.F) {
	// Seed corpus
	f.Add(false, make([]byte, AcceptSessionSize))
	f.Add(true, make([]byte, AcceptSessionSizeAuth))

	f.Fuzz(func(t *testing.T, includeHMAC bool, data []byte) {
		msg := &AcceptSession{}
		_ = msg.Unmarshal(data, includeHMAC)
	})
}

// FuzzStartSessions fuzzes StartSessions unmarshaling
func FuzzStartSessions(f *testing.F) {
	// Seed corpus
	f.Add(false, make([]byte, StartSessionsSize))
	f.Add(true, make([]byte, StartSessionsSizeAuth))

	f.Fuzz(func(t *testing.T, includeHMAC bool, data []byte) {
		msg := &StartSessions{}
		_ = msg.Unmarshal(data, includeHMAC)
	})
}

// FuzzStartAck fuzzes StartAck unmarshaling
func FuzzStartAck(f *testing.F) {
	// Seed corpus
	f.Add(false, make([]byte, StartAckSize))
	f.Add(true, make([]byte, StartAckSizeAuth))

	f.Fuzz(func(t *testing.T, includeHMAC bool, data []byte) {
		msg := &StartAck{}
		_ = msg.Unmarshal(data, includeHMAC)
	})
}

// FuzzStopSessions fuzzes StopSessions unmarshaling
func FuzzStopSessions(f *testing.F) {
	// Seed corpus
	f.Add(false, make([]byte, StopSessionsSize))
	f.Add(true, make([]byte, StopSessionsSizeAuth))

	f.Fuzz(func(t *testing.T, includeHMAC bool, data []byte) {
		msg := &StopSessions{}
		_ = msg.Unmarshal(data, includeHMAC)
	})
}

// FuzzSenderTestPacket fuzzes unauthenticated sender test packet unmarshaling
func FuzzSenderTestPacket(f *testing.F) {
	// Seed corpus with various sizes
	f.Add(make([]byte, SenderTestPacketMinSize))       // Minimum size (14 bytes)
	f.Add(make([]byte, SenderTestPacketMinSize+100))   // With padding
	f.Add(make([]byte, SenderTestPacketMinSize+1000))  // Larger padding

	f.Fuzz(func(t *testing.T, data []byte) {
		packet := &SenderTestPacket{}
		_ = packet.Unmarshal(data)
	})
}

// FuzzReflectorTestPacket fuzzes unauthenticated reflector test packet unmarshaling
func FuzzReflectorTestPacket(f *testing.F) {
	// Seed corpus with various sizes
	f.Add(make([]byte, ReflectorTestPacketMinSize))      // Minimum size (41 bytes)
	f.Add(make([]byte, ReflectorTestPacketMinSize+100))  // With padding
	f.Add(make([]byte, ReflectorTestPacketMinSize+1000)) // Larger padding

	f.Fuzz(func(t *testing.T, data []byte) {
		packet := &ReflectorTestPacket{}
		_ = packet.Unmarshal(data)
	})
}

// FuzzSenderTestPacketAuth fuzzes authenticated sender test packet unmarshaling
func FuzzSenderTestPacketAuth(f *testing.F) {
	// Seed corpus with various sizes
	f.Add(make([]byte, SenderTestPacketAuthMinSize))      // Minimum size (48 bytes)
	f.Add(make([]byte, SenderTestPacketAuthMinSize+100))  // With padding
	f.Add(make([]byte, SenderTestPacketAuthMinSize+1000)) // Larger padding

	f.Fuzz(func(t *testing.T, data []byte) {
		packet := &SenderTestPacketAuth{}
		_ = packet.Unmarshal(data)
	})
}

// FuzzReflectorTestPacketAuth fuzzes authenticated reflector test packet unmarshaling
func FuzzReflectorTestPacketAuth(f *testing.F) {
	// Seed corpus with various sizes
	f.Add(make([]byte, ReflectorTestPacketAuthMinSize))      // Minimum size (112 bytes)
	f.Add(make([]byte, ReflectorTestPacketAuthMinSize+100))  // With padding
	f.Add(make([]byte, ReflectorTestPacketAuthMinSize+1000)) // Larger padding

	f.Fuzz(func(t *testing.T, data []byte) {
		packet := &ReflectorTestPacketAuth{}
		_ = packet.Unmarshal(data)
	})
}

// FuzzRequestTWSessionIndividual fuzzes RFC 5938 individual session request
func FuzzRequestTWSessionIndividual(f *testing.F) {
	// Seed corpus
	f.Add(false, make([]byte, 128)) // Base size without HMAC
	f.Add(true, make([]byte, 144))  // With HMAC (128 + 16)

	f.Fuzz(func(t *testing.T, includeHMAC bool, data []byte) {
		msg := &RequestTWSessionIndividual{}
		_ = msg.Unmarshal(data, includeHMAC)
	})
}

// FuzzStopNSessions fuzzes RFC 5938 Stop-N-Sessions command
func FuzzStopNSessions(f *testing.F) {
	// Seed corpus - minimum is 16 bytes + 0 sessions
	f.Add(false, make([]byte, 16)) // No sessions, no HMAC
	f.Add(false, make([]byte, 32)) // 1 session (16 + 16), no HMAC
	f.Add(true, make([]byte, 48))  // 1 session + HMAC (16 + 16 + 16)

	f.Fuzz(func(t *testing.T, includeHMAC bool, data []byte) {
		msg := &StopNSessions{}
		_ = msg.Unmarshal(data, includeHMAC)
	})
}

// FuzzTypePDescriptorValidation fuzzes Type-P Descriptor validation
func FuzzTypePDescriptorValidation(f *testing.F) {
	// Seed corpus with valid and invalid values
	f.Add(uint32(0x00000000)) // Valid: all zeros
	f.Add(uint32(0x00B80000)) // Valid: DSCP 46 (EF)
	f.Add(uint32(0x00FF0000)) // Invalid: DSCP bits 14-15 not zero
	f.Add(uint32(0x01000000)) // Invalid: padding byte not zero
	f.Add(uint32(0x00000001)) // Invalid: reserved bits not zero
	f.Add(uint32(0xFFFFFFFF)) // Invalid: all bits set

	f.Fuzz(func(t *testing.T, descriptor uint32) {
		// Validation should never panic
		_ = validateTypePDescriptor(descriptor)
	})
}
