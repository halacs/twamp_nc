package messages

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
)

func TestSenderTestPacket_Marshal(t *testing.T) {
	// RFC 5357 Section 4.1.2: TWAMP-Test Sender Packet Format (Unauthenticated)
	// Minimum packet size: 14 octets
	//   Octets 0-3:   Sequence Number
	//   Octets 4-11:  Timestamp (NTP format per RFC 5905)
	//   Octets 12-13: Error Estimate (format per RFC 4656 Section 4.1.2)
	//   Octets 14+:   Packet Padding (SHOULD be zero, MAY be non-zero per RFC 5357)
	tests := []struct {
		name            string
		packet          SenderTestPacket
		expectedMinSize int
		validateTTL     bool
		expectError     bool
	}{
		{
			name: "basic packet with padding",
			packet: SenderTestPacket{
				SeqNumber:     42,
				Timestamp:     common.FromTime(time.Unix(1234567890, 123456789)),
				ErrorEstimate: common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				PaddingSize:   10, // Results in 24 octets total (14 base + 10 padding)
			},
			expectedMinSize: 24, // RFC 5357: 14 octets minimum + 10 padding
			validateTTL:     false,
			expectError:     false,
		},
		{
			name: "packet with medium padding",
			packet: SenderTestPacket{
				SeqNumber:     100,
				Timestamp:     common.FromTime(time.Unix(1234567890, 987654321)),
				ErrorEstimate: common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50},
				PaddingSize:   20,
			},
			expectedMinSize: 34,
			validateTTL:     false,
			expectError:     false,
		},
		{
			name: "packet with no padding",
			packet: SenderTestPacket{
				SeqNumber:     1,
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{},
				PaddingSize:   0,
			},
			expectedMinSize: 14,
			validateTTL:     false,
			expectError:     false,
		},
		{
			name: "packet with minimal padding (1 byte)",
			packet: SenderTestPacket{
				SeqNumber:     999,
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{S: true, Scale: 15, Multiplier: 255},
				PaddingSize:   1,
			},
			expectedMinSize: 15,
			validateTTL:     false,
			expectError:     false,
		},
		{
			name: "packet with large padding",
			packet: SenderTestPacket{
				SeqNumber:     4294967295, // Max uint32
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{},
				PaddingSize:   1000,
			},
			expectedMinSize: 1014,
			validateTTL:     false,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Marshal()

			if tt.expectError {
				if err == nil {
					t.Errorf("Marshal() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Marshal() unexpected error: %v", err)
				return
			}

			if len(data) != tt.expectedMinSize {
				t.Errorf("Marshal() returned data size = %d, expected %d", len(data), tt.expectedMinSize)
			}

			// Validate sequence number
			seqNum := binary.BigEndian.Uint32(data[0:4])
			if seqNum != tt.packet.SeqNumber {
				t.Errorf("Marshal() sequence number = %d, expected %d", seqNum, tt.packet.SeqNumber)
			}

			// Validate timestamp
			var ts common.TWAMPTimestamp
			ts.Unmarshal(data[4:12])
			if ts.Seconds != tt.packet.Timestamp.Seconds || ts.Fraction != tt.packet.Timestamp.Fraction {
				t.Errorf("Marshal() timestamp mismatch")
			}

			// Validate error estimate
			ee := binary.BigEndian.Uint16(data[12:14])
			expectedEE := tt.packet.ErrorEstimate.ToUint16()
			if ee != expectedEE {
				t.Errorf("Marshal() error estimate = %d, expected %d", ee, expectedEE)
			}

			// RFC 5357 Section 4.1.2: "Packet Padding in TWAMP-Test SHOULD be composed
			// of all zeros, with the length of the Packet Padding chosen such that
			// the IP packet size equals the Padding Length specified"
			if tt.packet.PaddingSize > 0 {
				paddingStart := 14 // After 14-octet base packet per RFC 5357
				paddingData := data[paddingStart:]

				// Validate zero padding per RFC 5357 Section 4.1.2
				for i, b := range paddingData {
					if b != 0 {
						t.Errorf("Marshal() padding at index %d = %d, expected 0 per RFC 5357 Section 4.1.2", i, b)
						break
					}
				}
			}
		})
	}
}

func TestSenderTestPacket_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedPacket SenderTestPacket
		expectError    bool
		errorType      error
	}{
		{
			name: "valid packet with padding",
			data: func() []byte {
				buf := make([]byte, 24)
				binary.BigEndian.PutUint32(buf[0:4], 42)
				ts := common.FromTime(time.Unix(1234567890, 123456789))
				ts.Marshal(buf[4:12])
				ee := common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100}
				binary.BigEndian.PutUint16(buf[12:14], ee.ToUint16())
				// Rest is zero padding
				return buf
			}(),
			expectedPacket: SenderTestPacket{
				SeqNumber:     42,
				Timestamp:     common.FromTime(time.Unix(1234567890, 123456789)),
				ErrorEstimate: common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				PaddingSize:   10,
			},
			expectError: false,
		},
		{
			name: "valid packet without padding",
			data: func() []byte {
				buf := make([]byte, 14)
				binary.BigEndian.PutUint32(buf[0:4], 999)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[4:12])
				binary.BigEndian.PutUint16(buf[12:14], 0)
				return buf
			}(),
			expectedPacket: SenderTestPacket{
				SeqNumber:     999,
				Timestamp:     common.FromTime(time.Unix(1234567890, 0)),
				ErrorEstimate: common.ErrorEstimate{},
				PaddingSize:   0,
			},
			expectError: false,
		},
		{
			name:        "packet too short",
			data:        make([]byte, 13),
			expectError: true,
			errorType:   common.ErrInvalidMessageLength,
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
			errorType:   common.ErrInvalidMessageLength,
		},
		{
			name: "packet with maximum values",
			data: func() []byte {
				buf := make([]byte, 100)
				binary.BigEndian.PutUint32(buf[0:4], 4294967295) // Max uint32
				ts := common.TWAMPTimestamp{Seconds: 4294967295, Fraction: 4294967295}
				ts.Marshal(buf[4:12])
				binary.BigEndian.PutUint16(buf[12:14], 65535) // Max uint16
				buf[14] = 128                                 // TTL
				return buf
			}(),
			expectedPacket: SenderTestPacket{
				SeqNumber: 4294967295,
				Timestamp: common.TWAMPTimestamp{Seconds: 4294967295, Fraction: 4294967295},
				ErrorEstimate: func() common.ErrorEstimate {
					var ee common.ErrorEstimate
					ee.FromUint16(65535)
					return ee
				}(),
				PaddingSize: 86,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var packet SenderTestPacket
			err := packet.Unmarshal(tt.data)

			if tt.expectError {
				if err == nil {
					t.Errorf("Unmarshal() expected error but got none")
				} else if tt.errorType != nil && err != tt.errorType {
					t.Errorf("Unmarshal() error = %v, expected %v", err, tt.errorType)
				}
				return
			}

			if err != nil {
				t.Errorf("Unmarshal() unexpected error: %v", err)
				return
			}

			if packet.SeqNumber != tt.expectedPacket.SeqNumber {
				t.Errorf("Unmarshal() SeqNumber = %d, expected %d", packet.SeqNumber, tt.expectedPacket.SeqNumber)
			}

			if packet.Timestamp.Seconds != tt.expectedPacket.Timestamp.Seconds ||
				packet.Timestamp.Fraction != tt.expectedPacket.Timestamp.Fraction {
				t.Errorf("Unmarshal() Timestamp mismatch")
			}

			if packet.ErrorEstimate.ToUint16() != tt.expectedPacket.ErrorEstimate.ToUint16() {
				t.Errorf("Unmarshal() ErrorEstimate = %d, expected %d",
					packet.ErrorEstimate.ToUint16(), tt.expectedPacket.ErrorEstimate.ToUint16())
			}

			if packet.PaddingSize != tt.expectedPacket.PaddingSize {
				t.Errorf("Unmarshal() PaddingSize = %d, expected %d", packet.PaddingSize, tt.expectedPacket.PaddingSize)
			}

			// TTL field removed per RFC compliance
		})
	}
}

func TestSenderTestPacket_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet SenderTestPacket
	}{
		{
			name: "round trip with padding",
			packet: SenderTestPacket{
				SeqNumber:     12345,
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{S: true, Scale: 10, Multiplier: 200},
				PaddingSize:   50,
			},
		},
		{
			name: "round trip with large padding",
			packet: SenderTestPacket{
				SeqNumber:     67890,
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{S: false, Scale: 15, Multiplier: 100},
				PaddingSize:   100,
			},
		},
		{
			name: "round trip without padding",
			packet: SenderTestPacket{
				SeqNumber:     1,
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{},
				PaddingSize:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.packet.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}

			// Unmarshal
			var decoded SenderTestPacket
			err = decoded.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal() error: %v", err)
			}

			// Compare (excluding TTL for packets without padding)
			if decoded.SeqNumber != tt.packet.SeqNumber {
				t.Errorf("Round trip SeqNumber = %d, expected %d", decoded.SeqNumber, tt.packet.SeqNumber)
			}

			if decoded.Timestamp.Seconds != tt.packet.Timestamp.Seconds ||
				decoded.Timestamp.Fraction != tt.packet.Timestamp.Fraction {
				t.Errorf("Round trip Timestamp mismatch")
			}

			if decoded.ErrorEstimate.ToUint16() != tt.packet.ErrorEstimate.ToUint16() {
				t.Errorf("Round trip ErrorEstimate mismatch")
			}

			if decoded.PaddingSize != tt.packet.PaddingSize {
				t.Errorf("Round trip PaddingSize = %d, expected %d", decoded.PaddingSize, tt.packet.PaddingSize)
			}

			// TTL field removed per RFC compliance - no validation needed
		})
	}
}

func TestSenderTestPacketAuth_Marshal(t *testing.T) {
	tests := []struct {
		name         string
		packet       SenderTestPacketAuth
		expectedSize int
		expectError  bool
	}{
		{
			name: "basic authenticated packet",
			packet: SenderTestPacketAuth{
				SeqNumber:     42,
				MBZ:           [12]byte{},
				Timestamp:     common.FromTime(time.Unix(1234567890, 123456789)),
				ErrorEstimate: common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				MBZ2:          [6]byte{},
				HMAC:          [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				PaddingSize:   20,
			},
			expectedSize: 68,
			expectError:  false,
		},
		{
			name: "authenticated packet without padding",
			packet: SenderTestPacketAuth{
				SeqNumber:     999,
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{},
				HMAC:          [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240},
				PaddingSize:   0,
			},
			expectedSize: 48,
			expectError:  false,
		},
		{
			name: "authenticated packet with large padding",
			packet: SenderTestPacketAuth{
				SeqNumber:     4294967295,
				Timestamp:     common.FromTime(time.Now()),
				ErrorEstimate: common.ErrorEstimate{S: true, Scale: 15, Multiplier: 255},
				HMAC:          [16]byte{},
				PaddingSize:   500,
			},
			expectedSize: 548,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Marshal()

			if tt.expectError {
				if err == nil {
					t.Errorf("Marshal() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Marshal() unexpected error: %v", err)
				return
			}

			if len(data) != tt.expectedSize {
				t.Errorf("Marshal() returned data size = %d, expected %d", len(data), tt.expectedSize)
			}

			// Validate sequence number
			seqNum := binary.BigEndian.Uint32(data[0:4])
			if seqNum != tt.packet.SeqNumber {
				t.Errorf("Marshal() sequence number = %d, expected %d", seqNum, tt.packet.SeqNumber)
			}

			// Validate MBZ fields are zeros
			for i := 4; i < 16; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ at index %d = %d, expected 0", i, data[i])
				}
			}

			// Validate timestamp
			var ts common.TWAMPTimestamp
			ts.Unmarshal(data[16:24])
			if ts.Seconds != tt.packet.Timestamp.Seconds || ts.Fraction != tt.packet.Timestamp.Fraction {
				t.Errorf("Marshal() timestamp mismatch")
			}

			// Validate error estimate
			ee := binary.BigEndian.Uint16(data[24:26])
			expectedEE := tt.packet.ErrorEstimate.ToUint16()
			if ee != expectedEE {
				t.Errorf("Marshal() error estimate = %d, expected %d", ee, expectedEE)
			}

			// Validate second MBZ
			for i := 26; i < 32; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ2 at index %d = %d, expected 0", i, data[i])
				}
			}

			// Validate HMAC
			if !bytes.Equal(data[32:48], tt.packet.HMAC[:]) {
				t.Errorf("Marshal() HMAC mismatch")
			}
		})
	}
}

func TestSenderTestPacketAuth_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedPacket SenderTestPacketAuth
		expectError    bool
		errorType      error
	}{
		{
			name: "valid authenticated packet",
			data: func() []byte {
				buf := make([]byte, 68)
				binary.BigEndian.PutUint32(buf[0:4], 42)
				// MBZ (12 bytes) - already zeros
				ts := common.FromTime(time.Unix(1234567890, 123456789))
				ts.Marshal(buf[16:24])
				ee := common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100}
				binary.BigEndian.PutUint16(buf[24:26], ee.ToUint16())
				// MBZ2 (6 bytes) - already zeros
				hmac := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				copy(buf[32:48], hmac[:])
				// Padding
				return buf
			}(),
			expectedPacket: SenderTestPacketAuth{
				SeqNumber:     42,
				Timestamp:     common.FromTime(time.Unix(1234567890, 123456789)),
				ErrorEstimate: common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				HMAC:          [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				PaddingSize:   20,
			},
			expectError: false,
		},
		{
			name: "packet with non-zero MBZ",
			data: func() []byte {
				buf := make([]byte, 48)
				binary.BigEndian.PutUint32(buf[0:4], 42)
				buf[5] = 1 // Non-zero in MBZ field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name: "packet with non-zero MBZ2",
			data: func() []byte {
				buf := make([]byte, 48)
				binary.BigEndian.PutUint32(buf[0:4], 42)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[16:24])
				binary.BigEndian.PutUint16(buf[24:26], 0)
				buf[27] = 1 // Non-zero in MBZ2 field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name:        "packet too short",
			data:        make([]byte, 47),
			expectError: true,
			errorType:   common.ErrInvalidMessageLength,
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
			errorType:   common.ErrInvalidMessageLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var packet SenderTestPacketAuth
			err := packet.Unmarshal(tt.data)

			if tt.expectError {
				if err == nil {
					t.Errorf("Unmarshal() expected error but got none")
				} else if tt.errorType != nil && err != tt.errorType {
					t.Errorf("Unmarshal() error = %v, expected %v", err, tt.errorType)
				}
				return
			}

			if err != nil {
				t.Errorf("Unmarshal() unexpected error: %v", err)
				return
			}

			if packet.SeqNumber != tt.expectedPacket.SeqNumber {
				t.Errorf("Unmarshal() SeqNumber = %d, expected %d", packet.SeqNumber, tt.expectedPacket.SeqNumber)
			}

			if packet.Timestamp.Seconds != tt.expectedPacket.Timestamp.Seconds ||
				packet.Timestamp.Fraction != tt.expectedPacket.Timestamp.Fraction {
				t.Errorf("Unmarshal() Timestamp mismatch")
			}

			if packet.ErrorEstimate.ToUint16() != tt.expectedPacket.ErrorEstimate.ToUint16() {
				t.Errorf("Unmarshal() ErrorEstimate mismatch")
			}

			if !bytes.Equal(packet.HMAC[:], tt.expectedPacket.HMAC[:]) {
				t.Errorf("Unmarshal() HMAC mismatch")
			}

			if packet.PaddingSize != tt.expectedPacket.PaddingSize {
				t.Errorf("Unmarshal() PaddingSize = %d, expected %d", packet.PaddingSize, tt.expectedPacket.PaddingSize)
			}
		})
	}
}

func TestReflectorTestPacket_Marshal(t *testing.T) {
	// RFC 5357 Section 4.2.1: TWAMP-Test Reflector Packet Format (Unauthenticated)
	// Minimum packet size: 41 octets
	//   Octets 0-3:   Sequence Number
	//   Octets 4-11:  Timestamp
	//   Octets 12-13: Error Estimate
	//   Octets 14-15: MBZ (Must Be Zero per RFC 5357)
	//   Octets 16-23: Receive Timestamp
	//   Octets 24-27: Sender Sequence Number
	//   Octets 28-35: Sender Timestamp
	//   Octets 36-37: Sender Error Estimate
	//   Octets 38-39: MBZ (Must Be Zero per RFC 5357)
	//   Octet 40:     Sender TTL
	//   Octets 41+:   Packet Padding
	tests := []struct {
		name         string
		packet       ReflectorTestPacket
		expectedSize int
		expectError  bool
	}{
		{
			name: "basic reflector packet",
			packet: ReflectorTestPacket{
				SeqNumber:           100,
				Timestamp:           common.FromTime(time.Unix(1234567890, 0)),
				ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				MBZ:                 [2]byte{}, // RFC 5357: MUST be zero
				ReceiveTimestamp:    common.FromTime(time.Unix(1234567891, 0)),
				SenderSeqNumber:     99,
				SenderTimestamp:     common.FromTime(time.Unix(1234567889, 0)),
				SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50},
				MBZ2:                [2]byte{}, // RFC 5357: MUST be zero
				SenderTTL:           64,
				PaddingSize:         10, // Results in 51 octets total (41 base + 10 padding)
			},
			expectedSize: 51, // RFC 5357: 41 octets minimum + 10 padding
			expectError:  false,
		},
		{
			name: "reflector packet without padding",
			packet: ReflectorTestPacket{
				SeqNumber:           1,
				Timestamp:           common.FromTime(time.Now()),
				ErrorEstimate:       common.ErrorEstimate{},
				ReceiveTimestamp:    common.FromTime(time.Now()),
				SenderSeqNumber:     0,
				SenderTimestamp:     common.FromTime(time.Now()),
				SenderErrorEstimate: common.ErrorEstimate{},
				SenderTTL:           255,
				PaddingSize:         0,
			},
			expectedSize: 41,
			expectError:  false,
		},
		{
			name: "reflector packet with large padding",
			packet: ReflectorTestPacket{
				SeqNumber:           4294967295,
				Timestamp:           common.FromTime(time.Now()),
				ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 15, Multiplier: 255},
				ReceiveTimestamp:    common.FromTime(time.Now()),
				SenderSeqNumber:     4294967294,
				SenderTimestamp:     common.FromTime(time.Now()),
				SenderErrorEstimate: common.ErrorEstimate{S: true, Scale: 15, Multiplier: 255},
				SenderTTL:           128,
				PaddingSize:         500,
			},
			expectedSize: 541,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Marshal()

			if tt.expectError {
				if err == nil {
					t.Errorf("Marshal() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Marshal() unexpected error: %v", err)
				return
			}

			if len(data) != tt.expectedSize {
				t.Errorf("Marshal() returned data size = %d, expected %d", len(data), tt.expectedSize)
			}

			// Validate fields
			seqNum := binary.BigEndian.Uint32(data[0:4])
			if seqNum != tt.packet.SeqNumber {
				t.Errorf("Marshal() sequence number = %d, expected %d", seqNum, tt.packet.SeqNumber)
			}

			// Validate MBZ fields
			if data[14] != 0 || data[15] != 0 {
				t.Errorf("Marshal() MBZ not zeros")
			}
			if data[38] != 0 || data[39] != 0 {
				t.Errorf("Marshal() MBZ2 not zeros")
			}

			// Validate Sender TTL
			if data[40] != tt.packet.SenderTTL {
				t.Errorf("Marshal() SenderTTL = %d, expected %d", data[40], tt.packet.SenderTTL)
			}
		})
	}
}

func TestReflectorTestPacket_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedPacket ReflectorTestPacket
		expectError    bool
		errorType      error
	}{
		{
			name: "valid reflector packet",
			data: func() []byte {
				buf := make([]byte, 51)
				binary.BigEndian.PutUint32(buf[0:4], 100)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[4:12])
				ee := common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100}
				binary.BigEndian.PutUint16(buf[12:14], ee.ToUint16())
				// MBZ (2 bytes) - already zeros
				recvTs := common.FromTime(time.Unix(1234567891, 0))
				recvTs.Marshal(buf[16:24])
				binary.BigEndian.PutUint32(buf[24:28], 99)
				senderTs := common.FromTime(time.Unix(1234567889, 0))
				senderTs.Marshal(buf[28:36])
				senderEE := common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50}
				binary.BigEndian.PutUint16(buf[36:38], senderEE.ToUint16())
				// MBZ2 (2 bytes) - already zeros
				buf[40] = 64 // SenderTTL
				return buf
			}(),
			expectedPacket: ReflectorTestPacket{
				SeqNumber:           100,
				Timestamp:           common.FromTime(time.Unix(1234567890, 0)),
				ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				ReceiveTimestamp:    common.FromTime(time.Unix(1234567891, 0)),
				SenderSeqNumber:     99,
				SenderTimestamp:     common.FromTime(time.Unix(1234567889, 0)),
				SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50},
				SenderTTL:           64,
				PaddingSize:         10,
			},
			expectError: false,
		},
		{
			name: "packet with non-zero MBZ",
			data: func() []byte {
				buf := make([]byte, 41)
				buf[14] = 1 // Non-zero in MBZ field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name: "packet with non-zero MBZ2",
			data: func() []byte {
				buf := make([]byte, 41)
				buf[38] = 1 // Non-zero in MBZ2 field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name:        "packet too short",
			data:        make([]byte, 40),
			expectError: true,
			errorType:   common.ErrInvalidMessageLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var packet ReflectorTestPacket
			err := packet.Unmarshal(tt.data)

			if tt.expectError {
				if err == nil {
					t.Errorf("Unmarshal() expected error but got none")
				} else if tt.errorType != nil && err != tt.errorType {
					t.Errorf("Unmarshal() error = %v, expected %v", err, tt.errorType)
				}
				return
			}

			if err != nil {
				t.Errorf("Unmarshal() unexpected error: %v", err)
				return
			}

			if packet.SeqNumber != tt.expectedPacket.SeqNumber {
				t.Errorf("Unmarshal() SeqNumber = %d, expected %d", packet.SeqNumber, tt.expectedPacket.SeqNumber)
			}

			if packet.SenderSeqNumber != tt.expectedPacket.SenderSeqNumber {
				t.Errorf("Unmarshal() SenderSeqNumber = %d, expected %d", packet.SenderSeqNumber, tt.expectedPacket.SenderSeqNumber)
			}

			if packet.SenderTTL != tt.expectedPacket.SenderTTL {
				t.Errorf("Unmarshal() SenderTTL = %d, expected %d", packet.SenderTTL, tt.expectedPacket.SenderTTL)
			}

			if packet.PaddingSize != tt.expectedPacket.PaddingSize {
				t.Errorf("Unmarshal() PaddingSize = %d, expected %d", packet.PaddingSize, tt.expectedPacket.PaddingSize)
			}
		})
	}
}

func TestReflectorTestPacketAuth_Marshal(t *testing.T) {
	tests := []struct {
		name         string
		packet       ReflectorTestPacketAuth
		expectedSize int
		expectError  bool
	}{
		{
			name: "basic authenticated reflector packet",
			packet: ReflectorTestPacketAuth{
				SeqNumber:           100,
				Timestamp:           common.FromTime(time.Unix(1234567890, 0)),
				ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				ReceiveTimestamp:    common.FromTime(time.Unix(1234567891, 0)),
				SenderSeqNumber:     99,
				SenderTimestamp:     common.FromTime(time.Unix(1234567889, 0)),
				SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50},
				SenderTTL:           64,
				HMAC:                [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				PaddingSize:         20,
			},
			expectedSize: 132,
			expectError:  false,
		},
		{
			name: "authenticated reflector packet without padding",
			packet: ReflectorTestPacketAuth{
				SeqNumber:           1,
				Timestamp:           common.FromTime(time.Now()),
				ErrorEstimate:       common.ErrorEstimate{},
				ReceiveTimestamp:    common.FromTime(time.Now()),
				SenderSeqNumber:     0,
				SenderTimestamp:     common.FromTime(time.Now()),
				SenderErrorEstimate: common.ErrorEstimate{},
				SenderTTL:           255,
				HMAC:                [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240},
				PaddingSize:         0,
			},
			expectedSize: 112,
			expectError:  false,
		},
		{
			name: "authenticated reflector packet with large padding",
			packet: ReflectorTestPacketAuth{
				SeqNumber:           4294967295,
				Timestamp:           common.FromTime(time.Now()),
				ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 15, Multiplier: 255},
				ReceiveTimestamp:    common.FromTime(time.Now()),
				SenderSeqNumber:     4294967294,
				SenderTimestamp:     common.FromTime(time.Now()),
				SenderErrorEstimate: common.ErrorEstimate{S: true, Scale: 15, Multiplier: 255},
				SenderTTL:           128,
				HMAC:                [16]byte{},
				PaddingSize:         500,
			},
			expectedSize: 612,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Marshal()

			if tt.expectError {
				if err == nil {
					t.Errorf("Marshal() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Marshal() unexpected error: %v", err)
				return
			}

			if len(data) != tt.expectedSize {
				t.Errorf("Marshal() returned data size = %d, expected %d", len(data), tt.expectedSize)
			}

			// Validate sequence number
			seqNum := binary.BigEndian.Uint32(data[0:4])
			if seqNum != tt.packet.SeqNumber {
				t.Errorf("Marshal() sequence number = %d, expected %d", seqNum, tt.packet.SeqNumber)
			}

			// Validate all MBZ fields are zeros
			// MBZ1 (12 bytes)
			for i := 4; i < 16; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ1 at index %d = %d, expected 0", i, data[i])
				}
			}

			// MBZ2 (6 bytes)
			for i := 26; i < 32; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ2 at index %d = %d, expected 0", i, data[i])
				}
			}

			// MBZ3 (8 bytes)
			for i := 40; i < 48; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ3 at index %d = %d, expected 0", i, data[i])
				}
			}

			// MBZ4 (12 bytes)
			for i := 52; i < 64; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ4 at index %d = %d, expected 0", i, data[i])
				}
			}

			// MBZ5 (6 bytes)
			for i := 74; i < 80; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ5 at index %d = %d, expected 0", i, data[i])
				}
			}

			// MBZ6 (15 bytes)
			for i := 81; i < 96; i++ {
				if data[i] != 0 {
					t.Errorf("Marshal() MBZ6 at index %d = %d, expected 0", i, data[i])
				}
			}

			// Validate Sender TTL
			if data[80] != tt.packet.SenderTTL {
				t.Errorf("Marshal() SenderTTL = %d, expected %d", data[80], tt.packet.SenderTTL)
			}

			// Validate HMAC
			if !bytes.Equal(data[96:112], tt.packet.HMAC[:]) {
				t.Errorf("Marshal() HMAC mismatch")
			}
		})
	}
}

func TestReflectorTestPacketAuth_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedPacket ReflectorTestPacketAuth
		expectError    bool
		errorType      error
	}{
		{
			name: "valid authenticated reflector packet",
			data: func() []byte {
				buf := make([]byte, 112)
				binary.BigEndian.PutUint32(buf[0:4], 100)
				// MBZ (12 bytes) - already zeros
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[16:24])
				ee := common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100}
				binary.BigEndian.PutUint16(buf[24:26], ee.ToUint16())
				// MBZ2 (6 bytes) - already zeros
				recvTs := common.FromTime(time.Unix(1234567891, 0))
				recvTs.Marshal(buf[32:40])
				// MBZ3 (8 bytes) - already zeros
				binary.BigEndian.PutUint32(buf[48:52], 99)
				// MBZ4 (12 bytes) - already zeros
				senderTs := common.FromTime(time.Unix(1234567889, 0))
				senderTs.Marshal(buf[64:72])
				senderEE := common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50}
				binary.BigEndian.PutUint16(buf[72:74], senderEE.ToUint16())
				// MBZ5 (6 bytes) - already zeros
				buf[80] = 64 // SenderTTL
				// MBZ6 (15 bytes) - already zeros
				hmac := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				copy(buf[96:112], hmac[:])
				return buf
			}(),
			expectedPacket: ReflectorTestPacketAuth{
				SeqNumber:           100,
				Timestamp:           common.FromTime(time.Unix(1234567890, 0)),
				ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
				ReceiveTimestamp:    common.FromTime(time.Unix(1234567891, 0)),
				SenderSeqNumber:     99,
				SenderTimestamp:     common.FromTime(time.Unix(1234567889, 0)),
				SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50},
				SenderTTL:           64,
				HMAC:                [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				PaddingSize:         0,
			},
			expectError: false,
		},
		{
			name: "packet with non-zero MBZ1",
			data: func() []byte {
				buf := make([]byte, 112)
				buf[5] = 1 // Non-zero in MBZ field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name: "packet with non-zero MBZ2",
			data: func() []byte {
				buf := make([]byte, 112)
				binary.BigEndian.PutUint32(buf[0:4], 100)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[16:24])
				binary.BigEndian.PutUint16(buf[24:26], 0)
				buf[27] = 1 // Non-zero in MBZ2 field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name: "packet with non-zero MBZ3",
			data: func() []byte {
				buf := make([]byte, 112)
				binary.BigEndian.PutUint32(buf[0:4], 100)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[16:24])
				binary.BigEndian.PutUint16(buf[24:26], 0)
				recvTs := common.FromTime(time.Unix(1234567891, 0))
				recvTs.Marshal(buf[32:40])
				buf[41] = 1 // Non-zero in MBZ3 field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name: "packet with non-zero MBZ4",
			data: func() []byte {
				buf := make([]byte, 112)
				binary.BigEndian.PutUint32(buf[0:4], 100)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[16:24])
				binary.BigEndian.PutUint16(buf[24:26], 0)
				recvTs := common.FromTime(time.Unix(1234567891, 0))
				recvTs.Marshal(buf[32:40])
				binary.BigEndian.PutUint32(buf[48:52], 99)
				buf[53] = 1 // Non-zero in MBZ4 field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name: "packet with non-zero MBZ5",
			data: func() []byte {
				buf := make([]byte, 112)
				binary.BigEndian.PutUint32(buf[0:4], 100)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[16:24])
				binary.BigEndian.PutUint16(buf[24:26], 0)
				recvTs := common.FromTime(time.Unix(1234567891, 0))
				recvTs.Marshal(buf[32:40])
				binary.BigEndian.PutUint32(buf[48:52], 99)
				senderTs := common.FromTime(time.Unix(1234567889, 0))
				senderTs.Marshal(buf[64:72])
				binary.BigEndian.PutUint16(buf[72:74], 0)
				buf[75] = 1 // Non-zero in MBZ5 field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name: "packet with non-zero MBZ6",
			data: func() []byte {
				buf := make([]byte, 112)
				binary.BigEndian.PutUint32(buf[0:4], 100)
				ts := common.FromTime(time.Unix(1234567890, 0))
				ts.Marshal(buf[16:24])
				binary.BigEndian.PutUint16(buf[24:26], 0)
				recvTs := common.FromTime(time.Unix(1234567891, 0))
				recvTs.Marshal(buf[32:40])
				binary.BigEndian.PutUint32(buf[48:52], 99)
				senderTs := common.FromTime(time.Unix(1234567889, 0))
				senderTs.Marshal(buf[64:72])
				binary.BigEndian.PutUint16(buf[72:74], 0)
				buf[80] = 64 // SenderTTL
				buf[82] = 1  // Non-zero in MBZ6 field
				return buf
			}(),
			expectError: true,
			errorType:   common.ErrInvalidMBZ,
		},
		{
			name:        "packet too short",
			data:        make([]byte, 111),
			expectError: true,
			errorType:   common.ErrInvalidMessageLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var packet ReflectorTestPacketAuth
			err := packet.Unmarshal(tt.data)

			if tt.expectError {
				if err == nil {
					t.Errorf("Unmarshal() expected error but got none")
				} else if tt.errorType != nil && err != tt.errorType {
					t.Errorf("Unmarshal() error = %v, expected %v", err, tt.errorType)
				}
				return
			}

			if err != nil {
				t.Errorf("Unmarshal() unexpected error: %v", err)
				return
			}

			if packet.SeqNumber != tt.expectedPacket.SeqNumber {
				t.Errorf("Unmarshal() SeqNumber = %d, expected %d", packet.SeqNumber, tt.expectedPacket.SeqNumber)
			}

			if packet.SenderSeqNumber != tt.expectedPacket.SenderSeqNumber {
				t.Errorf("Unmarshal() SenderSeqNumber = %d, expected %d", packet.SenderSeqNumber, tt.expectedPacket.SenderSeqNumber)
			}

			if packet.SenderTTL != tt.expectedPacket.SenderTTL {
				t.Errorf("Unmarshal() SenderTTL = %d, expected %d", packet.SenderTTL, tt.expectedPacket.SenderTTL)
			}

			if !bytes.Equal(packet.HMAC[:], tt.expectedPacket.HMAC[:]) {
				t.Errorf("Unmarshal() HMAC mismatch")
			}
		})
	}
}

func TestReflectorTestPacket_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet ReflectorTestPacket
	}{
		{
			name: "round trip with padding",
			packet: ReflectorTestPacket{
				SeqNumber:           12345,
				Timestamp:           common.FromTime(time.Now()),
				ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 10, Multiplier: 200},
				ReceiveTimestamp:    common.FromTime(time.Now().Add(time.Millisecond)),
				SenderSeqNumber:     12344,
				SenderTimestamp:     common.FromTime(time.Now().Add(-time.Millisecond)),
				SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 5, Multiplier: 100},
				SenderTTL:           64,
				PaddingSize:         100,
			},
		},
		{
			name: "round trip without padding",
			packet: ReflectorTestPacket{
				SeqNumber:           1,
				Timestamp:           common.FromTime(time.Now()),
				ErrorEstimate:       common.ErrorEstimate{},
				ReceiveTimestamp:    common.FromTime(time.Now()),
				SenderSeqNumber:     0,
				SenderTimestamp:     common.FromTime(time.Now()),
				SenderErrorEstimate: common.ErrorEstimate{},
				SenderTTL:           255,
				PaddingSize:         0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.packet.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}

			// Unmarshal
			var decoded ReflectorTestPacket
			err = decoded.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal() error: %v", err)
			}

			// Compare all fields
			if decoded.SeqNumber != tt.packet.SeqNumber {
				t.Errorf("Round trip SeqNumber = %d, expected %d", decoded.SeqNumber, tt.packet.SeqNumber)
			}

			if decoded.SenderSeqNumber != tt.packet.SenderSeqNumber {
				t.Errorf("Round trip SenderSeqNumber = %d, expected %d", decoded.SenderSeqNumber, tt.packet.SenderSeqNumber)
			}

			if decoded.SenderTTL != tt.packet.SenderTTL {
				t.Errorf("Round trip SenderTTL = %d, expected %d", decoded.SenderTTL, tt.packet.SenderTTL)
			}

			if decoded.PaddingSize != tt.packet.PaddingSize {
				t.Errorf("Round trip PaddingSize = %d, expected %d", decoded.PaddingSize, tt.packet.PaddingSize)
			}
		})
	}
}

func TestAuthPackets_RoundTrip(t *testing.T) {
	t.Run("SenderTestPacketAuth round trip", func(t *testing.T) {
		original := SenderTestPacketAuth{
			SeqNumber:     12345,
			Timestamp:     common.FromTime(time.Now()),
			ErrorEstimate: common.ErrorEstimate{S: true, Scale: 10, Multiplier: 200},
			HMAC:          [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			PaddingSize:   50,
		}

		data, err := original.Marshal()
		if err != nil {
			t.Fatalf("Marshal() error: %v", err)
		}

		var decoded SenderTestPacketAuth
		err = decoded.Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal() error: %v", err)
		}

		if decoded.SeqNumber != original.SeqNumber {
			t.Errorf("Round trip SeqNumber = %d, expected %d", decoded.SeqNumber, original.SeqNumber)
		}

		if !bytes.Equal(decoded.HMAC[:], original.HMAC[:]) {
			t.Errorf("Round trip HMAC mismatch")
		}

		if decoded.PaddingSize != original.PaddingSize {
			t.Errorf("Round trip PaddingSize = %d, expected %d", decoded.PaddingSize, original.PaddingSize)
		}
	})

	t.Run("ReflectorTestPacketAuth round trip", func(t *testing.T) {
		original := ReflectorTestPacketAuth{
			SeqNumber:           12345,
			Timestamp:           common.FromTime(time.Now()),
			ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 10, Multiplier: 200},
			ReceiveTimestamp:    common.FromTime(time.Now().Add(time.Millisecond)),
			SenderSeqNumber:     12344,
			SenderTimestamp:     common.FromTime(time.Now().Add(-time.Millisecond)),
			SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 5, Multiplier: 100},
			SenderTTL:           64,
			HMAC:                [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240},
			PaddingSize:         100,
		}

		data, err := original.Marshal()
		if err != nil {
			t.Fatalf("Marshal() error: %v", err)
		}

		var decoded ReflectorTestPacketAuth
		err = decoded.Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal() error: %v", err)
		}

		if decoded.SeqNumber != original.SeqNumber {
			t.Errorf("Round trip SeqNumber = %d, expected %d", decoded.SeqNumber, original.SeqNumber)
		}

		if decoded.SenderSeqNumber != original.SenderSeqNumber {
			t.Errorf("Round trip SenderSeqNumber = %d, expected %d", decoded.SenderSeqNumber, original.SenderSeqNumber)
		}

		if decoded.SenderTTL != original.SenderTTL {
			t.Errorf("Round trip SenderTTL = %d, expected %d", decoded.SenderTTL, original.SenderTTL)
		}

		if !bytes.Equal(decoded.HMAC[:], original.HMAC[:]) {
			t.Errorf("Round trip HMAC mismatch")
		}
	})
}

// Benchmark tests
func BenchmarkSenderTestPacket_Marshal(b *testing.B) {
	packet := SenderTestPacket{
		SeqNumber:     42,
		Timestamp:     common.FromTime(time.Now()),
		ErrorEstimate: common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
		PaddingSize:   100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = packet.Marshal()
	}
}

func BenchmarkSenderTestPacket_Unmarshal(b *testing.B) {
	packet := SenderTestPacket{
		SeqNumber:     42,
		Timestamp:     common.FromTime(time.Now()),
		ErrorEstimate: common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
		PaddingSize:   100,
	}
	data, _ := packet.Marshal()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p SenderTestPacket
		_ = p.Unmarshal(data)
	}
}

func BenchmarkReflectorTestPacket_Marshal(b *testing.B) {
	packet := ReflectorTestPacket{
		SeqNumber:           100,
		Timestamp:           common.FromTime(time.Now()),
		ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
		ReceiveTimestamp:    common.FromTime(time.Now()),
		SenderSeqNumber:     99,
		SenderTimestamp:     common.FromTime(time.Now()),
		SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50},
		SenderTTL:           64,
		PaddingSize:         100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = packet.Marshal()
	}
}

func BenchmarkReflectorTestPacket_Unmarshal(b *testing.B) {
	packet := ReflectorTestPacket{
		SeqNumber:           100,
		Timestamp:           common.FromTime(time.Now()),
		ErrorEstimate:       common.ErrorEstimate{S: true, Scale: 5, Multiplier: 100},
		ReceiveTimestamp:    common.FromTime(time.Now()),
		SenderSeqNumber:     99,
		SenderTimestamp:     common.FromTime(time.Now()),
		SenderErrorEstimate: common.ErrorEstimate{S: false, Scale: 3, Multiplier: 50},
		SenderTTL:           64,
		PaddingSize:         100,
	}
	data, _ := packet.Marshal()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p ReflectorTestPacket
		_ = p.Unmarshal(data)
	}
}
