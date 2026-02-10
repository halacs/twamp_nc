// pkg/twamp/messages/test_rfc6038_auth_test.go
// Additional tests for RFC 6038 authenticated packet types

package messages

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ncode/twamp/common"
)

// Tests for authenticated RFC 6038 packet types

func TestSenderTestPacketAuthReflectOctets_Marshal_Unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		packet  *SenderTestPacketAuthReflectOctets
		wantErr bool
	}{
		{
			name: "With custom padding data",
			packet: &SenderTestPacketAuthReflectOctets{
				SeqNumber:     12345,
				MBZ:           [12]byte{},
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 2, S: false},
				MBZ2:          [6]byte{},
				HMAC:          [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
				PaddingSize:   16,
				PaddingData:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
			},
			wantErr: false,
		},
		{
			name: "With random padding",
			packet: &SenderTestPacketAuthReflectOctets{
				SeqNumber:     67890,
				MBZ:           [12]byte{},
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 3, Scale: 4, S: true},
				MBZ2:          [6]byte{},
				HMAC:          [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
				PaddingSize:   32,
				PaddingData:   nil, // Will generate random
			},
			wantErr: false,
		},
		{
			name: "No padding",
			packet: &SenderTestPacketAuthReflectOctets{
				SeqNumber:     99999,
				MBZ:           [12]byte{},
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 0, Scale: 0, S: false},
				MBZ2:          [6]byte{},
				HMAC:          [16]byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
				PaddingSize:   0,
				PaddingData:   nil,
			},
			wantErr: false,
		},
		{
			name: "Insufficient padding data",
			packet: &SenderTestPacketAuthReflectOctets{
				SeqNumber:     11111,
				MBZ:           [12]byte{},
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 2, Scale: 3, S: true},
				MBZ2:          [6]byte{},
				HMAC:          [16]byte{0x11, 0x22, 0x33, 0x44},
				PaddingSize:   16,
				PaddingData:   []byte{0x01, 0x02, 0x03, 0x04}, // Less than PaddingSize
			},
			wantErr: false, // Should generate random for missing bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.packet.Marshal()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Marshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Check size
			expectedSize := SenderTestPacketAuthMinSize + tt.packet.PaddingSize
			if len(data) != expectedSize {
				t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
			}

			// Verify MBZ fields are zero
			for i := 4; i < 16; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ field at byte %d is non-zero: %d", i, data[i])
				}
			}
			for i := 26; i < 32; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ2 field at byte %d is non-zero: %d", i, data[i])
				}
			}

			// If custom padding was provided and sufficient, verify it's in the packet
			if tt.packet.PaddingData != nil && len(tt.packet.PaddingData) >= tt.packet.PaddingSize && tt.packet.PaddingSize > 0 {
				paddingInPacket := data[SenderTestPacketAuthMinSize:]
				if !bytes.Equal(paddingInPacket, tt.packet.PaddingData[:tt.packet.PaddingSize]) {
					t.Errorf("Padding data mismatch: got %x, want %x", paddingInPacket, tt.packet.PaddingData[:tt.packet.PaddingSize])
				}
			}

			// Unmarshal
			result := &SenderTestPacketAuthReflectOctets{}
			err = result.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Verify fields
			if result.SeqNumber != tt.packet.SeqNumber {
				t.Errorf("SeqNumber mismatch: got %d, want %d", result.SeqNumber, tt.packet.SeqNumber)
			}

			if result.ErrorEstimate.ToUint16() != tt.packet.ErrorEstimate.ToUint16() {
				t.Errorf("ErrorEstimate mismatch: got %v, want %v", result.ErrorEstimate, tt.packet.ErrorEstimate)
			}

			if !bytes.Equal(result.HMAC[:], tt.packet.HMAC[:]) {
				t.Errorf("HMAC mismatch: got %x, want %x", result.HMAC, tt.packet.HMAC)
			}

			if result.PaddingSize != tt.packet.PaddingSize {
				t.Errorf("PaddingSize mismatch: got %d, want %d", result.PaddingSize, tt.packet.PaddingSize)
			}

			// If padding was present, verify it was extracted
			if tt.packet.PaddingSize > 0 {
				if len(result.PaddingData) != tt.packet.PaddingSize {
					t.Errorf("Extracted padding size mismatch: got %d, want %d", len(result.PaddingData), tt.packet.PaddingSize)
				}

				// If custom padding was used and sufficient, verify content matches
				if tt.packet.PaddingData != nil && len(tt.packet.PaddingData) >= tt.packet.PaddingSize {
					if !bytes.Equal(result.PaddingData, tt.packet.PaddingData[:tt.packet.PaddingSize]) {
						t.Errorf("Extracted padding data mismatch: got %x, want %x", result.PaddingData, tt.packet.PaddingData[:tt.packet.PaddingSize])
					}
				}
			}
		})
	}
}

func TestSenderTestPacketAuthReflectOctets_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		errType error
	}{
		{
			name:    "Data too short",
			data:    make([]byte, SenderTestPacketAuthMinSize-1),
			wantErr: true,
			errType: common.ErrInvalidMessageLength,
		},
		{
			name: "Non-zero MBZ field",
			data: func() []byte {
				packet := &SenderTestPacketAuthReflectOctets{
					SeqNumber:     12345,
					Timestamp:     common.Now(),
					ErrorEstimate: common.ErrorEstimate{},
					HMAC:          [16]byte{0x01, 0x02, 0x03, 0x04},
					PaddingSize:   0,
				}
				data, _ := packet.Marshal()
				// Corrupt MBZ field
				data[8] = 0xFF
				return data
			}(),
			wantErr: true,
			errType: common.ErrInvalidMBZ,
		},
		{
			name: "Non-zero MBZ2 field",
			data: func() []byte {
				packet := &SenderTestPacketAuthReflectOctets{
					SeqNumber:     12345,
					Timestamp:     common.Now(),
					ErrorEstimate: common.ErrorEstimate{},
					HMAC:          [16]byte{0x01, 0x02, 0x03, 0x04},
					PaddingSize:   0,
				}
				data, _ := packet.Marshal()
				// Corrupt MBZ2 field
				data[30] = 0xFF
				return data
			}(),
			wantErr: true,
			errType: common.ErrInvalidMBZ,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := &SenderTestPacketAuthReflectOctets{}
			err := packet.Unmarshal(tt.data)

			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != tt.errType {
				t.Errorf("Error type mismatch: got %v, want %v", err, tt.errType)
			}
		})
	}
}

func TestReflectorTestPacketAuthReflectOctets_Marshal(t *testing.T) {
	reflectedPadding := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	tests := []struct {
		name    string
		packet  *ReflectorTestPacketAuthReflectOctets
		wantErr bool
	}{
		{
			name: "With reflected padding",
			packet: &ReflectorTestPacketAuthReflectOctets{
				SeqNumber:           54321,
				MBZ:                 [12]byte{},
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 5, Scale: 6, S: false},
				MBZ2:                [6]byte{},
				ReceiveTimestamp:    common.Now(),
				MBZ3:                [8]byte{},
				SenderSeqNumber:     12345,
				MBZ4:                [12]byte{},
				SenderTimestamp:     common.Now(),
				SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 2, S: true},
				MBZ5:                [6]byte{},
				SenderTTL:           64,
				MBZ6:                [3]byte{},
				HMAC:                [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
				ReflectedPadding:    reflectedPadding,
			},
			wantErr: false,
		},
		{
			name: "Without reflected padding",
			packet: &ReflectorTestPacketAuthReflectOctets{
				SeqNumber:           99999,
				MBZ:                 [12]byte{},
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 0, Scale: 0, S: false},
				MBZ2:                [6]byte{},
				ReceiveTimestamp:    common.Now(),
				MBZ3:                [8]byte{},
				SenderSeqNumber:     88888,
				MBZ4:                [12]byte{},
				SenderTimestamp:     common.Now(),
				SenderErrorEstimate: common.ErrorEstimate{Multiplier: 7, Scale: 8, S: false},
				MBZ5:                [6]byte{},
				SenderTTL:           128,
				MBZ6:                [3]byte{},
				HMAC:                [16]byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
				ReflectedPadding:    nil,
			},
			wantErr: false,
		},
		{
			name: "Large reflected padding",
			packet: &ReflectorTestPacketAuthReflectOctets{
				SeqNumber:           11111,
				MBZ:                 [12]byte{},
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 3, Scale: 4, S: true},
				MBZ2:                [6]byte{},
				ReceiveTimestamp:    common.Now(),
				MBZ3:                [8]byte{},
				SenderSeqNumber:     22222,
				MBZ4:                [12]byte{},
				SenderTimestamp:     common.Now(),
				SenderErrorEstimate: common.ErrorEstimate{Multiplier: 2, Scale: 3, S: false},
				MBZ5:                [6]byte{},
				SenderTTL:           255,
				MBZ6:                [3]byte{},
				HMAC:                [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
				ReflectedPadding:    make([]byte, 256), // Large padding
			},
			wantErr: false,
		},
		{
			name: "Empty reflected padding slice",
			packet: &ReflectorTestPacketAuthReflectOctets{
				SeqNumber:           12345,
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 2, S: false},
				ReceiveTimestamp:    common.Now(),
				SenderSeqNumber:     54321,
				SenderTimestamp:     common.Now(),
				SenderErrorEstimate: common.ErrorEstimate{Multiplier: 3, Scale: 4, S: true},
				SenderTTL:           64,
				HMAC:                [16]byte{0x01, 0x02, 0x03, 0x04},
				ReflectedPadding:    []byte{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.packet.Marshal()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Marshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Check size
			expectedSize := ReflectorTestPacketAuthMinSize + len(tt.packet.ReflectedPadding)
			if len(data) != expectedSize {
				t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
			}

			// Verify all MBZ fields are zero
			// MBZ (12 bytes at offset 4-15)
			for i := 4; i < 16; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ field at byte %d is non-zero: %d", i, data[i])
				}
			}
			// MBZ2 (6 bytes at offset 26-31)
			for i := 26; i < 32; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ2 field at byte %d is non-zero: %d", i, data[i])
				}
			}
			// MBZ3 (8 bytes at offset 40-47)
			for i := 40; i < 48; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ3 field at byte %d is non-zero: %d", i, data[i])
				}
			}
			// MBZ4 (12 bytes at offset 52-63)
			for i := 52; i < 64; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ4 field at byte %d is non-zero: %d", i, data[i])
				}
			}
			// MBZ5 (6 bytes at offset 74-79)
			for i := 74; i < 80; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ5 field at byte %d is non-zero: %d", i, data[i])
				}
			}
			// MBZ6 (3 bytes at offset 81-83)
			for i := 81; i < 84; i++ {
				if data[i] != 0 {
					t.Errorf("MBZ6 field at byte %d is non-zero: %d", i, data[i])
				}
			}

			// Verify HMAC is copied
			if !bytes.Equal(data[96:112], tt.packet.HMAC[:]) {
				t.Errorf("HMAC mismatch: got %x, want %x", data[96:112], tt.packet.HMAC[:])
			}

			// Verify reflected padding
			if len(tt.packet.ReflectedPadding) > 0 {
				paddingInPacket := data[ReflectorTestPacketAuthMinSize:]
				if !bytes.Equal(paddingInPacket, tt.packet.ReflectedPadding) {
					t.Errorf("Reflected padding mismatch: got %x, want %x", paddingInPacket, tt.packet.ReflectedPadding)
				}
			}

			// Verify specific field values in marshaled data
			// Sequence Number (4 bytes)
			seqNum := binary.BigEndian.Uint32(data[0:4])
			if seqNum != tt.packet.SeqNumber {
				t.Errorf("SeqNumber mismatch: got %d, want %d", seqNum, tt.packet.SeqNumber)
			}

			// Sender Sequence Number (4 bytes at offset 48)
			senderSeqNum := binary.BigEndian.Uint32(data[48:52])
			if senderSeqNum != tt.packet.SenderSeqNumber {
				t.Errorf("SenderSeqNumber mismatch: got %d, want %d", senderSeqNum, tt.packet.SenderSeqNumber)
			}

			// Sender TTL (1 byte at offset 80)
			if data[80] != tt.packet.SenderTTL {
				t.Errorf("SenderTTL mismatch: got %d, want %d", data[80], tt.packet.SenderTTL)
			}
		})
	}
}
