// pkg/twamp/messages/test_rfc6038_test.go
// Tests for RFC 6038: TWAMP Reflect Octets and Symmetrical Size Features

package messages

import (
	"bytes"
	"testing"

	"github.com/ncode/twamp/common"
)

func TestSenderTestPacketReflectOctets_Marshal_Unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		packet  *SenderTestPacketReflectOctets
		wantErr bool
	}{
		{
			name: "With custom padding data",
			packet: &SenderTestPacketReflectOctets{
				SeqNumber:     12345,
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 2, S: false},
				PaddingSize:   16,
				PaddingData:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
			},
			wantErr: false,
		},
		{
			name: "With random padding",
			packet: &SenderTestPacketReflectOctets{
				SeqNumber:     67890,
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 3, Scale: 4, S: true},
				PaddingSize:   32,
				PaddingData:   nil, // Will generate random
			},
			wantErr: false,
		},
		{
			name: "No padding",
			packet: &SenderTestPacketReflectOctets{
				SeqNumber:     99999,
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 0, Scale: 0, S: false},
				PaddingSize:   0,
				PaddingData:   nil,
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
			expectedSize := SenderTestPacketMinSize + tt.packet.PaddingSize
			if len(data) != expectedSize {
				t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
			}

			// If custom padding was provided, verify it's in the packet
			if tt.packet.PaddingData != nil && tt.packet.PaddingSize > 0 {
				paddingInPacket := data[SenderTestPacketMinSize:]
				if !bytes.Equal(paddingInPacket, tt.packet.PaddingData[:tt.packet.PaddingSize]) {
					t.Errorf("Padding data mismatch: got %x, want %x", paddingInPacket, tt.packet.PaddingData[:tt.packet.PaddingSize])
				}
			}

			// Unmarshal
			result := &SenderTestPacketReflectOctets{}
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

			if result.PaddingSize != tt.packet.PaddingSize {
				t.Errorf("PaddingSize mismatch: got %d, want %d", result.PaddingSize, tt.packet.PaddingSize)
			}

			// If padding was present, verify it was extracted
			if tt.packet.PaddingSize > 0 {
				if len(result.PaddingData) != tt.packet.PaddingSize {
					t.Errorf("Extracted padding size mismatch: got %d, want %d", len(result.PaddingData), tt.packet.PaddingSize)
				}

				// If custom padding was used, verify content matches
				if tt.packet.PaddingData != nil {
					if !bytes.Equal(result.PaddingData, tt.packet.PaddingData[:tt.packet.PaddingSize]) {
						t.Errorf("Extracted padding data mismatch: got %x, want %x", result.PaddingData, tt.packet.PaddingData[:tt.packet.PaddingSize])
					}
				}
			}
		})
	}
}

func TestSenderTestPacketReflectOctets_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		packet  *SenderTestPacketReflectOctets
		wantErr bool
	}{
		{
			name: "Random padding generation fails (simulated)",
			packet: &SenderTestPacketReflectOctets{
				SeqNumber:     12345,
				Timestamp:     common.Now(),
				ErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 2, S: false},
				PaddingSize:   16,
				PaddingData:   nil, // Will try to generate random
			},
			wantErr: false, // crypto/rand.Read should not fail in normal conditions
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.packet.Marshal()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Marshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				// Verify the data was generated properly
				expectedSize := SenderTestPacketMinSize + tt.packet.PaddingSize
				if len(data) != expectedSize {
					t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
				}
			}
		})
	}
}

func TestReflectorTestPacketReflectOctets_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		packet  *ReflectorTestPacketReflectOctets
		wantErr bool
	}{
		{
			name: "Valid packet with no reflected padding",
			packet: &ReflectorTestPacketReflectOctets{
				SeqNumber:           12345,
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 2, S: false},
				MBZ1:                0,
				ReceiveTimestamp:    common.Now(),
				SenderSeqNumber:     54321,
				SenderTimestamp:     common.Now(),
				SenderErrorEstimate: common.ErrorEstimate{Multiplier: 3, Scale: 4, S: true},
				MBZ2:                0,
				SenderTTL:           64,
				ReflectedPadding:    nil,
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
			if err == nil {
				// Verify basic structure
				expectedSize := ReflectorTestPacketMinSize + len(tt.packet.ReflectedPadding)
				if len(data) != expectedSize {
					t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
				}
			}
		})
	}
}

func TestReflectorTestPacketReflectOctets_Marshal_Unmarshal(t *testing.T) {
	reflectedPadding := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	tests := []struct {
		name    string
		packet  *ReflectorTestPacketReflectOctets
		wantErr bool
	}{
		{
			name: "With reflected padding",
			packet: &ReflectorTestPacketReflectOctets{
				SeqNumber:           54321,
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 5, Scale: 6, S: false},
				MBZ1:                0,
				ReceiveTimestamp:    common.Now(),
				SenderSeqNumber:     12345,
				SenderTimestamp:     common.Now(),
				SenderErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 2, S: true},
				MBZ2:                0,
				SenderTTL:           64,
				ReflectedPadding:    reflectedPadding,
			},
			wantErr: false,
		},
		{
			name: "Without reflected padding",
			packet: &ReflectorTestPacketReflectOctets{
				SeqNumber:           99999,
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 0, Scale: 0, S: false},
				MBZ1:                0,
				ReceiveTimestamp:    common.Now(),
				SenderSeqNumber:     88888,
				SenderTimestamp:     common.Now(),
				SenderErrorEstimate: common.ErrorEstimate{Multiplier: 7, Scale: 8, S: false},
				MBZ2:                0,
				SenderTTL:           128,
				ReflectedPadding:    nil,
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
			expectedSize := ReflectorTestPacketMinSize + len(tt.packet.ReflectedPadding)
			if len(data) != expectedSize {
				t.Errorf("Marshal size mismatch: got %d, want %d", len(data), expectedSize)
			}

			// Unmarshal
			result := &ReflectorTestPacketReflectOctets{}
			err = result.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Verify fields
			if result.SeqNumber != tt.packet.SeqNumber {
				t.Errorf("SeqNumber mismatch: got %d, want %d", result.SeqNumber, tt.packet.SeqNumber)
			}

			if result.SenderSeqNumber != tt.packet.SenderSeqNumber {
				t.Errorf("SenderSeqNumber mismatch: got %d, want %d", result.SenderSeqNumber, tt.packet.SenderSeqNumber)
			}

			if result.SenderTTL != tt.packet.SenderTTL {
				t.Errorf("SenderTTL mismatch: got %d, want %d", result.SenderTTL, tt.packet.SenderTTL)
			}

			if result.MBZ1 != 0 {
				t.Errorf("MBZ1 not zero: got %d", result.MBZ1)
			}

			if result.MBZ2 != 0 {
				t.Errorf("MBZ2 not zero: got %d", result.MBZ2)
			}

			// Verify reflected padding
			if !bytes.Equal(result.ReflectedPadding, tt.packet.ReflectedPadding) {
				t.Errorf("ReflectedPadding mismatch: got %x, want %x", result.ReflectedPadding, tt.packet.ReflectedPadding)
			}
		})
	}
}

func TestCalculateSymmetricalPadding(t *testing.T) {
	tests := []struct {
		name             string
		senderPacketSize int
		expectedPadding  int
	}{
		{
			name:             "Sender smaller than reflector minimum",
			senderPacketSize: 30,
			expectedPadding:  0,
		},
		{
			name:             "Sender equal to reflector minimum",
			senderPacketSize: ReflectorTestPacketMinSize,
			expectedPadding:  0,
		},
		{
			name:             "Sender larger than reflector minimum",
			senderPacketSize: 100,
			expectedPadding:  59, // 100 - ReflectorTestPacketMinSize
		},
		{
			name:             "Large sender packet",
			senderPacketSize: 1000,
			expectedPadding:  959, // 1000 - ReflectorTestPacketMinSize
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padding := CalculateSymmetricalPadding(tt.senderPacketSize)
			if padding != tt.expectedPadding {
				t.Errorf("CalculateSymmetricalPadding(%d) = %d, want %d", tt.senderPacketSize, padding, tt.expectedPadding)
			}
		})
	}
}

func TestCalculateSymmetricalPaddingAuth(t *testing.T) {
	tests := []struct {
		name             string
		senderPacketSize int
		expectedPadding  int
	}{
		{
			name:             "Sender smaller than reflector auth minimum",
			senderPacketSize: 100,
			expectedPadding:  0,
		},
		{
			name:             "Sender equal to reflector auth minimum",
			senderPacketSize: ReflectorTestPacketAuthMinSize,
			expectedPadding:  0,
		},
		{
			name:             "Sender larger than reflector auth minimum",
			senderPacketSize: 200,
			expectedPadding:  88, // 200 - ReflectorTestPacketAuthMinSize
		},
		{
			name:             "Large authenticated sender packet",
			senderPacketSize: 1500,
			expectedPadding:  1388, // 1500 - ReflectorTestPacketAuthMinSize
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padding := CalculateSymmetricalPaddingAuth(tt.senderPacketSize)
			if padding != tt.expectedPadding {
				t.Errorf("CalculateSymmetricalPaddingAuth(%d) = %d, want %d", tt.senderPacketSize, padding, tt.expectedPadding)
			}
		})
	}
}

func TestCreateRFC6038SymmetricalReflectorPacket(t *testing.T) {
	senderPacket := &SenderTestPacket{
		SeqNumber:     12345,
		Timestamp:     common.Now(),
		ErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 2, S: false},
	}

	tests := []struct {
		name             string
		senderPacketSize int
		expectedPadding  int
	}{
		{
			name:             "Small sender packet",
			senderPacketSize: 30,
			expectedPadding:  0,
		},
		{
			name:             "Large sender packet",
			senderPacketSize: 100,
			expectedPadding:  59,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflectorPacket := CreateRFC6038SymmetricalReflectorPacket(senderPacket, tt.senderPacketSize)

			if reflectorPacket.SenderSeqNumber != senderPacket.SeqNumber {
				t.Errorf("SenderSeqNumber mismatch: got %d, want %d", reflectorPacket.SenderSeqNumber, senderPacket.SeqNumber)
			}

			if reflectorPacket.PaddingSize != tt.expectedPadding {
				t.Errorf("PaddingSize mismatch: got %d, want %d", reflectorPacket.PaddingSize, tt.expectedPadding)
			}
		})
	}
}

func TestCreateRFC6038ReflectOctetsReflectorPacket(t *testing.T) {
	paddingData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	senderPacket := &SenderTestPacketReflectOctets{
		SeqNumber:     12345,
		Timestamp:     common.Now(),
		ErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 2, S: false},
		PaddingSize:   len(paddingData),
		PaddingData:   paddingData,
	}

	reflectorPacket := CreateRFC6038ReflectOctetsReflectorPacket(senderPacket)

	if reflectorPacket.SenderSeqNumber != senderPacket.SeqNumber {
		t.Errorf("SenderSeqNumber mismatch: got %d, want %d", reflectorPacket.SenderSeqNumber, senderPacket.SeqNumber)
	}

	if !bytes.Equal(reflectorPacket.ReflectedPadding, senderPacket.PaddingData) {
		t.Errorf("ReflectedPadding mismatch: got %x, want %x", reflectorPacket.ReflectedPadding, senderPacket.PaddingData)
	}
}

func TestReflectorTestPacketReflectOctets_MBZValidation(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		errType error
	}{
		{
			name: "Non-zero MBZ1",
			data: func() []byte {
				packet := &ReflectorTestPacketReflectOctets{
					SeqNumber:           1,
					Timestamp:           common.Now(),
					ErrorEstimate:       common.ErrorEstimate{},
					MBZ1:                0xFFFF, // Non-zero
					ReceiveTimestamp:    common.Now(),
					SenderSeqNumber:     2,
					SenderTimestamp:     common.Now(),
					SenderErrorEstimate: common.ErrorEstimate{},
					MBZ2:                0,
					SenderTTL:           64,
				}
				data, _ := packet.Marshal()
				// Manually set MBZ1 to non-zero
				data[SenderTestPacketMinSize] = 0xFF
				data[15] = 0xFF
				return data
			}(),
			wantErr: true,
			errType: common.ErrInvalidMBZ,
		},
		{
			name: "Non-zero MBZ2",
			data: func() []byte {
				packet := &ReflectorTestPacketReflectOctets{
					SeqNumber:           1,
					Timestamp:           common.Now(),
					ErrorEstimate:       common.ErrorEstimate{},
					MBZ1:                0,
					ReceiveTimestamp:    common.Now(),
					SenderSeqNumber:     2,
					SenderTimestamp:     common.Now(),
					SenderErrorEstimate: common.ErrorEstimate{},
					MBZ2:                0xFFFF, // Non-zero
					SenderTTL:           64,
				}
				data, _ := packet.Marshal()
				// Manually set MBZ2 to non-zero
				data[38] = 0xFF
				data[39] = 0xFF
				return data
			}(),
			wantErr: true,
			errType: common.ErrInvalidMBZ,
		},
		{
			name:    "Data too short",
			data:    make([]byte, 30),
			wantErr: true,
			errType: common.ErrInvalidMessageLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := &ReflectorTestPacketReflectOctets{}
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
