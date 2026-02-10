package messages

import "testing"

func TestPaddingHelpers(t *testing.T) {
	if got := GenerateZeroPadding(0); len(got) != 0 {
		t.Fatalf("zero padding size 0 should be empty")
	}
	if got := GenerateZeroPadding(4); len(got) != 4 || got[0] != 0 || got[3] != 0 {
		t.Fatalf("zero padding not zero‑filled or wrong size")
	}
	randPad, err := GenerateRandomPadding(8)
	if err != nil || len(randPad) != 8 {
		t.Fatalf("random padding failure: %v len=%d", err, len(randPad))
	}
	allZero := true
	for _, b := range randPad {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("random padding appears to be all zeros – very unlikely, investigate")
	}
}

func TestFillZeroPadding(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty buffer", 0},
		{"small buffer", 10},
		{"medium buffer", 100},
		{"large buffer", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.size)
			// Fill with non-zero values first
			for i := range buf {
				buf[i] = byte(i % 256)
			}

			FillZeroPadding(buf)

			// Verify all bytes are zero
			for i, b := range buf {
				if b != 0 {
					t.Errorf("Buffer not zeroed at index %d: got %d", i, b)
					break
				}
			}
		})
	}
}

func TestFillRandomPadding(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty buffer", 0},
		{"small buffer", 16},
		{"medium buffer", 128},
		{"large buffer", 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.size == 0 {
				// Empty buffer should succeed without error
				buf := make([]byte, 0)
				err := FillRandomPadding(buf)
				if err != nil {
					t.Errorf("FillRandomPadding returned error for empty buffer: %v", err)
				}
				return
			}

			buf := make([]byte, tt.size)
			err := FillRandomPadding(buf)
			if err != nil {
				t.Errorf("FillRandomPadding returned error: %v", err)
				return
			}

			// Check that not all bytes are zero (statistically should be true)
			allZero := true
			for _, b := range buf {
				if b != 0 {
					allZero = false
					break
				}
			}

			if allZero && tt.size > 0 {
				t.Error("Random padding appears to be all zeros")
			}
		})
	}
}

func TestGenerateRandomPaddingEdgeCases(t *testing.T) {
	// Test negative size - should return empty slice, not error
	pad, err := GenerateRandomPadding(-1)
	if err != nil {
		t.Errorf("Unexpected error for negative size: %v", err)
	}
	if len(pad) != 0 {
		t.Error("Expected empty slice for negative size")
	}

	// Test zero size
	pad, err = GenerateRandomPadding(0)
	if err != nil {
		t.Errorf("Unexpected error for zero size: %v", err)
	}
	if len(pad) != 0 {
		t.Error("Expected empty slice for zero size")
	}
}
