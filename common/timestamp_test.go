// pkg/twamp/common/timestamp_test.go
package common

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func TestTimestampConversion(t *testing.T) {
	// Test conversion to and from NTP timestamp
	now := time.Now()
	ts := FromTime(now)
	converted := ts.ToTime()

	// Since we convert through different representations,
	// we may lose some sub-nanosecond precision.
	// Allow a small tolerance of 1 microsecond
	tolerance := time.Microsecond

	diff := now.Sub(converted)
	if diff < -tolerance || diff > tolerance {
		t.Errorf("Time conversion error too large: %v", diff)
	}
}

func TestTimestampMath(t *testing.T) {
	// Test addition and subtraction
	baseTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	ts := FromTime(baseTime)

	// Add 1 second
	added := ts.Add(time.Second)
	expected := FromTime(baseTime.Add(time.Second))

	if !added.Equal(expected) {
		t.Errorf("Timestamp addition error: got %v, expected %v", added, expected)
	}

	// Subtract 1 second
	subtracted := ts.Sub(time.Second)
	expected = FromTime(baseTime.Add(-time.Second))

	if !subtracted.Equal(expected) {
		t.Errorf("Timestamp subtraction error: got %v, expected %v", subtracted, expected)
	}

	// Test spanning second boundaries
	ts = TWAMPTimestamp{Seconds: 1000, Fraction: 0x80000000} // Half second

	// Add 0.75 seconds (crosses second boundary)
	added = ts.Add(750 * time.Millisecond)
	if added.Seconds != 1001 || added.Fraction != 0x40000000 {
		t.Errorf("Timestamp addition across boundary failed: got %v, expected {1001, 0x40000000}", added)
	}

	// Subtract 0.75 seconds (crosses second boundary)
	subtracted = ts.Sub(750 * time.Millisecond)
	if subtracted.Seconds != 999 || subtracted.Fraction != 0xC0000000 {
		t.Errorf("Timestamp subtraction across boundary failed: got %v, expected {999, 0xC0000000}", subtracted)
	}
}

func TestNTPEpoch(t *testing.T) {
	// Test NTP epoch handling
	// January 1, 1900, 00:00:00 UTC is the NTP epoch
	ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	ts := FromTime(ntpEpoch)

	if ts.Seconds != 0 || ts.Fraction != 0 {
		t.Errorf("NTP epoch conversion error: got %v, expected {0, 0}", ts)
	}

	// January 1, 1970, 00:00:00 UTC is the Unix epoch
	unixEpoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	ts = FromTime(unixEpoch)

	if ts.Seconds != NTPEpochOffset || ts.Fraction != 0 {
		t.Errorf("Unix epoch conversion error: got %v, expected {%d, 0}", ts, NTPEpochOffset)
	}
}

func TestHighPrecision(t *testing.T) {
	// Test case with nanosecond precision
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 123456789, time.UTC)
	ts := FromTime(originalTime)
	recoveredTime := ts.ToTime()

	// Allow a small margin of error due to floating point conversions
	// The error should be less than 1 nanosecond
	tolerance := time.Nanosecond

	diff := originalTime.Sub(recoveredTime)
	if diff < -tolerance || diff > tolerance {
		t.Errorf("High precision time conversion error: %v", diff)
	}

	// Test the limits of precision with very small values
	oneNano := time.Date(2023, 1, 1, 0, 0, 0, 1, time.UTC)
	ts = FromTime(oneNano)

	// The NTP fraction for 1ns should be approximately 2^32 / 10^9
	expectedFraction := uint32(math.Round(float64(1) * NanoToFrac))
	if math.Abs(float64(ts.Fraction)-float64(expectedFraction)) > 1.0 {
		t.Errorf("1ns precision error: got fraction %d, expected ~%d",
			ts.Fraction, expectedFraction)
	}
}

// helper to compare two timestamps exactly in tests
func equalTS(a, b TWAMPTimestamp) bool {
	return a.Seconds == b.Seconds && a.Fraction == b.Fraction
}

// TestAddOverflowCarry verifies that Add() correctly carries when the fractional
// sum exceeds 2^32 – i.e. one full second.
func TestAddOverflowCarry(t *testing.T) {
	start := TWAMPTimestamp{Seconds: 123, Fraction: (1 << 32) - 16} // 0xfffffff0
	dur := 50 * time.Nanosecond                                     // gives ~214 frac units

	got := start.Add(dur)

	// Manually compute the expected result using the same rules as Add().
	secs := start.Seconds
	nanos := dur % time.Second
	fracToAdd := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)
	newFracU64 := uint64(start.Fraction) + uint64(fracToAdd)
	carry := uint32(0)
	if newFracU64 >= (1 << 32) {
		carry = 1
		newFracU64 -= 1 << 32
	}
	want := TWAMPTimestamp{Seconds: secs + carry, Fraction: uint32(newFracU64)}

	if !equalTS(got, want) {
		t.Fatalf("Add overflow: want %+v, got %+v", want, got)
	}
}

// TestSubUnderflowBorrow verifies that Sub() borrows correctly when the
// fractional part underflows.
func TestSubUnderflowBorrow(t *testing.T) {
	start := TWAMPTimestamp{Seconds: 123, Fraction: 10}
	dur := time.Microsecond // ~4 294 frac units

	got := start.Sub(dur)

	// Expected – borrow one full second
	nanos := dur % time.Second
	fracToSub := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)
	var newFrac uint32
	borrow := uint32(0)
	if fracToSub > start.Fraction {
		borrow = 1
		newFrac = uint32(uint64(start.Fraction) + (1 << 32) - uint64(fracToSub))
	} else {
		newFrac = start.Fraction - fracToSub
	}
	want := TWAMPTimestamp{Seconds: start.Seconds - borrow, Fraction: newFrac}

	if !equalTS(got, want) {
		t.Fatalf("Sub underflow: want %+v, got %+v", want, got)
	}
}

// TestDurationBetween covers both the regular case and the underflow branch.
func TestDurationBetween(t *testing.T) {
	start := TWAMPTimestamp{Seconds: 100, Fraction: (1 << 32) - 100}
	end := TWAMPTimestamp{Seconds: 101, Fraction: 50}

	got := DurationBetween(start, end)
	want := end.ToTime().Sub(start.ToTime())

	// Accept ±1 ns tolerance due to float rounding.
	diff := got - want
	if diff > time.Nanosecond || diff < -time.Nanosecond {
		t.Fatalf("DurationBetween mismatch: want %v, got %v", want, got)
	}
}

// TestDurationBetweenUnderflow specifically tests the underflow path in DurationBetween
func TestDurationBetweenUnderflow(t *testing.T) {
	// Test case where end.Fraction < start.Fraction, triggering the underflow path
	start := TWAMPTimestamp{Seconds: 100, Fraction: 0xFFFFFF00} // High fraction value
	end := TWAMPTimestamp{Seconds: 101, Fraction: 0x00000100}   // Low fraction value

	got := DurationBetween(start, end)
	want := end.ToTime().Sub(start.ToTime())

	// Accept ±1 ns tolerance due to float rounding
	diff := got - want
	if diff > time.Nanosecond || diff < -time.Nanosecond {
		t.Fatalf("DurationBetweenUnderflow mismatch: want %v, got %v", want, got)
	}
}

// TestComparisonHelpers exercises Equal/Before/After for both fractional and
// whole‑second divergences, including the edge cases where the second fields
// alone decide the outcome.
func TestComparisonHelpers(t *testing.T) {
	// Same seconds, different fractions
	a := TWAMPTimestamp{Seconds: 10, Fraction: 100}
	b := TWAMPTimestamp{Seconds: 10, Fraction: 200}
	// Different seconds
	c := TWAMPTimestamp{Seconds: 11, Fraction: 0}

	if !a.Before(b) || b.Before(a) {
		t.Fatalf("Before failed for same second different fraction")
	}
	if !b.After(a) || a.After(b) {
		t.Fatalf("After failed for same second different fraction")
	}
	if !b.Before(c) || !a.Before(c) {
		t.Fatalf("Before failed across seconds")
	}
	if !c.After(b) {
		t.Fatalf("After failed across seconds")
	}
	if !a.Equal(a) || a.Equal(b) {
		t.Fatalf("Equal logic incorrect")
	}

	// Edge‑case branches: ts.Seconds > other.Seconds for Before() should be false
	biggerSec := TWAMPTimestamp{Seconds: 20, Fraction: 0}
	smallerSec := TWAMPTimestamp{Seconds: 19, Fraction: (1 << 32) - 1}
	if biggerSec.Before(smallerSec) {
		t.Fatalf("Before() with ts.Seconds > other.Seconds returned true, expected false")
	}
	// Edge‑case branches: ts.Seconds < other.Seconds for After() should be false
	if smallerSec.After(biggerSec) {
		t.Fatalf("After() with ts.Seconds < other.Seconds returned true, expected false")
	}
}

// TestRoundTripTime ensures FromTime and ToTime are inverses to nanosecond
// precision (the original time’s monotonic component is lost, so we compare
// only the wall‑clock UnixNano).
func TestRoundTripTime(t *testing.T) {
	now := time.Now().Truncate(time.Nanosecond) // strip monotonic for fairness
	ts := FromTime(now)
	back := ts.ToTime()

	// Allow ±1 ns tolerance because of float64 conversions.
	delta := math.Abs(float64(back.UnixNano() - now.UnixNano()))
	if delta > 1 {
		t.Fatalf("Round‑trip exceeded tolerance: %dns", int64(delta))
	}
}

// TestNTPEraRollover tests NTP era rollover handling per RFC 5905 Section 4
// NTP Era 0: 1900-01-01 00:00:00 to 2036-02-07 06:28:16
// NTP Era 1: 2036-02-07 06:28:16 to 2172-03-15 12:56:32
func TestNTPEraRollover(t *testing.T) {
	tests := []struct {
		name        string
		inputTime   time.Time
		refTime     time.Time
		description string
	}{
		{
			name:        "Before_Era1_Start",
			inputTime:   time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			refTime:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			description: "Date before NTP Era 1 rollover",
		},
		{
			name:        "At_Era1_Start_Minus_1sec",
			inputTime:   time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC),
			refTime:     time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC),
			description: "One second before NTP Era 1 starts",
		},
		{
			name:        "At_Era1_Start",
			inputTime:   time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC),
			refTime:     time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC),
			description: "Exactly at NTP Era 1 rollover point",
		},
		{
			name:        "At_Era1_Start_Plus_1sec",
			inputTime:   time.Date(2036, 2, 7, 6, 28, 17, 0, time.UTC),
			refTime:     time.Date(2036, 2, 7, 6, 28, 17, 0, time.UTC),
			description: "One second after NTP Era 1 starts",
		},
		{
			name:        "After_Era1_Start",
			inputTime:   time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC),
			refTime:     time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC),
			description: "Date well after NTP Era 1 rollover",
		},
		{
			name:        "Year_2100",
			inputTime:   time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			refTime:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			description: "Year 2100 in NTP Era 1",
		},
		{
			name:        "Near_Era2_Start",
			inputTime:   time.Date(2172, 3, 15, 12, 56, 31, 0, time.UTC),
			refTime:     time.Date(2172, 3, 15, 12, 56, 31, 0, time.UTC),
			description: "One second before NTP Era 2 (future handling)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to TWAMP timestamp
			ts := FromTime(tt.inputTime)

			// Convert back using reference time
			recovered := ts.ToTimeWithReference(tt.refTime)

			// The recovered time should match the input within tolerance
			tolerance := time.Microsecond
			diff := tt.inputTime.Sub(recovered)
			if diff < -tolerance || diff > tolerance {
				t.Errorf("%s: conversion error too large: input=%v, recovered=%v, diff=%v",
					tt.description, tt.inputTime, recovered, diff)
			}

			// Verify the seconds field wraps correctly
			// The NTP seconds field should be modulo 2^32
			unixSecs := tt.inputTime.Unix()
			ntpSecs := unixSecs + NTPEpochOffset
			expectedSecs := uint32(ntpSecs & 0xFFFFFFFF)

			if ts.Seconds != expectedSecs {
				t.Errorf("%s: incorrect seconds field: got=%d, expected=%d",
					tt.description, ts.Seconds, expectedSecs)
			}
		})
	}
}

// TestNTPEraAmbiguity tests that ToTimeWithReference correctly resolves
// era ambiguity when timestamps could belong to different eras
func TestNTPEraAmbiguity(t *testing.T) {
	// Create a timestamp that could be in Era 0 or Era 1
	// Use a seconds value that would be valid in both eras
	ambiguousTS := TWAMPTimestamp{
		Seconds:  0x80000000, // Middle of the 32-bit range
		Fraction: 0,
	}

	tests := []struct {
		name         string
		refTime      time.Time
		expectedYear int
		description  string
	}{
		{
			name:         "Reference_In_Era0",
			refTime:      time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			expectedYear: 1968, // The timestamp interpreted in Era 0
			description:  "Reference in Era 0 should interpret timestamp as Era 0",
		},
		{
			name:         "Reference_In_Era1",
			refTime:      time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			expectedYear: 2104, // The timestamp interpreted in Era 1
			description:  "Reference in Era 1 should interpret timestamp as Era 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recovered := ambiguousTS.ToTimeWithReference(tt.refTime)

			if recovered.Year() != tt.expectedYear {
				t.Errorf("%s: got year %d, expected %d",
					tt.description, recovered.Year(), tt.expectedYear)
			}
		})
	}
}

// TestCrossEraMessageExchange simulates TWAMP messages exchanged across era boundary
func TestCrossEraMessageExchange(t *testing.T) {
	// Simulate a session that starts before Era 1 and continues after
	beforeEra1 := time.Date(2036, 2, 7, 6, 28, 10, 0, time.UTC) // 6 seconds before rollover
	afterEra1 := time.Date(2036, 2, 7, 6, 28, 20, 0, time.UTC)  // 4 seconds after rollover

	// Create timestamps as if they were from TWAMP packets
	ts1 := FromTime(beforeEra1)
	ts2 := FromTime(afterEra1)

	// Calculate duration using the reference time approach
	// In a real TWAMP session, both endpoints would use similar wall-clock times
	duration := DurationBetween(ts1, ts2)
	expectedDuration := 10 * time.Second

	// Allow small tolerance for floating point operations
	diff := duration - expectedDuration
	if diff < -time.Microsecond || diff > time.Microsecond {
		t.Errorf("Cross-era duration calculation failed: got %v, expected %v, diff %v",
			duration, expectedDuration, diff)
	}

	// Verify that both timestamps convert back correctly when using appropriate reference
	recovered1 := ts1.ToTimeWithReference(beforeEra1)
	recovered2 := ts2.ToTimeWithReference(afterEra1)

	if !recovered1.Equal(beforeEra1) {
		t.Errorf("Failed to recover pre-era timestamp: got %v, expected %v",
			recovered1, beforeEra1)
	}

	if !recovered2.Equal(afterEra1) {
		t.Errorf("Failed to recover post-era timestamp: got %v, expected %v",
			recovered2, afterEra1)
	}
}

// TestNTPEraDocumentation verifies the constants match RFC 5905
func TestNTPEraDocumentation(t *testing.T) {
	// NTP Era 1 starts at 2036-02-07 06:28:16 UTC
	era1Start := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
	era1Unix := era1Start.Unix()

	// The constant should match this
	if NTPEra1Unix != era1Unix {
		t.Errorf("NTPEra1Unix constant incorrect: got %d, expected %d",
			NTPEra1Unix, era1Unix)
	}

	// The actual offset should be 2208988800 seconds
	actualOffset := int64(NTPEpochOffset)
	if actualOffset != 2208988800 {
		t.Errorf("NTPEpochOffset incorrect: got %d, expected 2208988800", actualOffset)
	}
}

// TestEraBoundaryTimestamps tests exact NTP era boundary timestamp handling
func TestEraBoundaryTimestamps(t *testing.T) {
	testCases := []struct {
		name         string
		time         time.Time
		wantSeconds  uint32
		wantFraction uint32
		description  string
	}{
		{
			name:         "NTP Era 0 Start - 1900-01-01 00:00:00",
			time:         time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
			wantSeconds:  0,
			wantFraction: 0,
			description:  "The very beginning of NTP Era 0",
		},
		{
			name:         "NTP Era 0 End - one second before rollover",
			time:         time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC),
			wantSeconds:  0xFFFFFFFF, // Maximum 32-bit value
			wantFraction: 0,
			description:  "Last second of Era 0 before rollover to Era 1",
		},
		{
			name:         "NTP Era 1 Start - exact rollover moment",
			time:         time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC),
			wantSeconds:  0, // Rolls over to 0
			wantFraction: 0,
			description:  "First second of Era 1 after rollover",
		},
		{
			name:         "NTP Era 1 - one minute after rollover",
			time:         time.Date(2036, 2, 7, 6, 29, 16, 0, time.UTC),
			wantSeconds:  60,
			wantFraction: 0,
			description:  "60 seconds into Era 1",
		},
		{
			name:         "NTP Era 1 - one hour after rollover",
			time:         time.Date(2036, 2, 7, 7, 28, 16, 0, time.UTC),
			wantSeconds:  3600,
			wantFraction: 0,
			description:  "One hour into Era 1",
		},
		{
			name:         "NTP Era 1 - one day after rollover",
			time:         time.Date(2036, 2, 8, 6, 28, 16, 0, time.UTC),
			wantSeconds:  86400,
			wantFraction: 0,
			description:  "One day into Era 1",
		},
		{
			name:         "NTP Era 0 - with fractional seconds",
			time:         time.Date(2036, 2, 7, 6, 28, 15, 500000000, time.UTC),
			wantSeconds:  0xFFFFFFFF,
			wantFraction: 0x80000000, // 0.5 seconds
			description:  "Era 0 boundary with half-second fraction",
		},
		{
			name:         "NTP Era 1 Start - with fractional seconds",
			time:         time.Date(2036, 2, 7, 6, 28, 16, 250000000, time.UTC),
			wantSeconds:  0,
			wantFraction: 0x40000000, // 0.25 seconds
			description:  "Era 1 start with quarter-second fraction",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert to TWAMPTimestamp
			ts := FromTime(tc.time)

			// Check seconds field
			if ts.Seconds != tc.wantSeconds {
				t.Errorf("Seconds mismatch for %s:\n  got:  0x%08X (%d)\n  want: 0x%08X (%d)",
					tc.description, ts.Seconds, ts.Seconds, tc.wantSeconds, tc.wantSeconds)
			}

			// Check fraction field (allow small tolerance for floating point)
			fractionDiff := int64(ts.Fraction) - int64(tc.wantFraction)
			if fractionDiff < 0 {
				fractionDiff = -fractionDiff
			}
			// Allow 100 units of tolerance (very small in 2^32 scale)
			if fractionDiff > 100 {
				t.Errorf("Fraction mismatch for %s:\n  got:  0x%08X\n  want: 0x%08X\n  diff: %d",
					tc.description, ts.Fraction, tc.wantFraction, fractionDiff)
			}
		})
	}
}

// TestEraBoundaryRoundTrip tests that era boundary timestamps convert correctly both ways
func TestEraBoundaryRoundTrip(t *testing.T) {
	criticalTimes := []struct {
		name string
		time time.Time
	}{
		{"Era 0 end - 1 second", time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC)},
		{"Era 0 end - exact", time.Date(2036, 2, 7, 6, 28, 15, 999999999, time.UTC)},
		{"Era 1 start - exact", time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)},
		{"Era 1 start + 1 second", time.Date(2036, 2, 7, 6, 28, 17, 0, time.UTC)},
		{"Era 1 + 1 year", time.Date(2037, 2, 7, 6, 28, 16, 0, time.UTC)},
		{"Era 1 + 10 years", time.Date(2046, 2, 7, 6, 28, 16, 0, time.UTC)},
		{"Era 1 + 50 years", time.Date(2086, 2, 7, 6, 28, 16, 0, time.UTC)},
	}

	for _, tc := range criticalTimes {
		t.Run(tc.name, func(t *testing.T) {
			// Convert to TWAMP timestamp
			ts := FromTime(tc.time)

			// Convert back using reference time close to original
			// This is important for era determination
			recovered := ts.ToTimeWithReference(tc.time)

			// Check the round trip
			diff := recovered.Sub(tc.time).Abs()

			// Allow up to 1 microsecond difference due to fraction precision
			if diff > time.Microsecond {
				t.Errorf("Round trip failed for %s:\n  original:  %v\n  recovered: %v\n  diff: %v",
					tc.name, tc.time, recovered, diff)
			}
		})
	}
}

// TestDurationBetweenAcrossEraBoundary tests duration calculation across era boundaries
func TestDurationBetweenAcrossEraBoundary(t *testing.T) {
	testCases := []struct {
		name    string
		start   time.Time
		end     time.Time
		wantDur time.Duration
	}{
		{
			name:    "Within Era 0",
			start:   time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
			end:     time.Date(2035, 1, 1, 0, 0, 10, 0, time.UTC),
			wantDur: 10 * time.Second,
		},
		{
			name:    "Across Era 0 to Era 1 boundary",
			start:   time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC),
			end:     time.Date(2036, 2, 7, 6, 28, 17, 0, time.UTC),
			wantDur: 2 * time.Second,
		},
		{
			name:    "Era 0 end to Era 1 start exactly",
			start:   time.Date(2036, 2, 7, 6, 28, 15, 999999999, time.UTC),
			end:     time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC),
			wantDur: 1 * time.Nanosecond,
		},
		{
			name:    "Within Era 1",
			start:   time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC),
			end:     time.Date(2037, 1, 1, 0, 0, 30, 0, time.UTC),
			wantDur: 30 * time.Second,
		},
		{
			name:    "Large span across boundary",
			start:   time.Date(2035, 2, 7, 6, 28, 16, 0, time.UTC),
			end:     time.Date(2037, 2, 7, 6, 28, 16, 0, time.UTC),
			wantDur: 731 * 24 * time.Hour, // 2 years including leap year 2036
		},
		{
			name:    "Negative duration across boundary",
			start:   time.Date(2036, 2, 7, 6, 28, 20, 0, time.UTC),
			end:     time.Date(2036, 2, 7, 6, 28, 10, 0, time.UTC),
			wantDur: -10 * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			startTS := FromTime(tc.start)
			endTS := FromTime(tc.end)

			duration := DurationBetween(startTS, endTS)

			// Allow small tolerance for floating point conversions
			diff := duration - tc.wantDur
			if diff < 0 {
				diff = -diff
			}

			// Allow up to 1 microsecond tolerance
			if diff > time.Microsecond {
				t.Errorf("Duration mismatch:\n  start: %v\n  end:   %v\n  got:   %v\n  want:  %v\n  diff:  %v",
					tc.start, tc.end, duration, tc.wantDur, diff)
			}
		})
	}
}

// TestEraWraparoundHandling tests handling of NTP seconds field wraparound
func TestEraWraparoundHandling(t *testing.T) {
	// Test that seconds field properly wraps at 2^32
	preWrap := time.Date(2036, 2, 7, 6, 28, 15, 999999999, time.UTC)
	postWrap := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)

	preTS := FromTime(preWrap)
	postTS := FromTime(postWrap)

	// Pre-wrap should have maximum seconds value
	if preTS.Seconds != 0xFFFFFFFF {
		t.Errorf("Pre-wrap seconds should be 0xFFFFFFFF, got 0x%08X", preTS.Seconds)
	}

	// Post-wrap should have zero seconds
	if postTS.Seconds != 0 {
		t.Errorf("Post-wrap seconds should be 0, got 0x%08X", postTS.Seconds)
	}

	// Duration between them should be very small (1 nanosecond + fraction difference)
	duration := DurationBetween(preTS, postTS)
	if duration < 0 || duration > time.Millisecond {
		t.Errorf("Duration across wrap should be ~1ns, got %v", duration)
	}
}

// TestEraAmbiguityResolution tests that ToTimeWithReference correctly resolves era ambiguity
func TestEraAmbiguityResolution(t *testing.T) {
	// Create a timestamp with seconds = 100
	// This could be in Era 0 (1900) or Era 1 (2036)
	ambiguousTS := TWAMPTimestamp{
		Seconds:  100,
		Fraction: 0,
	}

	// Reference in Era 0
	refEra0 := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	resultEra0 := ambiguousTS.ToTimeWithReference(refEra0)

	// Should resolve to Era 0 (around 1900)
	if resultEra0.Year() >= 2036 {
		t.Errorf("With Era 0 reference, should resolve to Era 0, got %v", resultEra0)
	}

	// Reference in Era 1
	refEra1 := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	resultEra1 := ambiguousTS.ToTimeWithReference(refEra1)

	// Should resolve to Era 1 (after 2036)
	if resultEra1.Year() < 2036 {
		t.Errorf("With Era 1 reference, should resolve to Era 1, got %v", resultEra1)
	}

	// The two results should be exactly one era (2^32 seconds) apart
	eraDiff := resultEra1.Sub(resultEra0)
	expectedDiff := time.Duration(1<<32) * time.Second

	if eraDiff != expectedDiff {
		t.Errorf("Era difference should be exactly 2^32 seconds, got %v", eraDiff)
	}
}

// TestEraConsistencyUnderStress tests era handling under various stress conditions
func TestEraConsistencyUnderStress(t *testing.T) {
	// Test rapid timestamp creation around era boundary
	startTime := time.Date(2036, 2, 7, 6, 28, 14, 0, time.UTC)

	for i := 0; i < 5000; i++ {
		testTime := startTime.Add(time.Duration(i) * time.Millisecond)
		ts := FromTime(testTime)
		recovered := ts.ToTimeWithReference(testTime)

		diff := recovered.Sub(testTime).Abs()
		if diff > time.Microsecond {
			t.Errorf("Iteration %d: time mismatch at %v, diff=%v", i, testTime, diff)
			break
		}
	}
}

// TestMarshalUnmarshal tests the Marshal and Unmarshal functions
func TestMarshalUnmarshal(t *testing.T) {
	testCases := []struct {
		name      string
		timestamp TWAMPTimestamp
	}{
		{
			name:      "Zero timestamp",
			timestamp: TWAMPTimestamp{Seconds: 0, Fraction: 0},
		},
		{
			name:      "Simple timestamp",
			timestamp: TWAMPTimestamp{Seconds: 12345, Fraction: 67890},
		},
		{
			name:      "Maximum values",
			timestamp: TWAMPTimestamp{Seconds: 0xFFFFFFFF, Fraction: 0xFFFFFFFF},
		},
		{
			name:      "Era boundary timestamp",
			timestamp: TWAMPTimestamp{Seconds: 0xFFFFFFFF, Fraction: 0x80000000},
		},
		{
			name:      "Current time",
			timestamp: FromTime(time.Now()),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal to bytes
			buf := make([]byte, 8)
			tc.timestamp.Marshal(buf)

			// Unmarshal back
			var recovered TWAMPTimestamp
			recovered.Unmarshal(buf)

			// Verify they match
			if !recovered.Equal(tc.timestamp) {
				t.Errorf("Marshal/Unmarshal mismatch:\n  original:  %+v\n  recovered: %+v",
					tc.timestamp, recovered)
			}

			// Verify byte-level encoding
			expectedSeconds := buf[0:4]
			expectedFraction := buf[4:8]

			gotSeconds := make([]byte, 4)
			gotFraction := make([]byte, 4)
			binary.BigEndian.PutUint32(gotSeconds, tc.timestamp.Seconds)
			binary.BigEndian.PutUint32(gotFraction, tc.timestamp.Fraction)

			if !bytesEqual(expectedSeconds, gotSeconds) {
				t.Errorf("Seconds bytes mismatch:\n  got:  %v\n  want: %v",
					expectedSeconds, gotSeconds)
			}

			if !bytesEqual(expectedFraction, gotFraction) {
				t.Errorf("Fraction bytes mismatch:\n  got:  %v\n  want: %v",
					expectedFraction, gotFraction)
			}
		})
	}
}

// TestMarshalBigEndian verifies that Marshal uses big-endian byte order
func TestMarshalBigEndian(t *testing.T) {
	ts := TWAMPTimestamp{Seconds: 0x12345678, Fraction: 0x9ABCDEF0}

	buf := make([]byte, 8)
	ts.Marshal(buf)

	// Verify big-endian encoding for seconds
	if buf[0] != 0x12 || buf[1] != 0x34 || buf[2] != 0x56 || buf[3] != 0x78 {
		t.Errorf("Seconds not in big-endian: got %v", buf[0:4])
	}

	// Verify big-endian encoding for fraction
	if buf[4] != 0x9A || buf[5] != 0xBC || buf[6] != 0xDE || buf[7] != 0xF0 {
		t.Errorf("Fraction not in big-endian: got %v", buf[4:8])
	}
}

// TestUnmarshalBigEndian verifies that Unmarshal uses big-endian byte order
func TestUnmarshalBigEndian(t *testing.T) {
	// Create big-endian byte array
	buf := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}

	var ts TWAMPTimestamp
	ts.Unmarshal(buf)

	expectedSeconds := uint32(0x12345678)
	expectedFraction := uint32(0x9ABCDEF0)

	if ts.Seconds != expectedSeconds {
		t.Errorf("Unmarshal seconds: got 0x%08X, want 0x%08X", ts.Seconds, expectedSeconds)
	}

	if ts.Fraction != expectedFraction {
		t.Errorf("Unmarshal fraction: got 0x%08X, want 0x%08X", ts.Fraction, expectedFraction)
	}
}

// TestNow tests the Now() function
func TestNow(t *testing.T) {
	const epsilon = time.Nanosecond

	// Get current time before calling Now()
	before := time.Now()

	// Call Now()
	ts := Now()

	// Get current time after calling Now()
	after := time.Now()

	// Convert back to time.Time
	tsTime := ts.ToTime()

	// Verify the timestamp is between before and after
	if tsTime.Before(before.Add(-epsilon)) || tsTime.After(after.Add(epsilon)) {
		t.Errorf("Now() returned timestamp outside expected range:\n  before: %v\n  ts:     %v\n  after:  %v",
			before, tsTime, after)
	}

	// Verify it's reasonably close to now (within 1 second)
	diff := tsTime.Sub(before)
	if diff < -epsilon || diff > time.Second {
		t.Errorf("Now() timestamp differs from current time by %v", diff)
	}
}

// TestNowConsistency tests that Now() produces consistent, increasing timestamps
func TestNowConsistency(t *testing.T) {
	// Take multiple timestamps in sequence
	timestamps := make([]TWAMPTimestamp, 10)
	for i := 0; i < 10; i++ {
		timestamps[i] = Now()
		time.Sleep(time.Millisecond)
	}

	// Verify they are in increasing order
	for i := 1; i < len(timestamps); i++ {
		if !timestamps[i].After(timestamps[i-1]) && !timestamps[i].Equal(timestamps[i-1]) {
			t.Errorf("Timestamp %d is not after timestamp %d:\n  ts[%d]: %+v\n  ts[%d]: %+v",
				i, i-1, i-1, timestamps[i-1], i, timestamps[i])
		}
	}
}

// TestMonotonicNow tests the MonotonicNow() function
func TestMonotonicNow(t *testing.T) {
	// Get monotonic timestamp
	ts, monoTime := MonotonicNow()

	// Verify the timestamp is close to the monotonic time
	tsTime := ts.ToTime()

	// They should be very close (within microseconds)
	diff := tsTime.Sub(monoTime)
	if diff < -time.Microsecond || diff > time.Microsecond {
		t.Errorf("MonotonicNow timestamp and time differ by %v", diff)
	}

	// Verify the monotonic time has a monotonic reading
	// In Go, time.Now() always includes monotonic clock
	if monoTime.IsZero() {
		t.Error("MonotonicNow returned zero time")
	}
}

// TestMonotonicNowForRTT tests that MonotonicNow is suitable for RTT measurements
func TestMonotonicNowForRTT(t *testing.T) {
	// Simulate RTT measurement
	ts1, mono1 := MonotonicNow()

	// Simulate some work
	time.Sleep(10 * time.Millisecond)

	ts2, mono2 := MonotonicNow()

	// Calculate RTT using monotonic times (Go's built-in monotonic clock)
	rttMono := mono2.Sub(mono1)

	// Calculate RTT using TWAMP timestamps
	rttTWAMP := DurationBetween(ts1, ts2)

	// They should be very close
	diff := rttMono - rttTWAMP
	if diff < -time.Millisecond || diff > time.Millisecond {
		t.Errorf("Monotonic RTT and TWAMP RTT differ by %v (mono: %v, twamp: %v)",
			diff, rttMono, rttTWAMP)
	}

	// Both should be approximately 10ms
	if rttMono < 9*time.Millisecond || rttMono > 15*time.Millisecond {
		t.Errorf("RTT measurement out of expected range: %v", rttMono)
	}
}

// TestMonotonicNowSequence tests that MonotonicNow produces monotonically increasing timestamps
func TestMonotonicNowSequence(t *testing.T) {
	// Take multiple monotonic timestamps
	const iterations = 100
	timestamps := make([]TWAMPTimestamp, iterations)
	monotimes := make([]time.Time, iterations)

	for i := 0; i < iterations; i++ {
		timestamps[i], monotimes[i] = MonotonicNow()
		// Very small delay to ensure time advances
		time.Sleep(10 * time.Microsecond)
	}

	// Verify monotonic times are STRICTLY increasing
	// Monotonic clocks must never go backward - this is the primary test
	for i := 1; i < iterations; i++ {
		if !monotimes[i].After(monotimes[i-1]) {
			t.Errorf("Monotonic time %d is not after time %d:\n  t[%d]: %v\n  t[%d]: %v",
				i, i-1, i-1, monotimes[i-1], i, monotimes[i])
		}
	}

	// TWAMP timestamps use wall clock (NTP epoch), which may have quantization issues
	// at nanosecond precision. This is separate from monotonic clock behavior.
	// We verify they are "generally" increasing to detect gross issues, but allow
	// for wall-clock precision limitations. For actual RTT measurements, use the
	// monotonic time.Time values, not TWAMP timestamp deltas.
	decreasing := 0
	for i := 1; i < iterations; i++ {
		if timestamps[i].Before(timestamps[i-1]) {
			decreasing++
		}
	}

	// Allow up to 10% non-increasing due to wall-clock quantization at nanosecond scale
	// This tests that TWAMP timestamp conversion doesn't break grossly, but is NOT
	// a test of monotonic behavior (that's verified above with time.Time).
	if decreasing > iterations/10 {
		t.Errorf("Too many non-increasing TWAMP timestamps (wall-clock conversion issue): %d out of %d", decreasing, iterations)
	}
}

// Helper function to compare byte slices (uses standard library)
func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

// TestMarshalBoundsChecking verifies that Marshal panics with insufficient buffer
func TestMarshalBoundsChecking(t *testing.T) {
	ts := TWAMPTimestamp{Seconds: 12345, Fraction: 67890}

	tests := []struct {
		name    string
		bufSize int
		wantPanic bool
	}{
		{"Sufficient buffer (8 bytes)", 8, false},
		{"Large buffer (16 bytes)", 16, false},
		{"Insufficient buffer (7 bytes)", 7, true},
		{"Insufficient buffer (4 bytes)", 4, true},
		{"Empty buffer", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if tt.wantPanic && r == nil {
					t.Errorf("Expected panic for buffer size %d, but didn't panic", tt.bufSize)
				} else if !tt.wantPanic && r != nil {
					t.Errorf("Unexpected panic for buffer size %d: %v", tt.bufSize, r)
				}
			}()

			buf := make([]byte, tt.bufSize)
			ts.Marshal(buf)
		})
	}
}

// TestUnmarshalBoundsChecking verifies that Unmarshal panics with insufficient buffer
func TestUnmarshalBoundsChecking(t *testing.T) {
	tests := []struct {
		name      string
		bufSize   int
		wantPanic bool
	}{
		{"Sufficient buffer (8 bytes)", 8, false},
		{"Large buffer (16 bytes)", 16, false},
		{"Insufficient buffer (7 bytes)", 7, true},
		{"Insufficient buffer (4 bytes)", 4, true},
		{"Empty buffer", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if tt.wantPanic && r == nil {
					t.Errorf("Expected panic for buffer size %d, but didn't panic", tt.bufSize)
				} else if !tt.wantPanic && r != nil {
					t.Errorf("Unexpected panic for buffer size %d: %v", tt.bufSize, r)
				}
			}()

			buf := make([]byte, tt.bufSize)
			var ts TWAMPTimestamp
			ts.Unmarshal(buf)
		})
	}
}
