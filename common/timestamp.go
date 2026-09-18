// pkg/twamp/common/timestamp.go
package common

import (
	"encoding/binary"
	"time"
)

// NTP constants
const (
	// NTPEpochOffset NTP epoch starts on Jan 1, 1900, while Unix time starts on Jan 1, 1970
	// This is the offset in seconds between the two epochs
	NTPEpochOffset = 2208988800

	// NTPEra1Unix represents the Unix timestamp (seconds since January 1, 1970 UTC)
	// for NTP Era 1 start (February 7, 2036 06:28:16 UTC) when the 32-bit NTP seconds
	// field rolls over. This is NOT an NTP timestamp - it's Unix epoch seconds.
	NTPEra1Unix = int64(2085978496)

	// NanoToFrac is the multiplier to convert nanoseconds to NTP fractional part
	// 2^32 / 10^9
	NanoToFrac = float64(1<<32) / 1e9

	// FracToNano is the multiplier to convert NTP fractional part to nanoseconds
	// 10^9 / 2^32
	FracToNano = 1e9 / float64(1<<32)
)

// TWAMPTimestamp represents the 64-bit NTP-style timestamp used in TWAMP
type TWAMPTimestamp struct {
	Seconds  uint32 // Seconds since NTP epoch (January 1, 1900)
	Fraction uint32 // Fractional part of second (1/2^32 seconds)
}

// FromTime creates a TWAMPTimestamp from a Go time.Time
// with precise handling of nanoseconds and NTP era rollover
func FromTime(t time.Time) TWAMPTimestamp {
	// Get the Unix time
	unixSecs := t.Unix()

	// Handle NTP era rollover (RFC 5905 Section 4)
	// NTP uses a 32-bit seconds counter that rolls over every ~136 years
	// Era 0: 1900-01-01 to 2036-02-07 06:28:16
	// Era 1: 2036-02-07 06:28:16 to 2172-03-15 12:56:32
	//
	// We need to handle times after the Era 1 start point
	ntpSecs := unixSecs + NTPEpochOffset

	// The NTP seconds field is only 32 bits, so it wraps around
	// This is correct behavior per RFC 5905 - receivers must handle era context
	secs := uint32(ntpSecs & 0xFFFFFFFF)

	// Convert nanoseconds to NTP fraction with high precision
	// We multiply by 2^32 then divide by 10^9 to get the correct scale
	nanos := t.Nanosecond()
	frac := uint32(float64(nanos) * NanoToFrac)

	return TWAMPTimestamp{
		Seconds:  secs,
		Fraction: frac,
	}
}

// ToTime converts a TWAMPTimestamp to a Go time.Time
// with precise handling of fractional parts and NTP era context
func (ts TWAMPTimestamp) ToTime() time.Time {
	return ts.ToTimeWithReference(time.Now())
}

// Duration converts an NTP timestamp-shaped interval to a Go duration.
// Request-TW-Session.Timeout is an interval, not an absolute timestamp, but
// it uses the same 32.32 wire representation. Keep the fractional part when
// converting it; dropping it changes the RFC 5357 post-Stop grace period.
func (ts TWAMPTimestamp) Duration() time.Duration {
	return time.Duration(ts.Seconds)*time.Second +
		time.Duration(float64(ts.Fraction)*FracToNano)*time.Nanosecond
}

// ToTimeWithReference converts a TWAMPTimestamp to a Go time.Time using a reference time
// to resolve NTP era ambiguity. This is necessary because NTP's 32-bit seconds field
// wraps around every ~136 years (RFC 5905 Section 4).
//
// For TWAMP measurements, the reference time should typically be close to when the
// timestamp was created (within 68 years) to ensure correct era determination.
func (ts TWAMPTimestamp) ToTimeWithReference(ref time.Time) time.Time {
	// For TWAMP, we use a simple algorithm: interpret the timestamp in the same era
	// as the reference time. This works well for TWAMP measurements where the reference
	// is typically close to when the measurement was taken.

	// Get Unix time of the reference
	refUnix := ref.Unix()

	// Determine which era the reference time is in based on Unix epoch
	// Era 0: before Feb 7, 2036
	// Era 1: after Feb 7, 2036
	var ntpSecs64 int64
	if refUnix < NTPEra1Unix {
		// Reference is in Era 0, interpret timestamp as Era 0
		ntpSecs64 = int64(ts.Seconds)
	} else {
		// Reference is in Era 1, interpret timestamp as Era 1
		ntpSecs64 = (1 << 32) + int64(ts.Seconds)
	}

	// Convert to Unix time
	secs := ntpSecs64 - NTPEpochOffset

	// Convert fractional part to nanoseconds
	// We multiply by 10^9 then divide by 2^32 to get nanoseconds
	nanos := int64(float64(ts.Fraction) * FracToNano)

	return time.Unix(secs, nanos)
}

// Marshal converts a TWAMPTimestamp to network bytes
// Requires b to be at least 8 bytes. Panics if buffer is too small.
func (ts TWAMPTimestamp) Marshal(b []byte) {
	if len(b) < 8 {
		panic("TWAMPTimestamp.Marshal: buffer too small (need 8 bytes)")
	}
	binary.BigEndian.PutUint32(b[0:4], ts.Seconds)
	binary.BigEndian.PutUint32(b[4:8], ts.Fraction)
}

// Unmarshal parses network bytes into a TWAMPTimestamp
// Requires b to be at least 8 bytes. Panics if buffer is too small.
func (ts *TWAMPTimestamp) Unmarshal(b []byte) {
	if len(b) < 8 {
		panic("TWAMPTimestamp.Unmarshal: buffer too small (need 8 bytes)")
	}
	ts.Seconds = binary.BigEndian.Uint32(b[0:4])
	ts.Fraction = binary.BigEndian.Uint32(b[4:8])
}

// Now returns the current time as a TWAMPTimestamp
func Now() TWAMPTimestamp {
	return FromTime(time.Now())
}

// MonotonicNow returns the current time from monotonic clock as a TWAMPTimestamp
// This is crucial for accurate RTT measurements that avoid issues with system time jumps
func MonotonicNow() (TWAMPTimestamp, time.Time) {
	// In Go, time.Now() includes a monotonic clock reading
	// When doing t2.Sub(t1), Go uses the monotonic reading if both have it
	now := time.Now()
	return FromTime(now), now
}

// DurationBetween calculates the duration between two TWAMPTimestamps
// This function assumes the timestamps are relatively close in time (within 68 years)
// and handles NTP era wrapping correctly
func DurationBetween(start, end TWAMPTimestamp) time.Duration {
	// Calculate seconds difference as uint32 to handle wrap-around
	var secDiff int64

	// Handle NTP era wrapping - if end appears to be much smaller than start,
	// it probably wrapped around (crossed era boundary)
	if end.Seconds < start.Seconds && (start.Seconds-end.Seconds) > (1<<31) {
		// Era wrapped forward
		secDiff = int64(end.Seconds) + (1 << 32) - int64(start.Seconds)
	} else if start.Seconds < end.Seconds && (end.Seconds-start.Seconds) > (1<<31) {
		// Era wrapped backward (negative duration)
		secDiff = int64(end.Seconds) - (int64(start.Seconds) + (1 << 32))
	} else {
		// Normal case, no era wrapping
		secDiff = int64(end.Seconds) - int64(start.Seconds)
	}

	// Calculate fraction difference, handling underflow
	var fracDiff int64
	if end.Fraction >= start.Fraction {
		fracDiff = int64(end.Fraction) - int64(start.Fraction)
	} else {
		fracDiff = int64(end.Fraction) + (1 << 32) - int64(start.Fraction)
		secDiff-- // Borrow one second
	}

	// Convert the fraction difference to nanoseconds
	nanoDiff := int64(float64(fracDiff) * FracToNano)

	// Combine seconds and nanoseconds to get the total duration
	return time.Duration(secDiff)*time.Second + time.Duration(nanoDiff)*time.Nanosecond
}

// Add adds a duration to a TWAMPTimestamp
func (ts TWAMPTimestamp) Add(d time.Duration) TWAMPTimestamp {
	// Convert duration to seconds and nanoseconds
	secs := d / time.Second
	nanos := d % time.Second

	// Convert nanoseconds to NTP fraction
	fracToAdd := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)

	// Add fraction parts
	// Use uint64 to avoid overflow in intermediate calculation
	newFracU64 := uint64(ts.Fraction) + uint64(fracToAdd)

	// Handle overflow in fraction
	carry := uint32(0)
	if newFracU64 >= (1 << 32) {
		carry = 1
		newFracU64 -= 1 << 32
	}

	// Convert back to uint32 after handling overflow
	newFrac := uint32(newFracU64)

	// Add seconds and any carry from fraction
	newSecs := ts.Seconds + uint32(secs) + carry

	return TWAMPTimestamp{
		Seconds:  newSecs,
		Fraction: newFrac,
	}
}

// Sub subtracts a duration from a TWAMPTimestamp
func (ts TWAMPTimestamp) Sub(d time.Duration) TWAMPTimestamp {
	// Convert duration to seconds and nanoseconds
	secs := d / time.Second
	nanos := d % time.Second

	// Convert nanoseconds to NTP fraction
	fracToSub := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)

	// Subtract fraction parts, handling underflow
	borrow := uint32(0)
	var newFrac uint32

	if fracToSub > ts.Fraction {
		// Handle underflow correctly
		borrow = 1
		// Use uint64 for intermediate calculation to avoid overflow
		newFrac = uint32(uint64(ts.Fraction) + (1 << 32) - uint64(fracToSub))
	} else {
		newFrac = ts.Fraction - fracToSub
	}

	// Subtract seconds and any borrow from fraction
	newSecs := ts.Seconds - uint32(secs) - borrow

	return TWAMPTimestamp{
		Seconds:  newSecs,
		Fraction: newFrac,
	}
}

// Equal checks if two TWAMPTimestamps are equal
func (ts TWAMPTimestamp) Equal(other TWAMPTimestamp) bool {
	return ts.Seconds == other.Seconds && ts.Fraction == other.Fraction
}

// Before checks if this timestamp is before another
func (ts TWAMPTimestamp) Before(other TWAMPTimestamp) bool {
	if ts.Seconds < other.Seconds {
		return true
	}
	if ts.Seconds > other.Seconds {
		return false
	}
	return ts.Fraction < other.Fraction
}

// After checks if this timestamp is after another
func (ts TWAMPTimestamp) After(other TWAMPTimestamp) bool {
	if ts.Seconds > other.Seconds {
		return true
	}
	if ts.Seconds < other.Seconds {
		return false
	}
	return ts.Fraction > other.Fraction
}
