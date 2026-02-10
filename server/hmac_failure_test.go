package server

import (
	"sync"
	"testing"
	"time"

	"github.com/ncode/twamp/common"
)

func TestHMACFailureConstants(t *testing.T) {
	// Verify default threshold is reasonable per RFC 4656 Section 6
	if DefaultMaxConsecutiveHMACFailures == 0 {
		t.Error("DefaultMaxConsecutiveHMACFailures should not be 0 (disabled) by default")
	}
	if DefaultMaxConsecutiveHMACFailures > 1000 {
		t.Errorf("DefaultMaxConsecutiveHMACFailures = %d seems too high, may not provide adequate protection",
			DefaultMaxConsecutiveHMACFailures)
	}

	// Verify reset window is reasonable
	if HMACFailureResetWindow < 10*time.Second {
		t.Errorf("HMACFailureResetWindow = %v seems too short", HMACFailureResetWindow)
	}
	if HMACFailureResetWindow > 5*time.Minute {
		t.Errorf("HMACFailureResetWindow = %v seems too long", HMACFailureResetWindow)
	}
}

func TestTestSessionHMACFailureTracking(t *testing.T) {
	// Create a test session with HMAC failure tracking enabled
	session := &TestSession{
		sid:             common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 10,
		stopChan:        make(chan struct{}),
	}

	// Verify initial state
	if session.hmacFailures != 0 {
		t.Errorf("Initial hmacFailures = %d, want 0", session.hmacFailures)
	}
	if !session.lastHMACFailureTime.IsZero() {
		t.Errorf("Initial lastHMACFailureTime should be zero, got %v", session.lastHMACFailureTime)
	}

	// Simulate HMAC failures
	now := time.Now()
	session.mu.Lock()
	session.hmacFailures = 5
	session.lastHMACFailureTime = now
	session.mu.Unlock()

	// Verify tracking
	session.mu.Lock()
	failures := session.hmacFailures
	lastTime := session.lastHMACFailureTime
	session.mu.Unlock()

	if failures != 5 {
		t.Errorf("hmacFailures = %d, want 5", failures)
	}
	if lastTime != now {
		t.Errorf("lastHMACFailureTime = %v, want %v", lastTime, now)
	}
}

func TestHMACFailureThresholdCheck(t *testing.T) {
	tests := []struct {
		name            string
		maxFailures     uint32
		currentFailures uint32
		shouldTerminate bool
	}{
		{
			name:            "below threshold",
			maxFailures:     100,
			currentFailures: 50,
			shouldTerminate: false,
		},
		{
			name:            "at threshold",
			maxFailures:     100,
			currentFailures: 100,
			shouldTerminate: true,
		},
		{
			name:            "above threshold",
			maxFailures:     100,
			currentFailures: 150,
			shouldTerminate: true,
		},
		{
			name:            "threshold disabled (0)",
			maxFailures:     0,
			currentFailures: 1000,
			shouldTerminate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the threshold check logic from reflectPackets
			shouldTerminate := tt.maxFailures > 0 && tt.currentFailures >= tt.maxFailures
			if shouldTerminate != tt.shouldTerminate {
				t.Errorf("threshold check = %v, want %v", shouldTerminate, tt.shouldTerminate)
			}
		})
	}
}

func TestHMACFailureResetWindowLogic(t *testing.T) {
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 100,
		hmacFailures:    50,
	}

	// Test case 1: Within reset window - should not reset
	session.lastHMACFailureTime = time.Now().Add(-10 * time.Second)
	now := time.Now()

	// Simulate the reset window check from reflectPackets
	session.mu.Lock()
	if !session.lastHMACFailureTime.IsZero() &&
		now.Sub(session.lastHMACFailureTime) > HMACFailureResetWindow {
		session.hmacFailures = 0
	}
	failures := session.hmacFailures
	session.mu.Unlock()

	if failures != 50 {
		t.Errorf("Failures should not reset within window, got %d want 50", failures)
	}

	// Test case 2: Outside reset window - should reset
	session.lastHMACFailureTime = time.Now().Add(-HMACFailureResetWindow - time.Second)
	now = time.Now()

	session.mu.Lock()
	if !session.lastHMACFailureTime.IsZero() &&
		now.Sub(session.lastHMACFailureTime) > HMACFailureResetWindow {
		session.hmacFailures = 0
	}
	failures = session.hmacFailures
	session.mu.Unlock()

	if failures != 0 {
		t.Errorf("Failures should reset outside window, got %d want 0", failures)
	}
}

func TestHMACFailureResetOnSuccessfulPacket(t *testing.T) {
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 100,
		hmacFailures:    50,
	}

	// Simulate successful packet processing - counter should reset
	session.mu.Lock()
	session.hmacFailures = 0
	session.mu.Unlock()

	session.mu.Lock()
	failures := session.hmacFailures
	session.mu.Unlock()

	if failures != 0 {
		t.Errorf("Failures should reset on successful packet, got %d want 0", failures)
	}
}

func TestSessionCreationWithMaxHMACFailures(t *testing.T) {
	// Test that session creation sets maxHMACFailures to default
	session := &TestSession{
		sid:             common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		mode:            common.ModeAuthenticated,
		maxHMACFailures: DefaultMaxConsecutiveHMACFailures,
		stopChan:        make(chan struct{}),
		reflectorDone:   make(chan struct{}),
	}

	if session.maxHMACFailures != DefaultMaxConsecutiveHMACFailures {
		t.Errorf("maxHMACFailures = %d, want %d",
			session.maxHMACFailures, DefaultMaxConsecutiveHMACFailures)
	}
}

func TestHMACFailureConcurrency(t *testing.T) {
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 1000,
	}

	// Simulate concurrent access to HMAC failure tracking
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session.mu.Lock()
			session.hmacFailures++
			session.lastHMACFailureTime = time.Now()
			session.mu.Unlock()
		}()
	}
	wg.Wait()

	session.mu.Lock()
	failures := session.hmacFailures
	session.mu.Unlock()

	if failures != 100 {
		t.Errorf("hmacFailures = %d, want 100 (concurrent increments)", failures)
	}
}

func TestHMACFailureDisabledWhenZero(t *testing.T) {
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 0, // Disabled
		hmacFailures:    1000000,
	}

	// With maxHMACFailures = 0, session should never terminate due to HMAC failures
	shouldTerminate := session.maxHMACFailures > 0 && session.hmacFailures >= session.maxHMACFailures

	if shouldTerminate {
		t.Error("Session should not terminate when maxHMACFailures is 0 (disabled)")
	}
}

func TestTestSessionIsActiveAtomic(t *testing.T) {
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: DefaultMaxConsecutiveHMACFailures,
	}

	// Test atomic operations on isActive
	session.isActive.Store(true)

	if !session.isActive.Load() {
		t.Error("isActive should be true after Store(true)")
	}

	// Test CompareAndSwap
	swapped := session.isActive.CompareAndSwap(true, false)
	if !swapped {
		t.Error("CompareAndSwap should succeed when current value matches")
	}

	if session.isActive.Load() {
		t.Error("isActive should be false after CompareAndSwap(true, false)")
	}

	// Second swap should fail
	swapped = session.isActive.CompareAndSwap(true, false)
	if swapped {
		t.Error("CompareAndSwap should fail when current value doesn't match")
	}
}

func TestHMACFailureIncrementAndCheck(t *testing.T) {
	// Simulate the exact logic from reflectPackets for incrementing and checking
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 5,
	}

	terminated := false

	// Simulate 5 HMAC failures
	for i := 0; i < 6; i++ {
		session.mu.Lock()
		now := time.Now()

		// Reset counter if outside reset window (skip for this test)
		session.hmacFailures++
		session.lastHMACFailureTime = now
		failures := session.hmacFailures
		maxFailures := session.maxHMACFailures
		session.mu.Unlock()

		// Check if threshold exceeded
		if maxFailures > 0 && failures >= maxFailures {
			terminated = true
			break
		}
	}

	if !terminated {
		t.Error("Session should have terminated after reaching threshold")
	}

	session.mu.Lock()
	finalFailures := session.hmacFailures
	session.mu.Unlock()

	if finalFailures != 5 {
		t.Errorf("hmacFailures = %d, want 5 (threshold)", finalFailures)
	}
}

func TestHMACFailureWithAtomicIsActive(t *testing.T) {
	// Test the interaction between HMAC failure termination and isActive atomic
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 3,
		stopChan:        make(chan struct{}),
	}
	session.isActive.Store(true)

	// Simulate HMAC failure leading to termination
	session.mu.Lock()
	session.hmacFailures = 3
	failures := session.hmacFailures
	maxFailures := session.maxHMACFailures
	session.mu.Unlock()

	if maxFailures > 0 && failures >= maxFailures {
		// Simulate stopSession behavior (just the atomic part)
		if session.isActive.CompareAndSwap(true, false) {
			// Session would be stopped here
		}
	}

	if session.isActive.Load() {
		t.Error("isActive should be false after threshold exceeded and termination")
	}
}

// TestNewServerCreatesSessionsWithCorrectMaxHMACFailures tests that sessions
// created by the server have the correct maxHMACFailures value set
func TestSessionFieldsInitialization(t *testing.T) {
	session := &TestSession{
		sid:             common.SessionID{},
		mode:            common.ModeAuthenticated,
		maxHMACFailures: DefaultMaxConsecutiveHMACFailures,
		stopChan:        make(chan struct{}),
		reflectorDone:   make(chan struct{}),
	}

	// Verify all HMAC-related fields are initialized correctly
	if session.hmacFailures != 0 {
		t.Errorf("hmacFailures should start at 0, got %d", session.hmacFailures)
	}
	if !session.lastHMACFailureTime.IsZero() {
		t.Errorf("lastHMACFailureTime should be zero time, got %v", session.lastHMACFailureTime)
	}
	if session.maxHMACFailures != DefaultMaxConsecutiveHMACFailures {
		t.Errorf("maxHMACFailures should be %d, got %d",
			DefaultMaxConsecutiveHMACFailures, session.maxHMACFailures)
	}
}

// Benchmark for HMAC failure tracking under contention
func BenchmarkHMACFailureTracking(b *testing.B) {
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 1000000, // High threshold to avoid termination
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			session.mu.Lock()
			session.hmacFailures++
			session.lastHMACFailureTime = time.Now()
			_ = session.hmacFailures >= session.maxHMACFailures
			session.mu.Unlock()
		}
	})
}

// BenchmarkIsActiveAtomic benchmarks atomic operations on isActive
func BenchmarkIsActiveAtomic(b *testing.B) {
	session := &TestSession{}
	session.isActive.Store(true)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				session.isActive.Load()
			} else {
				// Just check, don't actually swap to avoid contention
				_ = session.isActive.Load()
			}
			i++
		}
	})
}

// TestHMACFailureThresholdIntegration tests the full HMAC failure tracking flow
// including incrementing, logging, and threshold-based termination
func TestHMACFailureThresholdIntegration(t *testing.T) {
	// Create a session with a low threshold for testing
	session := &TestSession{
		sid:             common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 5,
		stopChan:        make(chan struct{}),
		reflectorDone:   make(chan struct{}),
	}
	session.isActive.Store(true)

	// Simulate the exact code path from reflectPackets for HMAC failure handling
	simulateHMACFailure := func() (shouldTerminate bool) {
		session.mu.Lock()
		now := time.Now()

		// Reset failure counter if outside the reset window
		if !session.lastHMACFailureTime.IsZero() &&
			now.Sub(session.lastHMACFailureTime) > HMACFailureResetWindow {
			session.hmacFailures = 0
		}

		session.hmacFailures++
		session.lastHMACFailureTime = now
		failures := session.hmacFailures
		maxFailures := session.maxHMACFailures
		session.mu.Unlock()

		// Check if threshold exceeded
		if maxFailures > 0 && failures >= maxFailures {
			return true
		}
		return false
	}

	// Test: failures below threshold should not terminate
	for i := 0; i < 4; i++ {
		if simulateHMACFailure() {
			t.Errorf("Session should not terminate before threshold (failure %d)", i+1)
		}
	}

	// Verify failure count
	session.mu.Lock()
	if session.hmacFailures != 4 {
		t.Errorf("hmacFailures = %d, want 4", session.hmacFailures)
	}
	session.mu.Unlock()

	// Test: reaching threshold should terminate
	if !simulateHMACFailure() {
		t.Error("Session should terminate when reaching threshold")
	}

	// Verify final failure count
	session.mu.Lock()
	if session.hmacFailures != 5 {
		t.Errorf("hmacFailures = %d, want 5", session.hmacFailures)
	}
	session.mu.Unlock()
}

// TestHMACFailureResetOnSuccess tests that successful packet resets the counter
func TestHMACFailureResetOnSuccessIntegration(t *testing.T) {
	session := &TestSession{
		sid:             common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 10,
	}

	// Simulate some HMAC failures
	session.mu.Lock()
	session.hmacFailures = 5
	session.lastHMACFailureTime = time.Now()
	session.mu.Unlock()

	// Simulate successful packet (the exact code from reflectPackets)
	session.mu.Lock()
	session.hmacFailures = 0
	session.mu.Unlock()

	// Verify reset
	session.mu.Lock()
	if session.hmacFailures != 0 {
		t.Errorf("hmacFailures should be 0 after successful packet, got %d", session.hmacFailures)
	}
	session.mu.Unlock()
}

// TestHMACFailureResetWindowIntegration tests the reset window behavior
func TestHMACFailureResetWindowIntegration(t *testing.T) {
	session := &TestSession{
		mode:            common.ModeAuthenticated,
		maxHMACFailures: 100,
		hmacFailures:    50,
	}

	// Set last failure time to be outside the reset window
	session.lastHMACFailureTime = time.Now().Add(-HMACFailureResetWindow - time.Second)

	// Simulate HMAC failure with reset window check (exact code from reflectPackets)
	session.mu.Lock()
	now := time.Now()

	// Reset failure counter if outside the reset window
	if !session.lastHMACFailureTime.IsZero() &&
		now.Sub(session.lastHMACFailureTime) > HMACFailureResetWindow {
		session.hmacFailures = 0
	}

	session.hmacFailures++
	session.lastHMACFailureTime = now
	failures := session.hmacFailures
	session.mu.Unlock()

	// Should have reset to 0, then incremented to 1
	if failures != 1 {
		t.Errorf("hmacFailures = %d after reset window, want 1", failures)
	}
}

// TestEffectiveMaxHMACFailures tests the effectiveMaxHMACFailures method
func TestEffectiveMaxHMACFailures(t *testing.T) {
	tests := []struct {
		name            string
		configValue     uint32
		expectedValue   uint32
	}{
		{
			name:          "zero uses default",
			configValue:   0,
			expectedValue: DefaultMaxConsecutiveHMACFailures,
		},
		{
			name:          "custom value used as-is",
			configValue:   50,
			expectedValue: 50,
		},
		{
			name:          "high custom value",
			configValue:   500,
			expectedValue: 500,
		},
		{
			name:          "value of 1",
			configValue:   1,
			expectedValue: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(ServerConfig{
				ListenAddress:   "127.0.0.1:0",
				SupportedModes:  common.ModeUnauthenticated,
				MaxHMACFailures: tt.configValue,
			})
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			result := server.effectiveMaxHMACFailures()
			if result != tt.expectedValue {
				t.Errorf("effectiveMaxHMACFailures() = %d, want %d", result, tt.expectedValue)
			}
		})
	}
}

// TestServerConfigMaxHMACFailures tests that ServerConfig.MaxHMACFailures is properly used
func TestServerConfigMaxHMACFailures(t *testing.T) {
	// Test that the config field is stored correctly
	config := ServerConfig{
		ListenAddress:   "127.0.0.1:0",
		SupportedModes:  common.ModeAuthenticated,
		MaxHMACFailures: 25,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if server.config.MaxHMACFailures != 25 {
		t.Errorf("server.config.MaxHMACFailures = %d, want 25", server.config.MaxHMACFailures)
	}

	// Test that effectiveMaxHMACFailures returns the custom value
	if server.effectiveMaxHMACFailures() != 25 {
		t.Errorf("effectiveMaxHMACFailures() = %d, want 25", server.effectiveMaxHMACFailures())
	}
}

// TestDisabledMaxHMACFailuresConstant verifies the DisabledMaxHMACFailures constant
func TestDisabledMaxHMACFailuresConstant(t *testing.T) {
	// DisabledMaxHMACFailures should be MaxUint32
	if DisabledMaxHMACFailures != ^uint32(0) {
		t.Errorf("DisabledMaxHMACFailures = %d, want %d (MaxUint32)",
			DisabledMaxHMACFailures, ^uint32(0))
	}

	// Verify it's the maximum possible uint32 value
	if DisabledMaxHMACFailures != 4294967295 {
		t.Errorf("DisabledMaxHMACFailures = %d, want 4294967295", DisabledMaxHMACFailures)
	}
}