package client

import (
	"testing"
	"time"

	"github.com/ncode/twamp/common"
)

// TestGetSessionSimple tests GetSession function
func TestGetSessionSimple(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	// Test non-existent session
	sid := common.SessionID{1, 2, 3, 4}
	session, err := client.GetSession(sid)
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
	if session != nil {
		t.Error("Expected nil session for non-existent ID")
	}

	// Add a session
	testSession := &TestSession{
		sid:      sid,
		stopChan: make(chan struct{}),
	}
	client.currentSessions[sid] = testSession

	// Test existing session
	session, err = client.GetSession(sid)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if session != testSession {
		t.Error("Got wrong session")
	}
}

// TestGetSessionIDsSimple tests GetSessionIDs function
func TestGetSessionIDsSimple(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	// Test empty sessions
	ids := client.GetSessionIDs()
	if len(ids) != 0 {
		t.Errorf("Expected 0 session IDs, got %d", len(ids))
	}

	// Add some sessions
	sid1 := common.SessionID{1, 2, 3, 4}
	sid2 := common.SessionID{5, 6, 7, 8}
	client.currentSessions[sid1] = &TestSession{sid: sid1, stopChan: make(chan struct{})}
	client.currentSessions[sid2] = &TestSession{sid: sid2, stopChan: make(chan struct{})}

	// Test with sessions
	ids = client.GetSessionIDs()
	if len(ids) != 2 {
		t.Errorf("Expected 2 session IDs, got %d", len(ids))
	}

	// Verify both sessions are in the list
	found1, found2 := false, false
	for _, id := range ids {
		if id == sid1 {
			found1 = true
		}
		if id == sid2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Error("Not all session IDs were returned")
	}
}

// TestStopSessionSimple tests StopSession function
func TestStopSessionSimple(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	// Test stopping non-existent session
	sid := common.SessionID{1, 2, 3, 4}
	err := client.StopSession(sid)
	if err == nil {
		t.Error("Expected error for non-existent session")
	}

	// Add a session
	stopChan := make(chan struct{})
	client.currentSessions[sid] = &TestSession{
		sid:      sid,
		stopChan: stopChan,
	}

	// Start a goroutine that waits for stop signal
	stopped := make(chan bool)
	go func() {
		<-stopChan
		stopped <- true
	}()

	// Stop the session
	err = client.StopSession(sid)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify stop channel was closed (with timeout)
	select {
	case <-stopped:
		// Good, session was stopped
	case <-time.After(100 * time.Millisecond):
		t.Error("Session stop channel was not closed")
	}

	// Verify session was removed
	if _, exists := client.currentSessions[sid]; exists {
		t.Error("Session should have been removed after stopping")
	}
}

// TestStartSessionSimple tests StartSession function
func TestStartSessionSimple(t *testing.T) {
	client := &Client{
		currentSessions: make(map[common.SessionID]*TestSession),
	}

	// Test starting non-existent session
	sid := common.SessionID{1, 2, 3, 4}
	err := client.StartSession(sid)
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}
