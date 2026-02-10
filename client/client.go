package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/messages"
	"github.com/ncode/twamp/metrics"
)

// Sentinel errors for client operations
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionConflict = errors.New("session ID already in use")
	ErrServerGreeting  = errors.New("failed to read server greeting")
)

// ClientConfig contains configuration for TWAMP Control-Client
type ClientConfig struct {
	ServerAddress string
	PreferredMode common.Mode
	SharedSecret  string // Optional, for authenticated/encrypted modes
	KeyID         string // Optional, identifier for shared secret
	Timeout       time.Duration
	Logger        logging.Logger   // Optional logger (defaults to noop)
	Metrics       *metrics.Metrics // Optional metrics (defaults to nil, no metrics)
}

// Client implements a TWAMP Control-Client and Session-Sender
type Client struct {
	config                 ClientConfig
	conn                   net.Conn
	mode                   common.Mode // Negotiated mode (may include RFC 5618 mixed + RFC 6038 bits)
	controlMode            common.Mode // Actual mode for control protocol (RFC 5618)
	testMode               common.Mode // Actual mode for test protocol (RFC 5618)
	keyDerivation          *crypto.TWAMPKeys
	controlEncrypt         *crypto.CBCStream
	controlDecrypt         *crypto.CBCStream
	serverStartBytes       []byte
	serverStartHMACPending bool
	currentSessions        map[common.SessionID]*TestSession
	mu                     sync.Mutex
	logger                 logging.Logger
	metrics                *metrics.Metrics
}

// NewClient creates a new TWAMP client
func NewClient(config ClientConfig) *Client {
	// Set default timeout if not provided
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	// Set default logger if not provided (noop for backward compatibility)
	if config.Logger == nil {
		config.Logger = logging.NewNoop()
	}

	return &Client{
		config:          config,
		currentSessions: make(map[common.SessionID]*TestSession),
		logger:          config.Logger,
		metrics:         config.Metrics,
	}
}

// Connect establishes a TWAMP-Control connection to the server
func (c *Client) Connect(ctx context.Context) error {
	// Create a dialer with timeout
	dialer := net.Dialer{Timeout: c.config.Timeout}

	// Default to port 862 if not specified
	serverAddr := c.config.ServerAddress
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, "862")
	}

	// Connect to the server
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn

	// Handle ServerGreeting
	greeting, err := c.receiveServerGreeting()
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to receive server greeting: %w", err)
	}

	// Negotiate mode
	err = c.negotiateMode(greeting)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to negotiate mode: %w", err)
	}

	return nil
}

// receiveServerGreeting reads and parses the Server Greeting message
func (c *Client) receiveServerGreeting() (*messages.ServerGreeting, error) {
	// Server Greeting is 64 bytes per RFC 4656 Section 3.1
	buf := make([]byte, 64)

	// Read the greeting
	_, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrServerGreeting, err)
	}

	// Parse the greeting
	var greeting messages.ServerGreeting
	err = greeting.Unmarshal(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal server greeting: %w", err)
	}

	// Check that server supports at least one mode
	if greeting.Modes == 0 {
		return nil, common.ErrServerNoModes
	}

	return &greeting, nil
}

// receiveServerStart reads and parses the Server-Start message
func (c *Client) receiveServerStart() (*messages.ServerStart, error) {
	// Server-Start message is 48 bytes in RFC 5357
	buf := make([]byte, 48)

	// Read the response
	_, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read Server-Start: %w", err)
	}
	c.serverStartBytes = append([]byte(nil), buf...)

	// Parse the message
	var serverStart messages.ServerStart
	err = serverStart.Unmarshal(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Server-Start: %w", err)
	}

	return &serverStart, nil
}

// negotiateMode selects a compatible mode and completes the handshake
func (c *Client) negotiateMode(greeting *messages.ServerGreeting) error {
	if err := common.ValidateModeMask(c.config.PreferredMode); err != nil {
		return fmt.Errorf("invalid preferred mode: %w", err)
	}

	// Determine preferred mode, including all mode bits (security + RFC 5618 + RFC 6038)
	var selectedMode common.Mode

	// Extract security mode bits (0-2) and other mode bits (mixed, reflect-octets, symmetrical-size)
	securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
	preferredSecurity := c.config.PreferredMode & securityMask
	serverSecurity := common.Mode(greeting.Modes) & securityMask
	otherModeBits := c.config.PreferredMode &^ securityMask // RFC 5618 mixed + RFC 6038 modes

	// Select security mode
	var baseSecurity common.Mode
	if preferredSecurity&common.ModeEncrypted != 0 && serverSecurity&common.ModeEncrypted != 0 {
		baseSecurity = common.ModeEncrypted
	} else if preferredSecurity&common.ModeAuthenticated != 0 && serverSecurity&common.ModeAuthenticated != 0 {
		baseSecurity = common.ModeAuthenticated
	} else if preferredSecurity&common.ModeUnauthenticated != 0 && serverSecurity&common.ModeUnauthenticated != 0 {
		baseSecurity = common.ModeUnauthenticated
	} else {
		return common.ErrNoCompatibleMode
	}

	// Combine base security mode with other mode bits that server supports
	selectedMode = baseSecurity | (otherModeBits & common.Mode(greeting.Modes))

	// Create Setup-Response
	setupResponse := &messages.SetupResponse{
		Mode: uint32(selectedMode),
	}

	// For authenticated or encrypted modes, add security info
	// Check if base security mode requires authentication (not just unauthenticated)
	if baseSecurity != common.ModeUnauthenticated {
		if c.config.SharedSecret == "" {
			return common.ErrSharedSecretRequired
		}

		// Derive session keys
		aesKey, hmacKey, err := crypto.DeriveKey(c.config.SharedSecret, greeting.Salt[:], greeting.Count)
		if err != nil {
			return fmt.Errorf("failed to derive keys: %w", err)
		}

		// Store key derivation for use in subsequent communication
		c.keyDerivation = &crypto.TWAMPKeys{
			AESKey:  aesKey,
			HMACKey: hmacKey,
		}

		// Generate random IV for client
		clientIV, err := crypto.NewRandomIV()
		if err != nil {
			return fmt.Errorf("failed to generate client IV: %w", err)
		}
		c.keyDerivation.ClientIV = clientIV

		// Create token
		token, err := crypto.CreateToken(greeting.Challenge[:], aesKey, hmacKey)
		if err != nil {
			return fmt.Errorf("failed to create token: %w", err)
		}

		// Set token and KeyID in setup response
		copy(setupResponse.KeyID[:], c.config.KeyID)
		copy(setupResponse.Token[:], token)
		copy(setupResponse.ClientIV[:], clientIV)
	}

	// Marshal and send Setup-Response
	data, err := setupResponse.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal setup response: %w", err)
	}

	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send setup response: %w", err)
	}

	// Receive Server-Start
	serverStart, err := c.receiveServerStart()
	if err != nil {
		return fmt.Errorf("failed to receive server start: %w", err)
	}

	// Check if server accepted our setup
	if serverStart.Accept != common.AcceptOK {
		return common.NewTWAMPError(
			serverStart.Accept,
			fmt.Sprintf("Server rejected setup: %s",
				common.AcceptCodeToString(serverStart.Accept)))
	}

	// For authenticated or encrypted modes, store Server IV
	if baseSecurity != common.ModeUnauthenticated {
		c.keyDerivation.ServerIV = serverStart.ServerIV[:]
	}

	// Store negotiated mode
	c.mode = selectedMode

	// Resolve control and test modes per RFC 5618
	var resolveErr error
	c.controlMode, c.testMode, resolveErr = common.ResolveMixedModes(selectedMode)
	if resolveErr != nil {
		return fmt.Errorf("invalid mode combination: %w", resolveErr)
	}

	if c.controlRequiresAuthentication() {
		if c.keyDerivation == nil {
			return errors.New("control keys not initialized")
		}

		controlEncrypt, err := crypto.NewCBCStream(c.keyDerivation.AESKey, c.keyDerivation.ClientIV)
		if err != nil {
			return fmt.Errorf("failed to init control encrypt stream: %w", err)
		}

		controlDecrypt, err := crypto.NewCBCStream(c.keyDerivation.AESKey, c.keyDerivation.ServerIV)
		if err != nil {
			return fmt.Errorf("failed to init control decrypt stream: %w", err)
		}

		c.controlEncrypt = controlEncrypt
		c.controlDecrypt = controlDecrypt
		c.serverStartHMACPending = true
	} else {
		c.controlEncrypt = nil
		c.controlDecrypt = nil
		c.serverStartHMACPending = false
	}

	return nil
}

// controlRequiresAuthentication returns true if the control protocol requires authentication.
// It extracts the base security bits (0-2) from controlMode and checks if it's not unauthenticated.
func (c *Client) controlRequiresAuthentication() bool {
	securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
	controlSecurity := c.controlMode & securityMask
	return controlSecurity != common.ModeUnauthenticated
}

// calculateHMAC calculates HMAC for a message
func (c *Client) calculateHMAC(message []byte) ([]byte, error) {
	return crypto.CalculateHMAC(c.keyDerivation.HMACKey, message)
}

// verifyHMAC verifies HMAC for a message
func (c *Client) verifyHMAC(message, hmac []byte) (bool, error) {
	return crypto.VerifyHMAC(c.keyDerivation.HMACKey, message, hmac)
}

// receiveAndVerify receives a message and verifies its HMAC if in secure mode
func (c *Client) receiveAndVerify(expectedLen int, includeHMAC bool) ([]byte, error) {
	buf := make([]byte, expectedLen)
	_, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return nil, err
	}

	// If message includes HMAC, verify it
	if includeHMAC {
		if c.controlDecrypt == nil {
			return nil, errors.New("control decryption not initialized")
		}

		plaintext, err := c.controlDecrypt.Decrypt(buf)
		if err != nil {
			return nil, err
		}

		messageLen := expectedLen - 16 // Last 16 bytes are HMAC
		var hmacPrefix []byte
		if c.serverStartHMACPending {
			hmacPrefix = c.serverStartBytes
		}

		calculated, err := crypto.CalculateHMACWithPrefix(c.keyDerivation.HMACKey, hmacPrefix, plaintext[:messageLen])
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(calculated, plaintext[messageLen:]) {
			return nil, common.ErrHMACVerificationFailed
		}
		if c.serverStartHMACPending {
			c.serverStartHMACPending = false
		}

		return plaintext, nil
	}

	if expectedLen < 16 {
		return nil, common.ErrInvalidMessageLength
	}
	for i := expectedLen - 16; i < expectedLen; i++ {
		if buf[i] != 0 {
			return nil, common.ErrInvalidMBZ
		}
	}

	return buf, nil
}

// sendWithHMAC sends a message with HMAC if in secure mode
func (c *Client) sendWithHMAC(message []byte, addHMAC bool) error {
	if c.mode == common.ModeUnauthenticated || !addHMAC {
		_, err := c.conn.Write(message)
		return err
	}

	// Calculate HMAC
	hmac, err := c.calculateHMAC(message)
	if err != nil {
		return err
	}

	// Append HMAC to message
	messageWithHMAC := append(message, hmac...)

	// If encrypted mode, encrypt the message
	if c.mode == common.ModeEncrypted {
		encryptedMsg, err := crypto.EncryptTWAMPControlMessage(
			c.keyDerivation.AESKey,
			c.keyDerivation.ClientIV,
			messageWithHMAC,
		)
		if err != nil {
			return err
		}
		messageWithHMAC = encryptedMsg
	}

	_, err = c.conn.Write(messageWithHMAC)
	return err
}

func (c *Client) sendControlMessage(message []byte, includeHMAC bool) error {
	if len(message) < 16 {
		return common.ErrInvalidMessageLength
	}

	if includeHMAC {
		if c.controlEncrypt == nil {
			return errors.New("control encryption not initialized")
		}

		messageLen := len(message) - 16
		hmac, err := crypto.CalculateHMAC(c.keyDerivation.HMACKey, message[:messageLen])
		if err != nil {
			return err
		}
		copy(message[messageLen:], hmac)

		encrypted, err := c.controlEncrypt.Encrypt(message)
		if err != nil {
			return err
		}

		_, err = c.conn.Write(encrypted)
		return err
	}

	for i := len(message) - 16; i < len(message); i++ {
		message[i] = 0
	}

	_, err := c.conn.Write(message)
	return err
}

// RequestSession requests a new TWAMP test session
func (c *Client) RequestSession(config TestSessionConfig) (*TestSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate minimum required padding using helper function
	originalPadding := config.PaddingLength
	minPadding := calculateMinPadding(c.testMode)

	// Adjust padding if needed
	if config.PaddingLength < minPadding && minPadding > 0 {
		config.PaddingLength = minPadding
		c.logger.Warn("padding length increased to meet mode requirements",
			"original_length", originalPadding,
			logging.FieldPaddingLen, minPadding,
			logging.FieldMode, common.ModeToString(c.mode),
		)
	}

	// Set default timeout if not provided
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}

	// Set default receiver address if not provided
	if config.ReceiverAddress == "" {
		// Use server address from control connection
		host, _, err := net.SplitHostPort(c.config.ServerAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server address: %w", err)
		}
		config.ReceiverAddress = host
	}

	// Create request
	request := &messages.RequestTWSession{
		Command:         common.CmdRequestTWSession,
		IPVN:            4, // IPv4
		ConfSender:      0, // Must be 0 in TWAMP
		ConfReceiver:    0, // Must be 0 in TWAMP
		NumSlots:        0, // Must be 0 in TWAMP
		NumPackets:      0, // Must be 0 in TWAMP
		SenderPort:      config.SenderPort,
		ReceiverPort:    config.ReceiverPort,
		PaddingLength:   config.PaddingLength,
		TypePDescriptor: uint32(config.DSCP) << 18, // DSCP goes in bits 18-23 (byte 1, top 6 bits)
	}

	// Set addresses based on IP version using helper function
	isIPv6, ipBytes, err := parseAndValidateIP(config.ReceiverAddress)
	if err != nil {
		return nil, err
	}

	if !isIPv6 {
		// IPv4
		request.IPVN = 4
		copy(request.ReceiverAddress[:4], ipBytes)
	} else {
		// IPv6
		request.IPVN = 6
		copy(request.ReceiverAddress[:], ipBytes)
	}

	// Set timeout as TWAMP timestamp
	timeoutDuration := config.Timeout
	timeoutSeconds := uint32(timeoutDuration / time.Second)
	timeoutFraction := uint32(float64(timeoutDuration%time.Second) * common.NanoToFrac)
	request.Timeout = common.TWAMPTimestamp{
		Seconds:  timeoutSeconds,
		Fraction: timeoutFraction,
	}

	// Set start time to 0 (immediate start)
	request.StartTime = common.TWAMPTimestamp{
		Seconds:  0,
		Fraction: 0,
	}

	// Marshal the request
	data, err := request.Marshal(false)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := c.sendControlMessage(data, c.controlRequiresAuthentication()); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	respData, err := c.receiveAndVerify(messages.AcceptSessionSize, c.controlRequiresAuthentication())
	if err != nil {
		return nil, fmt.Errorf("failed to receive accept session response: %w", err)
	}

	// Parse the response
	var acceptSession messages.AcceptSession
	err = acceptSession.Unmarshal(respData, c.controlRequiresAuthentication())
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal accept session: %w", err)
	}

	// Check the accept code
	if acceptSession.Accept != common.AcceptOK {
		return nil, common.NewTWAMPError(
			acceptSession.Accept,
			fmt.Sprintf("Server rejected session: %s",
				common.AcceptCodeToString(acceptSession.Accept)))
	}

	// Check if port was changed by server
	if acceptSession.Port != 0 && acceptSession.Port != config.ReceiverPort {
		// Server suggested an alternate port
		config.ReceiverPort = acceptSession.Port
	}

	// Create a new test session
	// RFC 5618: Use testMode for test sessions, not the full negotiated mode
	session, err := NewTestSessionWithLoggerAndMetrics(config, acceptSession.SID, c.testMode, c.keyDerivation, c.logger, c.metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to create test session: %w", err)
	}

	// Store the session
	c.currentSessions[acceptSession.SID] = session

	// Record session creation (not started yet)
	if c.metrics != nil {
		c.metrics.RecordControlMessage("request_tw_session", "client", "success", metrics.ErrorTypeNone)
	}

	return session, nil
}

// StartSessions starts all requested test sessions
func (c *Client) StartSessions() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we have sessions to start
	if len(c.currentSessions) == 0 {
		return common.ErrNoSessionsToStart
	}

	// Create start command
	startCmd := &messages.StartSessions{
		Command: common.CmdStartSessions,
	}

	// Marshal the command
	data, err := startCmd.Marshal(false)
	if err != nil {
		return fmt.Errorf("failed to marshal start command: %w", err)
	}

	if err := c.sendControlMessage(data, c.controlRequiresAuthentication()); err != nil {
		return fmt.Errorf("failed to send start command: %w", err)
	}

	respData, err := c.receiveAndVerify(messages.StartAckSize, c.controlRequiresAuthentication())
	if err != nil {
		return fmt.Errorf("failed to receive start ack: %w", err)
	}

	// Parse the response
	var startAck messages.StartAck
	err = startAck.Unmarshal(respData, c.controlRequiresAuthentication())
	if err != nil {
		return fmt.Errorf("failed to unmarshal start ack: %w", err)
	}

	// Check the accept code
	if startAck.Accept != common.AcceptOK {
		return common.NewTWAMPError(
			startAck.Accept,
			fmt.Sprintf("Server rejected start command: %s",
				common.AcceptCodeToString(startAck.Accept)))
	}

	// Start all the test sessions
	for _, session := range c.currentSessions {
		// Skip if session is already active (e.g., started via StartSession)
		if session.IsActive() {
			continue
		}
		err := session.Start()
		if err != nil {
			return fmt.Errorf("failed to start test session: %w", err)
		}
	}

	return nil
}

// StopSessions stops all active test sessions
func (c *Client) StopSessions() error {
	return c.stopSessionsWith(func(session *TestSession) error {
		return session.Stop()
	})
}

func (c *Client) stopSessionsWith(stopFunc func(*TestSession) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we have sessions to stop
	if len(c.currentSessions) == 0 {
		return nil // No sessions to stop, return success
	}

	// Create stop command (RFC 5357 Section 3.8)
	// NumSessions MUST contain the number of sessions to stop per RFC 5357
	stopCmd := &messages.StopSessions{
		Command:     common.CmdStopSessions,
		Accept:      common.AcceptOK, // Normal completion
		NumSessions: uint32(len(c.currentSessions)),
	}

	// Marshal the command
	data, err := stopCmd.Marshal(false)
	if err != nil {
		return fmt.Errorf("failed to marshal stop command: %w", err)
	}

	if err := c.sendControlMessage(data, c.controlRequiresAuthentication()); err != nil {
		return fmt.Errorf("failed to send stop command: %w", err)
	}
	// Stop all the test sessions and track which ones we've processed
	stoppedSessions := make(map[common.SessionID]struct{})
	var stopErrs []error
	for sid, session := range c.currentSessions {
		err := stopFunc(session)
		if err != nil {
			// Log the error but continue stopping other sessions
			logging.WithSession(c.logger, sid, c.mode, "").Error(
				"failed to stop session",
				logging.FieldError, err,
			)
			stopErrs = append(stopErrs, fmt.Errorf("session %x: %w", sid, err))
		}
		stoppedSessions[sid] = struct{}{}
	}

	// Update current sessions to remove stopped ones
	for sid := range stoppedSessions {
		delete(c.currentSessions, sid)
	}

	if len(stopErrs) > 0 {
		return errors.Join(stopErrs...)
	}

	return nil
}

// StopNSessions stops N test sessions (RFC 5938 Section 3.4)
func (c *Client) StopNSessions(numSessions uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sessionIDs := make([]common.SessionID, 0, len(c.currentSessions))
	for sid := range c.currentSessions {
		sessionIDs = append(sessionIDs, sid)
	}
	sort.Slice(sessionIDs, func(i, j int) bool {
		return bytes.Compare(sessionIDs[i][:], sessionIDs[j][:]) < 0
	})

	stopCount := int(numSessions)
	if stopCount > len(sessionIDs) {
		stopCount = len(sessionIDs)
	}
	selected := sessionIDs[:stopCount]

	// Create stop command (RFC 5938 Section 3.4)
	stopCmd := &messages.StopNSessions{
		Command:     common.CmdStopNSessions,
		NumSessions: uint32(stopCount),
		SessionIDs:  selected,
	}

	// Marshal the command
	data, err := stopCmd.Marshal(false)
	if err != nil {
		return fmt.Errorf("failed to marshal stop-n-sessions command: %w", err)
	}

	if err := c.sendControlMessage(data, c.controlRequiresAuthentication()); err != nil {
		return fmt.Errorf("failed to send stop-n-sessions command: %w", err)
	}

	// Stop the specified number of sessions locally
	stoppedSessions := make(map[common.SessionID]struct{})
	for _, sid := range selected {
		session, exists := c.currentSessions[sid]
		if !exists {
			continue
		}

		err := session.Stop()
		if err != nil {
			// Log the error but continue stopping other sessions
			logging.WithSession(c.logger, sid, c.mode, "").Error(
				"failed to stop session",
				logging.FieldError, err,
			)
		}
		stoppedSessions[sid] = struct{}{}
	}

	// Update current sessions to remove stopped ones
	for sid := range stoppedSessions {
		delete(c.currentSessions, sid)
	}

	return nil
}

// RequestSessionIndividual requests a new TWAMP test session with a specific SID (RFC 5938 Section 3.1)
func (c *Client) RequestSessionIndividual(config TestSessionConfig, sid common.SessionID) (*TestSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if SID is already in use
	if _, exists := c.currentSessions[sid]; exists {
		return nil, fmt.Errorf("%w: %x", ErrSessionConflict, sid)
	}

	// Calculate minimum required padding using helper function
	originalPadding := config.PaddingLength
	minPadding := calculateMinPadding(c.testMode)

	// Adjust padding if needed
	if config.PaddingLength < minPadding && minPadding > 0 {
		config.PaddingLength = minPadding
		c.logger.Warn("padding length increased to meet mode requirements",
			"original_length", originalPadding,
			logging.FieldPaddingLen, minPadding,
			logging.FieldMode, common.ModeToString(c.mode),
		)
	}

	// Set default timeout if not provided
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}

	// Set default receiver address if not provided
	if config.ReceiverAddress == "" {
		// Use server address from control connection
		host, _, err := net.SplitHostPort(c.config.ServerAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server address: %w", err)
		}
		config.ReceiverAddress = host
	}

	// Create request (RFC 5938 uses RequestTWSessionIndividual)
	request := &messages.RequestTWSessionIndividual{
		RequestTWSession: messages.RequestTWSession{
			Command:         common.CmdRequestTWSessionIndividual,
			IPVN:            4, // IPv4
			ConfSender:      0, // Must be 0 in TWAMP
			ConfReceiver:    0, // Must be 0 in TWAMP
			NumSlots:        0, // Must be 0 in TWAMP
			NumPackets:      0, // Must be 0 in TWAMP
			SenderPort:      config.SenderPort,
			ReceiverPort:    config.ReceiverPort,
			PaddingLength:   config.PaddingLength,
			TypePDescriptor: uint32(config.DSCP) << 18, // DSCP goes in bits 18-23
			SID:             sid,                       // Use provided SID instead of server-generated
		},
	}

	// Set addresses based on IP version using helper function
	isIPv6, ipBytes, err := parseAndValidateIP(config.ReceiverAddress)
	if err != nil {
		return nil, err
	}

	if !isIPv6 {
		// IPv4
		request.RequestTWSession.IPVN = 4
		copy(request.RequestTWSession.ReceiverAddress[:4], ipBytes)
	} else {
		// IPv6
		request.RequestTWSession.IPVN = 6
		copy(request.RequestTWSession.ReceiverAddress[:], ipBytes)
	}

	// Set timeout as TWAMP timestamp
	timeoutDuration := config.Timeout
	timeoutSeconds := uint32(timeoutDuration / time.Second)
	timeoutFraction := uint32(float64(timeoutDuration%time.Second) * common.NanoToFrac)
	request.RequestTWSession.Timeout = common.TWAMPTimestamp{
		Seconds:  timeoutSeconds,
		Fraction: timeoutFraction,
	}

	// Set start time to 0 (immediate start)
	request.RequestTWSession.StartTime = common.TWAMPTimestamp{
		Seconds:  0,
		Fraction: 0,
	}

	// Marshal the request
	data, err := request.Marshal(false)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := c.sendControlMessage(data, c.controlRequiresAuthentication()); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	respData, err := c.receiveAndVerify(messages.AcceptSessionSize, c.controlRequiresAuthentication())
	if err != nil {
		return nil, fmt.Errorf("failed to receive accept session response: %w", err)
	}

	// Parse the response
	var acceptSession messages.AcceptSession
	err = acceptSession.Unmarshal(respData, c.controlRequiresAuthentication())
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal accept session: %w", err)
	}

	// Check the accept code
	if acceptSession.Accept != common.AcceptOK {
		return nil, common.NewTWAMPError(
			acceptSession.Accept,
			fmt.Sprintf("Server rejected session: %s",
				common.AcceptCodeToString(acceptSession.Accept)))
	}

	// Verify the SID matches what we requested
	if acceptSession.SID != sid {
		return nil, fmt.Errorf("server returned different SID: expected %x, got %x", sid, acceptSession.SID)
	}

	// Check if port was changed by server
	if acceptSession.Port != 0 && acceptSession.Port != config.ReceiverPort {
		// Server suggested an alternate port
		config.ReceiverPort = acceptSession.Port
	}

	// Create a new test session
	// RFC 5618: Use testMode for test sessions, not the full negotiated mode
	session, err := NewTestSessionWithLoggerAndMetrics(config, sid, c.testMode, c.keyDerivation, c.logger, c.metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to create test session: %w", err)
	}

	// Store the session
	c.currentSessions[sid] = session

	// Record session creation (not started yet)
	if c.metrics != nil {
		c.metrics.RecordControlMessage("request_tw_session_individual", "client", "success", metrics.ErrorTypeNone)
	}

	return session, nil
}

// StartSession starts a specific test session by SID (RFC 5938 extension)
// Note: This requires server support for individual session control
func (c *Client) StartSession(sid common.SessionID) error {
	c.mu.Lock()

	// Find the session
	session, exists := c.currentSessions[sid]
	if !exists {
		c.mu.Unlock()
		return fmt.Errorf("%w: %x", ErrSessionNotFound, sid)
	}

	// Start the session locally
	err := session.Start()
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to start test session %x: %w", sid, err)
	}

	// Release the lock before calling StartSessions to avoid deadlock
	c.mu.Unlock()

	// Note: RFC 5938 doesn't define a Start-Individual-Session command
	// Sessions created with Request-TW-Session-Individual still use
	// the regular Start-Sessions command to start
	// We need to send Start-Sessions to the server to start all sessions
	return c.StartSessions()
}

// StopSession stops a specific test session by SID (RFC 5938 extension)
func (c *Client) StopSession(sid common.SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find the session
	session, exists := c.currentSessions[sid]
	if !exists {
		return fmt.Errorf("%w: %x", ErrSessionNotFound, sid)
	}

	// Stop the session
	err := session.Stop()
	if err != nil {
		return fmt.Errorf("failed to stop test session %x: %w", sid, err)
	}

	// Remove from current sessions
	delete(c.currentSessions, sid)

	// Note: This is a local stop. For coordinated stop with server,
	// use StopNSessions(1) or StopSessions()
	return nil
}

// GetSession returns a test session by SID
func (c *Client) GetSession(sid common.SessionID) (*TestSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	session, exists := c.currentSessions[sid]
	if !exists {
		return nil, fmt.Errorf("%w: %x", ErrSessionNotFound, sid)
	}

	return session, nil
}

// GetSessionIDs returns the SIDs of all current sessions
func (c *Client) GetSessionIDs() []common.SessionID {
	c.mu.Lock()
	defer c.mu.Unlock()

	sids := make([]common.SessionID, 0, len(c.currentSessions))
	for sid := range c.currentSessions {
		sids = append(sids, sid)
	}
	return sids
}

// calculateMinPadding returns the minimum padding length required for a given mode
// This is a pure function for easier testing
func calculateMinPadding(mode common.Mode) uint32 {
	// Extract base security mode (ignore RFC 5618 mixed bit and RFC 6038 bits)
	securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
	baseMode := mode & securityMask

	switch baseMode {
	case common.ModeUnauthenticated:
		return 27 // RFC 5357 Section 4.1.2 recommended minimum padding
	case common.ModeAuthenticated:
		return 56 // RFC 5357 Section 4.1.2 recommended minimum padding
	case common.ModeEncrypted:
		return 56 // RFC 5357 Section 4.1.2 recommended minimum padding
	default:
		return 0
	}
}

// parseAndValidateIP parses and validates an IP address, returning IPv4/IPv6 indicator
// This is a pure function for easier testing
// Returns: (isIPv6, ipBytes, error)
func parseAndValidateIP(address string) (bool, []byte, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return false, nil, fmt.Errorf("%w: %s", common.ErrInvalidReceiverAddress, address)
	}

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		return false, ip4, nil
	}

	// IPv6
	return true, ip.To16(), nil
}

// Close closes the control connection and all test sessions.
//
// WARNING: Close is not safe for concurrent use. Calling Close from multiple
// goroutines simultaneously may result in race conditions. Ensure Close is
// called only once, after all other operations have completed.
// See: https://github.com/ncode/twamp/issues/XXX (TODO: file issue)
func (c *Client) Close() error {
	// Stop all sessions first
	c.StopSessions()

	// Close the control connection
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}

	return nil
}
