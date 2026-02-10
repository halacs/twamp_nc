// pkg/twamp/server/server.go
package server

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/crypto"
	"github.com/ncode/twamp/logging"
	"github.com/ncode/twamp/messages"
	"github.com/ncode/twamp/metrics"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Error definitions
var (
	// ErrNoAvailablePorts is returned when all ports in the configured range are in use
	ErrNoAvailablePorts = errors.New("no available ports in range")
	// common.ErrHMACVerificationFailed is returned when HMAC verification fails for a packet
	// ErrClientTerminatedConnection is returned when client requests to terminate (mode=0)
	ErrClientTerminatedConnection = errors.New("client requested to terminate connection")
	// ErrMissingGreeting is returned when server greeting is not available for token verification
	ErrMissingGreeting = errors.New("server greeting not available for token verification")
	// ErrDecryptFailed is returned when test packet decryption fails
	ErrDecryptFailed = errors.New("failed to decrypt test packet")
	// ErrUnmarshalFailed is returned when message/packet unmarshal fails
	ErrUnmarshalFailed = errors.New("failed to unmarshal message")
)

// ServerConfig contains configuration for TWAMP Server
type ServerConfig struct {
	ListenAddress   string
	SupportedModes  common.Mode       // Bit mask of supported modes
	SecretMap       map[string]string // KeyID to shared secret mapping
	SERVWAIT        time.Duration     // Default 900s
	REFWAIT         time.Duration     // Default 900s
	PortRange       [2]uint16         // Range of ports for reflection [min, max]
	DSCP            uint8
	ReceiverAllowlistCIDRs []string // CIDR blocks allowed as unauthenticated receivers
	ReceiverAllowlistIPs   []string // Explicit IPs allowed as unauthenticated receivers
	Logger          logging.Logger   // Optional logger (defaults to noop)
	Metrics         *metrics.Metrics // Optional metrics (defaults to nil, no metrics)
	MaxHMACFailures uint32           // Max consecutive HMAC failures before session termination (0 = use default)
}

// Server implements a TWAMP Server and Session-Reflector
type Server struct {
	config        ServerConfig
	listener      net.Listener
	sessions      map[common.SessionID]*TestSession
	sessionsMu    sync.RWMutex
	connections   map[net.Conn]*controlConnection
	connectionsMu sync.RWMutex
	portManager   *portManager
	stopChan      chan struct{}
	wg            sync.WaitGroup
	logger        logging.Logger
	metrics       *metrics.Metrics
	unauthAllowCIDRs []*net.IPNet
	unauthAllowIPs   map[string]struct{}
}

// HMAC failure policy constants per RFC 4656 Section 6.
// These control how the server responds to repeated HMAC verification failures.
const (
	// DefaultMaxConsecutiveHMACFailures is the default threshold for consecutive HMAC
	// failures before session termination. Set to 0 to disable (legacy behavior).
	// RFC 4656 Section 6 recommends implementations SHOULD have a policy for
	// authentication failures. A value of 100 balances resilience to transient
	// network corruption (avoid false positives) against sustained attack detection.
	DefaultMaxConsecutiveHMACFailures = 100

	// HMACFailureResetWindow is the time window after which HMAC failure counts
	// are reset if no failures occur. This prevents long-lived sessions from
	// accumulating failures over extended periods.
	HMACFailureResetWindow = 30 * time.Second

	// DisabledMaxHMACFailures indicates HMAC failure policy is disabled
	DisabledMaxHMACFailures = ^uint32(0) // MaxUint32, effectively disabled
)

// effectiveMaxHMACFailures returns the configured MaxHMACFailures value,
// or DefaultMaxConsecutiveHMACFailures if not explicitly set (0).
func (s *Server) effectiveMaxHMACFailures() uint32 {
	if s.config.MaxHMACFailures == 0 {
		return DefaultMaxConsecutiveHMACFailures
	}
	return s.config.MaxHMACFailures
}

// TestSession represents a server-side TWAMP test session
type TestSession struct {
	sid              common.SessionID
	reflectorPort    uint16
	conn             *net.UDPConn
	senderAddr       net.Addr
	senderPort       uint16
	mode             common.Mode
	sessionKeys      *crypto.TWAMPKeys
	timeout          time.Duration
	dscp             uint8
	reflectedPackets uint32
	startTime        time.Time
	isActive         atomic.Bool
	stopChan         chan struct{}
	reflectorDone    chan struct{} // Closed when reflector exits
	mu               sync.Mutex

	// HMAC failure tracking per RFC 4656 Section 6.
	// Access is protected by session.mu.
	hmacFailures        uint32    // Consecutive HMAC verification failures
	lastHMACFailureTime time.Time // Time of last HMAC failure (for reset window)
	maxHMACFailures     uint32    // Threshold for session termination (0 = disabled)
}

// controlConnection represents a TWAMP control connection
type controlConnection struct {
	conn          net.Conn
	mode          common.Mode // Negotiated mode (may include mixed security bit)
	controlMode   common.Mode // Actual mode for control protocol
	testMode      common.Mode // Actual mode for test protocol
	keyDerivation *crypto.TWAMPKeys
	controlEncrypt *crypto.CBCStream
	controlDecrypt *crypto.CBCStream
	serverStartBytes []byte
	serverStartHMACPending bool
	sessions      map[common.SessionID]*TestSession
	lastActivity  time.Time
	greeting      *messages.ServerGreeting
	cleanupDone   chan struct{} // Closed when cleanup is complete
}

// portManager manages UDP port allocation for test sessions
type portManager struct {
	minPort   uint16
	maxPort   uint16
	usedPorts map[uint16]bool
	mu        sync.Mutex
}

// newPortManager creates a new port manager for test sessions.
// If minPort is 0, it defaults to 20000. If maxPort is 0, it defaults to 30000.
// Returns an error if minPort > maxPort after applying defaults.
func newPortManager(minPort, maxPort uint16) (*portManager, error) {
	if minPort == 0 {
		minPort = 20000 // Default starting port
	}
	if maxPort == 0 {
		maxPort = 30000 // Default max port
	}

	// Validate range
	if minPort > maxPort {
		return nil, fmt.Errorf("%w: minPort (%d) > maxPort (%d)", common.ErrInvalidPortRange, minPort, maxPort)
	}

	return &portManager{
		minPort:   minPort,
		maxPort:   maxPort,
		usedPorts: make(map[uint16]bool),
	}, nil
}

// allocatePort allocates a port for session reflection
func (pm *portManager) allocatePort() (uint16, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Try to find an available port in the range
	for port := pm.minPort; port <= pm.maxPort; port++ {
		if !pm.usedPorts[port] {
			// Check if the port is available by trying to listen on it
			addr := &net.UDPAddr{Port: int(port)}
			conn, err := net.ListenUDP("udp", addr)
			if err == nil {
				// Port is available
				conn.Close()
				pm.usedPorts[port] = true
				return port, nil
			}
		}
	}

	return 0, ErrNoAvailablePorts
}

// usedPortCount returns the number of currently used ports
func (pm *portManager) usedPortCount() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return len(pm.usedPorts)
}

// releasePort releases a port back to the pool
func (pm *portManager) releasePort(port uint16) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	delete(pm.usedPorts, port)
}

// NewServer creates a new TWAMP server
func NewServer(config ServerConfig) (*Server, error) {
	const reservedModeBit14 = common.Mode(1 << 14)

	// Set default values if not provided
	if config.SERVWAIT == 0 {
		config.SERVWAIT = common.DefaultSERVWAIT
	}
	if config.REFWAIT == 0 {
		config.REFWAIT = common.DefaultREFWAIT
	}

	// Set default listen address if not provided
	if config.ListenAddress == "" {
		config.ListenAddress = ":862" // Default TWAMP control port
	}

	// Set default logger if not provided (noop for backward compatibility)
	if config.Logger == nil {
		config.Logger = logging.NewNoop()
	}
	if config.SupportedModes&reservedModeBit14 != 0 {
		return nil, fmt.Errorf("%w: reserved mode bit 14 not supported", common.ErrInvalidModeCombo)
	}

	portManager, err := newPortManager(config.PortRange[0], config.PortRange[1])
	if err != nil {
		return nil, fmt.Errorf("failed to create port manager: %w", err)
	}

	allowCIDRs, err := parseAllowCIDRs(config.ReceiverAllowlistCIDRs)
	if err != nil {
		return nil, err
	}

	allowIPs, err := parseAllowIPs(config.ReceiverAllowlistIPs)
	if err != nil {
		return nil, err
	}

	return &Server{
		config:           config,
		sessions:         make(map[common.SessionID]*TestSession),
		connections:      make(map[net.Conn]*controlConnection),
		portManager:      portManager,
		stopChan:         make(chan struct{}),
		logger:           config.Logger,
		metrics:          config.Metrics,
		unauthAllowCIDRs: allowCIDRs,
		unauthAllowIPs:   allowIPs,
	}, nil
}

// Start starts the TWAMP server
func (s *Server) Start(ctx context.Context) error {
	// Start TCP listener for TWAMP-Control
	listener, err := net.Listen("tcp", s.config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	s.listener = listener

	// Accept connections in a goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptConnections(ctx)
	}()

	return nil
}

// acceptConnections accepts and handles TWAMP-Control connections
func (s *Server) acceptConnections(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
			// Set accept timeout to allow for context cancellation checks
			s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

			conn, err := s.listener.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					// This is just a timeout, continue
					continue
				}
				// Log other errors but don't stop
				continue
			}

			// Handle each connection in a separate goroutine
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConnection(ctx, conn)
			}()
		}
	}
}

// handleConnection processes a single TWAMP-Control connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	// Create a new control connection
	cc := &controlConnection{
		conn:         conn,
		sessions:     make(map[common.SessionID]*TestSession),
		lastActivity: time.Now(),
		cleanupDone:  make(chan struct{}),
	}

	// Add to connections map
	s.connectionsMu.Lock()
	s.connections[conn] = cc
	s.connectionsMu.Unlock()

	// Ensure connection is removed when done
	defer func() {
		// Clean up any sessions associated with this connection FIRST
		// This ensures sessions are stopped before we lose the reference
		var reflectorChans []<-chan struct{}
		for _, session := range cc.sessions {
			reflectorChans = append(reflectorChans, session.reflectorDone)
			s.stopSession(session)
		}

		// Wait for all reflectors to finish (with timeout)
		for _, done := range reflectorChans {
			select {
			case <-done:
				// Reflector finished
			case <-time.After(1 * time.Second):
				// Timeout - continue anyway
			}
		}

		// Now remove the connection from the map
		s.connectionsMu.Lock()
		delete(s.connections, conn)
		s.connectionsMu.Unlock()

		// Finally close the connection
		conn.Close()

		// Signal cleanup is done (including reflectors)
		close(cc.cleanupDone)
	}()

	// Send server greeting
	err := s.sendServerGreeting(cc)
	if err != nil {
		return
	}

	// Handle client setup
	err = s.handleClientSetup(cc)
	if err != nil {
		return
	}

	// Main command loop
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		// Set deadline for SERVWAIT timeout
		cc.conn.SetReadDeadline(time.Now().Add(s.config.SERVWAIT))

		// Try to read a command
		cmd, err := s.readCommand(cc)
		if err != nil {
			// Check if this is a timeout (SERVWAIT expired)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if we've been idle too long
				if time.Since(cc.lastActivity) > s.config.SERVWAIT {
					return // Close connection due to SERVWAIT timeout
				}
				continue // Just a normal timeout, keep waiting
			}
			// Any other error (EOF, connection reset, etc)
			return
		}

		// If shutdown happens while blocked on read, exit before processing.
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		// Update last activity
		cc.lastActivity = time.Now()

		// Process the command
		switch cmd[0] { // First byte is command identifier
		case common.CmdRequestTWSession:
			err = s.handleRequestTWSession(cc, cmd)
		case common.CmdStartSessions:
			err = s.handleStartSessions(cc, cmd)
		case common.CmdStopSessions:
			err = s.handleStopSessions(cc, cmd)
		case common.CmdStopNSessions: // RFC 5938 Section 3.4
			err = s.handleStopNSessions(cc, cmd)
		case common.CmdRequestTWSessionIndividual: // RFC 5938 Section 3.1
			err = s.handleRequestTWSessionIndividual(cc, cmd)
		default:
			err = fmt.Errorf("unknown command: %d", cmd[0])
		}

		if err != nil {
			return // Close connection on error
		}
	}
}

// sendServerGreeting sends the initial Server Greeting
func (s *Server) sendServerGreeting(cc *controlConnection) error {
	// Create server greeting
	greeting := &messages.ServerGreeting{
		Modes: uint32(s.config.SupportedModes &^ common.Mode(1<<14)),
	}

	// Generate random challenge
	if _, err := io.ReadFull(rand.Reader, greeting.Challenge[:]); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Generate random salt
	if _, err := io.ReadFull(rand.Reader, greeting.Salt[:]); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Set Count to recommended value (RFC 4656 recommends at least 1024)
	greeting.Count = 1024

	// Marshal greeting
	data, err := greeting.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal greeting: %w", err)
	}

	// Store the greeting with the connection
	cc.greeting = greeting

	// Send greeting
	_, err = cc.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	return nil
}

// handleClientSetup handles the client's setup response
func (s *Server) handleClientSetup(cc *controlConnection) error {
	// Read client setup response
	buf := make([]byte, 164) // Size of setup response
	_, err := io.ReadFull(cc.conn, buf)
	if err != nil {
		return fmt.Errorf("failed to read setup response: %w", err)
	}

	// Parse setup response
	var setupResponse messages.SetupResponse
	err = setupResponse.Unmarshal(buf)
	if err != nil {
		return fmt.Errorf("%w (setup response): %v", ErrUnmarshalFailed, err)
	}

	// Check if requested mode is supported
	requestedMode := common.Mode(setupResponse.Mode)
	if requestedMode == 0 {
		// Client doesn't want to continue
		return ErrClientTerminatedConnection
	}
	if err := common.ValidateRequestedMode(requestedMode); err != nil {
		return fmt.Errorf("%w: %d", common.ErrInvalidModeCombo, requestedMode)
	}

	if requestedMode&s.config.SupportedModes == 0 {
		// Mode not supported
		return fmt.Errorf("%w: %d", common.ErrUnsupportedMode, requestedMode)
	}

	// Store the negotiated mode
	cc.mode = requestedMode

	// Resolve control and test modes per RFC 5618
	var resolveErr error
	cc.controlMode, cc.testMode, resolveErr = common.ResolveMixedModes(requestedMode)
	if resolveErr != nil {
		return fmt.Errorf("%w: %w", common.ErrInvalidModeCombo, resolveErr)
	}

	// Extract base security from control mode (bits 0-2) to check if authentication is needed
	// This is necessary because controlMode may have additional bits set (e.g., RFC 6038 modes)
	securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
	controlSecurity := cc.controlMode & securityMask

	// Handle authentication for secure modes (base security mode determines this)
	if controlSecurity != common.ModeUnauthenticated {
		// Extract KeyID from setup response
		keyIDLength := 0
		for i, b := range setupResponse.KeyID {
			if b == 0 {
				keyIDLength = i
				break
			}
		}
		keyID := string(setupResponse.KeyID[:keyIDLength])

		// Look up shared secret
		sharedSecret, ok := s.config.SecretMap[keyID]
		if !ok {
			// Unknown KeyID
			return fmt.Errorf("%w: %s", common.ErrUnknownKeyID, keyID)
		}

		// Verify that we have the greeting stored
		if cc.greeting == nil {
			return ErrMissingGreeting
		}

		// Derive session keys
		aesKey, hmacKey, err := crypto.DeriveKey(sharedSecret, cc.greeting.Salt[:], cc.greeting.Count)
		if err != nil {
			return fmt.Errorf("failed to derive keys: %w", err)
		}

		// Decrypt and verify token
		tokenContents, err := crypto.DecryptToken(setupResponse.Token[:], cc.greeting.Challenge[:])
		if err != nil {
			return fmt.Errorf("%w (token): %v", ErrDecryptFailed, err)
		}

		// Verify challenge matches
		if !compareBytes(tokenContents.Challenge, cc.greeting.Challenge[:]) {
			return errors.New("challenge mismatch in token")
		}

		// Store key derivation for this connection
		cc.keyDerivation = &crypto.TWAMPKeys{
			AESKey:   aesKey,
			HMACKey:  hmacKey,
			ClientIV: setupResponse.ClientIV[:],
		}

		// Generate server IV
		serverIV, err := crypto.NewRandomIV()
		if err != nil {
			return fmt.Errorf("failed to generate server IV: %w", err)
		}
		cc.keyDerivation.ServerIV = serverIV

		controlEncrypt, err := crypto.NewCBCStream(cc.keyDerivation.AESKey, cc.keyDerivation.ServerIV)
		if err != nil {
			return fmt.Errorf("failed to init control encrypt stream: %w", err)
		}

		controlDecrypt, err := crypto.NewCBCStream(cc.keyDerivation.AESKey, cc.keyDerivation.ClientIV)
		if err != nil {
			return fmt.Errorf("failed to init control decrypt stream: %w", err)
		}

		cc.controlEncrypt = controlEncrypt
		cc.controlDecrypt = controlDecrypt
	}

	// Send Server-Start message
	serverStart := &messages.ServerStart{
		Accept: common.AcceptOK,
	}

	// Fill in ServerIV for secure modes (base security of control mode)
	if controlSecurity != common.ModeUnauthenticated {
		copy(serverStart.ServerIV[:], cc.keyDerivation.ServerIV)
	} else {
		// Always generate ServerIV even in unauthenticated mode
		serverIV, err := crypto.NewRandomIV()
		if err != nil {
			return fmt.Errorf("failed to generate server IV: %w", err)
		}
		copy(serverStart.ServerIV[:], serverIV)
	}

	// Set start time
	serverStart.StartTime = common.FromTime(time.Now())

	// Marshal Server-Start
	data, err := serverStart.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal Server-Start: %w", err)
	}
	cc.serverStartBytes = append([]byte(nil), data...)
	cc.serverStartHMACPending = controlSecurity != common.ModeUnauthenticated

	// Make sure TCP sends this in a single packet by enabling TCP_NODELAY
	if tcpConn, ok := cc.conn.(*net.TCPConn); ok {
		// Disable Nagle algorithm to prevent combining small packets
		tcpConn.SetNoDelay(true)
	}

	// Send Server-Start
	written, err := cc.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send Server-Start: %w", err)
	}

	if written != len(data) {
		return fmt.Errorf("failed to send complete Server-Start: wrote %d of %d bytes",
			written, len(data))
	}

	return nil
}

// compareBytes safely compares two byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	// Use a constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(a, b) == 1
}

func enableTTLReceive(conn *net.UDPConn) {
	packetConn4 := ipv4.NewPacketConn(conn)
	_ = packetConn4.SetControlMessage(ipv4.FlagTTL, true)

	packetConn6 := ipv6.NewPacketConn(conn)
	_ = packetConn6.SetControlMessage(ipv6.FlagHopLimit, true)
}

func extractPacketTTL(oob []byte, addr net.Addr) (uint8, bool) {
	if len(oob) == 0 {
		return 0, false
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return 0, false
	}

	if udpAddr.IP.To4() != nil {
		cm := &ipv4.ControlMessage{}
		if err := cm.Parse(oob); err == nil && cm.TTL > 0 {
			return uint8(cm.TTL), true
		}
		return 0, false
	}

	cm := &ipv6.ControlMessage{}
	if err := cm.Parse(oob); err == nil && cm.HopLimit > 0 {
		return uint8(cm.HopLimit), true
	}

	return 0, false
}

func parseAllowCIDRs(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", common.ErrInvalidReceiverAddress, cidr)
		}
		parsed = append(parsed, ipNet)
	}

	return parsed, nil
}

func parseAllowIPs(ips []string) (map[string]struct{}, error) {
	if len(ips) == 0 {
		return nil, nil
	}

	parsed := make(map[string]struct{}, len(ips))
	for _, entry := range ips {
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("%w: %s", common.ErrInvalidReceiverAddress, entry)
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		parsed[ip.String()] = struct{}{}
	}

	return parsed, nil
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

func peerIP(addr net.Addr) net.IP {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func isLocalIP(ip net.IP) bool {
	ip = normalizeIP(ip)
	if ip == nil {
		return false
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			if normalizeIP(v.IP).Equal(ip) {
				return true
			}
		case *net.IPAddr:
			if normalizeIP(v.IP).Equal(ip) {
				return true
			}
		}
	}

	return false
}

func receiverIP(request *messages.RequestTWSession) net.IP {
	if request == nil {
		return nil
	}
	switch request.IPVN {
	case 4:
		return normalizeIP(net.IP(request.ReceiverAddress[:4]))
	case 6:
		return normalizeIP(net.IP(request.ReceiverAddress[:]))
	default:
		return nil
	}
}

func (s *Server) isAllowlisted(ip net.IP) bool {
	ip = normalizeIP(ip)
	if ip == nil {
		return false
	}

	if s.unauthAllowIPs != nil {
		if _, ok := s.unauthAllowIPs[ip.String()]; ok {
			return true
		}
	}
	for _, cidr := range s.unauthAllowCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func (s *Server) isUnauthReceiverAllowed(cc *controlConnection, request *messages.RequestTWSession) bool {
	receiver := receiverIP(request)
	if receiver == nil {
		return false
	}

	peerAddr := peerIP(cc.conn.RemoteAddr())
	if peerAddr != nil && normalizeIP(peerAddr).Equal(receiver) {
		return true
	}
	if isLocalIP(receiver) {
		return true
	}
	if s.isAllowlisted(receiver) {
		return true
	}

	return false
}

func maxSenderPadding(testMode common.Mode) uint32 {
	baseSize := messages.SenderTestPacketMinSize
	if testMode&(common.ModeAuthenticated|common.ModeEncrypted) != 0 {
		baseSize = messages.SenderTestPacketAuthMinSize
	}
	if baseSize >= common.MaxTWAMPPacketSize {
		return 0
	}
	return uint32(common.MaxTWAMPPacketSize - baseSize)
}

// controlRequiresAuthentication returns true if the control protocol requires authentication.
// It extracts the base security bits (0-2) from controlMode and checks if it's not unauthenticated.
func controlRequiresAuthentication(controlMode common.Mode) bool {
	securityMask := common.Mode(common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted)
	controlSecurity := controlMode & securityMask
	return controlSecurity != common.ModeUnauthenticated
}

func controlCommandLength(cmd byte, header []byte) (int, error) {
	switch cmd {
	case common.CmdRequestTWSession:
		return messages.RequestTWSessionSize, nil
	case common.CmdStartSessions:
		return messages.StartSessionsSize, nil
	case common.CmdStopSessions:
		return messages.StopSessionsSize, nil
	case common.CmdStopNSessions:
		if len(header) < 8 {
			return 0, common.ErrInvalidMessageLength
		}
		numSessions := binary.BigEndian.Uint32(header[4:8])
		cmdLength64 := int64(16) + int64(numSessions)*16 + 16
		if cmdLength64 > int64(math.MaxInt) {
			return 0, common.ErrInvalidMessageLength
		}
		return int(cmdLength64), nil
	case common.CmdRequestTWSessionIndividual:
		return messages.RequestTWSessionSize, nil
	default:
		return 0, fmt.Errorf("%w: %d", common.ErrUnknownCommand, cmd)
	}
}

// readCommand reads a command from the control connection
func (s *Server) readCommand(cc *controlConnection) ([]byte, error) {
	// Don't set deadline here - it's managed by handleConnection

	if controlRequiresAuthentication(cc.controlMode) {
		return s.readEncryptedCommand(cc)
	}

	return s.readPlainCommand(cc)
}

func (s *Server) readPlainCommand(cc *controlConnection) ([]byte, error) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(cc.conn, header); err != nil {
		return nil, err
	}

	if header[0] == common.CmdStopNSessions {
		baseHeaderLen := 16
		baseHeader := make([]byte, baseHeaderLen)
		baseHeader[0] = header[0]
		if _, err := io.ReadFull(cc.conn, baseHeader[1:]); err != nil {
			return nil, err
		}

		cmdLength, err := controlCommandLength(header[0], baseHeader)
		if err != nil {
			return nil, err
		}

		cmd := make([]byte, cmdLength)
		copy(cmd, baseHeader)
		if cmdLength > baseHeaderLen {
			if _, err := io.ReadFull(cc.conn, cmd[baseHeaderLen:]); err != nil {
				return nil, err
			}
		}

		return cmd, nil
	}

	cmdLength, err := controlCommandLength(header[0], nil)
	if err != nil {
		return nil, err
	}

	cmd := make([]byte, cmdLength)
	copy(cmd, header)
	if _, err := io.ReadFull(cc.conn, cmd[1:]); err != nil {
		return nil, err
	}

	return cmd, nil
}

func (s *Server) readEncryptedCommand(cc *controlConnection) ([]byte, error) {
	if cc.controlDecrypt == nil {
		return nil, errors.New("control decryption not initialized")
	}

	firstCipher := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(cc.conn, firstCipher); err != nil {
		return nil, err
	}

	firstPlain, err := cc.controlDecrypt.Decrypt(firstCipher)
	if err != nil {
		return nil, err
	}

	cmdLength, err := controlCommandLength(firstPlain[0], firstPlain)
	if err != nil {
		return nil, err
	}

	if cmdLength%aes.BlockSize != 0 {
		return nil, common.ErrInvalidMessageLength
	}

	remaining := cmdLength - len(firstPlain)
	cmd := make([]byte, cmdLength)
	copy(cmd, firstPlain)

	if remaining > 0 {
		restCipher := make([]byte, remaining)
		if _, err := io.ReadFull(cc.conn, restCipher); err != nil {
			return nil, err
		}

		restPlain, err := cc.controlDecrypt.Decrypt(restCipher)
		if err != nil {
			return nil, err
		}
		copy(cmd[len(firstPlain):], restPlain)
	}

	messageEnd := cmdLength - 16
	valid, err := crypto.VerifyHMAC(cc.keyDerivation.HMACKey, cmd[:messageEnd], cmd[messageEnd:])
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, common.ErrHMACVerificationFailed
	}

	return cmd, nil
}

// handleRequestTWSession handles a Request-TW-Session command
func (s *Server) handleRequestTWSession(cc *controlConnection, cmdData []byte) error {
	// Parse Request-TW-Session
	var request messages.RequestTWSession
	err := request.Unmarshal(cmdData, controlRequiresAuthentication(cc.controlMode))
	if err != nil {
		// Record control message error
		if s.metrics != nil {
			s.metrics.RecordControlMessage("request_tw_session", "server", "error", metrics.ErrorTypeParse)
		}
		return fmt.Errorf("%w (Request-TW-Session): %v", ErrUnmarshalFailed, err)
	}

	// RFC 5357 Section 3.5: SID in Request-TW-Session MUST be set to 0
	// The server generates the SID, client must send zeros
	if !request.SID.IsZero() {
		if s.metrics != nil {
			s.metrics.RecordControlMessage("request_tw_session", "server", "error", metrics.ErrorTypeParse)
		}
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}

	// Validate request
	if request.ConfSender != 0 || request.ConfReceiver != 0 {
		// TWAMP requires both to be 0
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}
	if !controlRequiresAuthentication(cc.controlMode) && !s.isUnauthReceiverAllowed(cc, &request) {
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}
	if request.PaddingLength > maxSenderPadding(cc.testMode) {
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}

	// Allocate a port for reflection
	reflectorPort, err := s.portManager.allocatePort()
	if err != nil {
		return s.sendAcceptSession(cc, common.AcceptTempResLimited, 0, common.SessionID{})
	}

	// Generate a unique SID
	var sid common.SessionID
	if _, err := io.ReadFull(rand.Reader, sid[:]); err != nil {
		s.portManager.releasePort(reflectorPort)
		return fmt.Errorf("failed to generate SID: %w", err)
	}

	// Extract DSCP value from Type-P Descriptor (bits 18-23)
	dscp := uint8((request.TypePDescriptor >> 18) & 0x3F)

	// Create test session
	// RFC 5618: Use testMode for test protocol (may differ from control mode in mixed security)
	session := &TestSession{
		sid:             sid,
		reflectorPort:   reflectorPort,
		senderPort:      request.SenderPort,
		mode:            cc.testMode, // RFC 5618: Use test mode, not negotiated mode
		timeout:         time.Duration(request.Timeout.Seconds) * time.Second,
		dscp:            dscp,
		stopChan:        make(chan struct{}),
		reflectorDone:   make(chan struct{}),
		maxHMACFailures: s.effectiveMaxHMACFailures(),
	}

	// Derive session keys for secure modes (only if test mode requires it)
	// RFC 5618: In mixed mode, test protocol may be unauthenticated even if control is encrypted
	if cc.testMode != common.ModeUnauthenticated && cc.keyDerivation != nil {
		testAESKey, testHMACKey, err := crypto.DeriveTestSessionKeys(
			cc.keyDerivation.AESKey,
			cc.keyDerivation.HMACKey,
			sid,
		)
		if err != nil {
			s.portManager.releasePort(reflectorPort)
			return fmt.Errorf("failed to derive test session keys: %w", err)
		}

		session.sessionKeys = &crypto.TWAMPKeys{
			TestAESKey:  testAESKey,
			TestHMACKey: testHMACKey,
			ClientIV:    cc.keyDerivation.ClientIV,
			ServerIV:    cc.keyDerivation.ServerIV,
		}
	}

	// Store session
	s.sessionsMu.Lock()
	s.sessions[sid] = session
	s.sessionsMu.Unlock()

	// Add to control connection's sessions
	cc.sessions[sid] = session

	// Record successful control message and session creation
	if s.metrics != nil {
		s.metrics.RecordControlMessage("request_tw_session", "server", "success", metrics.ErrorTypeNone)
		// Note: We don't RecordSessionStart here because the session isn't started yet
		// It will be recorded when StartSessions is received
	}

	// Update port usage
	if s.metrics != nil {
		s.metrics.SetPortUsage(s.portManager.usedPortCount())
	}

	// Send Accept-Session response
	return s.sendAcceptSession(cc, common.AcceptOK, reflectorPort, sid)
}

// sendAcceptSession sends an Accept-Session response
func (s *Server) sendAcceptSession(cc *controlConnection, acceptCode uint8, port uint16, sid common.SessionID) error {
	// Create Accept-Session message
	acceptSession := &messages.AcceptSession{
		Accept: acceptCode,
		Port:   port,
		SID:    sid,
	}

	// Marshal the message
	data, err := acceptSession.Marshal(false)
	if err != nil {
		return fmt.Errorf("failed to marshal Accept-Session: %w", err)
	}

	usePrefix := controlRequiresAuthentication(cc.controlMode) && cc.serverStartHMACPending
	var hmacPrefix []byte
	if usePrefix {
		hmacPrefix = cc.serverStartBytes
	}

	if err := s.sendControlMessage(cc, data, hmacPrefix); err != nil {
		return fmt.Errorf("failed to send Accept-Session: %w", err)
	}

	if usePrefix {
		cc.serverStartHMACPending = false
	}

	return nil
}

func (s *Server) sendControlMessage(cc *controlConnection, message []byte, hmacPrefix []byte) error {
	if len(message) < 16 {
		return common.ErrInvalidMessageLength
	}

	if controlRequiresAuthentication(cc.controlMode) {
		if cc.controlEncrypt == nil {
			return errors.New("control encryption not initialized")
		}

		messageLen := len(message) - 16
		hmac, err := crypto.CalculateHMACWithPrefix(cc.keyDerivation.HMACKey, hmacPrefix, message[:messageLen])
		if err != nil {
			return fmt.Errorf("failed to calculate HMAC: %w", err)
		}
		copy(message[messageLen:], hmac)

		encrypted, err := cc.controlEncrypt.Encrypt(message)
		if err != nil {
			return fmt.Errorf("failed to encrypt control message: %w", err)
		}

		_, err = cc.conn.Write(encrypted)
		return err
	}

	for i := len(message) - 16; i < len(message); i++ {
		message[i] = 0
	}

	_, err := cc.conn.Write(message)
	return err
}

// handleStartSessions handles a Start-Sessions command
func (s *Server) handleStartSessions(cc *controlConnection, cmdData []byte) error {
	// Parse Start-Sessions
	var startSessions messages.StartSessions
	err := startSessions.Unmarshal(cmdData, controlRequiresAuthentication(cc.controlMode))
	if err != nil {
		if s.metrics != nil {
			s.metrics.RecordControlMessage("start_sessions", "server", "error", metrics.ErrorTypeParse)
		}
		return fmt.Errorf("%w (Start-Sessions): %v", ErrUnmarshalFailed, err)
	}

	// Start all sessions for this connection
	for _, session := range cc.sessions {
		err := s.startSession(session)
		if err != nil {
			// If we can't start one session, respond with failure
			if s.metrics != nil {
				s.metrics.RecordControlMessage("start_sessions", "server", "error", metrics.ErrorTypeInternal)
			}
			return s.sendStartAck(cc, common.AcceptFailure)
		}
	}

	// Record successful control message
	if s.metrics != nil {
		s.metrics.RecordControlMessage("start_sessions", "server", "success", metrics.ErrorTypeNone)
	}

	// Send Start-Ack
	return s.sendStartAck(cc, common.AcceptOK)
}

// sendStartAck sends a Start-Ack response
func (s *Server) sendStartAck(cc *controlConnection, acceptCode uint8) error {
	// Create Start-Ack message
	startAck := &messages.StartAck{
		Accept: acceptCode,
	}

	// Marshal the message
	data, err := startAck.Marshal(false)
	if err != nil {
		return fmt.Errorf("failed to marshal Start-Ack: %w", err)
	}

	usePrefix := controlRequiresAuthentication(cc.controlMode) && cc.serverStartHMACPending
	var hmacPrefix []byte
	if usePrefix {
		hmacPrefix = cc.serverStartBytes
	}

	if err := s.sendControlMessage(cc, data, hmacPrefix); err != nil {
		return fmt.Errorf("failed to send Start-Ack: %w", err)
	}

	if usePrefix {
		cc.serverStartHMACPending = false
	}

	return nil
}

// startSession starts a test session
func (s *Server) startSession(session *TestSession) error {
	// Only start if not already active
	if session.isActive.Load() {
		return nil
	}

	// Start UDP listener
	addr := &net.UDPAddr{Port: int(session.reflectorPort)}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", session.reflectorPort, err)
	}
	enableTTLReceive(conn)

	// Set DSCP from session (RFC 5357: "The same value of DSCP MUST be used in test packets")
	// Use session.dscp from Type-P Descriptor, fallback to server config
	dscp := session.dscp
	if dscp == 0 {
		dscp = s.config.DSCP
	}
	if dscp != 0 {
		if err := common.SetDSCP(conn, dscp); err != nil {
			logging.WithSession(s.logger, session.sid, session.mode, "").Warn(
				"failed to set DSCP on session socket",
				logging.FieldDSCP, dscp,
				logging.FieldError, err,
			)
		}
	}

	// Set TTL to 255 per RFC 5357 Section 4.2.1
	// The reflector SHOULD set the TTL in the reflected packet's IP header to 255
	if err := common.SetTTL(conn, 255); err != nil {
		logging.WithSession(s.logger, session.sid, session.mode, "").Warn(
			"failed to set TTL to 255 on session socket (RFC 5357)",
			logging.FieldError, err,
		)
	}

	// Enable TTL reception to extract sender's TTL from incoming packets
	if err := common.EnableTTLReception(conn); err != nil {
		logging.WithSession(s.logger, session.sid, session.mode, "").Warn(
			"failed to enable TTL reception on session socket",
			logging.FieldError, err,
		)
	}

	session.mu.Lock()
	session.conn = conn
	session.startTime = time.Now()
	// Create a new stop channel if needed
	if session.stopChan == nil {
		session.stopChan = make(chan struct{})
	}
	session.mu.Unlock()

	// Mark as active using atomic
	session.isActive.Store(true)

	// Record session start
	if s.metrics != nil {
		modeStr := common.ModeToString(session.mode)
		s.metrics.RecordSessionStart(modeStr, "server")
	}

	// Start receiving and reflecting packets
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if session.reflectorDone != nil {
			defer close(session.reflectorDone) // Signal when reflector exits
		}
		s.reflectPackets(session)
	}()

	return nil
}

// reflectPackets receives and reflects test packets for a session
func (s *Server) reflectPackets(session *TestSession) {
	defer func() {
		session.mu.Lock()
		conn := session.conn
		session.conn = nil
		session.mu.Unlock()

		if conn != nil {
			conn.Close()
		}
	}()

	// Get buffer from pool
	buf := common.PacketBufferPool.Get()
	defer func() {
		// Reset buffer to full capacity before returning to pool
		common.PacketBufferPool.Put(buf[:cap(buf)])
	}()
	oob := make([]byte, 128)

	for {
		// Check if session is active using atomic
		if !session.isActive.Load() {
			return
		}

		// Get connection and stopChan safely
		session.mu.Lock()
		conn := session.conn
		stopChan := session.stopChan
		session.mu.Unlock()

		if conn == nil {
			return
		}

		// Set read deadline to allow for context cancellation
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		// Use select with the local stopChan copy
		select {
		case <-stopChan:
			return
		default:
			// Receive test packet (with optional TTL/Hop Limit metadata)
			n, oobn, _, addr, err := conn.ReadMsgUDP(buf, oob)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// This is a read timeout, check if REFWAIT has expired
					if time.Since(session.startTime) > s.config.REFWAIT {
						// Session has been idle too long, stop it
						s.stopSession(session)
						return
					}
					// Not expired yet, continue waiting
					continue
				}
				// Other errors, just continue
				continue
			}

			// Store sender address if not already set
			if session.senderAddr == nil {
				session.senderAddr = addr
			}

			senderTTL := uint8(255)
			if ttl, ok := extractPacketTTL(oob[:oobn], addr); ok {
				senderTTL = ttl
			}

			// Process and reflect the packet
			// NOTE: Activity timer reset moved to AFTER successful HMAC verification
			// to prevent attackers from keeping sessions alive with invalid packets
			err = s.processAndReflect(session, buf[:n], addr, senderTTL)
			if err != nil {
				// Record error metric
				if s.metrics != nil {
					if errors.Is(err, common.ErrHMACVerificationFailed) {
						s.metrics.RecordError("hmac_failed", "server")
					} else {
						s.metrics.RecordError("packet_processing", "server")
					}
				}

				// Handle HMAC verification failures with threshold-based termination
				// per RFC 4656 Section 6 recommendation for authentication failure policy
				if errors.Is(err, common.ErrHMACVerificationFailed) {
					session.mu.Lock()
					now := time.Now()

					// Reset failure counter if outside the reset window
					windowReset := false
					if !session.lastHMACFailureTime.IsZero() &&
						now.Sub(session.lastHMACFailureTime) > HMACFailureResetWindow {
						session.hmacFailures = 0
						windowReset = true
					}

					session.hmacFailures++
					session.lastHMACFailureTime = now
					failures := session.hmacFailures
					maxFailures := session.maxHMACFailures
					session.mu.Unlock()

					// Record reset window event for observability
					if windowReset && s.metrics != nil {
						s.metrics.RecordError("hmac_failure_window_reset", "server")
					}

					// Log at ERROR level for security visibility
					logging.WithSession(s.logger, session.sid, session.mode, addr.String()).Error(
						"TWAMP security error - HMAC verification failed",
						logging.FieldError, err,
						"consecutive_failures", failures,
						"max_failures", maxFailures,
					)

					// Check if threshold exceeded (0 = disabled for backward compatibility)
					if maxFailures > 0 && failures >= maxFailures {
						logging.WithSession(s.logger, session.sid, session.mode, addr.String()).Error(
							"TWAMP session terminated - HMAC failure threshold exceeded (RFC 4656 Section 6)",
							"consecutive_failures", failures,
							"threshold", maxFailures,
						)
						if s.metrics != nil {
							s.metrics.RecordError("hmac_threshold_exceeded", "server")
						}
						s.stopSession(session)
						return
					}
				} else {
					// Normal processing error - could be malformed packet
					logging.WithSession(s.logger, session.sid, session.mode, addr.String()).Warn(
						"failed to process TWAMP packet",
						logging.FieldError, err,
					)
				}
				continue
			}

			// Successful packet - reset HMAC failure counter and activity timer
			// NOTE: Activity timer is reset HERE (after HMAC verification) to prevent
			// attackers from keeping sessions alive indefinitely with invalid packets
			session.mu.Lock()
			session.hmacFailures = 0
			session.startTime = time.Now()
			session.mu.Unlock()

			// Record packet received
			if s.metrics != nil {
				modeStr := common.ModeToString(session.mode)
				s.metrics.RecordPacketReceived(modeStr, "server")
			}

			// Increment reflected packet count
			session.reflectedPackets++
		}
	}
}

// processAndReflect processes a test packet and reflects it back
func (s *Server) processAndReflect(session *TestSession, packet []byte, addr net.Addr, senderTTL uint8) error {
	// Get receive timestamp immediately
	rxTime := common.Now()

	var senderSeqNo uint32
	var senderTimestamp common.TWAMPTimestamp
	var senderErrorEstimate common.ErrorEstimate

	// Check if we're in RFC 6038 modes
	reflectOctetsMode := session.mode&common.ModeReflectOctets != 0
	symmetricalSizeMode := session.mode&common.ModeSymmetricalSize != 0
	var reflectedPadding []byte
	senderPacketSize := len(packet)

	// Parse packet based on mode
	if session.mode&(common.ModeAuthenticated|common.ModeEncrypted) != 0 {
		// Authenticated or encrypted mode
		isEncryptedMode := session.mode&common.ModeEncrypted != 0

		// RFC 4656 Section 6: HMAC MUST be verified BEFORE using packet data
		// Order: Decrypt -> Verify HMAC -> Parse
		if session.sessionKeys != nil {
			// RFC 5357 Section 4.1.2: Decrypt based on mode
			// - Authenticated mode: first 16 bytes decrypted with AES-ECB
			// - Encrypted mode: first 32 bytes decrypted with AES-CBC
			decryptedPacket, err := crypto.DecryptTWAMPTestPacket(
				session.sessionKeys.TestAESKey,
				session.sessionKeys.ClientIV,
				packet,
				!isEncryptedMode, // isAuthenticated = true when NOT encrypted
			)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrDecryptFailed, err)
			}
			packet = decryptedPacket

			// RFC 5357 Section 4.2.1: HMAC coverage differs by mode
			// - Authenticated mode: HMAC covers first 16 bytes (1 block)
			// - Encrypted mode: For sender packets, cover header up to HMAC position (32 bytes)
			hmacCoverage := common.HMACCoverage(isEncryptedMode, false)

			// Verify HMAC BEFORE parsing (RFC 4656 requirement)
			valid, err := crypto.VerifyHMAC(
				session.sessionKeys.TestHMACKey,
				packet[:hmacCoverage],
				packet[common.SenderHMACOffset:common.SenderHMACOffset+16],
			)
			if err != nil {
				return fmt.Errorf("failed to verify HMAC: %w", err)
			}
			if !valid {
				return common.ErrHMACVerificationFailed
			}
		}

		// Now safe to parse the packet after HMAC verification
		if reflectOctetsMode {
			// Use RFC 6038 packet format that preserves padding
			var senderPacket messages.SenderTestPacketAuthReflectOctets
			err := senderPacket.Unmarshal(packet)
			if err != nil {
				return fmt.Errorf("%w (test packet reflect octets): %v", ErrUnmarshalFailed, err)
			}
			// Extract fields
			senderSeqNo = senderPacket.SeqNumber
			senderTimestamp = senderPacket.Timestamp
			senderErrorEstimate = senderPacket.ErrorEstimate
			reflectedPadding = senderPacket.PaddingData
		} else {
			// Standard authenticated packet
			var senderPacket messages.SenderTestPacketAuth
			err := senderPacket.Unmarshal(packet)
			if err != nil {
				return fmt.Errorf("%w (authenticated test packet): %v", ErrUnmarshalFailed, err)
			}
			// Extract fields
			senderSeqNo = senderPacket.SeqNumber
			senderTimestamp = senderPacket.Timestamp
			senderErrorEstimate = senderPacket.ErrorEstimate
		}
	} else {
		// Unauthenticated mode
		if reflectOctetsMode {
			// Use RFC 6038 packet format that preserves padding
			var senderPacket messages.SenderTestPacketReflectOctets
			err := senderPacket.Unmarshal(packet)
			if err != nil {
				return fmt.Errorf("%w (test packet reflect octets): %v", ErrUnmarshalFailed, err)
			}
			// Extract fields
			senderSeqNo = senderPacket.SeqNumber
			senderTimestamp = senderPacket.Timestamp
			senderErrorEstimate = senderPacket.ErrorEstimate
			reflectedPadding = senderPacket.PaddingData
		} else {
			// Standard unauthenticated packet
			var senderPacket messages.SenderTestPacket
			err := senderPacket.Unmarshal(packet)
			if err != nil {
				return fmt.Errorf("%w (unauthenticated test packet): %v", ErrUnmarshalFailed, err)
			}
			// Extract fields
			senderSeqNo = senderPacket.SeqNumber
			senderTimestamp = senderPacket.Timestamp
			senderErrorEstimate = senderPacket.ErrorEstimate
		}

		// TTL is extracted from IP header, not the packet itself
		// Per RFC 5357, the sender doesn't include TTL in the packet
		// The reflector should get it from the IP header (not implemented here)
	}

	// Create reflection packet
	var reflectPacket []byte
	var err error

	// Get transmit timestamp right before sending
	txTime := common.Now()

	// Create appropriate packet type based on mode
	reflectorSeqNo := session.reflectedPackets
	if session.mode&(common.ModeAuthenticated|common.ModeEncrypted) != 0 {
		// Authenticated or encrypted mode
		isEncryptedMode := session.mode&common.ModeEncrypted != 0

		if reflectOctetsMode {
			// RFC 6038: Use reflect-octets packet format
			padding := reflectedPadding
			if symmetricalSizeMode {
				baseSize := messages.ReflectorTestPacketAuthMinSize
				currentSize := baseSize + len(padding)
				if senderPacketSize > currentSize {
					extra := senderPacketSize - currentSize
					expanded := make([]byte, len(padding)+extra)
					copy(expanded, padding)
					padding = expanded
				}
			}

			reflectorPacket := &messages.ReflectorTestPacketAuthReflectOctets{
				SeqNumber:           reflectorSeqNo,
				Timestamp:           txTime,
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    rxTime,
				SenderSeqNumber:     senderSeqNo,
				SenderTimestamp:     senderTimestamp,
				SenderErrorEstimate: senderErrorEstimate,
				SenderTTL:           senderTTL,
				ReflectedPadding:    padding,
			}

			// Marshal the packet
			rawPacket, err := reflectorPacket.Marshal()
			if err != nil {
				return fmt.Errorf("failed to marshal reflector packet with reflect octets: %w", err)
			}

			// If in authenticated or encrypted mode, calculate HMAC and encrypt
			if session.sessionKeys != nil {
				// RFC 5357 Section 4.2.1: HMAC coverage differs by mode
				// - Authenticated mode: HMAC covers first 16 bytes (1 block)
				// - Encrypted mode: HMAC covers first 96 bytes (6 blocks)
				hmacCoverage := common.HMACCoverage(isEncryptedMode, true)

				hmac, err := crypto.CalculateHMAC(session.sessionKeys.TestHMACKey, rawPacket[:hmacCoverage])
				if err != nil {
					return fmt.Errorf("failed to calculate HMAC: %w", err)
				}

				// Copy HMAC into packet at correct offset (always 96 for reflector packets)
				copy(rawPacket[common.ReflectorHMACOffset:common.ReflectorHMACOffset+16], hmac)

				// RFC 5357 Section 4.1.2: Encryption is REQUIRED in both modes
				// - Authenticated mode: first 16 bytes encrypted with AES-ECB
				// - Encrypted mode: first 96 bytes encrypted with AES-CBC
				rawPacket, err = crypto.EncryptTWAMPReflectorTestPacket(
					session.sessionKeys.TestAESKey,
					session.sessionKeys.ServerIV,
					rawPacket,
					!isEncryptedMode, // isAuthenticated = true when NOT encrypted
				)
				if err != nil {
					return fmt.Errorf("failed to encrypt reflector packet: %w", err)
				}
			}
			reflectPacket = rawPacket
		} else {
			// Standard authenticated mode packet
			paddingSize := 0
			if symmetricalSizeMode {
				paddingSize = messages.CalculateSymmetricalPaddingAuth(senderPacketSize)
			}
			reflectorPacket := &messages.ReflectorTestPacketAuth{
				SeqNumber:           reflectorSeqNo,
				Timestamp:           txTime,
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    rxTime,
				SenderSeqNumber:     senderSeqNo,
				SenderTimestamp:     senderTimestamp,
				SenderErrorEstimate: senderErrorEstimate,
				SenderTTL:           senderTTL,
				PaddingSize:         paddingSize,
			}

			// Marshal the packet
			rawPacket, err := reflectorPacket.Marshal()
			if err != nil {
				return fmt.Errorf("failed to marshal reflector packet: %w", err)
			}

			// If in authenticated or encrypted mode, calculate HMAC and encrypt
			if session.sessionKeys != nil {
				// RFC 5357 Section 4.2.1: HMAC coverage differs by mode
				// - Authenticated mode: HMAC covers first 16 bytes (1 block)
				// - Encrypted mode: HMAC covers first 96 bytes (6 blocks)
				hmacCoverage := common.HMACCoverage(isEncryptedMode, true)

				hmac, err := crypto.CalculateHMAC(session.sessionKeys.TestHMACKey, rawPacket[:hmacCoverage])
				if err != nil {
					return fmt.Errorf("failed to calculate HMAC: %w", err)
				}

				// Copy HMAC into packet at correct offset (always 96 for reflector packets)
				copy(rawPacket[common.ReflectorHMACOffset:common.ReflectorHMACOffset+16], hmac)

				// RFC 5357 Section 4.1.2: Encryption is REQUIRED in both modes
				// - Authenticated mode: first 16 bytes encrypted with AES-ECB
				// - Encrypted mode: first 96 bytes encrypted with AES-CBC
				rawPacket, err = crypto.EncryptTWAMPReflectorTestPacket(
					session.sessionKeys.TestAESKey,
					session.sessionKeys.ServerIV,
					rawPacket,
					!isEncryptedMode, // isAuthenticated = true when NOT encrypted
				)
				if err != nil {
					return fmt.Errorf("failed to encrypt reflector packet: %w", err)
				}
			}
			reflectPacket = rawPacket
		}
	} else {
		// Unauthenticated mode
		if reflectOctetsMode {
			// RFC 6038: Use reflect-octets packet format
			padding := reflectedPadding
			if symmetricalSizeMode {
				baseSize := messages.ReflectorTestPacketMinSize
				currentSize := baseSize + len(padding)
				if senderPacketSize > currentSize {
					extra := senderPacketSize - currentSize
					expanded := make([]byte, len(padding)+extra)
					copy(expanded, padding)
					padding = expanded
				}
			}

			reflectorPacket := &messages.ReflectorTestPacketReflectOctets{
				SeqNumber:           reflectorSeqNo,
				Timestamp:           txTime,
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    rxTime,
				SenderSeqNumber:     senderSeqNo,
				SenderTimestamp:     senderTimestamp,
				SenderErrorEstimate: senderErrorEstimate,
				SenderTTL:           senderTTL,
				ReflectedPadding:    padding, // RFC 6038: Reflect the sender's padding
			}

			// Marshal the packet
			reflectPacket, err = reflectorPacket.Marshal()
			if err != nil {
				return fmt.Errorf("failed to marshal reflector packet with reflect octets: %w", err)
			}
		} else if symmetricalSizeMode {
			// RFC 6038: Symmetrical size mode - make reflector packet same size as sender
			paddingSize := messages.CalculateSymmetricalPadding(senderPacketSize)
			reflectorPacket := &messages.ReflectorTestPacket{
				SeqNumber:           reflectorSeqNo,
				Timestamp:           txTime,
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    rxTime,
				SenderSeqNumber:     senderSeqNo,
				SenderTimestamp:     senderTimestamp,
				SenderErrorEstimate: senderErrorEstimate,
				SenderTTL:           senderTTL,
				PaddingSize:         paddingSize, // RFC 6038: Calculated to match sender size
			}

			// Marshal the packet
			reflectPacket, err = reflectorPacket.Marshal()
			if err != nil {
				return fmt.Errorf("failed to marshal reflector packet with symmetrical size: %w", err)
			}
		} else {
			// Standard unauthenticated mode packet
			reflectorPacket := &messages.ReflectorTestPacket{
				SeqNumber:           reflectorSeqNo,
				Timestamp:           txTime,
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    rxTime,
				SenderSeqNumber:     senderSeqNo,
				SenderTimestamp:     senderTimestamp,
				SenderErrorEstimate: senderErrorEstimate,
				SenderTTL:           senderTTL,
				PaddingSize:         max(0, len(packet)-41), // Avoid negative padding
			}

			// Marshal the packet
			reflectPacket, err = reflectorPacket.Marshal()
			if err != nil {
				return fmt.Errorf("failed to marshal reflector packet: %w", err)
			}
		}
	}

	// TTL Setting Note:
	// Per RFC 5357 Section 4.2.1, the reflector SHOULD set the TTL in the
	// reflected packet's IP header to 255. This ensures maximum reach for
	// the reflected packet and helps with path MTU discovery.
	//
	// Setting the outgoing TTL requires platform-specific socket options:
	// - IPv4: IP_TTL socket option
	// - IPv6: IPV6_UNICAST_HOPS socket option
	//
	// Implementation options:
	// 1. Use golang.org/x/net/ipv4 or ipv6 packages:
	//    p := ipv4.NewPacketConn(session.conn)
	//    p.SetTTL(255)
	// 2. Use syscall.SetsockoptInt with the raw file descriptor
	// 3. Set TTL when creating the UDP connection initially
	//
	// The current implementation relies on the system default TTL, which
	// is typically 64 on Linux/Unix and 128 on Windows.

	// Send the reflection
	_, err = session.conn.WriteTo(reflectPacket, addr)
	if err != nil {
		return fmt.Errorf("failed to send reflector packet: %w", err)
	}

	// Record packet sent
	if s.metrics != nil {
		modeStr := common.ModeToString(session.mode)
		s.metrics.RecordPacketSent(modeStr, "server")
	}

	return nil
}

// handleStopSessions handles a Stop-Sessions command
// RFC 5357 Section 3.8
func (s *Server) handleStopSessions(cc *controlConnection, cmdData []byte) error {
	// Parse Stop-Sessions
	var stopSessions messages.StopSessions
	err := stopSessions.Unmarshal(cmdData, controlRequiresAuthentication(cc.controlMode))
	if err != nil {
		if s.metrics != nil {
			s.metrics.RecordControlMessage("stop_sessions", "server", "error", metrics.ErrorTypeParse)
		}
		return fmt.Errorf("%w (Stop-Sessions): %v", ErrUnmarshalFailed, err)
	}

	// RFC 5357 Section 3.8: Validate NumSessions matches active sessions
	// "Number of Sessions MUST contain the number of send sessions started
	// by the Control-Client that have not been previously terminated by a
	// Stop-Sessions command. If the Stop-Sessions message does not account
	// for exactly the number of sessions in progress, then it is to be
	// considered invalid, the TWAMP-Control connection SHOULD be closed,
	// and any results obtained considered invalid."
	activeSessions := uint32(len(cc.sessions))
	if stopSessions.NumSessions != activeSessions {
		if s.metrics != nil {
			s.metrics.RecordControlMessage("stop_sessions", "server", "error", metrics.ErrorTypeInvalidState)
		}
		peerAddr := "unknown"
		if cc.conn != nil {
			peerAddr = cc.conn.RemoteAddr().String()
		}
		s.logger.Warn("Stop-Sessions NumSessions mismatch",
			"received", stopSessions.NumSessions,
			"active", activeSessions,
			"peer", peerAddr,
		)
		// Per RFC: connection SHOULD be closed - return error to trigger close
		return fmt.Errorf("RFC 5357 violation: NumSessions=%d does not match active sessions=%d",
			stopSessions.NumSessions, activeSessions)
	}

	// Stop all sessions for this connection.
	// First, capture sessions to stop and clear the map immediately.
	//
	// NOTE: Per RFC 5357 Section 3.8, "the TWAMP-Control connection SHOULD be
	// closed" after Stop-Sessions, so subsequent commands are not expected.
	// We clear cc.sessions immediately for defensive session accounting in case
	// the connection remains open unexpectedly. Sessions continue reflecting
	// packets until time.AfterFunc fires (allowing in-flight packets to complete),
	// but are no longer associated with this control connection.
	sessionsToStop := make([]*TestSession, 0, len(cc.sessions))
	for _, session := range cc.sessions {
		sessionsToStop = append(sessionsToStop, session)
	}
	cc.sessions = make(map[common.SessionID]*TestSession)

	// Schedule actual cleanup after timeout to allow reflector to process
	// any packets still in flight per RFC 5357 Section 3.8
	for _, session := range sessionsToStop {
		sess := session // Capture for closure
		time.AfterFunc(sess.timeout, func() {
			s.stopSession(sess)
		})
	}

	// Record successful control message
	if s.metrics != nil {
		s.metrics.RecordControlMessage("stop_sessions", "server", "success", metrics.ErrorTypeNone)
	}

	// Return success (client may close connection after this)
	return nil
}

// handleStopNSessions handles a Stop-N-Sessions command (RFC 5938 Section 3.4)
func (s *Server) handleStopNSessions(cc *controlConnection, cmdData []byte) error {
	// Parse Stop-N-Sessions command
	var stopNSessions messages.StopNSessions
	err := stopNSessions.Unmarshal(cmdData, controlRequiresAuthentication(cc.controlMode))
	if err != nil {
		return fmt.Errorf("%w (Stop-N-Sessions): %v", ErrUnmarshalFailed, err)
	}

	// RFC 5938 Section 3.4: Stop-N-Sessions stops sessions by their SIDs.
	// Unlike Stop-Sessions (RFC 5357 Section 3.8), the connection remains open
	// for subsequent commands, so we must remove stopped sessions from cc.sessions
	// immediately to maintain accurate session accounting.
	if stopNSessions.NumSessions == 0 || len(stopNSessions.SessionIDs) == 0 {
		// Nothing to stop
		return nil
	}
	for _, sid := range stopNSessions.SessionIDs {
		session, exists := cc.sessions[sid]
		if !exists {
			// Session not found on this connection - skip (may have already been stopped)
			continue
		}

		// Remove from connection's session map immediately
		delete(cc.sessions, sid)

		// Schedule actual cleanup after timeout to allow reflector to process
		// any packets still in flight
		sess := session // Capture for closure
		time.AfterFunc(sess.timeout, func() {
			s.stopSession(sess)
		})
	}

	return nil
}

// handleRequestTWSessionIndividual handles a Request-TW-Session-Individual command (RFC 5938 Section 3.1)
func (s *Server) handleRequestTWSessionIndividual(cc *controlConnection, cmdData []byte) error {
	// Parse Request-TW-Session-Individual command
	var request messages.RequestTWSessionIndividual
	err := request.Unmarshal(cmdData, controlRequiresAuthentication(cc.controlMode))
	if err != nil {
		return fmt.Errorf("%w (Request-TW-Session-Individual): %v", ErrUnmarshalFailed, err)
	}

	// Validate request (similar to regular Request-TW-Session)
	if request.ConfSender != 0 || request.ConfReceiver != 0 {
		// TWAMP requires both to be 0
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}
	if !controlRequiresAuthentication(cc.controlMode) && !s.isUnauthReceiverAllowed(cc, &request.RequestTWSession) {
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}
	if request.PaddingLength > maxSenderPadding(cc.testMode) {
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}

	// Allocate a port for reflection
	reflectorPort, err := s.portManager.allocatePort()
	if err != nil {
		return s.sendAcceptSession(cc, common.AcceptTempResLimited, 0, common.SessionID{})
	}

	// RFC 5938 Section 3.1: Client specifies the SID for individual session control.
	// This is different from RFC 5357 Section 3.5 Request-TW-Session where SID MUST be zero.
	// Note: SID can be non-zero here - that's the whole point of individual control.
	sid := request.SID

	// Check if SID is already in use
	s.sessionsMu.RLock()
	if _, exists := s.sessions[sid]; exists {
		s.sessionsMu.RUnlock()
		s.portManager.releasePort(reflectorPort)
		// Session ID already in use
		return s.sendAcceptSession(cc, common.AcceptFailure, 0, common.SessionID{})
	}
	s.sessionsMu.RUnlock()

	// Extract DSCP value from Type-P Descriptor (bits 18-23)
	dscp := uint8((request.TypePDescriptor >> 18) & 0x3F)

	// Create test session
	// RFC 5618: Use testMode for test protocol (may differ from control mode in mixed security)
	session := &TestSession{
		sid:             sid,
		reflectorPort:   reflectorPort,
		senderPort:      request.SenderPort,
		mode:            cc.testMode, // RFC 5618: Use test mode, not negotiated mode
		timeout:         time.Duration(request.Timeout.Seconds) * time.Second,
		dscp:            dscp,
		stopChan:        make(chan struct{}),
		reflectorDone:   make(chan struct{}),
		maxHMACFailures: s.effectiveMaxHMACFailures(),
	}

	// Derive session keys for secure modes (only if test mode requires it)
	// RFC 5618: In mixed mode, test protocol may be unauthenticated even if control is encrypted
	if cc.testMode != common.ModeUnauthenticated && cc.keyDerivation != nil {
		testAESKey, testHMACKey, err := crypto.DeriveTestSessionKeys(
			cc.keyDerivation.AESKey,
			cc.keyDerivation.HMACKey,
			sid,
		)
		if err != nil {
			s.portManager.releasePort(reflectorPort)
			return fmt.Errorf("failed to derive test session keys: %w", err)
		}

		session.sessionKeys = &crypto.TWAMPKeys{
			TestAESKey:  testAESKey,
			TestHMACKey: testHMACKey,
			ClientIV:    cc.keyDerivation.ClientIV,
			ServerIV:    cc.keyDerivation.ServerIV,
		}
	}

	// Store session
	s.sessionsMu.Lock()
	s.sessions[sid] = session
	s.sessionsMu.Unlock()

	// Add to control connection's sessions
	cc.sessions[sid] = session

	// Send Accept-Session response
	return s.sendAcceptSession(cc, common.AcceptOK, reflectorPort, sid)
}

// stopSession stops a test session
func (s *Server) stopSession(session *TestSession) {
	// Fast check if already stopped using atomic
	if !session.isActive.CompareAndSwap(true, false) {
		return // Already inactive
	}

	// Get stopChan and conn reference safely
	session.mu.Lock()
	stopChan := session.stopChan
	session.stopChan = nil
	conn := session.conn
	session.mu.Unlock()

	// Safe to close outside the lock
	if stopChan != nil {
		close(stopChan)
	}

	// Close the UDP connection to unblock any pending reads
	if conn != nil {
		conn.Close()
	}

	// Remove from sessions map
	s.sessionsMu.Lock()
	delete(s.sessions, session.sid)
	s.sessionsMu.Unlock()

	// Release port
	s.portManager.releasePort(session.reflectorPort)

	// Record session end
	if s.metrics != nil {
		modeStr := common.ModeToString(session.mode)
		s.metrics.RecordSessionEnd(modeStr, "server")
	}

	// Update port usage
	if s.metrics != nil {
		s.metrics.SetPortUsage(s.portManager.usedPortCount())
	}
}

// WaitForConnectionCleanup returns a channel that will be closed when
// the specified connection's cleanup is complete. Returns immediately closed
// channel if connection not found.
func (s *Server) WaitForConnectionCleanup(conn net.Conn) <-chan struct{} {
	s.connectionsMu.RLock()
	cc, ok := s.connections[conn]
	s.connectionsMu.RUnlock()

	if !ok {
		// Connection not found or already cleaned up
		// Return a closed channel to indicate cleanup is done
		ch := make(chan struct{})
		close(ch)
		return ch
	}

	return cc.cleanupDone
}

// Addr returns the server's listening address
// Returns nil if the server is not started
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Stop stops the TWAMP server
func (s *Server) Stop() error {
	// Signal acceptConnections to stop
	close(s.stopChan)

	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Stop all sessions
	s.sessionsMu.Lock()
	// Copy sessions to avoid holding lock while stopping
	sessions := make([]*TestSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.sessionsMu.Unlock()

	// Now stop them without holding the lock
	for _, session := range sessions {
		s.stopSession(session)
	}

	// Close all connections
	s.connectionsMu.Lock()
	for conn := range s.connections {
		conn.Close()
	}
	s.connectionsMu.Unlock()

	// Wait for all goroutines to finish
	s.wg.Wait()

	return nil
}
