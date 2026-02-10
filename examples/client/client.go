// examples/client/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/ncode/twamp/client"
	"github.com/ncode/twamp/common"
)

func main() {
	// Get configuration from environment variables with sensible defaults
	serverAddr := os.Getenv("TWAMP_SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = "127.0.0.1:8620"
	}

	senderPortStr := os.Getenv("TWAMP_SENDER_PORT")
	senderPort := 10000
	if senderPortStr != "" {
		if parsedPort, err := strconv.Atoi(senderPortStr); err == nil && parsedPort > 0 && parsedPort <= 65535 {
			senderPort = parsedPort
		} else {
			log.Printf("Invalid TWAMP_SENDER_PORT value: %s, using default %d", senderPortStr, senderPort)
		}
	}

	receiverPortStr := os.Getenv("TWAMP_RECEIVER_PORT")
	receiverPort := 20000
	if receiverPortStr != "" {
		if parsedPort, err := strconv.Atoi(receiverPortStr); err == nil && parsedPort > 0 && parsedPort <= 65535 {
			receiverPort = parsedPort
		} else {
			log.Printf("Invalid TWAMP_RECEIVER_PORT value: %s, using default %d", receiverPortStr, receiverPort)
		}
	}

	// Get authentication configuration from environment
	sharedSecret := os.Getenv("TWAMP_SHARED_SECRET")
	if sharedSecret == "" {
		sharedSecret = "test-password"
	}

	keyID := os.Getenv("TWAMP_KEY_ID")
	if keyID == "" {
		keyID = "test-user"
	}

	// Determine mode from environment
	var preferredMode common.Mode = common.ModeUnauthenticated
	modeStr := os.Getenv("TWAMP_MODE")
	switch modeStr {
	case "authenticated":
		preferredMode = common.ModeAuthenticated
	case "encrypted":
		preferredMode = common.ModeEncrypted
	case "unauthenticated", "":
		preferredMode = common.ModeUnauthenticated
	default:
		log.Printf("Unknown TWAMP_MODE: %s, using unauthenticated", modeStr)
	}

	// Create a client
	cfg := client.ClientConfig{
		ServerAddress: serverAddr,
		PreferredMode: preferredMode,
		SharedSecret:  sharedSecret,
		KeyID:         keyID,
		Timeout:       5 * time.Second,
	}

	log.Printf("Connecting to TWAMP server at %s with mode %d", serverAddr, preferredMode)
	twampClient := client.NewClient(cfg)

	// Connect to TWAMP server
	ctx := context.Background()
	err := twampClient.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer twampClient.Close()

	// Request a test session
	sessionCfg := client.TestSessionConfig{
		SenderPort:   uint16(senderPort),
		ReceiverPort: uint16(receiverPort),
		// PaddingLength: 27, // minimum unauthenticated padding
		// PaddingLength: 56, // minimum authenticated/encrypted padding
		Timeout: 2 * time.Second,
	}

	log.Printf("Requesting test session with sender port %d, receiver port %d", senderPort, receiverPort)
	session, err := twampClient.RequestSession(sessionCfg)
	if err != nil {
		log.Fatalf("Failed to request session: %v", err)
	}

	// Start sessions
	err = twampClient.StartSessions()
	if err != nil {
		log.Fatalf("Failed to start sessions: %v", err)
	}

	// Start receiving responses
	session.StartReceiving(ctx)

	// Get packet count from environment
	packetCountStr := os.Getenv("TWAMP_PACKET_COUNT")
	packetCount := 10
	if packetCountStr != "" {
		if parsed, err := strconv.Atoi(packetCountStr); err == nil && parsed > 0 {
			packetCount = parsed
		} else {
			log.Printf("Invalid TWAMP_PACKET_COUNT: %s, using default %d", packetCountStr, packetCount)
		}
	}

	// Send test packets at 1-second intervals
	log.Printf("Sending %d test packets...", packetCount)
	for i := 0; i < packetCount; i++ {
		err = session.SendTestPacket()
		if err != nil {
			log.Printf("Failed to send test packet: %v", err)
		}
		time.Sleep(1 * time.Second)
	}

	// Get results
	results := session.GetResults()
	fmt.Printf("Test Results:\n")
	fmt.Printf("  Packets Sent: %d\n", results.PacketsSent)
	fmt.Printf("  Packets Received: %d\n", results.PacketsReceived)
	fmt.Printf("  Packets Lost: %d\n", results.PacketsLost)
	fmt.Printf("  Min RTT: %v\n", results.MinRTT)
	fmt.Printf("  Max RTT: %v\n", results.MaxRTT)
	fmt.Printf("  Avg RTT: %v\n", results.AvgRTT)
	fmt.Printf("  RTT variation: %d\n", results.RTTVariation)
	fmt.Printf("  Avg Forward Delay: %v\n", results.AvgForwardDelay)
	fmt.Printf("  Avg Reverse Delay: %v\n", results.AvgReverseDelay)
	fmt.Printf("  Delay Asymmetry: %f\n", results.DelayAsymmetry)

	// Stop sessions and cleanup
	err = twampClient.StopSessions()
	if err != nil {
		log.Printf("Failed to stop sessions: %v", err)
	}
}
