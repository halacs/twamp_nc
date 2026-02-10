// examples/server/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ncode/twamp/common"
	"github.com/ncode/twamp/server"
)

func main() {
	// Get listen address from environment with sensible default
	listenAddr := os.Getenv("TWAMP_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8620"
	}

	// Parse supported modes from environment
	var supportedModes common.Mode = common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted
	modesStr := os.Getenv("TWAMP_SUPPORTED_MODES")
	if modesStr != "" {
		modes := strings.Split(modesStr, ",")
		supportedModes = 0
		for _, mode := range modes {
			switch strings.TrimSpace(strings.ToLower(mode)) {
			case "unauthenticated":
				supportedModes |= common.ModeUnauthenticated
			case "authenticated":
				supportedModes |= common.ModeAuthenticated
			case "encrypted":
				supportedModes |= common.ModeEncrypted
			default:
				log.Printf("Unknown mode in TWAMP_SUPPORTED_MODES: %s", mode)
			}
		}
		if supportedModes == 0 {
			log.Printf("No valid modes specified, using all modes")
			supportedModes = common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted
		}
	}

	// Build secret map from environment
	// Format: TWAMP_SECRETS="user1:password1,user2:password2"
	secretMap := make(map[string]string)
	secretsStr := os.Getenv("TWAMP_SECRETS")
	if secretsStr != "" {
		pairs := strings.Split(secretsStr, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				user := strings.TrimSpace(parts[0])
				password := strings.TrimSpace(parts[1])
				if user != "" && password != "" {
					secretMap[user] = password
				}
			}
		}
	}

	// If no secrets provided and authenticated modes are enabled, add default for testing
	if len(secretMap) == 0 && (supportedModes&(common.ModeAuthenticated|common.ModeEncrypted)) != 0 {
		secretMap["test-user"] = "test-password"
		log.Printf("No TWAMP_SECRETS provided, using default test credentials")
	}

	// Create a server
	cfg := server.ServerConfig{
		ListenAddress:  listenAddr,
		SupportedModes: supportedModes,
		SecretMap:      secretMap,
	}

	// Log configuration
	log.Printf("Starting TWAMP server on %s", listenAddr)
	log.Printf("Supported modes: %s", describeModes(supportedModes))
	if len(secretMap) > 0 {
		users := make([]string, 0, len(secretMap))
		for user := range secretMap {
			users = append(users, user)
		}
		log.Printf("Configured users: %v", users)
	}

	twampServer, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start the server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = twampServer.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("TWAMP server is now listening on %s", listenAddr)
	log.Println("Environment variables:")
	log.Println("  TWAMP_LISTEN_ADDR - Server listen address (default: 127.0.0.1:8620)")
	log.Println("  TWAMP_SUPPORTED_MODES - Comma-separated list: unauthenticated,authenticated,encrypted")
	log.Println("  TWAMP_SECRETS - User credentials as user1:password1,user2:password2")

	// Wait for signal to shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")
	twampServer.Stop()
}

func describeModes(modes common.Mode) string {
	var modeList []string
	if modes&common.ModeUnauthenticated != 0 {
		modeList = append(modeList, "unauthenticated")
	}
	if modes&common.ModeAuthenticated != 0 {
		modeList = append(modeList, "authenticated")
	}
	if modes&common.ModeEncrypted != 0 {
		modeList = append(modeList, "encrypted")
	}
	if len(modeList) == 0 {
		return "none"
	}
	return fmt.Sprintf("[%s]", strings.Join(modeList, ", "))
}
