package server

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/ncode/twamp/crypto"
)

func sendControlMessageEncrypted(t *testing.T, conn net.Conn, encrypt *crypto.CBCStream, hmacKey []byte, message []byte) {
	t.Helper()
	if len(message) < 16 {
		t.Fatalf("control message too short: %d", len(message))
	}

	messageLen := len(message) - 16
	hmac, err := crypto.CalculateHMAC(hmacKey, message[:messageLen])
	if err != nil {
		t.Fatalf("CalculateHMAC failed: %v", err)
	}
	copy(message[messageLen:], hmac)

	encrypted, err := encrypt.Encrypt(message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := conn.Write(encrypted); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
}

func readControlMessageEncrypted(t *testing.T, conn net.Conn, decrypt *crypto.CBCStream, hmacKey []byte, size int, prefix []byte) []byte {
	t.Helper()
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	plaintext, err := decrypt.Decrypt(buf)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	messageLen := len(plaintext) - 16
	if messageLen < 0 {
		t.Fatalf("invalid control message length: %d", len(plaintext))
	}

	if prefix != nil {
		expected, err := crypto.CalculateHMACWithPrefix(hmacKey, prefix, plaintext[:messageLen])
		if err != nil {
			t.Fatalf("CalculateHMACWithPrefix failed: %v", err)
		}
		if !bytes.Equal(expected, plaintext[messageLen:]) {
			t.Fatalf("HMAC verification failed with prefix")
		}
	} else {
		ok, err := crypto.VerifyHMAC(hmacKey, plaintext[:messageLen], plaintext[messageLen:])
		if err != nil {
			t.Fatalf("VerifyHMAC failed: %v", err)
		}
		if !ok {
			t.Fatalf("HMAC verification failed")
		}
	}

	return plaintext
}
