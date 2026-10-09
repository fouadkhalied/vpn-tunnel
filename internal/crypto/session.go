// Package crypto holds the transport-data encryption and replay protection.
//
// Course: Chapter 2, lesson "AEAD Encryption (ChaCha20-Poly1305)".
// When you start it: go get golang.org/x/crypto
package crypto

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// Key is a 32-byte symmetric key.
type Key [32]byte

// Session holds the keys derived from one completed handshake.
type Session struct {
	SendKey     Key
	RecvKey     Key
	sendCounter uint64 // used as the AEAD nonce; must NEVER repeat for a key
	replay      ReplayWindow
}

// Seal encrypts one inner IP packet.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	// Prevent counter overflow and nonce reuse.
	if s.sendCounter == ^uint64(0) {
		return nil, ErrRekeyRequired
	}

	aead, err := chacha20poly1305.New(s.SendKey[:])
	if err != nil {
		return nil, err
	}

	nonce := makeNonce(s.sendCounter)

	// Output: [8-byte counter][ciphertext + 16-byte authentication tag].
	out := make([]byte, 8, 8+len(plaintext)+aead.Overhead())

	binary.LittleEndian.PutUint64(out[:8], s.sendCounter)

	out = aead.Seal(out, nonce[:], plaintext, nil)

	s.sendCounter++

	return out, nil
}

// Open authenticates and decrypts a packet.
func (s *Session) Open(packet []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(s.RecvKey[:])
	if err != nil {
		return nil, err
	}

	// 8 bytes counter + 16 bytes authentication tag minimum.
	if len(packet) < 8+aead.Overhead() {
		return nil, ErrInvalidPacket
	}

	// Extract the counter from the packet header.
	counter := binary.LittleEndian.Uint64(packet[:8])

	// Check counter
	if !s.replay.Check(counter) {
		return nil, ErrReplay
	}

	// Reconstruct the nonce used by the sender.
	nonce := makeNonce(counter)

	// Ciphertext starts immediately after the 8-byte counter.
	ciphertext := packet[8:]

	// Authenticate and decrypt BEFORE updating the replay window.
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}

	s.replay.Update(counter)

	return plaintext, nil
}

func makeNonce(counter uint64) [12]byte {
	var n [12]byte                                // 12 zero bytes
	binary.LittleEndian.PutUint64(n[4:], counter) // fill bytes 4..11
	return n
}
