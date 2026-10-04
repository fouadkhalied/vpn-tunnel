// Package crypto holds the transport-data encryption and replay protection.
//
// Course: Chapter 2, lesson "AEAD Encryption (ChaCha20-Poly1305)".
// When you start it: go get golang.org/x/crypto
package crypto

import "errors"

var ErrNotImplemented = errors.New("not implemented")
var ErrReplay = errors.New("replayed or too-old packet")

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
//
// TODO: chacha20poly1305.New(key[:]) from golang.org/x/crypto/chacha20poly1305.
// Nonce = 4 zero bytes + 8-byte little-endian counter. Output layout is your
// design: e.g. [8-byte counter][ciphertext+tag]. Increment sendCounter; if it
// nears 2^64 the session must be rekeyed.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	_ = plaintext
	return nil, ErrNotImplemented
}

// Open authenticates and decrypts a packet.
//
// TODO: read the counter, Open() the AEAD, and ONLY THEN check/update the
// replay window (never update state for packets that failed authentication).
func (s *Session) Open(packet []byte) ([]byte, error) {
	_ = packet
	return nil, ErrNotImplemented
}
