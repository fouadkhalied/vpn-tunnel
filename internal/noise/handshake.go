// Package noise implements the handshake that produces session keys.
//
// Course: Chapter 2, lessons "Noise Protocol Framework" .. key schedule.
// Primitives to bring in later: X25519 (golang.org/x/crypto/curve25519),
// BLAKE2s (golang.org/x/crypto/blake2s), HKDF built on BLAKE2s HMAC.
// WireGuard uses the Noise IKpsk2 pattern; follow the course's variant.
package noise

import "errors"

var ErrNotImplemented = errors.New("not implemented")

// KeyPair is a long-term or ephemeral X25519 key pair.
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKeyPair makes a fresh X25519 key pair.
//
// TODO: random 32 bytes from crypto/rand, then curve25519.X25519(priv, Basepoint).
// Remember to clamp the private key.
func GenerateKeyPair() (KeyPair, error) { return KeyPair{}, ErrNotImplemented }

// Handshake is the state for one handshake attempt with one peer.
type Handshake struct {
	static     KeyPair
	peerStatic [32]byte
	ephemeral  KeyPair
	chainKey   [32]byte // evolves with every DH via the KDF
	hash       [32]byte // transcript hash (binds all messages)
}

func NewInitiator(static KeyPair, peerStatic [32]byte) *Handshake {
	return &Handshake{static: static, peerStatic: peerStatic}
}

func NewResponder(static KeyPair) *Handshake {
	return &Handshake{static: static}
}

// TODO for each: mix DH results into chainKey, update the transcript hash,
// encrypt the payload with an AEAD keyed from the chain.
func (h *Handshake) CreateInitiation() ([]byte, error)  { return nil, ErrNotImplemented }
func (h *Handshake) ConsumeInitiation(msg []byte) error { return ErrNotImplemented }
func (h *Handshake) CreateResponse() ([]byte, error)    { return nil, ErrNotImplemented }
func (h *Handshake) ConsumeResponse(msg []byte) error   { return ErrNotImplemented }

// DeriveSession splits the final chain key into the two transport keys.
// Initiator's send key is the responder's receive key and vice versa.
// Forward secrecy: the ephemeral private keys must be wiped afterwards.
func (h *Handshake) DeriveSession() (send, recv [32]byte, err error) {
	return send, recv, ErrNotImplemented
}
