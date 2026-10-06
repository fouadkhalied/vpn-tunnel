package noise

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
)

var ErrNotImplemented = errors.New("not implemented")

// KeyPair is a long-term or ephemeral X25519 key pair.
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateRandomKeyPair generates a random X25519 key pair.
func GenerateRandomKeyPair() (KeyPair, error) {
	var privateKey [32]byte

	_, err := rand.Read(privateKey[:])
	if err != nil {
		return KeyPair{}, err
	}

	// Clamp the private scalar for Curve25519/X25519.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(
		privateKey[:],
		curve25519.Basepoint,
	)
	if err != nil {
		return KeyPair{}, err
	}

	var public [32]byte
	copy(public[:], publicKey)

	return KeyPair{
		Private: privateKey,
		Public:  public,
	}, nil
}

// Handshake is the state for one handshake attempt with one peer.
type Handshake struct {
	static     KeyPair
	peerStatic [32]byte
	ephemeral  KeyPair
	chainKey   [32]byte // Evolves with every DH via the KDF.
	hash       [32]byte // Transcript hash binds all messages.
}

// NewInitiator creates a new handshake from the initiator's
func NewInitiator(static KeyPair, peerStatic [32]byte) *Handshake {
	return &Handshake{
		static:     static,
		peerStatic: peerStatic,
	}
}

// NewResponder creates a new handshake from the responder's
func NewResponder(static KeyPair) *Handshake {
	return &Handshake{
		static: static,
	}
}

func (h *Handshake) CreateInitiation() ([]byte, error) {
	return nil, ErrNotImplemented
}

func (h *Handshake) ConsumeInitiation(msg []byte) error {
	return ErrNotImplemented
}

func (h *Handshake) CreateResponse() ([]byte, error) {
	return nil, ErrNotImplemented
}

func (h *Handshake) ConsumeResponse(msg []byte) error {
	return ErrNotImplemented
}

// DeriveSession splits the final chain key into the two transport keys.
//
// The initiator's send key is the responder's receive key,
// and the initiator's receive key is the responder's send key.
//
// Forward secrecy: ephemeral private keys must be wiped afterwards.
func (h *Handshake) DeriveSession() (send, recv [32]byte, err error) {
	return send, recv, ErrNotImplemented
}
