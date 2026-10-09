package noise

import "crypto/sha256"

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

// InitialChainKey creates the starting value for our handshake.
func InitialChainKey() [32]byte {
	return sha256.Sum256([]byte("My VPN Protocol"))
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
