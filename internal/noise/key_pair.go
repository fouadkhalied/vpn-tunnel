package noise

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

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
