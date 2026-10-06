package noise

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func mustKeyPair(t *testing.T) KeyPair {
	t.Helper()
	kp, err := GenerateRandomKeyPair()
	if err != nil {
		t.Fatalf("GenerateRandomKeyPair: %v", err)
	}
	return kp
}

func TestKeyPairsAreFresh(t *testing.T) {
	a, b := mustKeyPair(t), mustKeyPair(t)
	if a.Private == b.Private {
		t.Error("two calls returned the same private key")
	}
	if a.Public == b.Public {
		t.Error("two calls returned the same public key")
	}
}

func TestPrivateKeyIsClamped(t *testing.T) {
	for i := 0; i < 200; i++ { // random input, so check many keys
		kp := mustKeyPair(t)
		if kp.Private[0]&0x07 != 0 {
			t.Fatalf("lowest 3 bits of byte 0 must be clear: %08b", kp.Private[0])
		}
		if kp.Private[31]&0x80 != 0 {
			t.Fatalf("top bit of byte 31 must be clear: %08b", kp.Private[31])
		}
		if kp.Private[31]&0x40 == 0 {
			t.Fatalf("second-highest bit of byte 31 must be set: %08b", kp.Private[31])
		}
	}
}

func TestPublicMatchesPrivate(t *testing.T) {
	kp := mustKeyPair(t)
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, kp.Public[:]) {
		t.Error("Public is not X25519(Private, Basepoint)")
	}
}

func TestBothSidesDeriveSameSecret(t *testing.T) {
	alice, bob, eve := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)

	s1, err := curve25519.X25519(alice.Private[:], bob.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	s2, err := curve25519.X25519(bob.Private[:], alice.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("alice and bob derived different secrets")
	}

	var zero [32]byte
	if bytes.Equal(s1, zero[:]) {
		t.Error("shared secret is all zeros")
	}

	// a third party with only public keys + her own private key gets something else
	s3, err := curve25519.X25519(eve.Private[:], alice.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, s3) {
		t.Error("an unrelated key pair derived the same secret")
	}
}

// Sanity check of the dependency itself, using RFC 7748 section 6.1 vectors.
// (If you later split out a deterministic keyPairFromPrivate, test it with these too.)
func TestRFC7748Vectors(t *testing.T) {
	dec := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	alicePriv := dec("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := dec("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := dec("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := dec("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	shared := dec("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	if got, _ := curve25519.X25519(alicePriv, curve25519.Basepoint); !bytes.Equal(got, alicePub) {
		t.Error("alice public mismatch")
	}
	if got, _ := curve25519.X25519(bobPriv, curve25519.Basepoint); !bytes.Equal(got, bobPub) {
		t.Error("bob public mismatch")
	}
	if got, _ := curve25519.X25519(alicePriv, bobPub); !bytes.Equal(got, shared) {
		t.Error("shared secret mismatch (alice side)")
	}
	if got, _ := curve25519.X25519(bobPriv, alicePub); !bytes.Equal(got, shared) {
		t.Error("shared secret mismatch (bob side)")
	}
}
