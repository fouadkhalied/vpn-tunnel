package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// newPair returns a sender and a receiver that share one key.
func newPair() (sender, receiver *Session) {
	key := Key{1, 2, 3, 4, 5, 6, 7, 8}
	return &Session{SendKey: key}, &Session{RecvKey: key}
}

func mustSeal(t *testing.T, s *Session, plaintext string) []byte {
	t.Helper()
	p, err := s.Seal([]byte(plaintext))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return p
}

func TestRoundTrip(t *testing.T) {
	sender, receiver := newPair()
	want := []byte("inner ip packet")

	packet := mustSeal(t, sender, string(want))
	if len(packet) != 8+len(want)+16 {
		t.Errorf("packet length = %d, want %d", len(packet), 8+len(want)+16)
	}

	got, err := receiver.Open(packet)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCounterAdvancesEverySeal(t *testing.T) {
	sender, _ := newPair()
	p0 := mustSeal(t, sender, "same")
	p1 := mustSeal(t, sender, "same")

	if binary.LittleEndian.Uint64(p0[:8]) != 0 || binary.LittleEndian.Uint64(p1[:8]) != 1 {
		t.Error("counters should be 0 then 1")
	}
	if bytes.Equal(p0, p1) {
		t.Error("same plaintext must give different packets")
	}
}

func TestReplayRejected(t *testing.T) {
	sender, receiver := newPair()
	packet := mustSeal(t, sender, "hello")

	if _, err := receiver.Open(packet); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := receiver.Open(packet); !errors.Is(err, ErrReplay) {
		t.Errorf("second Open error = %v, want ErrReplay", err)
	}
}

func TestOutOfOrderAccepted(t *testing.T) {
	sender, receiver := newPair()
	p0 := mustSeal(t, sender, "zero")
	p1 := mustSeal(t, sender, "one")
	p2 := mustSeal(t, sender, "two")

	for _, p := range [][]byte{p2, p0, p1} { // arrives as 2, 0, 1
		if _, err := receiver.Open(p); err != nil {
			t.Errorf("out-of-order packet rejected: %v", err)
		}
	}
}

func TestTooOldRejected(t *testing.T) {
	sender, receiver := newPair()
	old := mustSeal(t, sender, "old") // counter 0

	sender.sendCounter = 5000 // jump far ahead, past the window
	newer := mustSeal(t, sender, "new")

	if _, err := receiver.Open(newer); err != nil {
		t.Fatalf("Open newer: %v", err)
	}
	if _, err := receiver.Open(old); !errors.Is(err, ErrReplay) {
		t.Errorf("old packet error = %v, want ErrReplay", err)
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	sender, receiver := newPair()
	packet := mustSeal(t, sender, "hello")

	bad := append([]byte(nil), packet...)
	bad[10] ^= 1 // flip one bit of the ciphertext
	if _, err := receiver.Open(bad); err == nil {
		t.Error("tampered ciphertext was accepted")
	}

	bad = append([]byte(nil), packet...)
	bad[0] ^= 1 // change the counter: different nonce
	if _, err := receiver.Open(bad); err == nil {
		t.Error("packet with changed counter was accepted")
	}
}

// A failed packet must not use up its counter: the real packet must still work.
func TestFailedPacketDoesNotConsumeCounter(t *testing.T) {
	sender, receiver := newPair()
	packet := mustSeal(t, sender, "hello")

	bad := append([]byte(nil), packet...)
	bad[10] ^= 1
	if _, err := receiver.Open(bad); err == nil {
		t.Fatal("tampered packet was accepted")
	}
	if _, err := receiver.Open(packet); err != nil {
		t.Errorf("real packet rejected after a failed attempt: %v", err)
	}
}

// A forged packet with a huge counter must not move the window forward.
func TestForgedHugeCounterDoesNotMoveWindow(t *testing.T) {
	sender, receiver := newPair()
	packet := mustSeal(t, sender, "hello") // counter 0

	forged := append([]byte(nil), packet...)
	binary.LittleEndian.PutUint64(forged[:8], 1<<40)
	if _, err := receiver.Open(forged); err == nil {
		t.Fatal("forged packet was accepted")
	}

	if _, err := receiver.Open(packet); err != nil {
		t.Errorf("real packet rejected after a forged one: %v", err)
	}
}

func TestShortPacketRejected(t *testing.T) {
	_, receiver := newPair()
	for _, n := range []int{0, 1, 8, 23} { // minimum valid length is 24
		if _, err := receiver.Open(make([]byte, n)); !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("len %d: error = %v, want ErrInvalidPacket", n, err)
		}
	}
}

func TestWrongKeyRejected(t *testing.T) {
	sender, _ := newPair()
	packet := mustSeal(t, sender, "hello")

	other := &Session{RecvKey: Key{9, 9, 9}}
	if _, err := other.Open(packet); err == nil {
		t.Error("packet opened with the wrong key")
	}
}

func TestRekeyRequiredAtMaxCounter(t *testing.T) {
	sender, _ := newPair()
	sender.sendCounter = ^uint64(0)
	if _, err := sender.Seal([]byte("x")); !errors.Is(err, ErrRekeyRequired) {
		t.Errorf("error = %v, want ErrRekeyRequired", err)
	}
}

func TestMakeNonce(t *testing.T) {
	n := makeNonce(1)
	want := [12]byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	if n != want {
		t.Errorf("makeNonce(1) = %x, want %x", n, want)
	}
	if makeNonce(0) != [12]byte{} {
		t.Error("makeNonce(0) should be all zeros")
	}
}
