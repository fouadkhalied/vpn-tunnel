package peer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"vpntunnel/internal/crypto"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// newPair returns a "remote" session (the other machine) and a peer whose session
// shares its key, so packets sealed by the remote can be received by the peer
// and the other way round.
func newPair() (remote *crypto.Session, p *Peer) {
	key := crypto.Key{1, 2, 3, 4}
	p = New("laptop", [32]byte{}, nil, netip.AddrPort{})
	p.SetSession(&crypto.Session{SendKey: key, RecvKey: key})
	remote = &crypto.Session{SendKey: key, RecvKey: key}
	return remote, p
}

func seal(t *testing.T, s *crypto.Session, msg string) []byte {
	t.Helper()
	b, err := s.Seal([]byte(msg))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return b
}

func counterOf(packet []byte) uint64 { return binary.LittleEndian.Uint64(packet[:8]) }

// ---- New and accessors ----

func TestNewStoresFields(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	pub := [32]byte{9}
	p := New("alice", pub, allowed, ap("1.2.3.4:51820"))
	if p.Name != "alice" || p.PublicKey != pub {
		t.Errorf("name/key not stored: %q %v", p.Name, p.PublicKey)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != allowed[0] {
		t.Errorf("AllowedIPs = %v", p.AllowedIPs)
	}
	if p.Endpoint() != ap("1.2.3.4:51820") {
		t.Errorf("Endpoint = %v", p.Endpoint())
	}
}

func TestEndpointUnknownAtStart(t *testing.T) {
	p := New("x", [32]byte{}, nil, netip.AddrPort{})
	if p.Endpoint().IsValid() {
		t.Errorf("endpoint should be unknown, got %v", p.Endpoint())
	}
}

func TestSessionStartsNilAndCanBeSet(t *testing.T) {
	p := New("x", [32]byte{}, nil, netip.AddrPort{})
	if p.Session() != nil {
		t.Fatal("new peer should have no session")
	}
	s := &crypto.Session{}
	p.SetSession(s)
	if p.Session() != s {
		t.Error("SetSession did not store the session")
	}
}

// ---- Receive ----

func TestReceiveWithoutSession(t *testing.T) {
	p := New("x", [32]byte{}, nil, netip.AddrPort{})
	if _, err := p.Receive(make([]byte, 40), ap("1.2.3.4:1")); !errors.Is(err, ErrNoSession) {
		t.Errorf("error = %v, want ErrNoSession", err)
	}
}

func TestReceiveReturnsPlaintext(t *testing.T) {
	remote, p := newPair()
	got, err := p.Receive(seal(t, remote, "hello"), ap("1.2.3.4:1000"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("plaintext = %q, want hello", got)
	}
}

// Follows the five-row table from the lesson, with real encryption.
func TestRoamingLifecycle(t *testing.T) {
	remote, p := newPair()
	A, B, stranger := ap("1.2.3.4:1000"), ap("5.6.7.8:2000"), ap("9.9.9.9:9")

	p0 := seal(t, remote, "zero")
	p1 := seal(t, remote, "one")
	p2 := seal(t, remote, "two")
	p3 := seal(t, remote, "three")

	// 1. first contact: learned
	if _, err := p.Receive(p0, A); err != nil || p.Endpoint() != A {
		t.Fatalf("first contact: err=%v endpoint=%v", err, p.Endpoint())
	}
	// 2. same address: nothing changes
	if _, err := p.Receive(p1, A); err != nil || p.Endpoint() != A {
		t.Fatalf("same address: err=%v endpoint=%v", err, p.Endpoint())
	}
	// 3. new address, new counter: roamed
	if _, err := p.Receive(p2, B); err != nil || p.Endpoint() != B {
		t.Fatalf("roam: err=%v endpoint=%v", err, p.Endpoint())
	}
	// 4. old packet replayed from the old address: dropped, endpoint stays
	if _, err := p.Receive(p1, A); !errors.Is(err, crypto.ErrReplay) {
		t.Fatalf("replay: error = %v, want ErrReplay", err)
	}
	if p.Endpoint() != B {
		t.Fatalf("replay moved the endpoint back to %v", p.Endpoint())
	}
	// 5. forged packet from a stranger: dropped, endpoint stays
	forged := append([]byte(nil), p3...)
	forged[10] ^= 1
	if _, err := p.Receive(forged, stranger); err == nil {
		t.Fatal("forged packet was accepted")
	}
	if p.Endpoint() != B {
		t.Fatalf("forged packet moved the endpoint to %v", p.Endpoint())
	}
	// ...and the forged packet did not use up counter 3
	if _, err := p.Receive(p3, B); err != nil {
		t.Errorf("real packet rejected after a forged one: %v", err)
	}
}

func TestFailedReceiveKeepsConfiguredEndpoint(t *testing.T) {
	remote, p := newPair()
	configured := ap("1.1.1.1:51820")
	p.UpdateEndpoint(configured)

	bad := seal(t, remote, "x")
	bad[9] ^= 1
	if _, err := p.Receive(bad, ap("2.2.2.2:2")); err == nil {
		t.Fatal("tampered packet accepted")
	}
	if p.Endpoint() != configured {
		t.Errorf("endpoint changed to %v on a failed packet", p.Endpoint())
	}
}

func TestEndpointIsNotGatedByInnerAddresses(t *testing.T) {
	// The outer (public) address has nothing to do with AllowedIPs, which are tunnel addresses.
	remote, p := newPair()
	p.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	public := ap("203.0.113.5:40000")
	if _, err := p.Receive(seal(t, remote, "x"), public); err != nil {
		t.Fatal(err)
	}
	if p.Endpoint() != public {
		t.Errorf("endpoint = %v, want %v", p.Endpoint(), public)
	}
}

func TestPeersAreIndependent(t *testing.T) {
	remote1, p1 := newPair()
	_, p2 := newPair()
	if _, err := p1.Receive(seal(t, remote1, "x"), ap("1.1.1.1:1")); err != nil {
		t.Fatal(err)
	}
	if p2.Endpoint().IsValid() {
		t.Errorf("peer 2's endpoint changed: %v", p2.Endpoint())
	}
}

// ---- Send ----

func TestSendWithoutSession(t *testing.T) {
	p := New("x", [32]byte{}, nil, ap("1.2.3.4:1"))
	if _, _, err := p.Send([]byte("hi")); !errors.Is(err, ErrNoSession) {
		t.Errorf("error = %v, want ErrNoSession", err)
	}
}

func TestSendWithoutEndpoint(t *testing.T) {
	_, p := newPair() // session set, endpoint unknown
	if _, _, err := p.Send([]byte("hi")); !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("error = %v, want ErrNoEndpoint", err)
	}
}

func TestSendReturnsPacketForTheEndpoint(t *testing.T) {
	remote, p := newPair()
	ep := ap("203.0.113.5:40000")
	p.UpdateEndpoint(ep)

	packet, to, err := p.Send([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if to != ep {
		t.Errorf("destination = %v, want %v", to, ep)
	}
	got, err := remote.Open(packet)
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Errorf("remote could not open the packet: %q %v", got, err)
	}
}

func TestFailedSendDoesNotUseUpACounter(t *testing.T) {
	_, p := newPair()
	if _, _, err := p.Send([]byte("a")); !errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("setup: error = %v", err)
	}
	p.UpdateEndpoint(ap("1.2.3.4:1"))
	packet, _, err := p.Send([]byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	if c := counterOf(packet); c != 0 {
		t.Errorf("first real packet has counter %d, want 0", c)
	}
}

func TestSendCountersIncrease(t *testing.T) {
	_, p := newPair()
	p.UpdateEndpoint(ap("1.2.3.4:1"))
	p0, _, _ := p.Send([]byte("a"))
	p1, _, _ := p.Send([]byte("a"))
	if counterOf(p0) != 0 || counterOf(p1) != 1 {
		t.Errorf("counters = %d, %d; want 0, 1", counterOf(p0), counterOf(p1))
	}
}

func TestSendFollowsRoaming(t *testing.T) {
	remote, p := newPair()
	A, B := ap("1.2.3.4:1000"), ap("5.6.7.8:2000")
	p.Receive(seal(t, remote, "from A"), A)
	if _, to, _ := p.Send([]byte("x")); to != A {
		t.Fatalf("sent to %v, want %v", to, A)
	}
	p.Receive(seal(t, remote, "from B"), B)
	if _, to, _ := p.Send([]byte("x")); to != B {
		t.Errorf("after roaming, sent to %v, want %v", to, B)
	}
}

// ---- keepalive ----

func TestKeepaliveIsAnEmptyAuthenticatedPacket(t *testing.T) {
	remote, p := newPair()
	p.UpdateEndpoint(ap("1.2.3.4:1"))

	packet, _, err := p.Send(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 24 { // 8-byte counter + 16-byte tag, no data
		t.Errorf("keepalive length = %d, want 24", len(packet))
	}
	got, err := remote.Open(packet)
	if err != nil {
		t.Fatalf("remote could not open the keepalive: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("keepalive carried %d bytes of data", len(got))
	}
}

func TestKeepaliveFromNewAddressRoams(t *testing.T) {
	remote, p := newPair()
	A, B := ap("1.2.3.4:1000"), ap("5.6.7.8:2000")
	p.Receive(seal(t, remote, "data"), A)

	keepalive, err := remote.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Receive(keepalive, B)
	if err != nil || len(got) != 0 {
		t.Fatalf("keepalive: %q %v", got, err)
	}
	if p.Endpoint() != B {
		t.Errorf("endpoint = %v, want %v", p.Endpoint(), B)
	}
}

// ---- concurrency (run with: go test -race) ----

func TestConcurrentEndpointAndSessionAccess(t *testing.T) {
	p := New("x", [32]byte{}, nil, netip.AddrPort{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); p.UpdateEndpoint(ap("1.2.3.4:1")) }()
		go func() { defer wg.Done(); _ = p.Endpoint() }()
		go func() { defer wg.Done(); p.SetSession(&crypto.Session{}) }()
		go func() { defer wg.Done(); _ = p.Session() }()
	}
	wg.Wait()
}
