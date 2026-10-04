// Package peer holds per-peer state.
//
// Course: Chapter 3, lessons "Peer Configuration" .. "NAT Traversal & Endpoints".
package peer

import (
	"net/netip"
	"sync"

	"vpntunnel/internal/crypto"
)

type Peer struct {
	Name       string
	PublicKey  [32]byte
	AllowedIPs []netip.Prefix // routes TO this peer, and the allowed SOURCES from it

	mu       sync.RWMutex
	endpoint netip.AddrPort // where to send UDP; may be unknown until the peer contacts us
	session  *crypto.Session
}

func New(name string, pub [32]byte, allowed []netip.Prefix, endpoint netip.AddrPort) *Peer {
	return &Peer{Name: name, PublicKey: pub, AllowedIPs: allowed, endpoint: endpoint}
}

func (p *Peer) Endpoint() netip.AddrPort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.endpoint
}

// UpdateEndpoint implements roaming: after a packet authenticates, remember the
// UDP source address it came from (NAT rebinding, laptop changed Wi-Fi...).
// Only call this AFTER the packet decrypted successfully.
func (p *Peer) UpdateEndpoint(ep netip.AddrPort) {
	p.mu.Lock()
	p.endpoint = ep
	p.mu.Unlock()
}

func (p *Peer) Session() *crypto.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.session
}

func (p *Peer) SetSession(s *crypto.Session) {
	p.mu.Lock()
	p.session = s
	p.mu.Unlock()
}

// SourceAllowed is the inbound half of cryptokey routing: after decryption,
// the inner packet's source IP must be inside this peer's AllowedIPs.
//
// TODO: loop over AllowedIPs and check Contains.
func (p *Peer) SourceAllowed(src netip.Addr) bool {
	_ = src
	return false
}
