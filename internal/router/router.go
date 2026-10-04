// Package router decides which peer receives a packet (cryptokey routing).
//
// Course: the "Routing Decision" exercise (longest-prefix match).
package router

import (
	"fmt"
	"net/netip"
)

type route struct {
	peer   string
	prefix netip.Prefix
}

// Table maps destination IPs to peer names.
type Table struct {
	routes []route
}

func New() *Table { return &Table{} }

// Add registers peer for the CIDR block, e.g. Add("alice", "10.0.0.0/24").
func (t *Table) Add(peer, cidr string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("router: bad CIDR %q: %w", cidr, err)
	}
	// Zero the host bits so "10.0.0.5/24" is stored as "10.0.0.0/24".
	t.routes = append(t.routes, route{peer: peer, prefix: p.Masked()})
	return nil
}

// Lookup returns the peer with the longest matching prefix, or ok=false (DROP).
func (t *Table) Lookup(dst netip.Addr) (peer string, ok bool) {
	dst = dst.Unmap() // treat ::ffff:10.0.0.5 as 10.0.0.5
	best := -1        // -1 means "no match yet", so a /0 route (0 bits) can still win
	for _, r := range t.routes {
		if !r.prefix.Contains(dst) {
			continue
		}
		if bits := r.prefix.Bits(); bits > best {
			best = bits
			peer = r.peer
			ok = true
		}
	}
	return peer, ok
}
