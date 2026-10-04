// Package device ties everything together: the two packet loops.
//
//	outbound: TUN -> parse -> route lookup -> encrypt -> UDP
//	inbound:  UDP -> find peer -> decrypt -> check AllowedIPs -> TUN
//
// Course: Chapter 1 (loop), Chapter 3 (routing), Chapter 4 (performance).
package device

import (
	"context"
	"net"

	"vpntunnel/internal/packet"
	"vpntunnel/internal/peer"
	"vpntunnel/internal/router"
	"vpntunnel/internal/tun"
)

const maxPacket = 65536

type Device struct {
	tun    *tun.Device
	conn   *net.UDPConn
	routes *router.Table
	peers  map[string]*peer.Peer
}

func New(t *tun.Device, c *net.UDPConn, r *router.Table, peers []*peer.Peer) *Device {
	m := make(map[string]*peer.Peer, len(peers))
	for _, p := range peers {
		m[p.Name] = p
	}
	return &Device{tun: t, conn: c, routes: r, peers: m}
}

// Run starts both loops and returns when one fails or ctx is cancelled.
func (d *Device) Run(ctx context.Context) error {
	errc := make(chan error, 2)
	go func() { errc <- d.tunToUDP() }()
	go func() { errc <- d.udpToTun() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func (d *Device) tunToUDP() error {
	buf := make([]byte, maxPacket)
	for {
		n, err := d.tun.Read(buf)
		if err != nil {
			return err
		}
		hdr, err := packet.ParseIPv4(buf[:n])
		if err != nil {
			continue // not IPv4 / malformed: drop
		}
		name, ok := d.routes.Lookup(hdr.Dst)
		if !ok {
			continue // no route: DROP
		}
		p := d.peers[name]
		_ = p
		// TODO:
		//  1. sess := p.Session(); if nil, trigger a handshake and queue/drop
		//  2. enc, err := sess.Seal(buf[:n])
		//  3. d.conn.WriteToUDPAddrPort(enc, p.Endpoint())
	}
}

func (d *Device) udpToTun() error {
	buf := make([]byte, maxPacket)
	for {
		n, from, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		_, _ = n, from
		// TODO:
		//  1. identify the message type (handshake vs data) and the peer/session
		//  2. inner, err := sess.Open(buf[:n]); drop on error (and never reply!)
		//  3. hdr, _ := packet.ParseIPv4(inner); drop unless p.SourceAllowed(hdr.Src)
		//  4. p.UpdateEndpoint(from)  // roaming, only after successful auth
		//  5. d.tun.Write(inner)
	}
}
