// Package packet parses just enough of an IP packet to route it.
//
// Course: Chapter 1, lesson "Tunnel Encapsulation".
package packet

import (
	"errors"
	"net/netip"
)

const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrShortPacket    = errors.New("packet too short")
)

// IPv4Header holds the fields the VPN cares about.
type IPv4Header struct {
	Version  uint8
	IHL      uint8 // header length in 32-bit words
	TotalLen uint16
	Protocol uint8
	Src, Dst netip.Addr
}

// ParseIPv4 reads the header of an IPv4 packet.
//
// TODO:
//   - byte 0: version (high nibble) and IHL (low nibble)
//   - bytes 2-3: total length (big endian)
//   - byte 9: protocol
//   - bytes 12-15 source, 16-19 destination (netip.AddrFrom4)
//   - return ErrShortPacket if len(b) < 20 or < IHL*4
//   - reject Version != 4 (IPv6 can come later)
func ParseIPv4(b []byte) (IPv4Header, error) {
	_ = b
	return IPv4Header{}, ErrNotImplemented
}
