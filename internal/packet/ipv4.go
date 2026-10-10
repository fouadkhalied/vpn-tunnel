// Package packet parses just enough of an IP packet to route it.
//
// Course: Chapter 1, lesson "Tunnel Encapsulation".
package packet

import (
	"encoding/binary"
	"net/netip"
)

const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
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

func ParseIPv4(b []byte) (IPv4Header, error) {
	if len(b) < 20 {
		return IPv4Header{}, ErrShortPacket
	}

	version := b[0] >> 4
	ihl := b[0] & 0x0f

	if version != 4 {
		return IPv4Header{}, ErrInvalidVersion
	}

	headerLen := int(ihl) * 4
	if headerLen < 20 || len(b) < headerLen {
		return IPv4Header{}, ErrShortPacket
	}

	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < headerLen {
		return IPv4Header{}, ErrInvalidLength
	}
	if total > len(b) {
		return IPv4Header{}, ErrShortPacket
	}

	return IPv4Header{
		Version:  version,
		IHL:      ihl,
		TotalLen: binary.BigEndian.Uint16(b[2:4]),
		Protocol: b[9],
		Src:      netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}),
		Dst:      netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]}),
	}, nil
}
