package packet

import (
	"errors"
	"net/netip"
	"testing"
)

// A valid 20-byte IPv4 header: 10.0.0.2 -> 10.0.0.1, protocol 17 (UDP), total length 20.
var goodPacket = []byte{
	0x45, 0x00, 0x00, 0x14, // version 4, IHL 5 | tos | total length 20
	0x00, 0x00, 0x00, 0x00, // id, flags
	0x40, 0x11, 0x00, 0x00, // ttl | protocol 17 (UDP) | checksum
	10, 0, 0, 2, // source
	10, 0, 0, 1, // destination
}

// clone returns a copy so one test can't change the packet another test uses.
func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}

func TestParseIPv4Valid(t *testing.T) {
	h, err := ParseIPv4(goodPacket)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if h.Version != 4 {
		t.Errorf("Version = %d, want 4", h.Version)
	}
	if h.IHL != 5 {
		t.Errorf("IHL = %d, want 5", h.IHL)
	}
	if h.TotalLen != 20 {
		t.Errorf("TotalLen = %d, want 20", h.TotalLen)
	}
	if h.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17", h.Protocol)
	}
	if want := netip.MustParseAddr("10.0.0.2"); h.Src != want {
		t.Errorf("Src = %v, want %v", h.Src, want)
	}
	if want := netip.MustParseAddr("10.0.0.1"); h.Dst != want {
		t.Errorf("Dst = %v, want %v", h.Dst, want)
	}
}

func TestParseIPv4TooShort(t *testing.T) {
	for _, n := range []int{0, 1, 19} {
		if _, err := ParseIPv4(goodPacket[:n]); !errors.Is(err, ErrShortPacket) {
			t.Errorf("len %d: error = %v, want ErrShortPacket", n, err)
		}
	}
}

func TestParseIPv4NilInput(t *testing.T) {
	if _, err := ParseIPv4(nil); !errors.Is(err, ErrShortPacket) {
		t.Errorf("error = %v, want ErrShortPacket", err)
	}
}

func TestParseIPv4BadFirstByte(t *testing.T) {
	cases := []struct {
		name string
		b0   byte
		want error
	}{
		{"version 6", 0x65, ErrInvalidVersion},
		{"version 0", 0x05, ErrInvalidVersion},
		{"header longer than data (IHL 15 = 60 bytes)", 0x4F, ErrShortPacket},
		{"header below minimum (IHL 4 = 16 bytes)", 0x44, ErrShortPacket},
	}
	for _, c := range cases {
		p := clone(goodPacket)
		p[0] = c.b0
		if _, err := ParseIPv4(p); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", c.name, err, c.want)
		}
	}
}

// With IP options the header is longer than 20 bytes. The addresses are still
// at bytes 12-19, and the options must not be read as part of them.
func TestParseIPv4WithOptions(t *testing.T) {
	p := clone(goodPacket)
	p[0] = 0x46               // IHL 6 = 24-byte header
	p[3] = 24                 // total length 24
	p = append(p, 9, 9, 9, 9) // 4 option bytes
	h, err := ParseIPv4(p)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if h.IHL != 6 {
		t.Errorf("IHL = %d, want 6", h.IHL)
	}
	if want := netip.MustParseAddr("10.0.0.1"); h.Dst != want {
		t.Errorf("Dst = %v, want %v", h.Dst, want)
	}
}

func TestParseIPv4AddressesAreNotMixedUp(t *testing.T) {
	p := clone(goodPacket)
	copy(p[12:16], []byte{192, 168, 1, 7})
	copy(p[16:20], []byte{8, 8, 4, 4})
	h, err := ParseIPv4(p)
	if err != nil {
		t.Fatal(err)
	}
	if h.Src != netip.MustParseAddr("192.168.1.7") || h.Dst != netip.MustParseAddr("8.8.4.4") {
		t.Errorf("Src/Dst = %v / %v", h.Src, h.Dst)
	}
}

func TestParseIPv4TotalLenIsBigEndian(t *testing.T) {
	p := append(clone(goodPacket), make([]byte, 236)...) // 256 bytes of data
	p[2], p[3] = 0x01, 0x00                              // total length 256, not 1
	h, err := ParseIPv4(p)
	if err != nil {
		t.Fatal(err)
	}
	if h.TotalLen != 256 {
		t.Errorf("TotalLen = %d, want 256", h.TotalLen)
	}
}
