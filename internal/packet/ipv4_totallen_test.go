package packet

import (
	"errors"
	"testing"
)

func TestParseIPv4TotalLenSmallerThanHeader(t *testing.T) {
	p := clone(goodPacket)
	p[3] = 10 // total length 10, but the header alone is 20
	if _, err := ParseIPv4(p); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("error = %v, want ErrInvalidLength", err)
	}
}

func TestParseIPv4TotalLenLargerThanData(t *testing.T) {
	p := clone(goodPacket)
	p[3] = 100 // claims 100 bytes, only 20 present: truncated
	if _, err := ParseIPv4(p); !errors.Is(err, ErrShortPacket) {
		t.Errorf("error = %v, want ErrShortPacket", err)
	}
}

func TestParseIPv4PaddingAfterPacketIsAllowed(t *testing.T) {
	p := append(clone(goodPacket), make([]byte, 12)...) // 32 bytes, total length still 20
	if _, err := ParseIPv4(p); err != nil {
		t.Errorf("padded packet rejected: %v", err)
	}
}
