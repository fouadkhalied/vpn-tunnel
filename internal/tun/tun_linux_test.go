//go:build linux

package tun

import (
	"errors"
	"os"
	"strings"
	"testing"
	"unsafe"
)

// ---- tests that need no privileges ----

func TestIfreqSizeMatchesKernel(t *testing.T) {
	if got := unsafe.Sizeof(ifreq{}); got != 40 {
		t.Errorf("sizeof(ifreq) = %d, want 40", got)
	}
}

func TestNewIfreq(t *testing.T) {
	req, err := newIfreq("wg0")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(req.name[:4]); got != "wg0\x00" {
		t.Errorf("name bytes = %q, want %q", got, "wg0\x00")
	}
	if req.flags != iffTUN|iffNoPI {
		t.Errorf("flags = %#x, want %#x", req.flags, iffTUN|iffNoPI)
	}
	if got := req.ifName(); got != "wg0" {
		t.Errorf("ifName() = %q, want wg0", got)
	}
}

func TestNewIfreqNameLengths(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty lets the kernel choose", "", false},
		{"15 characters fit", strings.Repeat("a", 15), false},
		{"16 characters do not", strings.Repeat("a", 16), true},
		{"very long", strings.Repeat("a", 100), true},
		{"zero byte inside", "wg\x000", true},
	}
	for _, c := range cases {
		_, err := newIfreq(c.input)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
	if _, err := newIfreq(strings.Repeat("a", 16)); !errors.Is(err, ErrNameTooLong) {
		t.Errorf("16 chars: error = %v, want ErrNameTooLong", err)
	}
}

func TestIfNameStopsAtFirstZero(t *testing.T) {
	var req ifreq
	copy(req.name[:], "tun7\x00junk")
	if got := req.ifName(); got != "tun7" {
		t.Errorf("ifName() = %q, want tun7", got)
	}
	// a name that fills all 16 bytes has no zero to stop at
	copy(req.name[:], strings.Repeat("x", 16))
	if got := req.ifName(); len(got) != 16 {
		t.Errorf("full-width name length = %d, want 16", len(got))
	}
}

// Validation happens before the device is touched, so this needs no root.
func TestOpenRejectsLongNameWithoutTouchingTheKernel(t *testing.T) {
	if _, err := Open(strings.Repeat("a", 16)); !errors.Is(err, ErrNameTooLong) {
		t.Errorf("error = %v, want ErrNameTooLong", err)
	}
}

func TestOpenWithoutPrivilegeGivesHelpfulError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	d, err := Open("vpntest-np")
	if err == nil {
		d.Close()
		t.Skip("this user can create TUN devices")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("error %q should mention root / CAP_NET_ADMIN", err)
	}
}

// ---- tests that need root ----

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (run the compiled test binary with sudo)")
	}
}

func interfaceExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

func TestOpenCreatesAndCloseRemovesInterface(t *testing.T) {
	needRoot(t)
	d, err := Open("vpntest0")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if d.Name() != "vpntest0" {
		t.Errorf("Name() = %q, want vpntest0", d.Name())
	}
	if !interfaceExists("vpntest0") {
		t.Error("interface does not exist after Open")
	}
	if err := d.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if interfaceExists("vpntest0") {
		t.Error("interface still exists after Close")
	}
}

func TestOpenEmptyNameLetsKernelChoose(t *testing.T) {
	needRoot(t)
	d, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
	if !strings.HasPrefix(d.Name(), "tun") {
		t.Errorf("Name() = %q, want a name starting with tun", d.Name())
	}
	if !interfaceExists(d.Name()) {
		t.Errorf("interface %q does not exist", d.Name())
	}
}

func TestOpenSameNameTwiceFails(t *testing.T) {
	needRoot(t)
	first, err := Open("vpntest1")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	defer first.Close()
	second, err := Open("vpntest1")
	if err == nil {
		second.Close()
		t.Error("second Open with the same name succeeded")
	}
}
