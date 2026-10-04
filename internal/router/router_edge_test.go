package router

import (
	"net/netip"
	"testing"
)

func lookup(t *testing.T, tbl *Table, ip, want string, wantOK bool) {
	t.Helper()
	got, ok := tbl.Lookup(netip.MustParseAddr(ip))
	if got != want || ok != wantOK {
		t.Errorf("Lookup(%s) = %q,%v; want %q,%v", ip, got, ok, want, wantOK)
	}
}

func TestEdgeCases(t *testing.T) {
	tbl := New()
	for _, r := range [][2]string{
		{"host", "10.0.0.7/32"},
		{"net", "10.0.0.5/24"}, // host bits set: stored as 10.0.0.0/24
		{"first", "192.168.0.0/16"},
		{"second", "192.168.0.0/16"}, // duplicate prefix: first registered wins
	} {
		if err := tbl.Add(r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	lookup(t, tbl, "10.0.0.7", "host", true)
	lookup(t, tbl, "10.0.0.8", "net", true)
	lookup(t, tbl, "::ffff:10.0.0.8", "net", true) // IPv4-mapped
	lookup(t, tbl, "192.168.1.1", "first", true)
	lookup(t, tbl, "8.8.8.8", "", false)
}

func TestBadCIDR(t *testing.T) {
	if err := New().Add("x", "garbage"); err == nil {
		t.Error("expected an error for an invalid CIDR")
	}
}

func TestCatchAllOnly(t *testing.T) {
	tbl := New()
	if err := tbl.Add("catchall", "0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	lookup(t, tbl, "1.2.3.4", "catchall", true)
}
