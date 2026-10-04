package router

import (
	"net/netip"
	"testing"
)

func TestLongestPrefixMatch(t *testing.T) {
	tbl := New()
	for _, r := range [][2]string{
		{"alice", "10.0.0.0/24"},
		{"bob", "10.0.1.0/24"},
		{"catchall", "0.0.0.0/0"},
	} {
		if err := tbl.Add(r[0], r[1]); err != nil {
			t.Fatalf("Add(%s, %s): %v", r[0], r[1], err)
		}
	}
	cases := []struct{ ip, want string }{
		{"10.0.0.5", "alice"},
		{"10.0.1.5", "bob"},
		{"8.8.8.8", "catchall"},
	}
	for _, c := range cases {
		got, ok := tbl.Lookup(netip.MustParseAddr(c.ip))
		if !ok || got != c.want {
			t.Errorf("Lookup(%s) = %q, %v; want %q", c.ip, got, ok, c.want)
		}
	}
}

func TestNoRouteDrops(t *testing.T) {
	tbl := New()
	if err := tbl.Add("alice", "10.0.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if got, ok := tbl.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Errorf("expected DROP, got %q", got)
	}
}
