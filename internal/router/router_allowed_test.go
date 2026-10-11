package router

import (
	"net/netip"
	"testing"
)

func aliceBob(t *testing.T) *Table {
	t.Helper()
	tbl := New()
	for _, r := range [][2]string{{"alice", "10.0.0.0/24"}, {"bob", "10.0.0.128/25"}} {
		if err := tbl.Add(r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	return tbl
}

func allowed(tbl *Table, peer, ip string) bool {
	return tbl.Allowed(peer, netip.MustParseAddr(ip))
}

func TestAllowedOwnAddress(t *testing.T) {
	tbl := aliceBob(t)
	if !allowed(tbl, "alice", "10.0.0.5") {
		t.Error("alice should be allowed her own address 10.0.0.5")
	}
	if !allowed(tbl, "bob", "10.0.0.200") {
		t.Error("bob should be allowed 10.0.0.200")
	}
}

// The lesson's trap: alice's /24 contains 10.0.0.200, but bob's /25 owns it.
func TestAllowedRejectsAddressOwnedByMoreSpecificPeer(t *testing.T) {
	tbl := aliceBob(t)
	if allowed(tbl, "alice", "10.0.0.200") {
		t.Error("alice must not be allowed 10.0.0.200: the best match is bob")
	}
}

func TestAllowedRejectsOtherPeersAddress(t *testing.T) {
	tbl := aliceBob(t)
	if allowed(tbl, "bob", "10.0.0.5") {
		t.Error("bob must not be allowed 10.0.0.5: it belongs to alice")
	}
}

func TestAllowedUnknownAddressAndUnknownPeer(t *testing.T) {
	tbl := aliceBob(t)
	if allowed(tbl, "alice", "8.8.8.8") {
		t.Error("nobody owns 8.8.8.8")
	}
	if allowed(tbl, "carol", "10.0.0.5") {
		t.Error("an unknown peer is never allowed")
	}
	if allowed(New(), "alice", "10.0.0.5") {
		t.Error("an empty table allows nothing")
	}
}

func TestAllowedIPv4MappedAddress(t *testing.T) {
	tbl := aliceBob(t)
	if !allowed(tbl, "alice", "::ffff:10.0.0.5") {
		t.Error("::ffff:10.0.0.5 is 10.0.0.5")
	}
}

func TestAllowedCatchAllDoesNotStealMoreSpecificBlocks(t *testing.T) {
	tbl := New()
	tbl.Add("server", "0.0.0.0/0")
	tbl.Add("alice", "10.0.0.2/32")
	if !allowed(tbl, "server", "8.8.8.8") {
		t.Error("server owns everything else")
	}
	if allowed(tbl, "server", "10.0.0.2") {
		t.Error("server must not be allowed alice's /32")
	}
	if !allowed(tbl, "alice", "10.0.0.2") {
		t.Error("alice owns 10.0.0.2")
	}
}

// Step 1 of the plan: when two peers claim exactly the same block, the later one owns it.
func TestLaterPeerTakesIdenticalBlock(t *testing.T) {
	tbl := New()
	tbl.Add("first", "10.1.0.0/16")
	tbl.Add("second", "10.1.0.0/16")
	if got, _ := tbl.Lookup(netip.MustParseAddr("10.1.2.3")); got != "second" {
		t.Errorf("Lookup = %q, want second", got)
	}
	if allowed(tbl, "first", "10.1.2.3") {
		t.Error("first lost the block and must not be allowed")
	}
	if !allowed(tbl, "second", "10.1.2.3") {
		t.Error("second owns the block")
	}
}
