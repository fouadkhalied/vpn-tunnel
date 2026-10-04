package crypto

import (
	"math/rand"
	"testing"
)

func accept(w *ReplayWindow, c uint64) bool {
	if !w.Check(c) {
		return false
	}
	w.Update(c)
	return true
}

func TestLocate(t *testing.T) {
	var w ReplayWindow
	cases := []struct {
		counter uint64
		word    int
		mask    uint64
	}{
		{0, 0, 1}, {63, 0, 1 << 63}, {64, 1, 1}, {2047, 31, 1 << 63}, {2048, 0, 1},
	}
	for _, c := range cases {
		word, mask := w.locate(c.counter)
		if word != c.word || mask != c.mask {
			t.Errorf("locate(%d) = %d,%#x want %d,%#x", c.counter, word, mask, c.word, c.mask)
		}
	}
}

func TestSequence(t *testing.T) {
	var w ReplayWindow
	for _, s := range []struct {
		c    uint64
		want bool
	}{{1, true}, {2, true}, {5, true}, {4, true}, {4, false}, {0, true}, {0, false}} {
		if got := accept(&w, s.c); got != s.want {
			t.Errorf("accept(%d) = %v want %v", s.c, got, s.want)
		}
	}
}

func TestFirstPacketZero(t *testing.T) {
	var w ReplayWindow
	if !w.Check(0) {
		t.Error("first packet 0 must be acceptable")
	}
	w.Update(0)
	if w.Check(0) {
		t.Error("duplicate 0 must be rejected")
	}
}

func TestWindowEdge(t *testing.T) {
	var w ReplayWindow
	accept(&w, 2048)
	if w.Check(0) {
		t.Error("0 is exactly at the edge: reject")
	}
	if !w.Check(1) {
		t.Error("1 is just inside: accept")
	}
}

func TestStaleSlotsCleared(t *testing.T) {
	var w ReplayWindow
	accept(&w, 10)
	accept(&w, 2058) // 10 and 2058 share a slot
	if w.Check(10) {
		t.Error("10 is too old now")
	}
	if !w.Check(2057) || !w.Check(2058-2047) {
		t.Error("fresh in-window counters must be acceptable")
	}
	if w.Check(2058) {
		t.Error("2058 was just accepted: reject duplicate")
	}
}

func TestBigJump(t *testing.T) {
	var w ReplayWindow
	accept(&w, 5)
	accept(&w, 5000)
	if w.Check(5) {
		t.Error("5 is too old after a big jump")
	}
	if !w.Check(4999) {
		t.Error("4999 is inside the window and unseen")
	}
}

func TestCheckDoesNotMutate(t *testing.T) {
	var w ReplayWindow
	w.Check(100)
	w.Check(100)
	if !w.Check(100) {
		t.Error("Check must not record anything")
	}
}

// reference: the simple map version
type refWindow struct {
	highest int64
	seen    map[int64]bool
}

func (r *refWindow) accept(c int64) bool {
	n := int64(DefaultWindowSize)
	if c > r.highest {
		r.highest = c
		r.seen[c] = true
		return true
	}
	if c > r.highest-n && !r.seen[c] {
		r.seen[c] = true
		return true
	}
	return false
}

func TestAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 200; trial++ {
		var w ReplayWindow
		ref := &refWindow{highest: -1, seen: map[int64]bool{}}
		base := int64(0)
		for i := 0; i < 5000; i++ {
			var c int64
			switch rng.Intn(4) {
			case 0:
				base += int64(rng.Intn(5))
				c = base
			case 1:
				c = base - int64(rng.Intn(3000))
			case 2:
				base += int64(rng.Intn(4000))
				c = base
			default:
				c = base - int64(rng.Intn(20))
			}
			if c < 0 {
				c = 0
			}
			if got, want := accept(&w, uint64(c)), ref.accept(c); got != want {
				t.Fatalf("trial %d step %d counter %d: got %v want %v", trial, i, c, got, want)
			}
		}
	}
}
